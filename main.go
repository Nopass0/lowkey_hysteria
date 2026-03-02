package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/joho/godotenv"
	"github.com/quic-go/quic-go"
	"github.com/redis/go-redis/v9"
	"github.com/songgao/water"
	"github.com/vmihailenco/msgpack/v5"
)

// ---------------------------------------------------------
// Config & Globals
// ---------------------------------------------------------

var (
	ListenAddr string
	Port       = 7000
	ServerIP   string // auto-detected

	db  *pgxpool.Pool
	rdb *redis.Client

	tunDev *water.Interface
	clients = make(map[string]*quic.Conn)
	clientsMu sync.RWMutex
)

func loadConfig() {
	_ = godotenv.Load()

	ListenAddr = getenv("LISTEN_ADDR", ":7000")

	if addr, err := net.ResolveUDPAddr("udp", ListenAddr); err == nil && addr.Port != 0 {
		Port = addr.Port
	}

	ServerIP = detectPublicIP()
	log.Printf("[Config] ListenAddr=%s | PublicIP=%s", ListenAddr, ServerIP)
}

func getenv(key, fallback string) string {
	if v, ok := os.LookupEnv(key); ok && v != "" {
		return v
	}
	return fallback
}

func detectPublicIP() string {
	services := []string{
		"https://api.ipify.org",
		"https://ifconfig.me/ip",
		"https://icanhazip.com",
		"https://checkip.amazonaws.com",
	}
	client := &http.Client{Timeout: 5 * time.Second}
	for _, svc := range services {
		resp, err := client.Get(svc)
		if err != nil {
			continue
		}
		var buf [64]byte
		n, _ := resp.Body.Read(buf[:])
		resp.Body.Close()
		if n > 0 {
			if ip := strings.TrimSpace(string(buf[:n])); ip != "" {
				log.Printf("[Config] Public IP detected via %s: %s", svc, ip)
				return ip
			}
		}
	}
	return "127.0.0.1"
}

// ---------------------------------------------------------
// TUN Interface & Management
// ---------------------------------------------------------

func initTUN() {
	config := water.Config{
		DeviceType: water.TUN,
	}
	
	iface, err := water.New(config)
	if err != nil {
		log.Printf("[TUN] Failed to create TUN: %v. Running in auth-only mode.", err)
		return
	}
	tunDev = iface
	ifaceName := iface.Name()
	log.Printf("[TUN] Created interface: %s", ifaceName)

	// Bring UP and set IP (Linux specific)
	_ = exec.Command("ip", "addr", "add", "172.20.0.1/24", "dev", ifaceName).Run()
	_ = exec.Command("ip", "link", "set", ifaceName, "up").Run()

	go forwardTUNToQUIC()
}

func forwardTUNToQUIC() {
	buf := make([]byte, 2000)
	for {
		n, err := tunDev.Read(buf)
		if err != nil {
			log.Printf("[TUN] Read error: %v", err)
			break
		}
		packet := buf[:n]
		if len(packet) < 20 {
			continue
		}
		
		// Parse destination IP (simplistic IPv4 parser)
		destIP := net.IP(packet[16:20]).String()
		
		clientsMu.RLock()
		conn, ok := clients[destIP]
		clientsMu.RUnlock()
		
		if ok {
			_ = conn.SendDatagram(packet)
		}
	}
}

// ---------------------------------------------------------
// Database & Redis
// ---------------------------------------------------------

func initDB() {
	dsn := getenv("DATABASE_URL", "postgres://postgres:postgres@localhost:5432/lowkey")
	pool, err := pgxpool.New(context.Background(), dsn)
	if err != nil {
		log.Fatalf("[DB] Failed to connect to PostgreSQL: %v", err)
	}
	db = pool
	log.Println("[DB] Connected to PostgreSQL ✓")
}

func initRedis() {
	opt, err := redis.ParseURL(getenv("REDIS_URL", "redis://localhost:6379"))
	if err != nil {
		log.Fatalf("[Redis] Invalid REDIS_URL: %v", err)
	}
	rdb = redis.NewClient(opt)
	log.Println("[Redis] Connected ✓")
}

// ---------------------------------------------------------
// Server Registration & Heartbeat
// ---------------------------------------------------------

var serverId string

func registerServerDB() {
	protocols := []string{"hysteria2"}
	for {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		var id string
		err := db.QueryRow(ctx, `
			INSERT INTO vpn_servers (id, ip, port, "supportedProtocols", "serverType", status, "currentLoad", "lastSeenAt", "createdAt")
			VALUES (gen_random_uuid(), $1, $2, $3, 'dedicated', 'online', 0, NOW(), NOW())
			ON CONFLICT (ip, port)
			DO UPDATE SET status = 'online', "lastSeenAt" = NOW()
			RETURNING id
		`, ServerIP, Port, protocols).Scan(&id)
		cancel()

		if err == nil {
			serverId = id
			log.Printf("[Server] Registered as %s", serverId)
			return
		}
		log.Printf("[Server] Registration failed: %v — retrying in 10s...", err)
		time.Sleep(10 * time.Second)
	}
}

func startHeartbeatDB() {
	for range time.Tick(30 * time.Second) {
		if serverId == "" {
			continue
		}
		inc := loadCount()
		_, _ = db.Exec(context.Background(), `
			UPDATE vpn_servers SET "currentLoad" = $1, "lastSeenAt" = NOW(), status = 'online'
			WHERE id = $2
		`, inc, serverId)
	}
}

// ---------------------------------------------------------
// Native Hysteria2 Handshake
// ---------------------------------------------------------

type ClientHello struct {
	Auth    string `msgpack:"auth"`
	Rx      uint64 `msgpack:"rx"`
	Tx      uint64 `msgpack:"tx"`
	Padding []byte `msgpack:"padding"`
}

type ServerHello struct {
	Ok  bool   `msgpack:"ok"`
	Msg string `msgpack:"msg"`
	Id  uint32 `msgpack:"id"`
	Rx  uint64 `msgpack:"rx"`
	IP  string `msgpack:"ip"`
}

type IPPool struct {
	mu        sync.Mutex
	available []string
	used      map[string]bool
}

func newIPPool(subnet string) *IPPool {
	p := &IPPool{
		used: make(map[string]bool),
	}
	// Simplified: fill 172.20.0.2 - 172.20.0.254
	for i := 2; i < 255; i++ {
		p.available = append(p.available, fmt.Sprintf("172.20.0.%d", i))
	}
	return p
}

func (p *IPPool) Acquire() (string, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.available) == 0 {
		return "", false
	}
	ip := p.available[0]
	p.available = p.available[1:]
	p.used[ip] = true
	return ip, true
}

func (p *IPPool) Release(ip string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.used[ip] {
		delete(p.used, ip)
		p.available = append(p.available, ip)
	}
}

var vips = newIPPool("172.20.0.0/24")

var connCount struct {
	sync.Mutex
	n int
}

func incConn() { connCount.Lock(); connCount.n++; connCount.Unlock() }
func decConn() { connCount.Lock(); connCount.n--; connCount.Unlock() }
func loadCount() int { connCount.Lock(); defer connCount.Unlock(); return connCount.n }

func handleQUICConnection(conn *quic.Conn) {
	defer conn.CloseWithError(0, "closed")
	log.Printf("[QUIC] New connection from %s", conn.RemoteAddr())

	// 1. Handshake over a stream
	stream, err := conn.AcceptStream(context.Background())
	if err != nil {
		log.Printf("[QUIC] Failed to accept stream: %v", err)
		return
	}
	defer stream.Close()

	var hello ClientHello
	dec := msgpack.NewDecoder(stream)
	if err := dec.Decode(&hello); err != nil {
		return
	}

	authRes := authenticateVpnToken(hello.Auth)
	
	// 2. Allocate VIP
	var clientVIP string
	if authRes.ok {
		var ok bool
		clientVIP, ok = vips.Acquire()
		if !ok {
			authRes.ok = false
			authRes.reason = "ip pool exhausted"
		}
	}

	resp := ServerHello{
		Ok: authRes.ok, 
		Id: 1,
		IP: clientVIP,
	}
	if !authRes.ok {
		resp.Msg = authRes.reason
	}
	_ = msgpack.NewEncoder(stream).Encode(resp)

	if !authRes.ok {
		return
	}

	// 3. Register for routing
	clientsMu.Lock()
	clients[clientVIP] = conn
	clientsMu.Unlock()
	defer func() {
		clientsMu.Lock()
		delete(clients, clientVIP)
		clientsMu.Unlock()
		vips.Release(clientVIP)
	}()

	incConn()
	defer decConn()

	// 4. Forward QUIC -> TUN
	for {
		data, err := conn.ReceiveDatagram(context.Background())
		if err != nil {
			break
		}
		if tunDev != nil {
			_, _ = tunDev.Write(data)
		}
	}
}

func authenticateVpnToken(token string) authResult {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	if n, _ := rdb.Exists(ctx, "token:blocklist:"+token).Result(); n > 0 {
		return authResult{reason: "token revoked"}
	}

	var (
		userId    string
		expiresAt time.Time
	)
	err := db.QueryRow(ctx, `
		SELECT "userId", "expiresAt"
		FROM vpn_tokens
		WHERE token = $1
	`, token).Scan(&userId, &expiresAt)
	if err != nil {
		return authResult{reason: "token not found"}
	}
	if time.Now().After(expiresAt) {
		return authResult{reason: "token expired"}
	}

	var isLifetime bool
	var activeUntil time.Time
	err = db.QueryRow(ctx, `
		SELECT "isLifetime", "activeUntil"
		FROM subscriptions
		WHERE "userId" = $1
	`, userId).Scan(&isLifetime, &activeUntil)
	if err != nil {
		return authResult{reason: "no subscription"}
	}
	if !isLifetime && time.Now().After(activeUntil) {
		return authResult{reason: "subscription expired"}
	}

	return authResult{ok: true, userId: userId}
}

type authResult struct {
	ok     bool
	userId string
	reason string
}

// ---------------------------------------------------------
// TLS Helpers
// ---------------------------------------------------------

func generateSelfSignedCert() (tls.Certificate, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{Organization: []string{"Lowkey VPN"}},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &priv.PublicKey, priv)
	if err != nil {
		return tls.Certificate{}, err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	privBytes, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return tls.Certificate{}, err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: privBytes})
	return tls.X509KeyPair(certPEM, keyPEM)
}

// ---------------------------------------------------------
// Main
// ---------------------------------------------------------

func main() {
	log.Println("[Lowkey] Starting Native Hysteria2 Server...")

	loadConfig()
	initDB()
	initRedis()
	
	initTUN() 
	
	registerServerDB()
	go startHeartbeatDB()

	cert, err := generateSelfSignedCert()
	if err != nil {
		log.Fatalf("Failed to generate cert: %v", err)
	}

	tlsConf := &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"lowkey-vpn"},
	}

	quicConf := &quic.Config{
		EnableDatagrams: true,
		KeepAlivePeriod: 10 * time.Second,
	}

	listener, err := quic.ListenAddr(ListenAddr, tlsConf, quicConf)
	if err != nil {
		log.Fatalf("Failed to listen: %v", err)
	}
	log.Printf("[Server] Listening on %s...", ListenAddr)

	for {
		conn, err := listener.Accept(context.Background())
		if err != nil {
			log.Printf("[Server] Accept failed: %v", err)
			continue
		}
		go handleQUICConnection(conn)
	}
}
