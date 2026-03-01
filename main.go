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
	"strings"
	"sync"
	"time"

	"github.com/apernet/hysteria/core/v2/server"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/joho/godotenv"
	"github.com/redis/go-redis/v9"
	"golang.org/x/crypto/bcrypt"
)

// ---------------------------------------------------------
// Config
// ---------------------------------------------------------

var (
	ListenAddr string
	Port       = 7000
	ServerIP   string // auto-detected

	db  *pgxpool.Pool
	rdb *redis.Client
)

func loadConfig() {
	_ = godotenv.Load()

	ListenAddr = getenv("LISTEN_ADDR", ":7000")

	if addr, err := net.ResolveTCPAddr("tcp", ListenAddr); err == nil && addr.Port != 0 {
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

// detectPublicIP tries several public IP services in order.
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
	log.Println("[Config] WARNING: could not detect public IP, using 127.0.0.1")
	return "127.0.0.1"
}

// ---------------------------------------------------------
// Database connections
// ---------------------------------------------------------

func initDB() {
	dsn := getenv("DATABASE_URL", "postgres://postgres:postgres@localhost:5432/lowkey")
	pool, err := pgxpool.New(context.Background(), dsn)
	if err != nil {
		log.Fatalf("[DB] Failed to connect to PostgreSQL: %v", err)
	}
	if err := pool.Ping(context.Background()); err != nil {
		log.Fatalf("[DB] PostgreSQL ping failed: %v", err)
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
	if err := rdb.Ping(context.Background()).Err(); err != nil {
		log.Fatalf("[Redis] Ping failed: %v", err)
	}
	log.Println("[Redis] Connected ✓")
}

// ---------------------------------------------------------
// Server registration & heartbeat — direct to PostgreSQL
// ---------------------------------------------------------

// serverId holds the UUID of this server row in vpn_servers.
var serverId string

// registerServerDB upserts this node into vpn_servers by (ip, port).
// If a row with the same IP+port exists it is reused; otherwise a new row is created.
// Retries forever until the DB is reachable.
func registerServerDB() {
	log.Println("[Server] Registering in vpn_servers via PostgreSQL...")
	protocols := []string{"hysteria2"}

	for {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)

		var id string
		err := db.QueryRow(ctx, `
			INSERT INTO vpn_servers (ip, port, "supportedProtocols", "serverType", status, "currentLoad", "lastSeenAt", "createdAt")
			VALUES ($1, $2, $3, 'dedicated', 'online', 0, NOW(), NOW())
			ON CONFLICT (ip, port)
			DO UPDATE SET
				status        = 'online',
				"currentLoad" = 0,
				"lastSeenAt"  = NOW()
			RETURNING id
		`, ServerIP, Port, protocols).Scan(&id)
		cancel()

		if err != nil {
			log.Printf("[Server] Registration failed: %v — retrying in 10s...", err)
			time.Sleep(10 * time.Second)
			continue
		}

		serverId = id
		log.Printf("[Server] Registered/updated as %s", serverId)
		return
	}
}

// startHeartbeatDB updates currentLoad and lastSeenAt every 30 seconds directly in PostgreSQL.
func startHeartbeatDB() {
	ticker := time.NewTicker(30 * time.Second)
	for range ticker.C {
		if serverId == "" {
			continue
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		n := loadCount()
		_, err := db.Exec(ctx, `
			UPDATE vpn_servers
			SET "currentLoad" = $1, "lastSeenAt" = NOW(), status = 'online'
			WHERE id = $2
		`, n, serverId)
		cancel()

		if err != nil {
			log.Printf("[Server] Heartbeat DB update failed: %v", err)
		} else {
			log.Printf("[Server] Heartbeat: load=%d", n)
		}
	}
}

// markServerOffline sets status = 'offline' on clean shutdown.
func markServerOffline() {
	if serverId == "" {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_, _ = db.Exec(ctx, `UPDATE vpn_servers SET status='offline' WHERE id=$1`, serverId)
	log.Println("[Server] Marked offline in DB.")
}

// ---------------------------------------------------------
// Session cache — avoids repeated DB queries per packet
// ---------------------------------------------------------

type sessionEntry struct {
	userId    string
	expiresAt time.Time
}

type sessionCache struct {
	mu    sync.RWMutex
	store map[string]sessionEntry
}

var cache = &sessionCache{store: make(map[string]sessionEntry)}

func init() {
	go func() {
		for range time.Tick(5 * time.Minute) {
			now := time.Now()
			cache.mu.Lock()
			for k, v := range cache.store {
				if now.After(v.expiresAt) {
					delete(cache.store, k)
				}
			}
			cache.mu.Unlock()
		}
	}()
}

func (sc *sessionCache) get(key string) (sessionEntry, bool) {
	sc.mu.RLock()
	defer sc.mu.RUnlock()
	e, ok := sc.store[key]
	if ok && time.Now().Before(e.expiresAt) {
		return e, true
	}
	return sessionEntry{}, false
}

func (sc *sessionCache) set(key string, e sessionEntry) {
	sc.mu.Lock()
	defer sc.mu.Unlock()
	sc.store[key] = e
}

// ---------------------------------------------------------
// Direct PostgreSQL authentication
// ---------------------------------------------------------

type authResult struct {
	ok     bool
	userId string
	reason string
}

// authenticateLoginPassword verifies login+password against PostgreSQL,
// then checks subscription validity.
func authenticateLoginPassword(login, password string) authResult {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var (
		userId       string
		passwordHash string
		isBanned     bool
	)
	err := db.QueryRow(ctx, `
		SELECT id, "passwordHash", "isBanned"
		FROM users
		WHERE login = $1
	`, login).Scan(&userId, &passwordHash, &isBanned)
	if err != nil {
		return authResult{reason: fmt.Sprintf("user not found: %v", err)}
	}
	if isBanned {
		return authResult{reason: "user is banned"}
	}
	if err := bcrypt.CompareHashAndPassword([]byte(passwordHash), []byte(password)); err != nil {
		return authResult{reason: "wrong password"}
	}

	return checkSubscription(ctx, userId)
}

// checkSubscription verifies the user has an active subscription.
func checkSubscription(ctx context.Context, userId string) authResult {
	var isLifetime bool
	var activeUntil time.Time

	err := db.QueryRow(ctx, `
		SELECT "isLifetime", "activeUntil"
		FROM subscriptions
		WHERE "userId" = $1
	`, userId).Scan(&isLifetime, &activeUntil)
	if err != nil {
		return authResult{reason: "no subscription"}
	}
	if !isLifetime && time.Now().After(activeUntil) {
		return authResult{reason: fmt.Sprintf("subscription expired at %s", activeUntil.Format(time.RFC3339))}
	}
	return authResult{ok: true, userId: userId}
}

// authenticateVpnToken verifies a pre-issued VPN token using the DB and checks Redis blocklist.
func authenticateVpnToken(token string) authResult {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	// Redis blocklist fast-path
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

	subCtx, subCancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer subCancel()
	return checkSubscription(subCtx, userId)
}

// ---------------------------------------------------------
// Active connection counter
// ---------------------------------------------------------

var connCount struct {
	sync.Mutex
	n int
}

func incConn() { connCount.Lock(); connCount.n++; connCount.Unlock() }
func decConn() { connCount.Lock(); connCount.n--; connCount.Unlock() }
func loadCount() int { connCount.Lock(); defer connCount.Unlock(); return connCount.n }

// ---------------------------------------------------------
// Hysteria2 Authenticator
// Supports two auth string formats:
//   1. "login:password"  — verified directly against PostgreSQL
//   2. "<vpn-token>"     — verified via vpn_tokens table + Redis blocklist
// ---------------------------------------------------------

type ApiAuthenticator struct{}

func (a *ApiAuthenticator) Authenticate(addr net.Addr, auth string, tx uint64) (ok bool, id string) {
	// Fast path: session cache
	if entry, hit := cache.get(auth); hit {
		log.Printf("[Auth] Cache hit → user %s from %s", entry.userId, addr)
		return true, entry.userId
	}

	var result authResult
	if strings.Contains(auth, ":") {
		parts := strings.SplitN(auth, ":", 2)
		log.Printf("[Auth] Login attempt for %q from %s", parts[0], addr)
		result = authenticateLoginPassword(parts[0], parts[1])
	} else {
		log.Printf("[Auth] VPN token auth from %s", addr)
		result = authenticateVpnToken(auth)
	}

	if !result.ok {
		log.Printf("[Auth] Rejected from %s: %s", addr, result.reason)
		return false, ""
	}

	cache.set(auth, sessionEntry{
		userId:    result.userId,
		expiresAt: time.Now().Add(5 * time.Minute),
	})

	incConn()
	log.Printf("[Auth] Accepted → user %s from %s", result.userId, addr)
	return true, result.userId
}

// ---------------------------------------------------------
// Self-signed TLS certificate
// ---------------------------------------------------------

func generateSelfSignedCert() (tls.Certificate, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	tmpl := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{Organization: []string{"Lowkey VPN"}},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
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
	log.Println("[Lowkey] Starting Hysteria2 VPN Server (standalone mode)...")

	// 1. Load config + detect public IP
	loadConfig()

	// 2. Connect to PostgreSQL and Redis
	initDB()
	initRedis()
	defer db.Close()
	defer markServerOffline()

	// 3. Register this server directly in PostgreSQL, then start heartbeat
	registerServerDB()
	go startHeartbeatDB()

	// 4. Generate TLS cert
	tlsCert, err := generateSelfSignedCert()
	if err != nil {
		log.Fatalf("Failed to generate TLS cert: %v", err)
	}

	// 5. Listen UDP
	udpAddr, _ := net.ResolveUDPAddr("udp", ListenAddr)
	udpConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		log.Fatalf("Failed to listen UDP on %s: %v", ListenAddr, err)
	}
	log.Printf("[Lowkey] Listening QUIC/UDP on %s", ListenAddr)

	// 6. Configure & start Hysteria2
	hyConfig := &server.Config{
		Conn: udpConn,
		TLSConfig: server.TLSConfig{
			Certificates: []tls.Certificate{tlsCert},
		},
		Authenticator: &ApiAuthenticator{},
	}
	s, err := server.NewServer(hyConfig)
	if err != nil {
		log.Fatalf("Failed to create Hysteria2 server: %v", err)
	}

	log.Println("[Lowkey] Ready — no backend dependency, auth via PostgreSQL ✓")
	if err := s.Serve(); err != nil {
		log.Fatalf("Server error: %v", err)
	}
}
