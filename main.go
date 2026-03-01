package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
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
// Config — loaded from .env at startup
// ---------------------------------------------------------

var (
	ListenAddr  string
	Port        = 7000
	BackendBase string // optional fallback HTTP API
	ServerIP    string // auto-detected

	db  *pgxpool.Pool
	rdb *redis.Client
)

func loadConfig() {
	_ = godotenv.Load()

	ListenAddr  = getenv("LISTEN_ADDR", ":7000")
	BackendBase = getenv("BACKEND_URL", "http://localhost:3001")

	if addr, err := net.ResolveTCPAddr("tcp", ListenAddr); err == nil && addr.Port != 0 {
		Port = addr.Port
	}

	ServerIP = detectPublicIP()
	log.Printf("[Config] ListenAddr=%s | BackendURL=%s | PublicIP=%s", ListenAddr, BackendBase, ServerIP)
}

func getenv(key, fallback string) string {
	if v, ok := os.LookupEnv(key); ok && v != "" {
		return v
	}
	return fallback
}

// detectPublicIP tries several public IP services and returns the first result.
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
			ip := strings.TrimSpace(string(buf[:n]))
			if ip != "" {
				log.Printf("[Config] Public IP detected via %s: %s", svc, ip)
				return ip
			}
		}
	}
	log.Println("[Config] WARNING: could not detect public IP, using 127.0.0.1")
	return "127.0.0.1"
}

// ---------------------------------------------------------
// Database initialisation
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

// authenticateLoginPassword verifies login+password directly against PostgreSQL,
// then checks subscription validity via the same DB.
func authenticateLoginPassword(login, password string) authResult {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// ── Step 1: find user ──
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

	// ── Step 2: check ban ──
	if isBanned {
		return authResult{reason: "user is banned"}
	}

	// ── Step 3: verify password ──
	if err := bcrypt.CompareHashAndPassword([]byte(passwordHash), []byte(password)); err != nil {
		return authResult{reason: "wrong password"}
	}

	// ── Step 4: check active subscription ──
	return checkSubscription(ctx, userId)
}

// checkSubscription verifies user has an active subscription in the DB.
func checkSubscription(ctx context.Context, userId string) authResult {
	var isLifetime bool
	var activeUntil time.Time

	err := db.QueryRow(ctx, `
		SELECT "isLifetime", "activeUntil"
		FROM subscriptions
		WHERE "userId" = $1
	`, userId).Scan(&isLifetime, &activeUntil)
	if err != nil {
		return authResult{reason: "no active subscription found"}
	}

	if !isLifetime && time.Now().After(activeUntil) {
		return authResult{reason: fmt.Sprintf("subscription expired at %s", activeUntil.Format(time.RFC3339))}
	}

	return authResult{ok: true, userId: userId}
}

// authenticateVpnToken verifies a pre-issued VPN token directly against DB.
func authenticateVpnToken(token string) authResult {
	// Check Redis blocklist cache first (fast path)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	blocked, _ := rdb.Exists(ctx, "token:blocklist:"+token).Result()
	if blocked > 0 {
		return authResult{reason: "token is revoked"}
	}

	var (
		userId    string
		expiresAt time.Time
	)
	err := db.QueryRow(ctx, `
		SELECT vt."userId", vt."expiresAt"
		FROM vpn_tokens vt
		WHERE vt.token = $1
	`, token).Scan(&userId, &expiresAt)
	if err != nil {
		return authResult{reason: "token not found"}
	}

	if time.Now().After(expiresAt) {
		return authResult{reason: "token expired"}
	}

	// Verify subscription is still active
	subCtx, subCancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer subCancel()
	return checkSubscription(subCtx, userId)
}

// ---------------------------------------------------------
// Hysteria2 Authenticator
//
// Supports two auth string formats from the Hysteria2 client config:
//   1. "login:password"  — verifies directly against PostgreSQL
//   2. "<vpn-token>"     — verifies VPN token from DB
// ---------------------------------------------------------

type ApiAuthenticator struct{}

func (a *ApiAuthenticator) Authenticate(addr net.Addr, auth string, tx uint64) (ok bool, id string) {
	// Fast path: session cache hit
	if entry, hit := cache.get(auth); hit {
		log.Printf("[Auth] Cache hit → user %s from %s", entry.userId, addr)
		return true, entry.userId
	}

	var result authResult

	if strings.Contains(auth, ":") {
		// Format 1: login:password
		parts := strings.SplitN(auth, ":", 2)
		login, password := parts[0], parts[1]
		log.Printf("[Auth] Login attempt for %q from %s", login, addr)
		result = authenticateLoginPassword(login, password)
	} else {
		// Format 2: vpn-token
		log.Printf("[Auth] VPN token auth from %s", addr)
		result = authenticateVpnToken(auth)
	}

	if !result.ok {
		log.Printf("[Auth] Rejected from %s: %s", addr, result.reason)
		return false, ""
	}

	// Cache session for 5 minutes
	cache.set(auth, sessionEntry{
		userId:    result.userId,
		expiresAt: time.Now().Add(5 * time.Minute),
	})

	log.Printf("[Auth] Accepted → user %s from %s", result.userId, addr)
	return true, result.userId
}

// ---------------------------------------------------------
// Active connection counter (reported to backend on heartbeat)
// ---------------------------------------------------------

var connCount struct {
	sync.Mutex
	n int
}

func incConn() { connCount.Lock(); connCount.n++; connCount.Unlock() }
func decConn() { connCount.Lock(); connCount.n--; connCount.Unlock() }
func loadCount() int { connCount.Lock(); defer connCount.Unlock(); return connCount.n }

// ---------------------------------------------------------
// Fallback: Register & Heartbeat via backend HTTP API
// (works even when backend is down — server still authenticates via DB)
// ---------------------------------------------------------

var serverId string

func registerServer() {
	log.Println("[Server] Registering with backend API...")
	for {
		reqBody, _ := json.Marshal(map[string]interface{}{
			"ip":                 ServerIP,
			"port":               Port,
			"supportedProtocols": []string{"hysteria2"},
			"serverType":         "dedicated",
		})
		resp, err := http.Post(BackendBase+"/servers/register", "application/json", bytes.NewBuffer(reqBody))
		if err == nil {
			var result map[string]interface{}
			if err := json.NewDecoder(resp.Body).Decode(&result); err == nil {
				if sid, ok := result["serverId"].(string); ok {
					serverId = sid
					resp.Body.Close()
					log.Printf("[Server] Registered as %s", serverId)
					return
				}
			}
			resp.Body.Close()
		}
		log.Printf("[Server] Registration failed: %v — retrying in 15s...", err)
		time.Sleep(15 * time.Second)
	}
}

func startHeartbeat() {
	ticker := time.NewTicker(30 * time.Second)
	for range ticker.C {
		if serverId == "" {
			continue
		}
		reqBody, _ := json.Marshal(map[string]interface{}{
			"serverId":    serverId,
			"currentLoad": loadCount(),
		})
		_, err := http.Post(BackendBase+"/servers/heartbeat", "application/json", bytes.NewBuffer(reqBody))
		if err != nil {
			log.Printf("[Server] Heartbeat failed: %v", err)
		}
	}
}

// ---------------------------------------------------------
// Self-signed TLS certificate
// ---------------------------------------------------------

func generateSelfSignedCert() (tls.Certificate, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	template := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{Organization: []string{"Lowkey VPN"}},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return tls.Certificate{}, err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
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
	log.Println("[Lowkey] Starting Hysteria2 VPN Server...")

	// 0. Load config + auto-detect public IP
	loadConfig()

	// 1. Connect directly to PostgreSQL and Redis
	initDB()
	initRedis()

	// 2. Generate TLS cert
	tlsCert, err := generateSelfSignedCert()
	if err != nil {
		log.Fatalf("Failed to generate TLS cert: %v", err)
	}

	// 3. Register in backend (non-blocking, retries in background)
	go registerServer()
	go startHeartbeat()

	// 4. Listen UDP
	udpAddr, _ := net.ResolveUDPAddr("udp", ListenAddr)
	udpConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		log.Fatalf("Failed to listen UDP on %s: %v", ListenAddr, err)
	}
	log.Printf("[Lowkey] Listening QUIC/UDP on %s", ListenAddr)

	// 5. Configure & start Hysteria2
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

	log.Println("[Lowkey] Hysteria2 server ready — authentication via PostgreSQL ✓")
	if err := s.Serve(); err != nil {
		log.Fatalf("Server error: %v", err)
	}
}
