package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"log"
	"math/big"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/apernet/hysteria/core/v2/server"
)

// ---------------------------------------------------------
// Config
// ---------------------------------------------------------

const (
	ListenAddr  = ":7000"
	Port        = 7000
	BackendBase = "http://localhost:3001"
	ServerIP    = "127.0.0.1" // Change to public IP in production
)

// ---------------------------------------------------------
// Session cache — prevents repeated backend calls per connection
// ---------------------------------------------------------

type sessionEntry struct {
	userId    string
	expiresAt time.Time
}

type sessionCache struct {
	mu    sync.RWMutex
	store map[string]sessionEntry // key = "login:password" or resolved token
}

func newSessionCache() *sessionCache {
	sc := &sessionCache{store: make(map[string]sessionEntry)}
	// Cleanup goroutine
	go func() {
		for range time.Tick(5 * time.Minute) {
			sc.mu.Lock()
			now := time.Now()
			for k, v := range sc.store {
				if now.After(v.expiresAt) {
					delete(sc.store, k)
				}
			}
			sc.mu.Unlock()
		}
	}()
	return sc
}

func (sc *sessionCache) get(key string) (sessionEntry, bool) {
	sc.mu.RLock()
	defer sc.mu.RUnlock()
	entry, ok := sc.store[key]
	if ok && time.Now().Before(entry.expiresAt) {
		return entry, true
	}
	return sessionEntry{}, false
}

func (sc *sessionCache) set(key string, entry sessionEntry) {
	sc.mu.Lock()
	defer sc.mu.Unlock()
	sc.store[key] = entry
}

// ---------------------------------------------------------
// Backend API client helpers
// ---------------------------------------------------------

// loginResponse mirrors /auth/login response body
type loginResponse struct {
	Token string `json:"token"`
	User  struct {
		ID    string `json:"id"`
		Login string `json:"login"`
	} `json:"user"`
}

// loginToBackend calls POST /auth/login and returns a JWT token on success.
// Returns empty string on failure.
func loginToBackend(login, password string) (string, string, error) {
	body, _ := json.Marshal(map[string]string{
		"login":    login,
		"password": password,
	})

	resp, err := http.Post(BackendBase+"/auth/login", "application/json", bytes.NewBuffer(body))
	if err != nil {
		return "", "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", "", nil
	}

	var result loginResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", "", err
	}
	return result.Token, result.User.ID, nil
}

// validateTokenResponse mirrors /servers/validate-token response body
type validateTokenResponse struct {
	Valid   bool   `json:"valid"`
	Reason  string `json:"reason"`
	UserID  string `json:"userId"`
}

// validateToken calls POST /servers/validate-token and returns (valid, userId, error).
// The backend checks: token exists, not expired, user not banned, user has active subscription.
func validateToken(token string) (bool, string, error) {
	body, _ := json.Marshal(map[string]string{"token": token})

	resp, err := http.Post(BackendBase+"/servers/validate-token", "application/json", bytes.NewBuffer(body))
	if err != nil {
		return false, "", err
	}
	defer resp.Body.Close()

	var result validateTokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return false, "", err
	}
	return result.Valid, result.UserID, nil
}

// ---------------------------------------------------------
// Hysteria2 Authenticator
//
// Hysteria2 passes the auth string from the client config.
// We support two formats:
//
//   1. "login:password"  — app logs in and validates subscription
//   2. "<jwt-token>"     — session token issued by backend; validated directly
//
// ---------------------------------------------------------

var cache = newSessionCache()

type ApiAuthenticator struct{}

func (a *ApiAuthenticator) Authenticate(addr net.Addr, auth string, tx uint64) (ok bool, id string) {
	// Check session cache first
	if entry, hit := cache.get(auth); hit {
		log.Printf("[Auth] Cache hit for key %q → user %s", maskSecret(auth), entry.userId)
		return true, entry.userId
	}

	var userId string
	var valid bool

	if strings.Contains(auth, ":") {
		// ── Format 1: login:password ─────────────────────
		parts := strings.SplitN(auth, ":", 2)
		login, password := parts[0], parts[1]

		log.Printf("[Auth] Login attempt for user %q from %s", login, addr)

		// Step 1: authenticate with backend
		token, uid, err := loginToBackend(login, password)
		if err != nil {
			log.Printf("[Auth] Backend unreachable during login for %q: %v", login, err)
			return false, ""
		}
		if token == "" {
			log.Printf("[Auth] Login failed for %q: invalid credentials or banned", login)
			return false, ""
		}

		// Step 2: validate token (checks subscription + ban internally)
		// The backend creates a VpnToken only when the client explicitly calls the devices
		// endpoint. Here we just validate the JWT via /servers/validate-token.
		// We pass the bearer JWT directly.
		isValid, resolvedUID, err := validateTokenViaJWT(token)
		if err != nil || !isValid {
			reason := "unknown"
			if err != nil {
				reason = err.Error()
			}
			log.Printf("[Auth] Subscription/token check failed for %q: %s", login, reason)
			return false, ""
		}

		userId = resolvedUID
		if userId == "" {
			userId = uid
		}
		valid = true

		// Cache the auth string (login:pass) for 5 minutes
		cache.set(auth, sessionEntry{userId: userId, expiresAt: time.Now().Add(5 * time.Minute)})

	} else {
		// ── Format 2: raw VPN token (from the database) ──
		log.Printf("[Auth] Token validation from %s", addr)

		var err error
		valid, userId, err = validateToken(auth)
		if err != nil {
			log.Printf("[Auth] Backend unreachable during token validation: %v", err)
			return false, ""
		}
		if !valid {
			log.Printf("[Auth] Token rejected")
			return false, ""
		}

		// Cache for 5 minutes
		cache.set(auth, sessionEntry{userId: userId, expiresAt: time.Now().Add(5 * time.Minute)})
	}

	if valid {
		log.Printf("[Auth] Accepted → user %s from %s", userId, addr)
		return true, userId
	}
	return false, ""
}

// validateTokenViaJWT validates a JWT auth token using the backend's /auth/me
// endpoint (uses Bearer token to confirm active subscription).
func validateTokenViaJWT(jwtToken string) (bool, string, error) {
	req, err := http.NewRequest("GET", BackendBase+"/user/profile", nil)
	if err != nil {
		return false, "", err
	}
	req.Header.Set("Authorization", "Bearer "+jwtToken)

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return false, "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return false, "", nil
	}

	var profile struct {
		ID           string  `json:"id"`
		IsBanned     bool    `json:"isBanned"`
		Subscription *struct {
			IsLifetime  bool   `json:"isLifetime"`
			ActiveUntil string `json:"activeUntil"`
		} `json:"subscription"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&profile); err != nil {
		return false, "", err
	}

	if profile.IsBanned {
		log.Printf("[Auth] User %s is banned", profile.ID)
		return false, "", nil
	}

	sub := profile.Subscription
	if sub == nil {
		log.Printf("[Auth] User %s has no subscription", profile.ID)
		return false, "", nil
	}

	if !sub.IsLifetime {
		activeUntil, err := time.Parse(time.RFC3339, sub.ActiveUntil)
		if err == nil && time.Now().After(activeUntil) {
			log.Printf("[Auth] User %s subscription expired at %s", profile.ID, sub.ActiveUntil)
			return false, "", nil
		}
	}

	return true, profile.ID, nil
}

// maskSecret returns a short masked version of a secret key for safe logging.
func maskSecret(s string) string {
	if len(s) <= 6 {
		return "***"
	}
	return s[:3] + "***" + s[len(s)-3:]
}

// ---------------------------------------------------------
// Active connection counter (for heartbeat load reporting)
// ---------------------------------------------------------

var connCount struct {
	sync.Mutex
	n int
}

func incConn()  { connCount.Lock(); connCount.n++; connCount.Unlock() }
func decConn()  { connCount.Lock(); connCount.n--; connCount.Unlock() }
func loadCount() int { connCount.Lock(); defer connCount.Unlock(); return connCount.n }

// ---------------------------------------------------------
// API Registration & Heartbeat
// ---------------------------------------------------------

var serverId string

func registerServer() {
	log.Println("[Server] Registering with central API...")
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
				if id, ok := result["serverId"].(string); ok {
					serverId = id
					resp.Body.Close()
					log.Printf("[Server] Registered as %s", serverId)
					return
				}
			}
			resp.Body.Close()
		}
		log.Printf("[Server] Registration failed: %v. Retrying in 5s...", err)
		time.Sleep(5 * time.Second)
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
// Self-signed TLS certificate generation
// ---------------------------------------------------------

func generateSelfSignedCert() (tls.Certificate, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Lowkey VPN"},
		},
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

	// 1. Generate TLS Certificate
	tlsCert, err := generateSelfSignedCert()
	if err != nil {
		log.Fatalf("Failed to generate TLS certificate: %v", err)
	}

	// 2. Register server & start heartbeat
	go registerServer()
	go startHeartbeat()

	// 3. Configure UDP listener
	udpAddr, _ := net.ResolveUDPAddr("udp", ListenAddr)
	udpConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		log.Fatalf("Failed to listen UDP on %s: %v", ListenAddr, err)
	}
	log.Printf("[Lowkey] Listening QUIC/UDP on %s", ListenAddr)

	// 4. Configure Hysteria2 server
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

	// 5. Serve
	log.Println("[Lowkey] Hysteria2 server is ready. Waiting for connections...")
	if err := s.Serve(); err != nil {
		log.Fatalf("Hysteria2 server error: %v", err)
	}
}
