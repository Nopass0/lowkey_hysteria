// Package server implements the Hysteria2 VPN server with:
//   - Direct VoidDB token validation and session tracking
//   - SNI-based domain statistics (HTTP + HTTPS via DNS captive portal)
//   - Captive portal redirect for expired subscriptions
//   - Real-time active connection counting via heartbeat
package server

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/lowkey/hysteria-server/blocklist"
	"github.com/lowkey/hysteria-server/config"
	"github.com/lowkey/hysteria-server/stats"
	"github.com/lowkey/hysteria-server/voiddb"
)

// ─── Token validation result ──────────────────────────────────────────────────

// TokenInfo is returned by ValidateToken.
type TokenInfo struct {
	Valid    bool
	Reason   string
	UserID   string
	DeviceID string
	// SubscriptionExpired: token OK but sub lapsed — captive portal mode.
	SubscriptionExpired      bool
	MaxDevices               int
	MaxConcurrentConnections int
	SpeedLimitUpMbps         *int
	SpeedLimitDownMbps       *int
}

// ─── In-memory session ────────────────────────────────────────────────────────

type session struct {
	id                string
	userID            string
	deviceID          string
	deviceName        string
	deviceOS          string
	protocol          string
	serverID          string
	serverIP          string
	remoteAddr        string
	bytesUp           atomic.Int64
	bytesDown         atomic.Int64
	lastTrafficReport atomic.Int64
}

// ─── Server ───────────────────────────────────────────────────────────────────

// Server is the VPN server core.
type Server struct {
	cfg       *config.Config
	db        *voiddb.Client
	tracker   *stats.Tracker
	blocklist *blocklist.Blocklist

	activeSessions sync.Map // sessionID -> *session
	activeCount    atomic.Int64
	sessionMu      sync.Mutex
	sessionsByConn map[string][]*session
	sessionsByUser map[string][]*session

	httpClient *http.Client
}

// New creates a new Server.
func New(cfg *config.Config, db *voiddb.Client, tracker *stats.Tracker, bl *blocklist.Blocklist) *Server {
	return &Server{
		cfg:            cfg,
		db:             db,
		tracker:        tracker,
		blocklist:      bl,
		sessionsByConn: make(map[string][]*session),
		sessionsByUser: make(map[string][]*session),
		httpClient:     &http.Client{Timeout: 5 * time.Second},
	}
}

// ─── Token validation ─────────────────────────────────────────────────────────

// ValidateToken checks a VPN token against the central backend first, then
// falls back to direct VoidDB validation if the backend is unreachable.
func (s *Server) ValidateToken(token string) TokenInfo {
	if s.cfg.BackendURL != "" {
		if info, ok := s.validateTokenWithBackend(token); ok {
			return info
		}
	}

	return s.validateTokenWithVoidDB(token)
}

func (s *Server) validateTokenWithBackend(token string) (TokenInfo, bool) {
	payload := map[string]interface{}{
		"token":    token,
		"protocol": "hysteria2",
	}
	data, _ := json.Marshal(payload)
	req, err := http.NewRequest("POST", s.cfg.BackendURL+"/servers/validate-token", bytes.NewReader(data))
	if err != nil {
		log.Printf("[Auth] Backend request build failed: %v", err)
		return TokenInfo{}, false
	}
	req.Header.Set("Content-Type", "application/json")
	if s.cfg.BackendSecret != "" {
		req.Header.Set("X-Server-Secret", s.cfg.BackendSecret)
	}

	resp, err := s.httpClient.Do(req)
	if err != nil {
		log.Printf("[Auth] Backend validation unavailable: %v", err)
		return TokenInfo{}, false
	}
	defer resp.Body.Close()

	var result struct {
		Valid               bool   `json:"valid"`
		Reason              string `json:"reason"`
		UserID              string `json:"userId"`
		DeviceID            string `json:"deviceId"`
		SubscriptionExpired bool   `json:"subscriptionExpired"`
		Limits              struct {
			MaxDevices               int  `json:"maxDevices"`
			MaxConcurrentConnections int  `json:"maxConcurrentConnections"`
			SpeedLimitUpMbps         *int `json:"speedLimitUpMbps"`
			SpeedLimitDownMbps       *int `json:"speedLimitDownMbps"`
		} `json:"limits"`
		Message string `json:"message"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		log.Printf("[Auth] Backend validation decode failed: %v", err)
		return TokenInfo{}, false
	}

	if resp.StatusCode >= 400 {
		reason := result.Message
		if reason == "" {
			reason = result.Reason
		}
		if reason == "" {
			reason = fmt.Sprintf("backend auth error: %s", resp.Status)
		}
		return TokenInfo{Reason: reason}, true
	}

	return TokenInfo{
		Valid:                    result.Valid,
		Reason:                   result.Reason,
		UserID:                   result.UserID,
		DeviceID:                 result.DeviceID,
		SubscriptionExpired:      result.SubscriptionExpired,
		MaxDevices:               result.Limits.MaxDevices,
		MaxConcurrentConnections: result.Limits.MaxConcurrentConnections,
		SpeedLimitUpMbps:         result.Limits.SpeedLimitUpMbps,
		SpeedLimitDownMbps:       result.Limits.SpeedLimitDownMbps,
	}, true
}

func (s *Server) validateTokenWithVoidDB(token string) TokenInfo {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	col := s.db.DB("lowkey").Collection("vpn_tokens")
	doc, err := col.FindOne(ctx, voiddb.NewQuery().Where("token", voiddb.Eq, token))
	if err != nil || doc == nil {
		return TokenInfo{Reason: "Token not found"}
	}

	// Check VPN token expiry
	if expiresAt, _ := doc["expiresAt"].(string); expiresAt != "" {
		t, err := time.Parse(time.RFC3339, expiresAt)
		if err == nil && time.Now().After(t) {
			return TokenInfo{Reason: "VPN token expired"}
		}
	}

	userID, _ := doc["userId"].(string)
	if userID == "" {
		return TokenInfo{Reason: "Invalid token data"}
	}

	// Check user exists and is not banned
	userDoc, err := s.db.DB("lowkey").Collection("users").Get(ctx, userID)
	if err != nil || userDoc == nil {
		return TokenInfo{Reason: "User not found"}
	}
	if banned, _ := userDoc["isBanned"].(bool); banned {
		return TokenInfo{Reason: "User is banned"}
	}

	// Check subscription
	subDoc, err := s.db.DB("lowkey").Collection("subscriptions").FindOne(ctx,
		voiddb.NewQuery().Where("userId", voiddb.Eq, userID),
	)
	if err != nil || subDoc == nil {
		return TokenInfo{Reason: "No active subscription", UserID: userID, SubscriptionExpired: true}
	}

	isLifetime, _ := subDoc["isLifetime"].(bool)
	if !isLifetime {
		activeUntil, _ := subDoc["activeUntil"].(string)
		if activeUntil != "" {
			t, err := time.Parse(time.RFC3339, activeUntil)
			if err == nil && time.Now().After(t) {
				return TokenInfo{Valid: true, UserID: userID, SubscriptionExpired: true}
			}
		}
	}

	return TokenInfo{Valid: true, UserID: userID}
}

// ─── Session lifecycle ────────────────────────────────────────────────────────

// OpenSession creates an in-memory session and reports it to the backend.
func (s *Server) OpenSession(userID, deviceID, protocol, remoteAddr string) *session {
	deviceName, deviceOS := s.lookupDevice(deviceID)
	sess := &session{
		id:         uuid.New().String(),
		userID:     userID,
		deviceID:   deviceID,
		deviceName: deviceName,
		deviceOS:   deviceOS,
		protocol:   protocol,
		serverID:   s.cfg.ServerID,
		serverIP:   s.cfg.ServerIP,
		remoteAddr: remoteAddr,
	}
	s.activeSessions.Store(sess.id, sess)
	s.activeCount.Add(1)
	s.sessionMu.Lock()
	connKey := sessionConnKey(userID, remoteAddr)
	s.sessionsByConn[connKey] = append(s.sessionsByConn[connKey], sess)
	s.sessionsByUser[userID] = append(s.sessionsByUser[userID], sess)
	s.sessionMu.Unlock()
	go s.reportEvent("connect", sess, remoteAddr, 0, 0)
	return sess
}

// CloseSession finalises a session.
func (s *Server) CloseSession(sess *session) {
	s.activeSessions.Delete(sess.id)
	s.activeCount.Add(-1)
	s.sessionMu.Lock()
	s.sessionsByConn[sessionConnKey(sess.userID, sess.remoteAddr)] = removeSessionByID(
		s.sessionsByConn[sessionConnKey(sess.userID, sess.remoteAddr)],
		sess.id,
	)
	if len(s.sessionsByConn[sessionConnKey(sess.userID, sess.remoteAddr)]) == 0 {
		delete(s.sessionsByConn, sessionConnKey(sess.userID, sess.remoteAddr))
	}
	s.sessionsByUser[sess.userID] = removeSessionByID(s.sessionsByUser[sess.userID], sess.id)
	if len(s.sessionsByUser[sess.userID]) == 0 {
		delete(s.sessionsByUser, sess.userID)
	}
	s.sessionMu.Unlock()
	go s.reportEvent("disconnect", sess, "", sess.bytesUp.Load(), sess.bytesDown.Load())
}

// UpdateTraffic sends a mid-session traffic update.
func (s *Server) UpdateTraffic(sess *session) {
	go s.reportEvent("traffic", sess, "", sess.bytesUp.Load(), sess.bytesDown.Load())
}

func (s *Server) reportEvent(event string, sess *session, remoteAddr string, up, down int64) {
	payload := map[string]interface{}{
		"event":     event,
		"sessionId": sess.id,
		"userId":    sess.userID,
		"serverId":  sess.serverID,
		"serverIp":  sess.serverIP,
		"protocol":  sess.protocol,
		"bytesUp":   float64(up),
		"bytesDown": float64(down),
	}
	if sess.deviceID != "" {
		payload["deviceId"] = sess.deviceID
	}
	if sess.deviceName != "" {
		payload["deviceName"] = sess.deviceName
	}
	if sess.deviceOS != "" {
		payload["deviceOs"] = sess.deviceOS
	}
	if remoteAddr != "" {
		payload["remoteAddr"] = remoteAddr
	}
	data, _ := json.Marshal(payload)
	req, err := http.NewRequest("POST", s.cfg.BackendURL+"/servers/session-event", bytes.NewReader(data))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")
	if s.cfg.BackendSecret != "" {
		req.Header.Set("X-Server-Secret", s.cfg.BackendSecret)
	}
	resp, err := s.httpClient.Do(req)
	if err == nil {
		resp.Body.Close()
	}
}

// ─── Heartbeat ────────────────────────────────────────────────────────────────

// HeartbeatLoop registers this server and sends periodic heartbeats.
func (s *Server) HeartbeatLoop(ctx context.Context) {
	s.register()
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			s.sendHeartbeat()
		case <-ctx.Done():
			return
		}
	}
}

func (s *Server) register() {
	payload := map[string]interface{}{
		"ip":                 s.cfg.ServerIP,
		"hostname":           s.cfg.ServerHostname,
		"port":               s.listenPort(),
		"supportedProtocols": []string{"hysteria2"},
		"serverType":         "hysteria2",
	}
	data, _ := json.Marshal(payload)
	req, err := http.NewRequest("POST", s.cfg.BackendURL+"/servers/register", bytes.NewReader(data))
	if err != nil {
		log.Printf("[Heartbeat] Register request build failed: %v", err)
		return
	}
	req.Header.Set("Content-Type", "application/json")
	if s.cfg.BackendSecret != "" {
		req.Header.Set("X-Server-Secret", s.cfg.BackendSecret)
	}
	resp, err := s.httpClient.Do(req)
	if err != nil {
		log.Printf("[Heartbeat] Register failed: %v", err)
		return
	}
	defer resp.Body.Close()
	var result map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&result)
	if id, ok := result["serverId"].(string); ok && id != "" && s.cfg.ServerID == "" {
		s.cfg.ServerID = id
		log.Printf("[Heartbeat] Registered as server %s", id)
	}
}

func (s *Server) sendHeartbeat() {
	if s.cfg.ServerID == "" {
		s.register()
		return
	}
	payload := map[string]interface{}{
		"serverId":          s.cfg.ServerID,
		"currentLoad":       int(s.activeCount.Load()),
		"activeConnections": int(s.activeCount.Load()),
	}
	if s.blocklist != nil {
		payload["blocklistSyncAt"] = s.blocklist.LastSyncTime()
	}
	data, _ := json.Marshal(payload)
	req, err := http.NewRequest("POST", s.cfg.BackendURL+"/servers/heartbeat", bytes.NewReader(data))
	if err != nil {
		log.Printf("[Heartbeat] Heartbeat request build failed: %v", err)
		return
	}
	req.Header.Set("Content-Type", "application/json")
	if s.cfg.BackendSecret != "" {
		req.Header.Set("X-Server-Secret", s.cfg.BackendSecret)
	}
	resp, err := s.httpClient.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	if s.blocklist != nil {
		var hbResp struct {
			BlocklistVersion   int64 `json:"blocklistVersion"`
			ForceBlocklistSync bool  `json:"forceBlocklistSync"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&hbResp); err == nil {
			if hbResp.ForceBlocklistSync || hbResp.BlocklistVersion > s.blocklist.LastSyncTime() {
				log.Printf("[Heartbeat] Triggering immediate blocklist refresh (version=%d, localSync=%d)", hbResp.BlocklistVersion, s.blocklist.LastSyncTime())
				s.blocklist.ForceRefresh()
			}
		}
	}
}

// ─── TCP stream proxying ──────────────────────────────────────────────────────

func (s *Server) listenPort() int {
	if _, port, err := net.SplitHostPort(s.cfg.Listen); err == nil {
		if parsed, err := strconv.Atoi(port); err == nil {
			return parsed
		}
	}

	if strings.HasPrefix(s.cfg.Listen, ":") {
		if parsed, err := strconv.Atoi(strings.TrimPrefix(s.cfg.Listen, ":")); err == nil {
			return parsed
		}
	}

	return 443
}

// HandleTCPStream proxies one TCP stream, applying captive portal if expired.
// targetAddr is the destination host:port, conn is the client-side half.
func (s *Server) HandleTCPStream(conn net.Conn, targetAddr string, userID string, subscriptionExpired bool) {
	defer conn.Close()

	host, portStr, err := net.SplitHostPort(targetAddr)
	if err != nil {
		host = targetAddr
	}

	// Always track the domain (even expired users show in stats)
	s.tracker.Record(userID, host, 0)

	// ─ Captive portal mode ─────────────────────────────────────────────────
	if subscriptionExpired {
		if portStr == "80" || portStr == "8080" || portStr == "8000" {
			s.serveHTTPRedirect(conn)
		}
		// HTTPS and other ports: just close (client sees connection refused)
		return
	}

	// ─ Domain blocklist ────────────────────────────────────────────────────
	if s.blocklist != nil {
		if redirectURL, blocked := s.blocklist.IsBlocked(host); blocked {
			if portStr == "80" || portStr == "8080" || portStr == "8000" || portStr == "" {
				s.serveBlockedHTTPRedirect(conn, redirectURL)
			}
			// For HTTPS and other ports just drop the connection
			return
		}
	}

	// ─ Normal proxy ────────────────────────────────────────────────────────
	dst, err := net.DialTimeout("tcp", targetAddr, 10*time.Second)
	if err != nil {
		return
	}
	defer dst.Close()

	var wg sync.WaitGroup
	var upBytes, downBytes int64
	wg.Add(2)
	go func() {
		defer wg.Done()
		n, _ := io.Copy(dst, conn)
		atomic.AddInt64(&upBytes, n)
	}()
	go func() {
		defer wg.Done()
		n, _ := io.Copy(conn, dst)
		atomic.AddInt64(&downBytes, n)
	}()
	wg.Wait()

	// Update domain bytes
	s.tracker.Record(userID, host, upBytes+downBytes)
}

// serveHTTPRedirect sends an HTTP 302 to the billing page.
func (s *Server) serveHTTPRedirect(conn net.Conn) {
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 4096)
	conn.Read(buf) // drain the HTTP request

	billingURL := s.cfg.CaptivePortalURL
	body := captiveHTML(billingURL)
	resp := "HTTP/1.1 302 Found\r\n" +
		"Location: " + billingURL + "\r\n" +
		"Content-Type: text/html; charset=utf-8\r\n" +
		fmt.Sprintf("Content-Length: %d\r\n", len(body)) +
		"Connection: close\r\n\r\n" + body
	conn.Write([]byte(resp))
}

// serveBlockedHTTPRedirect sends an HTTP 302 to the blocked-domain redirect URL.
func (s *Server) serveBlockedHTTPRedirect(conn net.Conn, redirectURL string) {
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 4096)
	conn.Read(buf) // drain the HTTP request

	body := captiveHTML(redirectURL)
	resp := "HTTP/1.1 302 Found\r\n" +
		"Location: " + redirectURL + "\r\n" +
		"Content-Type: text/html; charset=utf-8\r\n" +
		fmt.Sprintf("Content-Length: %d\r\n", len(body)) +
		"Connection: close\r\n\r\n" + body
	conn.Write([]byte(resp))
}

func captiveHTML(billingURL string) string {
	return `<!DOCTYPE html><html lang="ru"><head><meta charset="utf-8">` +
		`<meta http-equiv="refresh" content="0; url=` + billingURL + `">` +
		`<title>Подписка истекла — Lowkey VPN</title></head><body>` +
		`<p>Подписка истекла. <a href="` + billingURL + `">Продлить</a></p>` +
		`</body></html>`
}

// ─── SNI extraction ───────────────────────────────────────────────────────────

// PeekSNI reads the TLS ClientHello from a connection and extracts the SNI.
// Returns the SNI hostname and a reconstructed connection with bytes un-consumed.
func PeekSNI(conn net.Conn) (string, net.Conn) {
	buf := make([]byte, 1024)
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, _ := conn.Read(buf)
	conn.SetReadDeadline(time.Time{})
	buf = buf[:n]

	sni := parseSNI(buf)
	rebuilt := &peekedConn{Conn: conn, reader: io.MultiReader(bytes.NewReader(buf), conn)}
	return sni, rebuilt
}

// parseSNI extracts the SNI hostname from a raw TLS ClientHello.
func parseSNI(data []byte) string {
	if len(data) < 9 || data[0] != 22 || data[5] != 1 {
		return ""
	}
	pos := 9 + 2 + 32 // skip record hdr + msg hdr + ProtocolVersion + Random
	if pos >= len(data) {
		return ""
	}
	// SessionID
	sidLen := int(data[pos])
	pos += 1 + sidLen
	if pos+2 > len(data) {
		return ""
	}
	// CipherSuites
	csLen := int(data[pos])<<8 | int(data[pos+1])
	pos += 2 + csLen
	if pos >= len(data) {
		return ""
	}
	// CompressionMethods
	cmLen := int(data[pos])
	pos += 1 + cmLen
	if pos+2 > len(data) {
		return ""
	}
	// Extensions
	extEnd := pos + 2 + (int(data[pos])<<8 | int(data[pos+1]))
	pos += 2
	for pos+4 <= extEnd && extEnd <= len(data) {
		t := int(data[pos])<<8 | int(data[pos+1])
		l := int(data[pos+2])<<8 | int(data[pos+3])
		pos += 4
		if t == 0 && pos+5 <= extEnd { // server_name extension
			if data[pos+2] == 0 { // host_name type
				nameLen := int(data[pos+3])<<8 | int(data[pos+4])
				start := pos + 5
				if start+nameLen <= extEnd {
					return string(data[start : start+nameLen])
				}
			}
		}
		pos += l
	}
	return ""
}

// peekedConn wraps net.Conn with buffered already-read bytes.
type peekedConn struct {
	net.Conn
	reader io.Reader
}

func (p *peekedConn) Read(b []byte) (int, error) { return p.reader.Read(b) }

// ─── TLS config ───────────────────────────────────────────────────────────────

// CaptivePortalListen returns the address of the HTTP captive portal server.
func (s *Server) CaptivePortalListen() string { return s.cfg.CaptivePortalListen }

// LoadTLSConfig loads a TLS certificate for the server.
func LoadTLSConfig(certFile, keyFile string) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("load TLS cert: %w", err)
	}
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"h3", "hysteria2"},
		MinVersion:   tls.VersionTLS13,
	}, nil
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

func stripPort(hostport string) string {
	if idx := strings.LastIndex(hostport, ":"); idx >= 0 {
		return hostport[:idx]
	}
	return hostport
}

func (s *Server) lookupDevice(deviceID string) (string, string) {
	if deviceID == "" {
		return "", ""
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	doc, err := s.db.DB("lowkey").Collection("devices").Get(ctx, deviceID)
	if err != nil || doc == nil {
		return "", ""
	}

	deviceName, _ := doc["name"].(string)
	deviceOS, _ := doc["os"].(string)
	return deviceName, deviceOS
}
