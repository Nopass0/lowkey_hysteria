// Package captive implements captive portal functionality for expired VPN subscriptions.
//
// Architecture:
//
//	For HTTP (port 80):  the VPN server intercepts the request and returns a
//	  302 redirect to the billing page directly.
//
//	For HTTPS (port 443): we use DNS hijacking — the DNS server returns this
//	  server's captive portal IP for ALL queries from expired users.
//	  The HTTPS captive portal server presents a TLS certificate for the portal
//	  domain itself with a <meta http-equiv="refresh"> redirect.
//	  The user will see a certificate mismatch warning for the original site,
//	  but the captive portal's own page loads without errors.
//
//	DNS server: listens on the VPN tunnel's internal DNS port (default 53).
//	  For normal users: forwards to 8.8.8.8.
//	  For expired users: returns captiveIP for all A/AAAA queries.
package captive

import (
	"crypto/tls"
	"fmt"
	"html"
	"log"
	"net"
	"net/http"
	"sync"
	"time"
)

// ─── HTTP redirect server (port 80) ──────────────────────────────────────────

const captivePageHTML = `<!DOCTYPE html>
<html lang="ru">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Подписка истекла — Lowkey VPN</title>
<style>
  *{box-sizing:border-box;margin:0;padding:0}
  body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;
       background:#0a0a0a;color:#f0f0f0;min-height:100vh;display:flex;
       align-items:center;justify-content:center;padding:20px}
  .wrap{background:#111;border:1px solid #222;border-radius:24px;
        padding:48px 40px;max-width:440px;width:100%;text-align:center;
        box-shadow:0 0 80px rgba(124,58,237,.15)}
  .icon{font-size:3rem;margin-bottom:20px;filter:drop-shadow(0 0 16px #7c3aed)}
  h1{font-size:1.5rem;font-weight:800;margin-bottom:12px;letter-spacing:-.02em}
  p{color:#888;line-height:1.6;margin-bottom:32px;font-size:.95rem}
  a.btn{display:inline-block;background:linear-gradient(135deg,#7c3aed,#6d28d9);
        color:#fff;text-decoration:none;padding:14px 32px;border-radius:12px;
        font-weight:700;font-size:1rem;transition:opacity .2s;
        box-shadow:0 4px 20px rgba(124,58,237,.4)}
  a.btn:hover{opacity:.85}
  .note{margin-top:24px;font-size:.75rem;color:#555;line-height:1.5}
</style>
</head>
<body>
<div class="wrap">
  <div class="icon">🔐</div>
  <h1>Подписка истекла</h1>
  <p>Ваша подписка <strong>Lowkey VPN</strong> завершилась.<br>
     Для восстановления доступа в интернет через наш сервис — продлите подписку.</p>
  <a class="btn" href="%s">Продлить подписку</a>
  <p class="note">
    Вы видите эту страницу, потому что подключены к Lowkey VPN<br>
    с истёкшей подпиской. Без подписки интернет недоступен.<br>
    Сайт <strong>lowkeyvpn.com</strong> работает без ограничений.
  </p>
</div>
</body>
</html>`

// HTTPServer serves the captive portal page on port 80.
type HTTPServer struct {
	billingURL string
	srv        *http.Server
}

// NewHTTP creates a new HTTP captive portal server.
func NewHTTP(listen, billingURL string) *HTTPServer {
	s := &HTTPServer{billingURL: billingURL}
	mux := http.NewServeMux()
	mux.HandleFunc("/", s.page)
	mux.HandleFunc("/generate_204", noContent)     // Android
	mux.HandleFunc("/hotspot-detect.html", noContent) // Apple
	mux.HandleFunc("/connecttest.txt", noContent)  // Windows
	s.srv = &http.Server{Addr: listen, Handler: mux,
		ReadTimeout: 5 * time.Second, WriteTimeout: 10 * time.Second}
	return s
}

func (s *HTTPServer) page(w http.ResponseWriter, r *http.Request) {
	safeURL := html.EscapeString(s.billingURL)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintf(w, captivePageHTML, safeURL)
}

func noContent(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusNoContent)
}

// Start runs the server in the background.
func (s *HTTPServer) Start() {
	go func() {
		log.Printf("[CaptiveHTTP] Listening on %s", s.srv.Addr)
		if err := s.srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Printf("[CaptiveHTTP] %v", err)
		}
	}()
}

// Stop gracefully shuts down the server.
func (s *HTTPServer) Stop() { s.srv.Close() }

// ─── HTTPS captive portal (port 443) ─────────────────────────────────────────

// HTTPSServer serves a TLS page that redirects expired users.
// It uses the service's own TLS certificate (lowkeyvpn.com).
// Users connecting to other HTTPS sites will see a cert mismatch for that domain,
// but the redirect page itself loads correctly from the captive portal's IP.
type HTTPSServer struct {
	billingURL string
	srv        *http.Server
}

// NewHTTPS creates a new HTTPS captive portal server.
func NewHTTPS(listen, certFile, keyFile, billingURL string) (*HTTPSServer, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("captive HTTPS cert: %w", err)
	}
	s := &HTTPSServer{billingURL: billingURL}
	mux := http.NewServeMux()
	mux.HandleFunc("/", s.page)
	s.srv = &http.Server{
		Addr:      listen,
		Handler:   mux,
		TLSConfig: &tls.Config{Certificates: []tls.Certificate{cert}},
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
	}
	return s, nil
}

func (s *HTTPSServer) page(w http.ResponseWriter, r *http.Request) {
	// Redirect immediately to the billing page
	http.Redirect(w, r, s.billingURL, http.StatusFound)
}

// Start runs the HTTPS captive portal in the background.
func (s *HTTPSServer) Start() {
	go func() {
		log.Printf("[CaptiveHTTPS] Listening on %s", s.srv.Addr)
		if err := s.srv.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
			log.Printf("[CaptiveHTTPS] %v", err)
		}
	}()
}

// Stop shuts down the server.
func (s *HTTPSServer) Stop() { s.srv.Close() }

// ─── DNS hijacking server ─────────────────────────────────────────────────────
// When a user has an expired subscription, all their DNS queries return
// the captive portal IP so that both HTTP and HTTPS traffic is intercepted.

// DNSServer is a simple DNS proxy that can override responses for specific clients.
type DNSServer struct {
	listen      string
	upstreamDNS string
	captiveIP   net.IP

	// expiredClients is the set of client IPs (as strings) that should receive
	// the captive portal IP for all A/AAAA queries.
	mu             sync.RWMutex
	expiredClients map[string]bool

	conn *net.UDPConn
}

// NewDNS creates a DNS server.
// captiveIP is the IP returned for expired users.
// upstreamDNS is the real resolver (e.g. "8.8.8.8:53").
func NewDNS(listen, captiveIP, upstreamDNS string) *DNSServer {
	return &DNSServer{
		listen:         listen,
		upstreamDNS:    upstreamDNS,
		captiveIP:      net.ParseIP(captiveIP),
		expiredClients: make(map[string]bool),
	}
}

// MarkExpired marks a client IP as having an expired subscription.
func (d *DNSServer) MarkExpired(clientIP string) {
	d.mu.Lock()
	d.expiredClients[clientIP] = true
	d.mu.Unlock()
}

// ClearExpired removes a client IP from the expired set.
func (d *DNSServer) ClearExpired(clientIP string) {
	d.mu.Lock()
	delete(d.expiredClients, clientIP)
	d.mu.Unlock()
}

// IsExpired checks if a client IP is expired.
func (d *DNSServer) IsExpired(clientIP string) bool {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.expiredClients[clientIP]
}

// Start begins serving DNS requests.
func (d *DNSServer) Start() {
	go func() {
		conn, err := net.ListenPacket("udp", d.listen)
		if err != nil {
			log.Printf("[DNS] Cannot listen on %s: %v", d.listen, err)
			return
		}
		d.conn = conn.(*net.UDPConn)
		log.Printf("[DNS] Listening on %s (captive IP: %s)", d.listen, d.captiveIP)

		buf := make([]byte, 512)
		for {
			n, addr, err := d.conn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			go d.handleDNS(buf[:n], addr)
		}
	}()
}

// Stop closes the DNS server.
func (d *DNSServer) Stop() {
	if d.conn != nil {
		d.conn.Close()
	}
}

// handleDNS processes a single DNS query.
func (d *DNSServer) handleDNS(query []byte, addr *net.UDPAddr) {
	clientIP := addr.IP.String()
	d.mu.RLock()
	expired := d.expiredClients[clientIP]
	d.mu.RUnlock()

	if expired && d.captiveIP != nil {
		// Build a DNS response that answers with the captive portal IP
		resp := buildCaptiveDNSResponse(query, d.captiveIP)
		if resp != nil {
			d.conn.WriteToUDP(resp, addr)
			return
		}
	}

	// Forward to upstream DNS
	upConn, err := net.DialTimeout("udp", d.upstreamDNS, 3*time.Second)
	if err != nil {
		return
	}
	defer upConn.Close()
	upConn.SetDeadline(time.Now().Add(3 * time.Second))
	upConn.Write(query)
	resp := make([]byte, 512)
	n, err := upConn.Read(resp)
	if err != nil {
		return
	}
	d.conn.WriteToUDP(resp[:n], addr)
}

// buildCaptiveDNSResponse constructs a DNS A-record response pointing to captiveIP.
// Minimal RFC-1035 implementation (handles A queries only, drops AAAA).
func buildCaptiveDNSResponse(query []byte, captiveIP net.IP) []byte {
	if len(query) < 12 {
		return nil
	}
	ipv4 := captiveIP.To4()
	if ipv4 == nil {
		return nil
	}

	// Copy header from query, set QR=1, AA=1, ANCOUNT=1
	resp := make([]byte, 0, len(query)+16)
	resp = append(resp, query[:12]...) // copy header
	resp[2] = (resp[2] | 0x80) &^ 0x78 // QR=1, Opcode=0, AA=1
	resp[3] = resp[3] &^ 0x0F           // RCODE=0
	resp[6] = 0; resp[7] = 1            // ANCOUNT=1
	resp[8] = 0; resp[9] = 0            // NSCOUNT=0
	resp[10] = 0; resp[11] = 0          // ARCOUNT=0

	// Copy question section
	resp = append(resp, query[12:]...)

	// Answer: name=ptr to question (0xC0 0x0C), type=A, class=IN, TTL=30, rdlength=4, rdata=IP
	resp = append(resp,
		0xC0, 0x0C, // name pointer to offset 12
		0x00, 0x01, // type A
		0x00, 0x01, // class IN
		0x00, 0x00, 0x00, 0x1E, // TTL 30 seconds
		0x00, 0x04, // rdlength 4
	)
	resp = append(resp, ipv4...)
	return resp
}

// ─── Helper ───────────────────────────────────────────────────────────────────

// SendReset sends a TCP RST to a connection (for HTTPS from expired users
// when DNS hijacking is not available).
func SendReset(conn net.Conn) {
	if tc, ok := conn.(*net.TCPConn); ok {
		tc.SetLinger(0)
	}
	conn.Close()
}
