// Package vpn implements a lightweight HTTP/3 (QUIC-based) VPN server that
// handles client connections via POST requests, performs authentication,
// assigns virtual IPs, and manages the packet forwarding lifecycle.
package vpn

import (
	"crypto/tls"
	"io"
	"log"
	"net"
	"net/http"
	"sync"

	"github.com/quic-go/quic-go/http3"
	"github.com/vmihailenco/msgpack/v5"

	"hysteria_server/auth"
	"hysteria_server/config"
	"hysteria_server/db"
	"hysteria_server/tun"
)

// ─── Wire protocol structures ────────────────────────────────────────────────

// ClientHello is the first message sent by the client.
// It carries the JWT auth token plus optional device metadata.
type ClientHello struct {
	_msgpack struct{} `msgpack:",asArray"`
	Auth     string   `msgpack:"auth"`    // JWT token
	Rx       uint64   `msgpack:"rx"`      // advertised receive bandwidth (bytes/s)
	Tx       uint64   `msgpack:"tx"`      // advertised transmit bandwidth (bytes/s)
	DevID    string   `msgpack:"devId"`   // device identifier
	DevName  string   `msgpack:"devName"` // human-readable device name
	DevOS    string   `msgpack:"devOS"`   // operating system
	Version  string   `msgpack:"ver"`     // client version string
	Padding  []byte   `msgpack:"padding"` // random padding (anti-fingerprinting)
}

// ─── Virtual IP pool ─────────────────────────────────────────────────────────

type ipPool struct {
	mu        sync.Mutex
	available []string
	used      map[string]bool
}

func newIPPool() *ipPool {
	p := &ipPool{used: make(map[string]bool)}
	for i := 2; i < 255; i++ {
		p.available = append(p.available, net.IPv4(172, 20, 0, byte(i)).String())
	}
	return p
}

func (p *ipPool) acquire() (string, bool) {
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

func (p *ipPool) release(ip string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.used[ip] {
		delete(p.used, ip)
		p.available = append(p.available, ip)
	}
}

var vips = newIPPool()

// ─── Connection counter ──────────────────────────────────────────────────────

var connCounter struct {
	sync.Mutex
	n int
}

func IncConn() { connCounter.Lock(); connCounter.n++; connCounter.Unlock() }
func DecConn() { connCounter.Lock(); connCounter.n--; connCounter.Unlock() }
func LoadCount() int { connCounter.Lock(); defer connCounter.Unlock(); return connCounter.n }

// ─── Server ──────────────────────────────────────────────────────────────────

func ListenAndServe(cfg *config.Config) {
	cert, err := generateSelfSignedCert()
	if err != nil {
		log.Fatalf("[VPN] TLS cert error: %v", err)
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{http3.NextProtoH3},
	}

	handler := http.NewServeMux()
	handler.HandleFunc("/tunnel", func(w http.ResponseWriter, r *http.Request) {
		handleTunnel(w, r, cfg)
	})

	server := http3.Server{
		Addr:      cfg.ListenAddr,
		Handler:   handler,
		TLSConfig: tlsConfig,
	}

	log.Printf("[VPN] HTTP/3 Server listening on %s ✓", cfg.ListenAddr)
	if err := server.ListenAndServe(); err != nil {
		log.Fatalf("[VPN] HTTP/3 Server error: %v", err)
	}
}

func handleTunnel(w http.ResponseWriter, r *http.Request, cfg *config.Config) {
	addrStr := r.RemoteAddr
	log.Printf("[VPN] New HTTP/3 tunnel request from %s", addrStr)

	// 1. Read ClientHello from request body (first bytes)
	decoder := msgpack.NewDecoder(r.Body)
	var hello ClientHello
	if err := decoder.Decode(&hello); err != nil {
		log.Printf("[VPN] Auth decode error from %s: %v", addrStr, err)
		http.Error(w, "invalid auth", http.StatusUnauthorized)
		return
	}

	authRes := auth.AuthenticateAndRegister(db.Pool, hello.Auth, cfg.JWTSecret)
	if !authRes.OK {
		log.Printf("[VPN] Auth rejected for %s: %s", addrStr, authRes.Reason)
		http.Error(w, "auth failed", http.StatusUnauthorized)
		return
	}

	clientVIP, ok := vips.acquire()
	if !ok {
		log.Printf("[VPN] IP pool exhausted for %s", addrStr)
		http.Error(w, "no IPs", http.StatusServiceUnavailable)
		return
	}
	defer vips.release(clientVIP)

	// Set headers to indicate streaming response
	w.Header().Set("Content-Type", "application/octet-stream")
	w.WriteHeader(http.StatusOK)
	
	// Create a pipe for Tun -> Response
	pr, pw := io.Pipe()
	tun.RegisterStreamClient(clientVIP, pw)
	defer tun.UnregisterClient(clientVIP)

	IncConn()
	defer DecConn()

	log.Printf("[VPN] Tunnel established for vip=%s from %s", clientVIP, addrStr)

	// Stream 1: TUN -> ResponseBody (Server to Client)
	go func() {
		_, _ = io.Copy(w, pr)
	}()

	// Stream 2: RequestBody -> TUN (Client to Server)
	buf := make([]byte, 2048)
	for {
		n, err := r.Body.Read(buf)
		if n > 0 {
			if tun.Device != nil {
				if _, werr := tun.Device.Write(buf[:n]); werr != nil {
					log.Printf("[VPN] TUN write error: %v", werr)
				}
			}
		}
		if err != nil {
			if err != io.EOF {
				log.Printf("[VPN] Tunnel read error from %s: %v", addrStr, err)
			}
			break
		}
	}
	log.Printf("[VPN] Tunnel closed for vip=%s", clientVIP)
}
