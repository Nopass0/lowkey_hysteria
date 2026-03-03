// Package vpn implements the native Hysteria2 QUIC server that handles client
// connections, performs authentication, assigns virtual IPs, and manages the
// packet forwarding lifecycle for each session.
package vpn

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
	"io"
	"log"
	"math/big"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/vmihailenco/msgpack/v5"

	"hysteria_server/auth"
	"hysteria_server/config"
	"hysteria_server/db"
	"hysteria_server/tun"
)

// ─── Hysteria2 wire protocol structures ──────────────────────────────────────

// ClientHello is the first message sent by the client after the QUIC handshake.
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

// ServerHello is the server's reply to a ClientHello.
type ServerHello struct {
	_msgpack struct{} `msgpack:",asArray"`
	Ok       bool     `msgpack:"ok"`  // true = accepted
	Msg      string   `msgpack:"msg"` // error reason when Ok=false
	Id       uint32   `msgpack:"id"`  // session ID (reserved)
	Rx       uint64   `msgpack:"rx"`  // server's receive limit
	IP       string   `msgpack:"ip"`  // assigned virtual IP for the client
}

// ─── Virtual IP pool ─────────────────────────────────────────────────────────

// ipPool manages the allocation of virtual IP addresses within the VPN subnet.
type ipPool struct {
	mu        sync.Mutex
	available []string
	used      map[string]bool
}

// newIPPool pre-fills the pool with addresses 172.20.0.2 – 172.20.0.254.
func newIPPool() *ipPool {
	p := &ipPool{used: make(map[string]bool)}
	for i := 2; i < 255; i++ {
		p.available = append(p.available, fmt.Sprintf("172.20.0.%d", i))
	}
	return p
}

// acquire returns the next free IP or ("", false) when the pool is exhausted.
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

// release returns an IP back to the pool.
func (p *ipPool) release(ip string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.used[ip] {
		delete(p.used, ip)
		p.available = append(p.available, ip)
	}
}

var vips = newIPPool()

// ─── Connection counter (used for heartbeat / load reporting) ─────────────

// connCounter tracks the number of currently active QUIC connections so the
// heartbeat goroutine can report an accurate currentLoad to the database.
var connCounter struct {
	sync.Mutex
	n int
}

// IncConn increments the active connection counter.
func IncConn() { connCounter.Lock(); connCounter.n++; connCounter.Unlock() }

// DecConn decrements the active connection counter.
func DecConn() { connCounter.Lock(); connCounter.n--; connCounter.Unlock() }

// LoadCount returns the current number of active connections.
func LoadCount() int { connCounter.Lock(); defer connCounter.Unlock(); return connCounter.n }

// ─── TLS helpers ─────────────────────────────────────────────────────────────

// GenerateSelfSignedCert creates an in-memory self-signed TLS certificate for
// the QUIC listener. Using a self-signed cert is acceptable here because VPN
// clients pin the server by public key or disable certificate verification.
//
// @returns tls.Certificate, error
func GenerateSelfSignedCert() (tls.Certificate, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("generate key: %w", err)
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
		return tls.Certificate{}, fmt.Errorf("create cert: %w", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	privBytes, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("marshal key: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: privBytes})
	return tls.X509KeyPair(certPEM, keyPEM)
}

// ─── Server ──────────────────────────────────────────────────────────────────

// ListenAndServe starts the QUIC listener on cfg.ListenAddr and handles
// incoming Hysteria2 connections. This call blocks until the process exits.
//
// @param cfg - application configuration
func ListenAndServe(cfg *config.Config) {
	cert, err := GenerateSelfSignedCert()
	if err != nil {
		log.Fatalf("[VPN] TLS cert: %v", err)
	}

	tlsConf := &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"lowkey-vpn"},
	}
	quicConf := &quic.Config{
		EnableDatagrams: true,
		KeepAlivePeriod: 10 * time.Second,
	}

	listener, err := quic.ListenAddr(cfg.ListenAddr, tlsConf, quicConf)
	if err != nil {
		log.Fatalf("[VPN] Failed to listen on %s: %v", cfg.ListenAddr, err)
	}
	log.Printf("[VPN] Listening on %s (Hysteria2/QUIC) ✓", cfg.ListenAddr)

	for {
		conn, err := listener.Accept(context.Background())
		if err != nil {
			log.Printf("[VPN] Accept error: %v", err)
			continue
		}
		go handleConnection(conn, cfg)
	}
}

// handleConnection manages the full lifecycle of a single client QUIC session:
// handshake → auth → IP allocation → packet forwarding → cleanup.
func handleConnection(conn *quic.Conn, cfg *config.Config) {
	defer conn.CloseWithError(0, "closed")
	log.Printf("[VPN] New connection from %s", conn.RemoteAddr())

	// Step 1: Read ClientHello over the first bidirectional stream.
	stream, err := conn.AcceptStream(context.Background())
	if err != nil {
		log.Printf("[VPN] AcceptStream error from %s: %v", conn.RemoteAddr(), err)
		return
	}
	defer stream.Close()

	buf := make([]byte, 2048)
	n, err := stream.Read(buf)
	if err != nil && err != io.EOF {
		log.Printf("[VPN] Read ClientHello error: %v", err)
		return
	}

	var hello ClientHello
	if err = msgpack.Unmarshal(buf[:n], &hello); err != nil {
		log.Printf("[VPN] Unmarshal ClientHello error: %v", err)
		return
	}
	log.Printf("[VPN] ClientHello from %s (dev=%s, os=%s)", conn.RemoteAddr(), hello.DevName, hello.DevOS)

	// Step 2: Authenticate.
	result := auth.AuthenticateAndRegister(db.Pool, hello.Auth, cfg.JWTSecret)

	// Step 3: Acquire virtual IP (only if auth succeeded).
	var clientVIP string
	if result.OK {
		var ok bool
		clientVIP, ok = vips.acquire()
		if !ok {
			result.OK = false
			result.Reason = "ip pool exhausted"
		}
	}

	// Step 4: Send ServerHello.
	resp := ServerHello{Ok: result.OK, Id: 1, IP: clientVIP}
	if !result.OK {
		resp.Msg = result.Reason
		log.Printf("[VPN] Auth rejected for %s: %s", conn.RemoteAddr(), result.Reason)
	}
	if encErr := msgpack.NewEncoder(stream).Encode(resp); encErr != nil {
		log.Printf("[VPN] Encode ServerHello error: %v", encErr)
	}
	if !result.OK {
		time.Sleep(200 * time.Millisecond)
		return
	}

	// Step 5: Register in TUN routing table.
	tun.RegisterClient(clientVIP, conn)
	defer func() {
		tun.UnregisterClient(clientVIP)
		vips.release(clientVIP)
	}()

	IncConn()
	defer DecConn()

	log.Printf("[VPN] Session started for user=%s vip=%s", result.UserID, clientVIP)

	// Step 6: Main receive loop — forward QUIC datagrams into the TUN device.
	for {
		data, err := conn.ReceiveDatagram(context.Background())
		if err != nil {
			log.Printf("[VPN] ReceiveDatagram error (vip=%s): %v", clientVIP, err)
			break
		}
		if tun.Device != nil {
			if _, werr := tun.Device.Write(data); werr != nil {
				log.Printf("[VPN] TUN write error: %v", werr)
			}
		}
	}
	log.Printf("[VPN] Session ended for vip=%s", clientVIP)
}
