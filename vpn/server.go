// Package vpn implements a lightweight UDP VPN server that handles client
// connections, performs authentication via MessagePack ClientHello, assigns
// virtual IPs, and manages the packet forwarding lifecycle for each session.
package vpn

import (
	"log"
	"net"
	"sync"
	"time"

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
		p.available = append(p.available, "172.20.0."+string(rune(i))) // optimization avoided for clarity
	}
	// proper init
	p.available = make([]string, 0, 253)
	for i := 2; i < 255; i++ {
		p.available = append(p.available, net.IPv4(172, 20, 0, byte(i)).String())
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

// connCounter tracks the number of currently active connections.
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

// ─── session map ─────────────────────────────────────────────────────────────

type session struct {
	addr     *net.UDPAddr
	vip      string
	userID   string
	lastSeen time.Time
}

var (
	sessions   = make(map[string]*session) // key is udpAddr.String()
	sessionsMu sync.RWMutex
)

// ─── Server ──────────────────────────────────────────────────────────────────

// ListenAndServe starts the UDP listener on cfg.ListenAddr and handles
// incoming connections. This call blocks until the process exits.
//
// @param cfg - application configuration
func ListenAndServe(cfg *config.Config) {
	addr, err := net.ResolveUDPAddr("udp", cfg.ListenAddr)
	if err != nil {
		log.Fatalf("[VPN] ResolveUDPAddr error: %v", err)
	}

	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		log.Fatalf("[VPN] Failed to listen on %s: %v", cfg.ListenAddr, err)
	}
	
	tun.ServerConn = conn
	defer conn.Close()

	log.Printf("[VPN] Listening on %s (UDP/Hysteria2-lite) ✓", cfg.ListenAddr)

	buf := make([]byte, 65535)
	for {
		n, remoteAddr, err := conn.ReadFromUDP(buf)
		if err != nil {
			log.Printf("[VPN] ReadFromUDP error: %v", err)
			continue
		}

		handlePacket(conn, remoteAddr, buf[:n], cfg)
	}
}

func handlePacket(conn *net.UDPConn, remoteAddr *net.UDPAddr, data []byte, cfg *config.Config) {
	addrStr := remoteAddr.String()

	sessionsMu.RLock()
	sess, exists := sessions[addrStr]
	sessionsMu.RUnlock()

	// If no session exists, we expect a ClientHello msgpack
	if !exists {
		var hello ClientHello
		if err := msgpack.Unmarshal(data, &hello); err != nil {
			log.Printf("[VPN] Unknown/Invalid Auth packet from %s (len: %d)", addrStr, len(data))
			return
		}

		authRes := auth.AuthenticateAndRegister(db.Pool, hello.Auth, cfg.JWTSecret)
		if !authRes.OK {
			log.Printf("[VPN] Auth rejected for %s: %s", addrStr, authRes.Reason)
			return
		}

		clientVIP, ok := vips.acquire()
		if !ok {
			log.Printf("[VPN] IP pool exhausted for %s", addrStr)
			return
		}

		sess = &session{
			addr:     remoteAddr,
			vip:      clientVIP,
			userID:   authRes.UserID,
			lastSeen: time.Now(),
		}

		sessionsMu.Lock()
		sessions[addrStr] = sess
		sessionsMu.Unlock()

		tun.RegisterClient(clientVIP, remoteAddr)
		IncConn()

		log.Printf("[VPN] Session started for user=%s vip=%s from %s (dev=%s)", authRes.UserID, clientVIP, addrStr, hello.DevName)
		return
	}

	// Update last seen
	sess.lastSeen = time.Now()

	// Forward raw IP packet into TUN device
	if tun.Device != nil && len(data) > 20 {
		src := net.IP(data[12:16]).String()
		dst := net.IP(data[16:20]).String()
		// Only log if destination is not internal or just everything for debug
		log.Printf("[UDP→TUN] Packet from %s: %s -> %s (%d bytes)", addrStr, src, dst, len(data))

		if _, werr := tun.Device.Write(data); werr != nil {
			log.Printf("[VPN] TUN write error: %v", werr)
		}
	}
}
