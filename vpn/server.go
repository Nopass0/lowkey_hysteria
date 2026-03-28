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
	"hysteria_server/heartbeat"
	"hysteria_server/telemetry"
	"hysteria_server/tun"
)

type ClientHello struct {
	_msgpack struct{} `msgpack:",asArray"`
	Auth     string   `msgpack:"auth"`
	Rx       uint64   `msgpack:"rx"`
	Tx       uint64   `msgpack:"tx"`
	DevID    string   `msgpack:"devId"`
	DevName  string   `msgpack:"devName"`
	DevOS    string   `msgpack:"devOS"`
	Version  string   `msgpack:"ver"`
	Padding  []byte   `msgpack:"padding"`
}

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

type countingWriter struct {
	dst     io.Writer
	onWrite func(int)
}

func (w *countingWriter) Write(p []byte) (int, error) {
	n, err := w.dst.Write(p)
	if n > 0 && w.onWrite != nil {
		w.onWrite(n)
	}
	return n, err
}

func ListenAndServe(cfg *config.Config) {
	cert, err := loadTLSCertificate(cfg)
	if err != nil {
		log.Fatalf("[VPN] TLS cert error: %v", err)
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{http3.NextProtoH3},
		MinVersion:   tls.VersionTLS13,
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

	log.Printf("[VPN] HTTP/3 server listening on %s", cfg.ListenAddr)
	if err := server.ListenAndServe(); err != nil {
		log.Fatalf("[VPN] HTTP/3 server error: %v", err)
	}
}

func handleTunnel(w http.ResponseWriter, r *http.Request, cfg *config.Config) {
	addrStr := r.RemoteAddr
	log.Printf("[VPN] New HTTP/3 tunnel request from %s", addrStr)

	decoder := msgpack.NewDecoder(r.Body)
	var hello ClientHello
	if err := decoder.Decode(&hello); err != nil {
		log.Printf("[VPN] Auth decode error from %s: %v", addrStr, err)
		http.Error(w, "invalid auth", http.StatusUnauthorized)
		return
	}

	authRes := auth.AuthenticateAndRegister(hello.Auth, cfg.JWTSecret)
	if !authRes.OK {
		log.Printf("[VPN] Auth rejected for %s: %s", addrStr, authRes.Reason)
		http.Error(w, "auth failed", http.StatusUnauthorized)
		return
	}

	clientVIP := r.Header.Get("X-Client-IP")
	releaseVIP := false
	if clientVIP == "" {
		if allocated, ok := vips.acquire(); ok {
			clientVIP = allocated
			releaseVIP = true
		}
	}
	if clientVIP == "" {
		log.Printf("[VPN] No VIP available for %s", addrStr)
		http.Error(w, "missing unique IP", http.StatusBadRequest)
		return
	}
	if releaseVIP {
		defer vips.release(clientVIP)
	}

	w.Header().Set("Content-Type", "application/octet-stream")
	w.WriteHeader(http.StatusOK)

	pr, pw := io.Pipe()
	tun.RegisterStreamClient(clientVIP, pw)
	defer tun.UnregisterClient(clientVIP)

	session := telemetry.StartHysteriaSession(telemetry.SessionInfo{
		UserID:        authRes.UserID,
		Protocol:      "hysteria2",
		ServerID:      heartbeat.ServerID(),
		ServerIP:      cfg.PublicIP,
		DeviceID:      hello.DevID,
		DeviceName:    hello.DevName,
		DeviceOS:      hello.DevOS,
		ClientVersion: hello.Version,
		VIP:           clientVIP,
		RemoteAddr:    addrStr,
	})
	defer session.Close()

	log.Printf("[VPN] Tunnel established for user=%s vip=%s from %s", authRes.UserID, clientVIP, addrStr)

	go func() {
		_, _ = io.Copy(&countingWriter{
			dst: w,
			onWrite: func(n int) {
				session.AddBytesDown(n)
			},
		}, pr)
	}()

	buf := make([]byte, 2048)
	for {
		n, err := r.Body.Read(buf)
		if n > 0 {
			session.AddBytesUp(n)
			telemetry.ObserveHysteriaPacket(
				authRes.UserID,
				heartbeat.ServerID(),
				cfg.PublicIP,
				addrStr,
				buf[:n],
			)
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

	log.Printf("[VPN] Tunnel closed for user=%s vip=%s", authRes.UserID, clientVIP)
}
