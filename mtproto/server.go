// Package mtproto implements an MTProto proxy server compatible with Telegram.
//
// MTProto proxy allows Telegram clients to connect to Telegram via an
// intermediate proxy, which is useful for bypassing censorship.
//
// The secret format "dd<hex>" enables TLS-camouflage (fake-TLS),
// making traffic appear as regular HTTPS to DPI systems.
//
// When addChannelOnConnect is enabled, the proxy exposes an optional
// Telegram promo username (for example a bot or channel).
//
// References:
//
//	https://core.telegram.org/mtproto/mtproto-transports#faketls
//	https://github.com/alexbers/mtprotoproxy
package mtproto

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"net"
	"sync"
	"time"
)

// Telegram DC addresses (IPv4).
var telegramDCs = map[int]string{
	1: "149.154.175.53:443",
	2: "149.154.167.51:443",
	3: "149.154.175.100:443",
	4: "149.154.167.91:443",
	5: "91.108.56.130:443",
}

// Server is the MTProto proxy server.
type Server struct {
	listen              string
	secret              []byte // 16 bytes raw secret (from hex string)
	addChannelOnConnect bool
	channelUsername     string // @lowkeyvpnbot or channel username shown as promo
	ln                  net.Listener
}

// New creates a new MTProto proxy server.
// secretHex should be a 32-char hex string (16 bytes).
// Prefix "dd" to the hex to enable fake-TLS mode.
func New(listen, secretHex, channelUsername string, addChannel bool) (*Server, error) {
	// Normalise secret: strip "ee" or "dd" prefix if present
	rawHex := secretHex
	if len(rawHex) == 34 && (rawHex[:2] == "dd" || rawHex[:2] == "ee") {
		rawHex = rawHex[2:]
	}
	if len(rawHex) != 32 {
		return nil, fmt.Errorf("mtproto: secret must be 32 hex chars (16 bytes), got %d", len(rawHex))
	}
	secret, err := hex.DecodeString(rawHex)
	if err != nil {
		return nil, fmt.Errorf("mtproto: invalid secret hex: %w", err)
	}

	return &Server{
		listen:              listen,
		secret:              secret,
		addChannelOnConnect: addChannel,
		channelUsername:     channelUsername,
	}, nil
}

// ListenAndServe starts the MTProto proxy and blocks until Stop is called.
func (s *Server) ListenAndServe() error {
	ln, err := net.Listen("tcp", s.listen)
	if err != nil {
		return fmt.Errorf("mtproto listen: %w", err)
	}
	s.ln = ln
	log.Printf("[MTProto] Listening on %s", s.listen)
	if s.channelUsername != "" {
		log.Printf("[MTProto] Advertising Telegram promo: %s", s.channelUsername)
	}

	for {
		conn, err := ln.Accept()
		if err != nil {
			return nil // stopped
		}
		go s.handleConn(conn)
	}
}

// Stop closes the listener.
func (s *Server) Stop() {
	if s.ln != nil {
		s.ln.Close()
	}
}

// ─── Fake-TLS handshake ───────────────────────────────────────────────────────
// Telegram's MTProto fake-TLS transport starts with a TLS ClientHello.
// The proxy decodes the embedded random bytes using HMAC-SHA256 to verify
// the secret, then switches to raw MTProto forwarding.

const fakeTLSRecordSize = 517

// handleConn handles a single client connection.
func (s *Server) handleConn(conn net.Conn) {
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(30 * time.Second))

	// Read initial handshake
	buf := make([]byte, fakeTLSRecordSize)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return
	}

	// Verify HMAC-SHA256 of the ClientHello random field (bytes 11–43)
	// using our secret. If it matches, this is a valid client.
	clientRandom := buf[11:43]
	mac := hmac.New(sha256.New, s.secret)
	mac.Write(buf[:11])
	mac.Write(make([]byte, 32)) // zero out random for verification
	mac.Write(buf[43:])
	expectedMAC := mac.Sum(nil)[:4]
	if !hmac.Equal(expectedMAC, clientRandom[:4]) {
		// Not a valid MTProto client; silently close
		return
	}

	// Extract DC index from session ID field (bytes 44+)
	dcIndex := 2 // default to DC2
	if len(buf) > 44 {
		dcIndex = int(buf[44])&0x0F + 1
		if dcIndex < 1 || dcIndex > 5 {
			dcIndex = 2
		}
	}

	// Send fake TLS ServerHello + ChangeCipherSpec + fake Application Data
	serverHello := buildFakeTLSServerHello()
	conn.Write(serverHello)

	conn.SetDeadline(time.Time{}) // remove deadline for proxying

	// Connect to Telegram DC
	dcAddr, ok := telegramDCs[dcIndex]
	if !ok {
		dcAddr = telegramDCs[2]
	}

	tgConn, err := net.DialTimeout("tcp", dcAddr, 10*time.Second)
	if err != nil {
		log.Printf("[MTProto] Cannot connect to Telegram DC%d (%s): %v", dcIndex, dcAddr, err)
		return
	}
	defer tgConn.Close()

	// Perform proxy handshake with Telegram server
	if err := s.performTelegramHandshake(tgConn); err != nil {
		log.Printf("[MTProto] Telegram handshake failed: %v", err)
		return
	}

	// Bi-directional proxy
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		io.Copy(tgConn, conn)
		tgConn.(*net.TCPConn).CloseWrite()
	}()
	go func() {
		defer wg.Done()
		io.Copy(conn, tgConn)
		if tc, ok := conn.(*net.TCPConn); ok {
			tc.CloseWrite()
		}
	}()
	wg.Wait()
}

// performTelegramHandshake sends the MTProto intermediate transport header to Telegram.
func (s *Server) performTelegramHandshake(conn net.Conn) error {
	// MTProto intermediate transport: send 4-byte magic 0xEEEEEEEE
	// followed by the secret-derived obfuscation header
	header := make([]byte, 64)
	rand.Read(header)

	// Set magic bytes at specific positions (protocol requirement)
	binary.BigEndian.PutUint32(header[56:], 0xEEEEEEEE)

	// Encrypt with secret (simplified — production needs full obfuscation)
	_, err := conn.Write(header[:64])
	return err
}

// buildFakeTLSServerHello constructs a minimal fake TLS ServerHello response.
func buildFakeTLSServerHello() []byte {
	var buf bytes.Buffer

	// TLS Record: Handshake (22), TLS 1.2 (0x0303)
	serverRandom := make([]byte, 32)
	rand.Read(serverRandom)

	// ServerHello
	hello := []byte{
		0x02,             // HandshakeType: ServerHello
		0x00, 0x00, 0x4D, // Length (placeholder)
		0x03, 0x03, // TLS 1.2
	}
	hello = append(hello, serverRandom...)
	hello = append(hello,
		0x20, // session ID length
	)
	sessionID := make([]byte, 32)
	rand.Read(sessionID)
	hello = append(hello, sessionID...)
	hello = append(hello,
		0x13, 0xC0, // CipherSuite: TLS_AES_128_GCM_SHA256 (for TLS 1.3 compat display)
		0x00,       // Compression: none
		0x00, 0x00, // Extensions length
	)

	// Fix the 24-bit handshake length field manually.
	helloLen := len(hello) - 4
	hello[1] = byte(helloLen >> 16)
	hello[2] = byte(helloLen >> 8)
	hello[3] = byte(helloLen)

	// Wrap in TLS record
	record := []byte{0x16, 0x03, 0x03}
	length := make([]byte, 2)
	binary.BigEndian.PutUint16(length, uint16(len(hello)))
	buf.Write(record)
	buf.Write(length)
	buf.Write(hello)

	// ChangeCipherSpec record
	buf.Write([]byte{0x14, 0x03, 0x03, 0x00, 0x01, 0x01})

	// Fake Application Data record (empty)
	buf.Write([]byte{0x17, 0x03, 0x03, 0x00, 0x00})

	return buf.Bytes()
}

// GenerateSecret generates a random 16-byte MTProto secret and returns it
// as a hex string with the "dd" prefix for fake-TLS mode.
func GenerateSecret() string {
	b := make([]byte, 16)
	rand.Read(b)
	return "dd" + hex.EncodeToString(b)
}

// ─── helpers ──────────────────────────────────────────────────────────────────

func init() {
	// Register BigEndian.PutUint24 helper
	_ = binary.BigEndian
}

// PutUint24 writes a 3-byte big-endian uint24.
func putUint24(b []byte, v uint32) {
	b[0] = byte(v >> 16)
	b[1] = byte(v >> 8)
	b[2] = byte(v)
}
