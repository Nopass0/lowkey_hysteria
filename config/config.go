// Package config loads all environment variables for the hysteria server.
// Values are read from a .env file (via godotenv) or from the process
// environment, with sensible defaults for local development.
//
// Usage:
//
//	cfg := config.Load()
package config

import (
	"log"
	"net"
	"os"
	"strconv"

	"github.com/joho/godotenv"
)

// Config holds the full application configuration.
type Config struct {
	// ListenAddr is the UDP address the QUIC / Hysteria2 listener binds to.
	// Example: ":7000"
	ListenAddr string

	// HTTPAddr is the TCP address the management HTTP API binds to.
	// Example: ":8080"
	HTTPAddr string

	// Port is the numeric port extracted from ListenAddr (used for DB registration).
	Port int

	// PublicIP is the public IP of this machine. When empty it is auto-detected.
	PublicIP string

	// PublicHostname is the public DNS hostname assigned to this node.
	PublicHostname string

	// CertFile is an optional TLS fullchain path used by the Hysteria listener.
	CertFile string

	// KeyFile is an optional TLS private key path used by the Hysteria listener.
	KeyFile string

	// VoidDBURL is the VoidDB HTTP endpoint.
	VoidDBURL string

	// VoidDBToken is an optional pre-issued bearer token.
	VoidDBToken string

	// VoidDBUsername is the login used when no bearer token is supplied.
	VoidDBUsername string

	// VoidDBPassword is the password used when no bearer token is supplied.
	VoidDBPassword string

	// JWTSecret is the shared HMAC secret used to verify user JWT tokens.
	JWTSecret []byte

	// BackendURL is the optional URL of the central backend API, used by the
	// server monitor to fall back to REST if direct-DB access is unavailable.
	BackendURL string

	// TochkaAPIKey is the Bearer token for the Tochka SBP REST API.
	TochkaAPIKey string

	// TochkaMerchantID is the merchant identifier in the Tochka system.
	TochkaMerchantID string

	// TochkaAccountID is the bank account identifier in the Tochka system.
	TochkaAccountID string

	// XrayPort is the TCP port the VLESS/Xray inbound listens on.
	XrayPort int
}

// Load reads configuration from the environment (+ optional .env file) and
// returns a fully populated Config struct.
func Load() *Config {
	// Best-effort .env loading — ignore errors (file may not exist in prod).
	_ = godotenv.Load()

	listenAddr := getenv("LISTEN_ADDR", ":7000")
	port       := 7000
	if addr, err := net.ResolveUDPAddr("udp", listenAddr); err == nil && addr.Port != 0 {
		port = addr.Port
	}

	jwtSecretStr := getenv("JWT_SECRET", "super-secret-key")

	cfg := &Config{
		ListenAddr:       listenAddr,
		HTTPAddr:         getenv("HTTP_ADDR", ":8080"),
		Port:             port,
		PublicIP:         getenv("SERVER_IP", ""),
		PublicHostname:   getenv("SERVER_HOSTNAME", ""),
		CertFile:         getenv("CERT_FILE", ""),
		KeyFile:          getenv("KEY_FILE", ""),
		VoidDBURL:        getenv("VOIDDB_URL", "http://localhost:7700"),
		VoidDBToken:      getenv("VOIDDB_TOKEN", ""),
		VoidDBUsername:   getenv("VOIDDB_USERNAME", "admin"),
		VoidDBPassword:   getenv("VOIDDB_PASSWORD", "admin"),
		JWTSecret:        []byte(jwtSecretStr),
		BackendURL:       getenv("BACKEND_URL", "http://localhost:3001"),
		TochkaAPIKey:     getenv("TOCHKA_API_KEY", ""),
		TochkaMerchantID: getenv("TOCHKA_MERCHANT_ID", ""),
		TochkaAccountID:  getenv("TOCHKA_ACCOUNT_ID", ""),
		XrayPort:         getenvInt("XRAY_PORT", 443),
	}

	log.Printf(
		"[Config] ListenAddr=%s | HTTPAddr=%s | PublicIP=%s | Hostname=%s | XrayPort=%d",
		cfg.ListenAddr,
		cfg.HTTPAddr,
		cfg.PublicIP,
		cfg.PublicHostname,
		cfg.XrayPort,
	)
	return cfg
}

// getenv returns the value of the environment variable named by key, or
// fallback when the variable is unset or empty.
func getenv(key, fallback string) string {
	if v, ok := os.LookupEnv(key); ok && v != "" {
		return v
	}
	return fallback
}

// getenvInt returns the integer value of an env variable, or fallback.
func getenvInt(key string, fallback int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return fallback
}
