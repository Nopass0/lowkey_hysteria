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

	// PublicIP is the auto-detected public IP of this machine.
	PublicIP string

	// DatabaseURL is the PostgreSQL connection string.
	DatabaseURL string

	// RedisURL is the Redis connection string.
	RedisURL string

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
		DatabaseURL:      getenv("DATABASE_URL", "postgres://postgres:postgres@localhost:5432/lowkey"),
		RedisURL:         getenv("REDIS_URL", "redis://localhost:6379"),
		JWTSecret:        []byte(jwtSecretStr),
		BackendURL:       getenv("BACKEND_URL", "http://localhost:3001"),
		TochkaAPIKey:     getenv("TOCHKA_API_KEY", ""),
		TochkaMerchantID: getenv("TOCHKA_MERCHANT_ID", ""),
		TochkaAccountID:  getenv("TOCHKA_ACCOUNT_ID", ""),
	}

	log.Printf("[Config] ListenAddr=%s | HTTPAddr=%s", cfg.ListenAddr, cfg.HTTPAddr)
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
