package server

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/lowkey/hysteria-server/config"
)

type tlsMaterialResponse struct {
	Hostname string `json:"hostname"`
	CertPEM  string `json:"certPem"`
	KeyPEM   string `json:"keyPem"`
	Message  string `json:"message"`
}

var tlsCacheNameSanitizer = regexp.MustCompile(`[^a-zA-Z0-9._-]+`)

// EnsureTLSMaterial makes sure the node has a usable TLS cert/key pair.
// If CERT_FILE and KEY_FILE are already configured, they are used as-is.
// Otherwise the node fetches TLS material from the backend and caches it locally.
func EnsureTLSMaterial(cfg *config.Config) error {
	if cfg.CertFile != "" || cfg.KeyFile != "" {
		if cfg.CertFile == "" || cfg.KeyFile == "" {
			return fmt.Errorf("CERT_FILE and KEY_FILE must both be set")
		}
		return nil
	}

	if cfg.ServerHostname == "" {
		return fmt.Errorf("SERVER_HOSTNAME is required when CERT_FILE and KEY_FILE are not set")
	}
	if cfg.BackendSecret == "" {
		return fmt.Errorf("BACKEND_SECRET is required when fetching TLS material from backend")
	}

	certPath, keyPath, err := fetchAndCacheTLSMaterial(cfg)
	if err != nil {
		return err
	}

	cfg.CertFile = certPath
	cfg.KeyFile = keyPath
	return nil
}

func fetchAndCacheTLSMaterial(cfg *config.Config) (string, string, error) {
	certPath, keyPath := tlsCachePaths(cfg)
	material, err := requestTLSMaterial(cfg)
	if err != nil {
		if cacheErr := validateTLSFiles(certPath, keyPath, cfg.ServerHostname); cacheErr == nil {
			log.Printf("[TLS] Backend TLS fetch failed, using cached files %s and %s", certPath, keyPath)
			return certPath, keyPath, nil
		}
		return "", "", err
	}

	if err := validateTLSMaterial([]byte(material.CertPEM), []byte(material.KeyPEM), cfg.ServerHostname); err != nil {
		return "", "", err
	}
	if err := os.MkdirAll(cfg.TLSCacheDir, 0o700); err != nil {
		return "", "", fmt.Errorf("create TLS cache dir: %w", err)
	}
	if err := os.WriteFile(certPath, []byte(material.CertPEM), 0o600); err != nil {
		return "", "", fmt.Errorf("write cached cert: %w", err)
	}
	if err := os.WriteFile(keyPath, []byte(material.KeyPEM), 0o600); err != nil {
		return "", "", fmt.Errorf("write cached key: %w", err)
	}

	log.Printf("[TLS] Cached TLS material for %s at %s", cfg.ServerHostname, certPath)
	return certPath, keyPath, nil
}

func requestTLSMaterial(cfg *config.Config) (*tlsMaterialResponse, error) {
	payload := map[string]string{
		"hostname": cfg.ServerHostname,
	}
	if cfg.ServerID != "" {
		payload["serverId"] = cfg.ServerID
	}

	data, _ := json.Marshal(payload)
	req, err := http.NewRequest("POST", strings.TrimRight(cfg.BackendURL, "/")+"/servers/tls-material", bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("build TLS material request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Server-Secret", cfg.BackendSecret)

	resp, err := (&http.Client{Timeout: 15 * time.Second}).Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch TLS material from backend: %w", err)
	}
	defer resp.Body.Close()

	var result tlsMaterialResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("decode TLS material response: %w", err)
	}
	if resp.StatusCode >= 400 {
		if result.Message == "" {
			result.Message = resp.Status
		}
		return nil, fmt.Errorf("backend TLS provisioning failed: %s", result.Message)
	}
	if result.CertPEM == "" || result.KeyPEM == "" {
		return nil, fmt.Errorf("backend returned empty TLS material")
	}

	return &result, nil
}

func tlsCachePaths(cfg *config.Config) (string, string) {
	name := tlsCacheNameSanitizer.ReplaceAllString(cfg.ServerHostname, "_")
	return filepath.Join(cfg.TLSCacheDir, name+".crt.pem"), filepath.Join(cfg.TLSCacheDir, name+".key.pem")
}

func validateTLSFiles(certPath, keyPath, hostname string) error {
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return err
	}
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return err
	}
	return validateTLSMaterial(certPEM, keyPEM, hostname)
}

func validateTLSMaterial(certPEM, keyPEM []byte, hostname string) error {
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return fmt.Errorf("invalid TLS key pair: %w", err)
	}
	if len(pair.Certificate) == 0 {
		return fmt.Errorf("TLS certificate chain is empty")
	}

	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return fmt.Errorf("parse TLS certificate: %w", err)
	}
	if hostname != "" {
		if err := leaf.VerifyHostname(hostname); err != nil {
			return fmt.Errorf("TLS certificate does not cover %s: %w", hostname, err)
		}
	}
	now := time.Now()
	if now.Before(leaf.NotBefore) {
		return fmt.Errorf("TLS certificate is not valid yet until %s", leaf.NotBefore.Format(time.RFC3339))
	}
	if now.After(leaf.NotAfter) {
		return fmt.Errorf("TLS certificate expired at %s", leaf.NotAfter.Format(time.RFC3339))
	}
	return nil
}
