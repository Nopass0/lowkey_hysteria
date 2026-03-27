package vpn

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"encoding/pem"
	"math/big"
	"net"
	"time"

	"hysteria_server/config"
)

func loadTLSCertificate(cfg *config.Config) (tls.Certificate, error) {
	if cfg.CertFile != "" || cfg.KeyFile != "" {
		if cfg.CertFile == "" || cfg.KeyFile == "" {
			return tls.Certificate{}, errors.New("CERT_FILE and KEY_FILE must both be set")
		}
		return tls.LoadX509KeyPair(cfg.CertFile, cfg.KeyFile)
	}

	return generateSelfSignedCert(cfg.PublicHostname, cfg.PublicIP)
}

// generateSelfSignedCert generates a basic self-signed certificate for QUIC/TLS.
// In production, CERT_FILE/KEY_FILE should be provided by certbot.
func generateSelfSignedCert(hostname, publicIP string) (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(30 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	if hostname != "" {
		template.DNSNames = []string{hostname}
	}
	if publicIP != "" {
		if ip := net.ParseIP(publicIP); ip != nil {
			template.IPAddresses = []net.IP{ip}
		}
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}

	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return tls.Certificate{}, err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	return tls.X509KeyPair(certPEM, keyPEM)
}
