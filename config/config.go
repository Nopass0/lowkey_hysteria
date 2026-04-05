package config

import (
	"log"
	"os"
	"strconv"

	"gopkg.in/yaml.v3"
)

type Config struct {
	// VoidDB direct connection
	VoidDBURL      string `yaml:"voiddb_url"`
	VoidDBUsername string `yaml:"voiddb_username"`
	VoidDBPassword string `yaml:"voiddb_password"`
	VoidDBToken    string `yaml:"voiddb_token"`

	// Central backend API (used for some operations)
	BackendURL    string `yaml:"backend_url"`
	BackendSecret string `yaml:"backend_secret"`
	TLSCacheDir   string `yaml:"tls_cache_dir"`

	// Hysteria2 server settings
	Listen        string `yaml:"listen"` // e.g. "0.0.0.0:443"
	CertFile      string `yaml:"cert_file"`
	KeyFile       string `yaml:"key_file"`
	Obfs          string `yaml:"obfs"`           // salamander obfuscation password
	BandwidthUp   int    `yaml:"bandwidth_up"`   // Mbps
	BandwidthDown int    `yaml:"bandwidth_down"` // Mbps

	// Server identity (registered in backend)
	ServerID       string `yaml:"server_id"`
	ServerIP       string `yaml:"server_ip"`
	ServerHostname string `yaml:"server_hostname"`

	// Captive portal - URL shown to expired users
	CaptivePortalURL    string `yaml:"captive_portal_url"`    // e.g. https://lowkeyvpn.com/me/billing
	CaptivePortalListen string `yaml:"captive_portal_listen"` // HTTP redirect, e.g. "0.0.0.0:8080"
	CaptiveHTTPSListen  string `yaml:"captive_https_listen"`  // HTTPS captive portal, e.g. "0.0.0.0:8443"
	CaptiveIP           string `yaml:"captive_ip"`            // public IP for DNS hijack
	DNSListen           string `yaml:"dns_listen"`            // DNS server for captive portal, e.g. "0.0.0.0:53"
	UpstreamDNS         string `yaml:"upstream_dns"`          // real resolver, e.g. "8.8.8.8:53"

	// MTProto proxy
	MTProtoEnabled             bool   `yaml:"mtproto_enabled"`
	MTProtoListen              string `yaml:"mtproto_listen"` // e.g. "0.0.0.0:8443"
	MTProtoSecret              string `yaml:"mtproto_secret"` // hex secret
	MTProtoAddChannelOnConnect bool   `yaml:"mtproto_add_channel"`
	MTProtoChannelUsername     string `yaml:"mtproto_channel"` // @channel_name

	// Domain stats flush interval (seconds)
	DomainFlushInterval int `yaml:"domain_flush_interval"` // default 60
}

func Load() *Config {
	cfg := &Config{}

	// Try to load from config.yaml
	if data, err := os.ReadFile("config.yaml"); err == nil {
		if err := yaml.Unmarshal(data, cfg); err != nil {
			log.Printf("[Config] Failed to parse config.yaml: %v", err)
		}
	}

	// Override with environment variables
	applyStringEnv("VOIDDB_URL", &cfg.VoidDBURL)
	applyStringEnv("VOIDDB_USERNAME", &cfg.VoidDBUsername)
	applyStringEnv("VOIDDB_PASSWORD", &cfg.VoidDBPassword)
	applyStringEnv("VOIDDB_TOKEN", &cfg.VoidDBToken)
	applyStringEnv("BACKEND_URL", &cfg.BackendURL)
	applyStringEnv("BACKEND_SECRET", &cfg.BackendSecret)
	applyStringEnv("TLS_CACHE_DIR", &cfg.TLSCacheDir)
	applyStringEnv("SERVER_ID", &cfg.ServerID)
	applyStringEnv("SERVER_IP", &cfg.ServerIP)
	applyStringEnv("SERVER_HOSTNAME", &cfg.ServerHostname)
	applyStringEnv("LISTEN", &cfg.Listen)
	applyStringEnv("CERT_FILE", &cfg.CertFile)
	applyStringEnv("KEY_FILE", &cfg.KeyFile)
	applyStringEnv("OBFS", &cfg.Obfs)
	applyStringEnv("CAPTIVE_PORTAL_URL", &cfg.CaptivePortalURL)
	applyStringEnv("CAPTIVE_PORTAL_LISTEN", &cfg.CaptivePortalListen)
	applyStringEnv("CAPTIVE_HTTPS_LISTEN", &cfg.CaptiveHTTPSListen)
	applyStringEnv("CAPTIVE_IP", &cfg.CaptiveIP)
	applyStringEnv("DNS_LISTEN", &cfg.DNSListen)
	applyStringEnv("UPSTREAM_DNS", &cfg.UpstreamDNS)
	applyStringEnv("MTPROTO_LISTEN", &cfg.MTProtoListen)
	applyStringEnv("MTPROTO_SECRET", &cfg.MTProtoSecret)
	applyStringEnv("MTPROTO_CHANNEL", &cfg.MTProtoChannelUsername)
	applyStringEnv("MTPROTO_BOT", &cfg.MTProtoChannelUsername)
	applyBoolEnv("MTPROTO_ENABLED", &cfg.MTProtoEnabled)
	applyBoolEnv("MTPROTO_ADD_CHANNEL", &cfg.MTProtoAddChannelOnConnect)
	applyBoolEnv("MTPROTO_ADD_BOT", &cfg.MTProtoAddChannelOnConnect)
	applyIntEnv("BANDWIDTH_UP", &cfg.BandwidthUp)
	applyIntEnv("BANDWIDTH_DOWN", &cfg.BandwidthDown)
	applyIntEnv("DOMAIN_FLUSH_INTERVAL", &cfg.DomainFlushInterval)

	// Defaults
	if cfg.BackendURL == "" {
		cfg.BackendURL = "https://lowkey.su/api"
	}
	if cfg.TLSCacheDir == "" {
		cfg.TLSCacheDir = "./tls-cache"
	}
	if cfg.Listen == "" {
		cfg.Listen = "0.0.0.0:443"
	}
	if cfg.CaptivePortalListen == "" {
		cfg.CaptivePortalListen = "0.0.0.0:8080"
	}
	if cfg.CaptiveHTTPSListen == "" {
		cfg.CaptiveHTTPSListen = "0.0.0.0:8443"
	}
	if cfg.DNSListen == "" {
		cfg.DNSListen = "0.0.0.0:53"
	}
	if cfg.MTProtoListen == "" {
		cfg.MTProtoListen = "0.0.0.0:8443"
	}
	if cfg.DomainFlushInterval == 0 {
		cfg.DomainFlushInterval = 60
	}
	if cfg.BandwidthUp == 0 {
		cfg.BandwidthUp = 1000
	}
	if cfg.BandwidthDown == 0 {
		cfg.BandwidthDown = 1000
	}
	if cfg.CaptivePortalURL == "" {
		cfg.CaptivePortalURL = "https://lowkey.su"
	}
	if cfg.UpstreamDNS == "" {
		cfg.UpstreamDNS = "8.8.8.8:53"
	}
	if cfg.MTProtoChannelUsername == "" {
		cfg.MTProtoChannelUsername = "@lowkeyvpnbot"
	}
	if cfg.ServerIP == "" {
		cfg.ServerIP = cfg.CaptiveIP
	}
	if cfg.CaptiveIP == "" {
		cfg.CaptiveIP = cfg.ServerIP
	}
	return cfg
}

func applyStringEnv(key string, target *string) {
	if v := os.Getenv(key); v != "" {
		*target = v
	}
}

func applyIntEnv(key string, target *int) {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			*target = n
		}
	}
}

func applyBoolEnv(key string, target *bool) {
	if v := os.Getenv(key); v != "" {
		if parsed, err := strconv.ParseBool(v); err == nil {
			*target = parsed
		}
	}
}
