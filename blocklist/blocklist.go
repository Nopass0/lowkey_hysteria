package blocklist

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/url"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	voidorm "github.com/Nopass0/void_go"

	"hysteria_server/config"
	"hysteria_server/db"
	"hysteria_server/heartbeat"
)

const syncInterval = 15 * time.Second

type Entry struct {
	Domain      string
	Reason      string
	RedirectURL string
}

type Manager struct {
	cfg *config.Config

	mu      sync.RWMutex
	entries map[string]Entry

	lastSync   atomic.Int64
	lastSynced atomic.Int64
	stopCh     chan struct{}
}

func New(cfg *config.Config) *Manager {
	m := &Manager{
		cfg:     cfg,
		entries: make(map[string]Entry),
		stopCh:  make(chan struct{}),
	}

	m.refresh()
	go m.loop()
	return m
}

func (m *Manager) Stop() {
	close(m.stopCh)
}

func (m *Manager) LastSyncTime() int64 {
	return m.lastSync.Load()
}

func (m *Manager) MatchHost(host string) (Entry, bool) {
	host = normalizeDomain(host)
	if host == "" {
		return Entry{}, false
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

	if entry, ok := m.entries[host]; ok {
		return entry, true
	}

	parts := strings.Split(host, ".")
	for i := 1; i < len(parts)-1; i++ {
		parent := strings.Join(parts[i:], ".")
		if entry, ok := m.entries[parent]; ok {
			return entry, true
		}
	}

	return Entry{}, false
}

func (m *Manager) RedirectURL(entry Entry, host string) string {
	base := strings.TrimSpace(entry.RedirectURL)
	if base == "" || m.shouldUseLocalBlockedPage(base) {
		base = m.defaultRedirectURL()
	}

	parsed, err := url.Parse(base)
	if err != nil {
		return base
	}

	query := parsed.Query()
	if host = normalizeDomain(host); host != "" && query.Get("domain") == "" {
		query.Set("domain", host)
	}
	if reason := strings.TrimSpace(entry.Reason); reason != "" && query.Get("reason") == "" {
		query.Set("reason", reason)
	}
	parsed.RawQuery = query.Encode()
	return parsed.String()
}

func (m *Manager) shouldUseLocalBlockedPage(raw string) bool {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return false
	}

	host := strings.ToLower(strings.TrimSpace(parsed.Hostname()))
	path := strings.TrimSpace(parsed.EscapedPath())
	if path == "" {
		path = strings.TrimSpace(parsed.Path)
	}

	return path == "/blocked" && (host == "lowkey.su" || host == "www.lowkey.su")
}

func (m *Manager) Domains() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()

	out := make([]string, 0, len(m.entries))
	for domain := range m.entries {
		out = append(out, domain)
	}
	sort.Strings(out)
	return out
}

func (m *Manager) loop() {
	ticker := time.NewTicker(syncInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			m.refresh()
		case <-m.stopCh:
			return
		}
	}
}

func (m *Manager) refresh() {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	rows, err := db.FindMany(
		ctx,
		"vpn_blocked_domains",
		voidorm.NewQuery().
			Where("isActive", voidorm.Eq, true).
			OrderBy("domain", voidorm.Asc),
	)
	if err != nil {
		log.Printf("[Blocklist] Sync failed: %v", err)
		return
	}

	nextEntries := make(map[string]Entry, len(rows))
	for _, row := range rows {
		domain := normalizeDomain(db.AsString(row, "domain"))
		if domain == "" {
			continue
		}
		nextEntries[domain] = Entry{
			Domain:      domain,
			Reason:      strings.TrimSpace(db.AsString(row, "reason")),
			RedirectURL: strings.TrimSpace(db.AsString(row, "redirectUrl")),
		}
	}

	m.mu.Lock()
	m.entries = nextEntries
	m.mu.Unlock()

	now := time.Now().UTC()
	m.lastSync.Store(now.UnixMilli())

	if serverID := heartbeat.ServerID(); serverID != "" {
		if _, err := db.Patch(ctx, "vpn_servers", serverID, voidorm.Doc{
			"lastBlocklistSyncAt": now,
			"blocklistForceSync":  false,
		}); err != nil {
			log.Printf("[Blocklist] Failed to update sync state: %v", err)
		}
	}

	count := int64(len(nextEntries))
	if previous := m.lastSynced.Swap(count); previous != count {
		log.Printf("[Blocklist] Loaded %d blocked domain(s)", count)
	}
}

func (m *Manager) defaultRedirectURL() string {
	host := strings.TrimSpace(m.cfg.PublicHostname)
	if host == "" {
		host = strings.TrimSpace(m.cfg.PublicIP)
	}
	if host == "" {
		host = "127.0.0.1"
	}

	port := httpPort(m.cfg.HTTPAddr)
	return fmt.Sprintf("http://%s:%d/blocked", host, port)
}

func httpPort(addr string) int {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return 8080
	}
	if _, port, err := net.SplitHostPort(addr); err == nil {
		if n := parsePort(port); n > 0 {
			return n
		}
	}
	if strings.HasPrefix(addr, ":") {
		if n := parsePort(strings.TrimPrefix(addr, ":")); n > 0 {
			return n
		}
	}
	return 8080
}

func parsePort(value string) int {
	n, err := net.LookupPort("tcp", value)
	if err != nil {
		return 0
	}
	return n
}

func normalizeDomain(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	value = strings.TrimRight(value, ".")

	if host, _, err := net.SplitHostPort(value); err == nil {
		value = host
	}

	return strings.Trim(value, ".")
}
