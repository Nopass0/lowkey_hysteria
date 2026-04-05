// Package blocklist maintains an in-memory list of blocked domains, refreshed
// periodically from the backend API. HandleTCPStream checks this list before
// proxying each connection and redirects blocked hosts.
package blocklist

import (
	"encoding/json"
	"io"
	"log"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const defaultRefreshInterval = 5 * time.Minute
const defaultRedirectURL = "https://lowkey.su/blocked"

// Entry is one blocked domain record.
type Entry struct {
	Domain      string
	Reason      string
	RedirectURL string
}

// Blocklist holds a thread-safe snapshot of blocked domains.
type Blocklist struct {
	mu      sync.RWMutex
	entries map[string]Entry // domain (lowercase) -> Entry

	backendURL    string
	backendSecret string
	httpClient    *http.Client

	lastSyncTime atomic.Int64 // Unix ms of last successful refresh
	forceCh      chan struct{} // triggers immediate refresh
	stopCh       chan struct{}
}

// New creates a Blocklist and starts the background refresh loop.
func New(backendURL, backendSecret string) *Blocklist {
	bl := &Blocklist{
		entries:       make(map[string]Entry),
		backendURL:    backendURL,
		backendSecret: backendSecret,
		httpClient:    &http.Client{Timeout: 10 * time.Second},
		forceCh:       make(chan struct{}, 1),
		stopCh:        make(chan struct{}),
	}
	bl.refresh()
	go bl.loop()
	return bl
}

// Stop halts the background refresh loop.
func (bl *Blocklist) Stop() {
	close(bl.stopCh)
}

// ForceRefresh triggers an immediate blocklist refresh (non-blocking).
func (bl *Blocklist) ForceRefresh() {
	select {
	case bl.forceCh <- struct{}{}:
	default:
	}
}

// LastSyncTime returns the Unix millisecond timestamp of the last successful refresh.
func (bl *Blocklist) LastSyncTime() int64 {
	return bl.lastSyncTime.Load()
}

// IsBlocked returns the redirect URL and true if the domain (or any parent
// domain up to the registered TLD) is blocked. Returns ("", false) otherwise.
func (bl *Blocklist) IsBlocked(host string) (redirectURL string, blocked bool) {
	if idx := strings.LastIndex(host, ":"); idx != -1 {
		host = host[:idx]
	}
	host = strings.ToLower(strings.TrimRight(host, "."))

	bl.mu.RLock()
	defer bl.mu.RUnlock()

	if e, ok := bl.entries[host]; ok {
		url := e.RedirectURL
		if url == "" {
			url = defaultRedirectURL
		}
		return url, true
	}

	parts := strings.Split(host, ".")
	for i := 1; i < len(parts)-1; i++ {
		parent := strings.Join(parts[i:], ".")
		if e, ok := bl.entries[parent]; ok {
			url := e.RedirectURL
			if url == "" {
				url = defaultRedirectURL
			}
			return url, true
		}
	}

	return "", false
}

// Size returns the number of currently loaded blocked domains.
func (bl *Blocklist) Size() int {
	bl.mu.RLock()
	defer bl.mu.RUnlock()
	return len(bl.entries)
}

func (bl *Blocklist) loop() {
	ticker := time.NewTicker(defaultRefreshInterval)
	defer ticker.Stop()
	for {
		select {
		case <-bl.stopCh:
			return
		case <-bl.forceCh:
			bl.refresh()
		case <-ticker.C:
			bl.refresh()
		}
	}
}

func (bl *Blocklist) refresh() {
	if bl.backendURL == "" {
		return
	}
	url := bl.backendURL + "/vpn/blocked-domains"
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		log.Printf("[Blocklist] Build request failed: %v", err)
		return
	}
	if bl.backendSecret != "" {
		req.Header.Set("X-Server-Secret", bl.backendSecret)
	}

	resp, err := bl.httpClient.Do(req)
	if err != nil {
		log.Printf("[Blocklist] Fetch failed: %v", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		log.Printf("[Blocklist] Backend returned %s", resp.Status)
		return
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Printf("[Blocklist] Read body failed: %v", err)
		return
	}

	var payload struct {
		Domains []struct {
			Domain      string `json:"domain"`
			Reason      string `json:"reason"`
			RedirectURL string `json:"redirectUrl"`
		} `json:"domains"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		log.Printf("[Blocklist] Parse failed: %v", err)
		return
	}

	newEntries := make(map[string]Entry, len(payload.Domains))
	for _, d := range payload.Domains {
		key := strings.ToLower(strings.TrimRight(d.Domain, "."))
		newEntries[key] = Entry{
			Domain:      key,
			Reason:      d.Reason,
			RedirectURL: d.RedirectURL,
		}
	}

	bl.mu.Lock()
	bl.entries = newEntries
	bl.mu.Unlock()

	bl.lastSyncTime.Store(time.Now().UnixMilli())
	log.Printf("[Blocklist] Loaded %d blocked domain(s)", len(newEntries))
}
