// Package stats tracks per-user domain visits and flushes them to the backend API.
package stats

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"sync"
	"time"
)

// DomainHit represents a single domain access event.
type DomainHit struct {
	Domain string
	Bytes  int64
}

// userStats holds in-memory counters for one user.
type userStats struct {
	domains map[string]*domainEntry
}

type domainEntry struct {
	visitCount int64
	bytes      int64
}

// Tracker accumulates domain hits per user and periodically flushes to backend.
type Tracker struct {
	mu          sync.Mutex
	data        map[string]*userStats // userId -> stats
	backendURL  string
	backendSecret string
	flushTicker *time.Ticker
	done        chan struct{}
}

// New creates a new domain stats tracker.
func New(backendURL, backendSecret string, flushIntervalSec int) *Tracker {
	t := &Tracker{
		data:          make(map[string]*userStats),
		backendURL:    backendURL,
		backendSecret: backendSecret,
		done:          make(chan struct{}),
	}
	interval := time.Duration(flushIntervalSec) * time.Second
	if interval <= 0 {
		interval = 60 * time.Second
	}
	t.flushTicker = time.NewTicker(interval)
	go t.flushLoop()
	return t
}

// Record adds a domain hit for the given user.
func (t *Tracker) Record(userID, domain string, bytes int64) {
	if domain == "" || userID == "" {
		return
	}
	// Strip port from domain
	if idx := indexByte(domain, ':'); idx >= 0 {
		domain = domain[:idx]
	}
	// Skip internal/private domains
	if isPrivateDomain(domain) {
		return
	}

	t.mu.Lock()
	defer t.mu.Unlock()

	us, ok := t.data[userID]
	if !ok {
		us = &userStats{domains: make(map[string]*domainEntry)}
		t.data[userID] = us
	}
	entry, ok := us.domains[domain]
	if !ok {
		entry = &domainEntry{}
		us.domains[domain] = entry
	}
	entry.visitCount++
	entry.bytes += bytes
}

func (t *Tracker) flushLoop() {
	for {
		select {
		case <-t.flushTicker.C:
			t.Flush()
		case <-t.done:
			t.Flush()
			return
		}
	}
}

// Flush sends all accumulated stats to the backend and resets counters.
func (t *Tracker) Flush() {
	t.mu.Lock()
	snapshot := t.data
	t.data = make(map[string]*userStats)
	t.mu.Unlock()

	for userID, us := range snapshot {
		if len(us.domains) == 0 {
			continue
		}

		type domainPayload struct {
			Domain           string  `json:"domain"`
			VisitCount       int64   `json:"visitCount"`
			BytesTransferred float64 `json:"bytesTransferred"`
		}
		domains := make([]domainPayload, 0, len(us.domains))
		for domain, entry := range us.domains {
			domains = append(domains, domainPayload{
				Domain:           domain,
				VisitCount:       entry.visitCount,
				BytesTransferred: float64(entry.bytes),
			})
		}

		payload := map[string]interface{}{
			"userId":  userID,
			"domains": domains,
		}
		if err := t.sendDomainReport(payload); err != nil {
			log.Printf("[Stats] Failed to flush domain stats for user %s: %v", userID, err)
		}
	}
}

func (t *Tracker) sendDomainReport(payload interface{}) error {
	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	req, err := http.NewRequest("POST", t.backendURL+"/servers/report-domains", bytes.NewReader(data))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if t.backendSecret != "" {
		req.Header.Set("X-Server-Secret", t.backendSecret)
	}

	resp, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return fmt.Errorf("backend returned %d", resp.StatusCode)
	}
	return nil
}

// Stop stops the flush loop and flushes remaining data.
func (t *Tracker) Stop() {
	t.flushTicker.Stop()
	close(t.done)
}

// isPrivateDomain returns true for localhost, IP literals, and internal domains.
func isPrivateDomain(d string) bool {
	if d == "localhost" || d == "" {
		return true
	}
	// Simple IP check: starts with digit
	if len(d) > 0 && d[0] >= '0' && d[0] <= '9' {
		return true
	}
	return false
}

func indexByte(s string, b byte) int {
	for i := 0; i < len(s); i++ {
		if s[i] == b {
			return i
		}
	}
	return -1
}
