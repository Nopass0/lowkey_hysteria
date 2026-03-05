// Package heartbeat provides two goroutines:
//
//  1. StartHeartbeatDB — periodically updates this server's own lastSeenAt
//     and currentLoad in the vpn_servers table, registering the node if needed.
//
//  2. StartServerMonitor — periodically marks any peer VPN server as "offline"
//     when its lastSeenAt has not been updated for more than 2 minutes. Both
//     the backend (TypeScript) and every Go node run this loop independently.
package heartbeat

import (
	"context"
	"encoding/json"
	"log"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"hysteria_server/config"
	"hysteria_server/vpn"
)

// serverID is the database UUID of this running VPN server instance.
// It is set once by RegisterServer and used by the heartbeat goroutine.
var serverID string

// RegisterServer inserts (or updates) this server's record in vpn_servers and
// stores the resulting UUID in the package-level serverID variable.
// It retries indefinitely until the operation succeeds.
//
// @param pool     - PostgreSQL pool
// @param cfg      - application configuration (PublicIP, Port)
// @param location - Human readable location (e.g. "Moscow, RU")
func RegisterServer(pool *pgxpool.Pool, cfg *config.Config, location string) {
	protocols := []string{"hysteria2"}
	for {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		var id string
		err := pool.QueryRow(ctx, `
			INSERT INTO vpn_servers (id, ip, port, "supportedProtocols", "serverType", status, "currentLoad", location, "connectLinkTemplate", "lastSeenAt", "createdAt")
			VALUES (gen_random_uuid(), $1, $2, $3, 'dedicated', 'online', 0, $4, $5, NOW(), NOW())
			ON CONFLICT (ip, port)
			DO UPDATE SET status = 'online', location = EXCLUDED.location, "connectLinkTemplate" = EXCLUDED."connectLinkTemplate", "lastSeenAt" = NOW()
			RETURNING id
		`, cfg.PublicIP, cfg.Port, protocols, location, "vless://{uuid}@" + cfg.PublicIP + ":443?encryption=none&security=reality&sni=google.com&fp=chrome&pbk=4kh0XQFo3wcPOnAU-o_Nokc3WQGWUVQEPQBurWHxUBM&sid=e12b6c973e573780&type=tcp&headerType=none#lowkey-" + location).Scan(&id)
		cancel()

		if err == nil {
			serverID = id
			log.Printf("[Heartbeat] Server registered in DB, ID=%s, Loc=%s", serverID, location)
			return
		}
		log.Printf("[Heartbeat] Registration failed: %v — retrying in 10s...", err)
		time.Sleep(10 * time.Second)
	}
}

// StartHeartbeatDB runs a background goroutine that updates this server's
// status and currentLoad in the database every 30 seconds.
//
// @param pool - PostgreSQL pool
func StartHeartbeatDB(pool *pgxpool.Pool) {
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for range ticker.C {
			if serverID == "" {
				continue
			}
			load := vpn.LoadCount()
			_, err := pool.Exec(context.Background(), `
				UPDATE vpn_servers
				SET "currentLoad" = $1, "lastSeenAt" = NOW(), status = 'online'
				WHERE id = $2
			`, load, serverID)
			if err != nil {
				log.Printf("[Heartbeat] DB update error: %v", err)
			}
		}
	}()
	log.Println("[Heartbeat] DB heartbeat goroutine started (30s interval).")
}

// StartServerMonitor runs a background goroutine that scans the vpn_servers
// table every 2 minutes and marks peers as "offline" when their lastSeenAt is
// older than 2 minutes. This is the same logic as in the TypeScript backend.
//
// @param pool - PostgreSQL pool
func StartServerMonitor(pool *pgxpool.Pool) {
	const interval = 2 * time.Minute
	const timeout  = 2 * time.Minute

	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for range ticker.C {
			threshold := time.Now().Add(-timeout)
			tag, err := pool.Exec(context.Background(), `
				UPDATE vpn_servers
				SET status = 'offline'
				WHERE status = 'online' AND "lastSeenAt" < $1 AND id != $2
			`, threshold, serverID)
			if err != nil {
				log.Printf("[Monitor] Update error: %v", err)
			} else if tag.RowsAffected() > 0 {
				log.Printf("[Monitor] Marked %d VPN server(s) offline.", tag.RowsAffected())
			}
		}
	}()
	log.Println("[Monitor] Server health-check goroutine started (2-min interval).")
}

// DetectPublicIP queries several well-known IP-echo services and returns the
// first successful result. Falls back to "127.0.0.1" on error.
//
// @returns publicIP string
func DetectPublicIP() string {
	services := []string{
		"https://api.ipify.org",
		"https://ifconfig.me/ip",
		"https://icanhazip.com",
		"https://checkip.amazonaws.com",
	}
	client := &http.Client{Timeout: 5 * time.Second}
	for _, svc := range services {
		resp, err := client.Get(svc)
		if err != nil {
			continue
		}
		var buf [64]byte
		n, _ := resp.Body.Read(buf[:])
		resp.Body.Close()
		if n > 0 {
			ip := strings.TrimSpace(string(buf[:n]))
			if net.ParseIP(ip) != nil {
				log.Printf("[Heartbeat] Public IP detected via %s: %s", svc, ip)
				return ip
			}
		}
	}
	log.Println("[Heartbeat] Could not detect public IP — using 127.0.0.1")
	return "127.0.0.1"
}

// DetectLocation queries ip-api.com to find the geographic location of the IP.
// Useful for displaying servers in the app (e.g., "Moscow, RU").
//
// @param ip - the public IP address
// @returns location string like "City, CC"
func DetectLocation(ip string) string {
	if ip == "127.0.0.1" || ip == "localhost" {
		return "Local Test, UN"
	}
	url := "http://ip-api.com/json/" + ip + "?fields=status,countryCode,city"
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		log.Printf("[Heartbeat] Geoloc IP error: %v", err)
		return "Unknown, UN"
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return "Unknown, UN"
	}

	var data struct {
		Status      string `json:"status"`
		City        string `json:"city"`
		CountryCode string `json:"countryCode"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		log.Printf("[Heartbeat] Geoloc JSON error: %v", err)
		return "Unknown, UN"
	}

	if data.Status != "success" || data.City == "" || data.CountryCode == "" {
		return "Unknown, UN"
	}

	return data.City + ", " + data.CountryCode
}
