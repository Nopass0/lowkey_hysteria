package heartbeat

import (
	"context"
	"encoding/json"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	voidorm "github.com/Nopass0/void_go"

	"hysteria_server/config"
	"hysteria_server/db"
	"hysteria_server/telemetry"
)

var (
	serverID string
	serverIP string
	serverMu sync.RWMutex
)

func ServerID() string {
	serverMu.RLock()
	defer serverMu.RUnlock()
	return serverID
}

func ServerIP() string {
	serverMu.RLock()
	defer serverMu.RUnlock()
	return serverIP
}

func shouldRefreshConnectLink(existing, generated, connectHost string) bool {
	if strings.TrimSpace(existing) == "" {
		return true
	}
	if !strings.Contains(existing, connectHost) {
		return true
	}
	if strings.Contains(existing, "security=reality") && !strings.Contains(existing, "flow=xtls-rprx-vision") {
		return true
	}
	if strings.Contains(existing, "security=reality") && !strings.Contains(existing, "packetEncoding=xudp") {
		return true
	}
	if !strings.Contains(existing, "pbk=") || !strings.Contains(existing, "sid=") {
		return true
	}
	return false
}

func RegisterServer(cfg *config.Config, location string) {
	protocols := []string{"hysteria2", "vless"}
	connectHost := cfg.PublicHostname
	if connectHost == "" {
		connectHost = cfg.PublicIP
	}
	connectLink := "vless://{uuid}@" + connectHost + ":" + strconv.Itoa(cfg.XrayPort) + "?encryption=none&flow=xtls-rprx-vision&security=reality&sni=google.com&fp=chrome&pbk=4kh0XQFo3wcPOnAU-o_Nokc3WQGWUVQEPQBurWHxUBM&sid=e12b6c973e573780&type=tcp&headerType=none&packetEncoding=xudp#lowkey-" + location

	for {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		doc, err := db.FindOne(
			ctx,
			"vpn_servers",
			voidorm.NewQuery().
				Where("ip", voidorm.Eq, cfg.PublicIP).
				Where("port", voidorm.Eq, cfg.Port),
		)
		if err == nil {
			id := db.AsString(doc, "_id")
			patch := voidorm.Doc{
				"status":             "online",
				"currentLoad":        telemetry.TotalLoad(),
				"location":           location,
				"supportedProtocols": protocols,
				"lastSeenAt":         time.Now().UTC(),
			}
			if cfg.PublicHostname != "" {
				patch["hostname"] = cfg.PublicHostname
			}
			if db.AsString(doc, "serverType") == "" {
				patch["serverType"] = "hybrid"
			}
			if shouldRefreshConnectLink(db.AsString(doc, "connectLinkTemplate"), connectLink, connectHost) {
				patch["connectLinkTemplate"] = connectLink
			}
			_, err = db.Patch(ctx, "vpn_servers", id, patch)
			cancel()
			if err == nil {
				serverMu.Lock()
				serverID = id
				serverIP = cfg.PublicIP
				serverMu.Unlock()
				log.Printf("[Heartbeat] Server registered in VoidDB, ID=%s, location=%s", id, location)
				return
			}
		} else {
			id, insertErr := db.Insert(ctx, "vpn_servers", voidorm.Doc{
				"ip":                  cfg.PublicIP,
				"hostname":            cfg.PublicHostname,
				"port":                cfg.Port,
				"status":              "online",
				"currentLoad":         telemetry.TotalLoad(),
				"lastSeenAt":          time.Now().UTC(),
				"createdAt":           time.Now().UTC(),
				"serverType":          "hybrid",
				"supportedProtocols":  protocols,
				"location":            location,
				"connectLinkTemplate": connectLink,
			})
			cancel()
			if insertErr == nil {
				serverMu.Lock()
				serverID = id
				serverIP = cfg.PublicIP
				serverMu.Unlock()
				log.Printf("[Heartbeat] Server created in VoidDB, ID=%s, location=%s", id, location)
				return
			}
			err = insertErr
		}
		log.Printf("[Heartbeat] Registration failed: %v, retrying in 10s...", err)
		time.Sleep(10 * time.Second)
	}
}

func UpdateCurrentLoadAsync() {
	id := ServerID()
	if id == "" {
		return
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_, err := db.Patch(ctx, "vpn_servers", id, voidorm.Doc{
			"currentLoad": telemetry.TotalLoad(),
			"lastSeenAt":  time.Now().UTC(),
			"status":      "online",
		})
		if err != nil {
			log.Printf("[Heartbeat] Immediate load update error: %v", err)
		}
	}()
}

func StartHeartbeatDB() {
	go func() {
		ticker := time.NewTicker(15 * time.Second)
		defer ticker.Stop()
		for range ticker.C {
			UpdateCurrentLoadAsync()
		}
	}()
	log.Println("[Heartbeat] VoidDB heartbeat started (15s interval)")
}

func StartServerMonitor() {
	const interval = 2 * time.Minute
	const timeout = 2 * time.Minute

	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for range ticker.C {
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			rows, err := db.FindMany(ctx, "vpn_servers", voidorm.NewQuery().Where("status", voidorm.Eq, "online"))
			cancel()
			if err != nil {
				log.Printf("[Monitor] Query error: %v", err)
				continue
			}

			threshold := time.Now().Add(-timeout)
			marked := 0
			selfID := ServerID()
			for _, row := range rows {
				id := db.AsString(row, "_id")
				if id == "" || id == selfID {
					continue
				}
				lastSeen := db.AsTime(row, "lastSeenAt")
				if lastSeen.IsZero() || lastSeen.Before(threshold) {
					ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
					if _, err := db.Patch(ctx, "vpn_servers", id, voidorm.Doc{"status": "offline"}); err == nil {
						marked++
					}
					cancel()
				}
			}
			if marked > 0 {
				log.Printf("[Monitor] Marked %d VPN server(s) offline", marked)
			}
		}
	}()
	log.Println("[Monitor] Peer monitor started (2m interval)")
}

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
	log.Println("[Heartbeat] Could not detect public IP, using 127.0.0.1")
	return "127.0.0.1"
}

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

	if resp.StatusCode != http.StatusOK {
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
