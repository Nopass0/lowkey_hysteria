package api

import (
	"context"
	"log"
	"net/http"
	"time"
)

type vpnServerResponse struct {
	ID        string `json:"id"`
	IP        string `json:"ip"`
	Port      int    `json:"port"`
	Location  string `json:"location"`
	Load      float64`json:"currentLoad"`
	MaxLoad   int    `json:"maxLoad"`
	IsOnline  bool   `json:"isOnline"`
	LatencyMs int    `json:"latencyMs"`
}

func (h *handler) getServers(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	rows, err := h.db.Query(ctx, "SELECT id, ip, port, location, current_load, max_load, is_online FROM vpn_servers WHERE is_online = true")
	if err != nil {
		log.Printf("[API] Failed to fetch servers: %v", err)
		writeJSON(w, http.StatusInternalServerError, errmsg("db error"))
		return
	}
	defer rows.Close()

	var servers []vpnServerResponse
	for rows.Next() {
		var s vpnServerResponse
		if err := rows.Scan(&s.ID, &s.IP, &s.Port, &s.Location, &s.Load, &s.MaxLoad, &s.IsOnline); err != nil {
			continue
		}
		s.LatencyMs = 25 // mock default ping 
		servers = append(servers, s)
	}

	writeJSON(w, http.StatusOK, servers)
}
