package api

import (
	"context"
	"net/http"
	"time"

	voidorm "github.com/Nopass0/void_go"

	"hysteria_server/db"
)

type vpnServerResponse struct {
	ID        string  `json:"id"`
	IP        string  `json:"ip"`
	Port      int     `json:"port"`
	Location  string  `json:"location"`
	Load      float64 `json:"currentLoad"`
	MaxLoad   int     `json:"maxLoad"`
	IsOnline  bool    `json:"isOnline"`
	LatencyMs int     `json:"latencyMs"`
}

func (h *handler) getServers(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	rows, err := db.FindMany(
		ctx,
		"vpn_servers",
		voidorm.NewQuery().
			Where("status", voidorm.Eq, "online").
			OrderBy("location", voidorm.Asc),
	)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, errmsg("db error"))
		return
	}

	servers := make([]vpnServerResponse, 0, len(rows))
	for _, row := range rows {
		load := db.AsInt(row, "currentLoad")
		servers = append(servers, vpnServerResponse{
			ID:        db.AsString(row, "_id"),
			IP:        db.AsString(row, "ip"),
			Port:      db.AsInt(row, "port"),
			Location:  db.AsString(row, "location"),
			Load:      float64(load),
			MaxLoad:   1000,
			IsOnline:  db.AsString(row, "status") == "online",
			LatencyMs: 25,
		})
	}

	writeJSON(w, http.StatusOK, servers)
}
