// main.go — точка входа для Lowkey VPN Hysteria2 сервера (рефакторированная версия).
//
// Запускает:
//  1. PostgreSQL + Redis подключения
//  2. Регистрацию и heartbeat сервера в БД
//  3. TUN интерфейс (Linux, only with CAP_NET_ADMIN)
//  4. Фоновый монитор оффлайн серверов
//  5. HTTP API на :8080 (прокси эндпоинты бэкенда)
//  6. QUIC / Hysteria2 VPN listener на :7000 (UDP)
//
// Все компоненты логируют в stdout. Используйте systemd/nohup для запуска
// в продакшен (см. scripts/install-service.sh и scripts/start.sh).
package main

import (
	"hysteria_server/api"
	"hysteria_server/config"
	"hysteria_server/db"
	"hysteria_server/heartbeat"
	"hysteria_server/tun"
	"hysteria_server/vpn"
	"hysteria_server/xray"
	"log"
)

func main() {
	log.Println("╔════════════════════════════════════════╗")
	log.Println("║   Lowkey VPN Hysteria2 Server v2.0    ║")
	log.Println("╚════════════════════════════════════════╝")

	// ── 1. Load configuration ─────────────────────────────────────────────
	cfg := config.Load()

	// Detect and store public IP for server registration.
	cfg.PublicIP = heartbeat.DetectPublicIP()
	
	locInfo := heartbeat.DetectLocation(cfg.PublicIP)

	// ── 2. Connect to PostgreSQL and Redis ────────────────────────────────
	db.InitDB(cfg)
	db.InitRedis(cfg)

	// ── 3. Register this server in the central DB and start heartbeat ─────
	heartbeat.RegisterServer(db.Pool, cfg, locInfo)
	heartbeat.StartHeartbeatDB(db.Pool)

	// ── 4. Start the peer-server monitor (marks stale nodes offline) ──────
	heartbeat.StartServerMonitor(db.Pool)

	// ── 5. Initialise TUN interface (no-op on non-Linux / no privileges) ──
	tun.Init()

	// ── 6. Start the management HTTP API in a background goroutine ────────
	router := api.NewRouter(db.Pool, cfg)
	go api.ListenAndServe(router, cfg.HTTPAddr)

	// ── 7. Start Xray User Sync goroutine ─────────────────────
	// Assuming Xray VLESS listens on port 443 
	go xray.SyncUsers(db.Pool, 443)

	// ── 8. Start the QUIC / Hysteria2 VPN server (blocks forever) ─────────
	vpn.ListenAndServe(cfg)
}
