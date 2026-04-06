package main

import (
	"log"

	"hysteria_server/api"
	"hysteria_server/blocklist"
	"hysteria_server/config"
	"hysteria_server/db"
	"hysteria_server/heartbeat"
	"hysteria_server/telemetry"
	"hysteria_server/tun"
	"hysteria_server/vpn"
	"hysteria_server/xray"
)

func main() {
	log.Println("Lowkey VPN Hysteria server booting")

	cfg := config.Load()
	if cfg.PublicIP == "" {
		cfg.PublicIP = heartbeat.DetectPublicIP()
	}
	location := heartbeat.DetectLocation(cfg.PublicIP)

	db.Init(cfg)

	heartbeat.RegisterServer(cfg, location)
	telemetry.RegisterLoadChangeCallback(heartbeat.UpdateCurrentLoadAsync)
	heartbeat.StartHeartbeatDB()
	heartbeat.StartServerMonitor()

	bl := blocklist.New(cfg)
	defer bl.Stop()

	tun.Init()

	router := api.NewRouter(cfg)
	go api.ListenAndServe(router, cfg.HTTPAddr)

	telemetry.StartVLESSTrafficSniffer(cfg.PublicIP)
	go xray.SyncUsers(cfg.XrayPort)
	go xray.StartStatsPoller()

	vpn.ListenAndServe(cfg, bl)
}
