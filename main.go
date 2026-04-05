package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/lowkey/hysteria-server/blocklist"
	"github.com/lowkey/hysteria-server/captive"
	"github.com/lowkey/hysteria-server/config"
	"github.com/lowkey/hysteria-server/mtproto"
	"github.com/lowkey/hysteria-server/server"
	"github.com/lowkey/hysteria-server/stats"
	"github.com/lowkey/hysteria-server/voiddb"
)

func main() {
	genSecret := flag.Bool("gen-mtproto-secret", false, "Generate an MTProto proxy secret and exit")
	flag.Parse()

	if *genSecret {
		fmt.Println(mtproto.GenerateSecret())
		os.Exit(0)
	}

	log.SetFlags(log.Ldate | log.Ltime | log.Lshortfile)
	log.Println("[Main] Starting Lowkey VPN server")

	cfg := config.Load()
	if cfg.VoidDBURL == "" {
		log.Fatal("[Config] VOIDDB_URL is required")
	}
	if cfg.BackendURL == "" {
		log.Fatal("[Config] BACKEND_URL is required")
	}
	if err := server.EnsureTLSMaterial(cfg); err != nil {
		log.Fatalf("[TLS] %v", err)
	}
	if cfg.ServerIP == "" {
		log.Printf("[Config] SERVER_IP is empty; registration and captive IP mapping will be incomplete")
	}
	if cfg.BackendSecret == "" {
		log.Printf("[Config] BACKEND_SECRET is empty; signed backend endpoints must allow unsigned nodes")
	}

	db := voiddb.New(cfg.VoidDBURL, cfg.VoidDBUsername, cfg.VoidDBPassword, cfg.VoidDBToken)
	tracker := stats.New(cfg.BackendURL, cfg.BackendSecret, cfg.DomainFlushInterval)
	defer tracker.Stop()

	bl := blocklist.New(cfg.BackendURL, cfg.BackendSecret)
	defer bl.Stop()

	vpnSrv := server.New(cfg, db, tracker, bl)

	httpPortal := captive.NewHTTP(cfg.CaptivePortalListen, cfg.CaptivePortalURL)
	httpPortal.Start()
	defer httpPortal.Stop()

	if cfg.CaptiveHTTPSListen != "" {
		httpsPortal, err := captive.NewHTTPS(cfg.CaptiveHTTPSListen, cfg.CertFile, cfg.KeyFile, cfg.CaptivePortalURL)
		if err != nil {
			log.Printf("[CaptiveHTTPS] Not started: %v", err)
		} else {
			httpsPortal.Start()
			defer httpsPortal.Stop()
		}
	}

	var dnsSrv *captive.DNSServer
	if cfg.DNSListen != "" && cfg.CaptiveIP != "" {
		dnsSrv = captive.NewDNS(cfg.DNSListen, cfg.CaptiveIP, cfg.UpstreamDNS)
		dnsSrv.Start()
		defer dnsSrv.Stop()
		log.Printf("[DNS] Captive portal DNS started (captive IP: %s)", cfg.CaptiveIP)
	}
	_ = dnsSrv

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go vpnSrv.HeartbeatLoop(ctx)

	if cfg.MTProtoEnabled && cfg.MTProtoSecret != "" {
		mtpSrv, err := mtproto.New(
			cfg.MTProtoListen,
			cfg.MTProtoSecret,
			cfg.MTProtoChannelUsername,
			cfg.MTProtoAddChannelOnConnect,
		)
		if err != nil {
			log.Printf("[MTProto] Failed to create: %v", err)
		} else {
			go func() {
				if err := mtpSrv.ListenAndServe(); err != nil {
					log.Printf("[MTProto] Error: %v", err)
				}
			}()
			defer mtpSrv.Stop()
			log.Printf("[MTProto] Proxy started on %s", cfg.MTProtoListen)
		}
	}

	tlsCfg, err := server.LoadTLSConfig(cfg.CertFile, cfg.KeyFile)
	if err != nil {
		log.Fatalf("[TLS] %v", err)
	}

	hyRuntime, err := server.NewHysteriaRuntime(cfg, vpnSrv, tlsCfg)
	if err != nil {
		log.Fatalf("[Hysteria2] %v", err)
	}
	defer hyRuntime.Close()

	go func() {
		if err := hyRuntime.Serve(); err != nil && err != http.ErrServerClosed {
			log.Printf("[Hysteria2] Error: %v", err)
		}
	}()

	log.Printf("[Hysteria2] Listening on %s", cfg.Listen)
	log.Printf("[CaptiveHTTP] Listening on %s", cfg.CaptivePortalListen)

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
	log.Println("[Main] Shutting down")
}
