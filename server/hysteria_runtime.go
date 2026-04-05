package server

import (
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"net"
	"net/http"
	"time"

	hycore "github.com/apernet/hysteria/core/v2/server"
	"github.com/lowkey/hysteria-server/config"
)

type runtimeIdentity struct {
	UserID   string `json:"userId"`
	DeviceID string `json:"deviceId,omitempty"`
}

func NewHysteriaRuntime(cfg *config.Config, vpnSrv *Server, tlsCfg *tls.Config) (hycore.Server, error) {
	packetConn, err := net.ListenPacket("udp", cfg.Listen)
	if err != nil {
		return nil, err
	}

	return hycore.NewServer(&hycore.Config{
		TLSConfig: hycore.TLSConfig{
			Certificates: tlsCfg.Certificates,
		},
		Conn: packetConn,
		BandwidthConfig: hycore.BandwidthConfig{
			MaxTx: mbpsToBytes(cfg.BandwidthUp),
			MaxRx: mbpsToBytes(cfg.BandwidthDown),
		},
		Authenticator:         &runtimeAuthenticator{vpnSrv: vpnSrv},
		EventLogger:           &runtimeEventLogger{vpnSrv: vpnSrv},
		TrafficLogger:         &runtimeTrafficLogger{vpnSrv: vpnSrv},
		IgnoreClientBandwidth: false,
		DisableUDP:            false,
		UDPIdleTimeout:        60 * time.Second,
		MasqHandler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, cfg.CaptivePortalURL, http.StatusFound)
		}),
	})
}

func mbpsToBytes(mbps int) uint64 {
	if mbps <= 0 {
		return 0
	}
	return uint64(mbps) * 125000
}

func encodeRuntimeIdentity(info TokenInfo) string {
	payload, _ := json.Marshal(runtimeIdentity{
		UserID:   info.UserID,
		DeviceID: info.DeviceID,
	})
	return base64.RawURLEncoding.EncodeToString(payload)
}

func decodeRuntimeIdentity(raw string) runtimeIdentity {
	if raw == "" {
		return runtimeIdentity{}
	}

	data, err := base64.RawURLEncoding.DecodeString(raw)
	if err != nil {
		return runtimeIdentity{UserID: raw}
	}

	var identity runtimeIdentity
	if err := json.Unmarshal(data, &identity); err != nil || identity.UserID == "" {
		return runtimeIdentity{UserID: raw}
	}

	return identity
}

type runtimeAuthenticator struct {
	vpnSrv *Server
}

func (a *runtimeAuthenticator) Authenticate(addr net.Addr, auth string, tx uint64) (bool, string) {
	info := a.vpnSrv.ValidateToken(auth)
	if !info.Valid || info.SubscriptionExpired {
		return false, ""
	}
	return true, encodeRuntimeIdentity(info)
}

type runtimeEventLogger struct {
	vpnSrv *Server
}

func (l *runtimeEventLogger) Connect(addr net.Addr, id string, tx uint64) {
	identity := decodeRuntimeIdentity(id)
	if identity.UserID == "" {
		return
	}
	l.vpnSrv.OpenSession(identity.UserID, identity.DeviceID, "hysteria2", addr.String())
}

func (l *runtimeEventLogger) Disconnect(addr net.Addr, id string, err error) {
	identity := decodeRuntimeIdentity(id)
	if identity.UserID == "" {
		return
	}
	l.vpnSrv.CloseLatestSession(identity.UserID, addr.String())
}

func (l *runtimeEventLogger) TCPRequest(addr net.Addr, id, reqAddr string) {
	identity := decodeRuntimeIdentity(id)
	if identity.UserID == "" {
		return
	}
	l.vpnSrv.RecordDomain(identity.UserID, reqAddr)
}

func (l *runtimeEventLogger) TCPError(addr net.Addr, id, reqAddr string, err error) {}

func (l *runtimeEventLogger) UDPRequest(addr net.Addr, id string, sessionID uint32, reqAddr string) {
	identity := decodeRuntimeIdentity(id)
	if identity.UserID == "" {
		return
	}
	l.vpnSrv.RecordDomain(identity.UserID, reqAddr)
}

func (l *runtimeEventLogger) UDPError(addr net.Addr, id string, sessionID uint32, err error) {}

type runtimeTrafficLogger struct {
	vpnSrv *Server
}

func (l *runtimeTrafficLogger) LogTraffic(id string, tx, rx uint64) bool {
	identity := decodeRuntimeIdentity(id)
	if identity.UserID == "" {
		return true
	}
	l.vpnSrv.RecordTraffic(identity.UserID, int64(tx), int64(rx))
	return true
}

func (l *runtimeTrafficLogger) LogOnlineState(id string, online bool) {}

func (l *runtimeTrafficLogger) TraceStream(stream hycore.HyStream, stats *hycore.StreamStats) {}

func (l *runtimeTrafficLogger) UntraceStream(stream hycore.HyStream) {}
