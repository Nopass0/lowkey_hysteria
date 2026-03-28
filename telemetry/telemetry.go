package telemetry

import (
	"context"
	"crypto/sha1"
	"encoding/hex"
	"log"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	voidorm "github.com/Nopass0/void_go"

	"hysteria_server/db"
)

const (
	sessionsCollection      = "vpn_sessions"
	userProtocolCollection  = "vpn_user_protocol_stats"
	domainStatsCollection   = "vpn_domain_stats"
	flushInterval           = 5 * time.Second
	vlessTouchInterval      = 20 * time.Second
	vlessDomainMinInterval  = 15 * time.Second
	vlessSessionStaleWindow = 5 * time.Minute
)

type SessionInfo struct {
	UserID        string
	Protocol      string
	ServerID      string
	ServerIP      string
	DeviceID      string
	DeviceName    string
	DeviceOS      string
	ClientVersion string
	VIP           string
	RemoteAddr    string
}

type SessionTracker struct {
	id            string
	info          SessionInfo
	bytesUp       atomic.Int64
	bytesDown     atomic.Int64
	closeOnce     sync.Once
	stopCh        chan struct{}
}

type vlessSnapshot struct {
	up     int64
	down   int64
	online int64
}

type reverseDNSCacheEntry struct {
	value     string
	expiresAt time.Time
}

var (
	hysteriaActive atomic.Int64
	vlessActive    atomic.Int64

	loadCbMu sync.RWMutex
	loadCb   func()

	vlessMu       sync.Mutex
	lastVLESSByUser = map[string]vlessSnapshot{}

	vlessSessionMu    sync.Mutex
	lastVLESSSessionTouch = map[string]time.Time{}

	domainTouchMu    sync.Mutex
	lastDomainTouch = map[string]time.Time{}

	vlessActiveCountMu sync.Mutex
	lastVLESSActiveCounts = map[string]int{}

	reverseDNSMu    sync.Mutex
	reverseDNSCache = map[string]reverseDNSCacheEntry{}
)

func RegisterLoadChangeCallback(fn func()) {
	loadCbMu.Lock()
	loadCb = fn
	loadCbMu.Unlock()
}

func notifyLoadChanged() {
	loadCbMu.RLock()
	fn := loadCb
	loadCbMu.RUnlock()
	if fn != nil {
		fn()
	}
}

func TotalLoad() int {
	return int(hysteriaActive.Load() + vlessActive.Load())
}

func SetVLESSActive(n int64) {
	vlessActive.Store(n)
	notifyLoadChanged()
}

func ResetVLESSUserActive(userID, serverID string) {
	vlessMu.Lock()
	prev := lastVLESSByUser[userID]
	lastVLESSByUser[userID] = vlessSnapshot{
		up:     prev.up,
		down:   prev.down,
		online: 0,
	}
	vlessMu.Unlock()

	applyUserProtocolSnapshot(userID, "vless", 0, 0, 0, 0, "", serverID)
}

func ApplyVLESSUserTraffic(userID, serverID string, up, down int64) {
	vlessMu.Lock()
	prev := lastVLESSByUser[userID]
	deltaUp := up
	deltaDown := down
	if up >= prev.up {
		deltaUp = up - prev.up
	}
	if down >= prev.down {
		deltaDown = down - prev.down
	}
	lastVLESSByUser[userID] = vlessSnapshot{
		up:     up,
		down:   down,
		online: prev.online,
	}
	vlessMu.Unlock()

	applyUserProtocolTrafficDelta(userID, "vless", deltaUp, deltaDown, serverID)
}

func SyncVLESSSessionCountsFromDB(serverID string) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	rows, err := db.FindMany(
		ctx,
		sessionsCollection,
		voidorm.NewQuery().
			Where("protocol", voidorm.Eq, "vless").
			Where("status", voidorm.Eq, "active").
			Where("lastSeenAt", voidorm.Gte, time.Now().UTC().Add(-vlessSessionStaleWindow)),
	)
	if err != nil {
		log.Printf("[Telemetry] Failed to sync VLESS session counts: %v", err)
		return
	}

	counts := make(map[string]int, len(rows))
	for _, row := range rows {
		userID := db.AsString(row, "userId")
		if userID == "" {
			continue
		}
		counts[userID]++
	}

	totalActive := 0
	for _, count := range counts {
		totalActive += count
	}

	vlessActiveCountMu.Lock()
	previous := lastVLESSActiveCounts
	lastVLESSActiveCounts = counts
	vlessActiveCountMu.Unlock()

	for userID, count := range counts {
		applyUserProtocolSnapshot(userID, "vless", count, 0, 0, 0, "", serverID)
	}
	for userID := range previous {
		if _, ok := counts[userID]; !ok {
			ResetVLESSUserActive(userID, serverID)
		}
	}

	SetVLESSActive(int64(totalActive))
}

func StartHysteriaSession(info SessionInfo) *SessionTracker {
	tracker := &SessionTracker{
		info:   info,
		stopCh: make(chan struct{}),
	}

	now := time.Now().UTC()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	id, err := db.Insert(ctx, sessionsCollection, voidorm.Doc{
		"userId":        info.UserID,
		"protocol":      info.Protocol,
		"serverId":      info.ServerID,
		"serverIp":      info.ServerIP,
		"deviceId":      info.DeviceID,
		"deviceName":    info.DeviceName,
		"deviceOs":      info.DeviceOS,
		"clientVersion": info.ClientVersion,
		"vip":           info.VIP,
		"remoteAddr":    info.RemoteAddr,
		"status":        "active",
		"connectedAt":   now,
		"lastSeenAt":    now,
		"bytesUp":       int64(0),
		"bytesDown":     int64(0),
	})
	cancel()
	if err != nil {
		log.Printf("[Telemetry] Failed to insert session: %v", err)
	}
	tracker.id = id

	hysteriaActive.Add(1)
	notifyLoadChanged()
	applyUserProtocolDelta(info.UserID, info.Protocol, 1, 1, 0, 0, info.DeviceID, info.ServerID)

	go tracker.flushLoop()
	return tracker
}

func (s *SessionTracker) AddBytesUp(n int) {
	if n > 0 {
		s.bytesUp.Add(int64(n))
	}
}

func (s *SessionTracker) AddBytesDown(n int) {
	if n > 0 {
		s.bytesDown.Add(int64(n))
	}
}

func (s *SessionTracker) Close() {
	s.closeOnce.Do(func() {
		close(s.stopCh)
		up := s.bytesUp.Load()
		down := s.bytesDown.Load()

		if s.id != "" {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			_, err := db.Patch(ctx, sessionsCollection, s.id, voidorm.Doc{
				"status":         "closed",
				"lastSeenAt":     time.Now().UTC(),
				"disconnectedAt": time.Now().UTC(),
				"bytesUp":        up,
				"bytesDown":      down,
			})
			cancel()
			if err != nil {
				log.Printf("[Telemetry] Failed to close session %s: %v", s.id, err)
			}
		}

		hysteriaActive.Add(-1)
		notifyLoadChanged()
		applyUserProtocolDelta(s.info.UserID, s.info.Protocol, -1, 0, up, down, s.info.DeviceID, s.info.ServerID)
	})
}

func (s *SessionTracker) flushLoop() {
	ticker := time.NewTicker(flushInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			if s.id == "" {
				continue
			}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			_, err := db.Patch(ctx, sessionsCollection, s.id, voidorm.Doc{
				"lastSeenAt": time.Now().UTC(),
				"bytesUp":    s.bytesUp.Load(),
				"bytesDown":  s.bytesDown.Load(),
			})
			cancel()
			if err != nil {
				log.Printf("[Telemetry] Session flush error: %v", err)
			}
		case <-s.stopCh:
			return
		}
	}
}

func ApplyVLESSUserSnapshot(userID, serverID string, up, down, online int64) {
	vlessMu.Lock()
	prev := lastVLESSByUser[userID]
	deltaUp := up
	deltaDown := down
	if up >= prev.up {
		deltaUp = up - prev.up
	}
	if down >= prev.down {
		deltaDown = down - prev.down
	}
	sessionDelta := int(0)
	if online > prev.online {
		sessionDelta = int(online - prev.online)
	}
	lastVLESSByUser[userID] = vlessSnapshot{up: up, down: down, online: online}
	vlessMu.Unlock()

	applyUserProtocolSnapshot(userID, "vless", int(online), sessionDelta, deltaUp, deltaDown, "", serverID)
}

func ObserveVLESSAccess(userID, serverID, serverIP, remoteAddr, destination, network string) {
	if userID == "" {
		return
	}

	now := time.Now().UTC()
	remoteHost := normalizeRemoteHost(remoteAddr)
	if remoteHost != "" {
		sessionKey := userID + "|" + serverID + "|" + remoteHost
		shouldTouch := false

		vlessSessionMu.Lock()
		lastTouch, ok := lastVLESSSessionTouch[sessionKey]
		if !ok || now.Sub(lastTouch) >= vlessTouchInterval {
			lastVLESSSessionTouch[sessionKey] = now
			shouldTouch = true
		}
		vlessSessionMu.Unlock()

		if shouldTouch {
			sessionID := stableID("vless-session", userID, serverID, remoteHost)
			upsertVLESSSession(sessionID, SessionInfo{
				UserID:     userID,
				Protocol:   "vless",
				ServerID:   serverID,
				ServerIP:   serverIP,
				RemoteAddr: remoteHost,
			}, now)
		}
	}

	domain, port := normalizeDestination(destination)
	if domain == "" {
		return
	}
	if port == 53 || port == 853 {
		return
	}

	if net.ParseIP(domain) != nil {
		resolvedDomain := resolveReverseDomain(domain)
		if resolvedDomain == "" {
			resolvedDomain = "ip-" + sanitizeIPKey(domain)
		}
		domain = resolvedDomain
		network = strings.ToLower(network) + "+ip"
	}

	observeDomain(userID, domain, strings.ToLower(network), port, serverID, serverIP, remoteHost, now)
}

func applyUserProtocolDelta(userID, protocol string, activeDelta, sessionDelta int, bytesUpDelta, bytesDownDelta int64, deviceID, serverID string) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	row, err := db.FindOne(
		ctx,
		userProtocolCollection,
		voidorm.NewQuery().
			Where("userId", voidorm.Eq, userID).
			Where("protocol", voidorm.Eq, protocol),
	)
	if err != nil {
		activeConnections := activeDelta
		if activeConnections < 0 {
			activeConnections = 0
		}
		_, insertErr := db.Insert(ctx, userProtocolCollection, voidorm.Doc{
			"userId":            userID,
			"protocol":          protocol,
			"sessionCount":      maxInt(sessionDelta, 0),
			"activeConnections": activeConnections,
			"totalBytesUp":      bytesUpDelta,
			"totalBytesDown":    bytesDownDelta,
			"lastSeenAt":        time.Now().UTC(),
			"lastDeviceId":      deviceID,
			"lastServerId":      serverID,
		})
		if insertErr != nil {
			log.Printf("[Telemetry] Failed to insert protocol stats: %v", insertErr)
		}
		return
	}

	currentActive := db.AsInt(row, "activeConnections") + activeDelta
	if currentActive < 0 {
		currentActive = 0
	}
	currentSessions := db.AsInt(row, "sessionCount") + sessionDelta
	if currentSessions < 0 {
		currentSessions = 0
	}

	patch := voidorm.Doc{
		"activeConnections": currentActive,
		"sessionCount":      currentSessions,
		"totalBytesUp":      int64(db.AsFloat64(row, "totalBytesUp")) + bytesUpDelta,
		"totalBytesDown":    int64(db.AsFloat64(row, "totalBytesDown")) + bytesDownDelta,
		"lastSeenAt":        time.Now().UTC(),
	}
	if deviceID != "" {
		patch["lastDeviceId"] = deviceID
	}
	if serverID != "" {
		patch["lastServerId"] = serverID
	}
	if _, err = db.Patch(ctx, userProtocolCollection, db.AsString(row, "_id"), patch); err != nil {
		log.Printf("[Telemetry] Failed to patch protocol stats: %v", err)
	}
}

func applyUserProtocolSnapshot(userID, protocol string, activeConnections, sessionDelta int, bytesUpDelta, bytesDownDelta int64, deviceID, serverID string) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	row, err := db.FindOne(
		ctx,
		userProtocolCollection,
		voidorm.NewQuery().
			Where("userId", voidorm.Eq, userID).
			Where("protocol", voidorm.Eq, protocol),
	)
	if err != nil {
		_, insertErr := db.Insert(ctx, userProtocolCollection, voidorm.Doc{
			"userId":            userID,
			"protocol":          protocol,
			"sessionCount":      maxInt(sessionDelta, 0),
			"activeConnections": maxInt(activeConnections, 0),
			"totalBytesUp":      bytesUpDelta,
			"totalBytesDown":    bytesDownDelta,
			"lastSeenAt":        time.Now().UTC(),
			"lastDeviceId":      deviceID,
			"lastServerId":      serverID,
		})
		if insertErr != nil {
			log.Printf("[Telemetry] Failed to insert VLESS stats: %v", insertErr)
		}
		return
	}

	patch := voidorm.Doc{
		"activeConnections": maxInt(activeConnections, 0),
		"sessionCount":      db.AsInt(row, "sessionCount") + maxInt(sessionDelta, 0),
		"totalBytesUp":      int64(db.AsFloat64(row, "totalBytesUp")) + bytesUpDelta,
		"totalBytesDown":    int64(db.AsFloat64(row, "totalBytesDown")) + bytesDownDelta,
		"lastSeenAt":        time.Now().UTC(),
	}
	if deviceID != "" {
		patch["lastDeviceId"] = deviceID
	}
	if serverID != "" {
		patch["lastServerId"] = serverID
	}
	if _, err = db.Patch(ctx, userProtocolCollection, db.AsString(row, "_id"), patch); err != nil {
		log.Printf("[Telemetry] Failed to patch VLESS stats: %v", err)
	}
}

func applyUserProtocolTrafficDelta(userID, protocol string, bytesUpDelta, bytesDownDelta int64, serverID string) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	row, err := db.FindOne(
		ctx,
		userProtocolCollection,
		voidorm.NewQuery().
			Where("userId", voidorm.Eq, userID).
			Where("protocol", voidorm.Eq, protocol),
	)
	if err != nil {
		_, insertErr := db.Insert(ctx, userProtocolCollection, voidorm.Doc{
			"userId":            userID,
			"protocol":          protocol,
			"sessionCount":      0,
			"activeConnections": 0,
			"totalBytesUp":      bytesUpDelta,
			"totalBytesDown":    bytesDownDelta,
			"lastSeenAt":        time.Now().UTC(),
			"lastServerId":      serverID,
		})
		if insertErr != nil {
			log.Printf("[Telemetry] Failed to insert VLESS traffic stats: %v", insertErr)
		}
		return
	}

	patch := voidorm.Doc{
		"totalBytesUp":   int64(db.AsFloat64(row, "totalBytesUp")) + bytesUpDelta,
		"totalBytesDown": int64(db.AsFloat64(row, "totalBytesDown")) + bytesDownDelta,
		"lastSeenAt":     time.Now().UTC(),
	}
	if serverID != "" {
		patch["lastServerId"] = serverID
	}
	if _, err = db.Patch(ctx, userProtocolCollection, db.AsString(row, "_id"), patch); err != nil {
		log.Printf("[Telemetry] Failed to patch VLESS traffic stats: %v", err)
	}
}

func stableID(parts ...string) string {
	sum := sha1.Sum([]byte(strings.Join(parts, "\n")))
	return hex.EncodeToString(sum[:])
}

func normalizeRemoteHost(value string) string {
	raw := strings.TrimSpace(strings.TrimPrefix(strings.TrimPrefix(value, "tcp:"), "udp:"))
	if raw == "" {
		return ""
	}
	if host, _, err := net.SplitHostPort(raw); err == nil {
		return strings.Trim(host, "[]")
	}
	if strings.Count(raw, ":") == 1 {
		if host, _, err := net.SplitHostPort(raw); err == nil {
			return strings.Trim(host, "[]")
		}
	}
	return strings.Trim(raw, "[]")
}

func normalizeDestination(value string) (string, int) {
	raw := strings.TrimSpace(strings.TrimPrefix(strings.TrimPrefix(value, "tcp:"), "udp:"))
	if raw == "" {
		return "", 0
	}

	if host, port, err := net.SplitHostPort(raw); err == nil {
		n, _ := strconv.Atoi(port)
		return strings.Trim(strings.ToLower(host), "[]"), n
	}

	lastColon := strings.LastIndex(raw, ":")
	if lastColon <= 0 || lastColon >= len(raw)-1 {
		return strings.Trim(strings.ToLower(raw), "[]"), 0
	}
	port, _ := strconv.Atoi(raw[lastColon+1:])
	host := raw[:lastColon]
	return strings.Trim(strings.ToLower(host), "[]"), port
}

func upsertVLESSSession(sessionID string, info SessionInfo, now time.Time) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	row, err := db.FindByID(ctx, sessionsCollection, sessionID)
	if err == nil {
		_, patchErr := db.Patch(ctx, sessionsCollection, sessionID, voidorm.Doc{
			"status":     "active",
			"lastSeenAt": now,
			"serverId":   info.ServerID,
			"serverIp":   info.ServerIP,
			"remoteAddr": info.RemoteAddr,
			"protocol":   info.Protocol,
		})
		if patchErr != nil {
			log.Printf("[Telemetry] Failed to touch VLESS session %s: %v", sessionID, patchErr)
		}
		_ = row
		return
	}

	if err != db.ErrNotFound {
		log.Printf("[Telemetry] Failed to fetch VLESS session %s: %v", sessionID, err)
		return
	}

	_, insertErr := db.Insert(ctx, sessionsCollection, voidorm.Doc{
		"id":           sessionID,
		"_id":          sessionID,
		"userId":       info.UserID,
		"protocol":     info.Protocol,
		"serverId":     info.ServerID,
		"serverIp":     info.ServerIP,
		"remoteAddr":   info.RemoteAddr,
		"status":       "active",
		"connectedAt":  now,
		"lastSeenAt":   now,
		"bytesUp":      int64(0),
		"bytesDown":    int64(0),
	})
	if insertErr != nil {
		log.Printf("[Telemetry] Failed to insert VLESS session %s: %v", sessionID, insertErr)
	}
}

func upsertDomainStat(userID, domain, network string, port int, serverID, serverIP, remoteAddr string, now time.Time) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	row, err := db.FindOne(
		ctx,
		domainStatsCollection,
		voidorm.NewQuery().
			Where("userId", voidorm.Eq, userID).
			Where("domain", voidorm.Eq, domain),
	)
	if err != nil {
		if err != db.ErrNotFound {
			log.Printf("[Telemetry] Failed to query domain stat %s for %s: %v", domain, userID, err)
			return
		}

		_, insertErr := db.Insert(ctx, domainStatsCollection, voidorm.Doc{
			"userId":           userID,
			"domain":           domain,
			"visitCount":       1,
			"bytesTransferred": int64(0),
			"firstVisitAt":     now,
			"lastVisitAt":      now,
			"lastNetwork":      network,
			"lastPort":         port,
			"lastRemoteAddr":   remoteAddr,
			"lastServerId":     serverID,
			"lastServerIp":     serverIP,
		})
		if insertErr != nil {
			log.Printf("[Telemetry] Failed to insert domain stat %s for %s: %v", domain, userID, insertErr)
		}
		return
	}

	_, patchErr := db.Patch(ctx, domainStatsCollection, db.AsString(row, "_id"), voidorm.Doc{
		"visitCount":     db.AsInt(row, "visitCount") + 1,
		"lastVisitAt":    now,
		"lastNetwork":    network,
		"lastPort":       port,
		"lastRemoteAddr": remoteAddr,
		"lastServerId":   serverID,
		"lastServerIp":   serverIP,
	})
	if patchErr != nil {
		log.Printf("[Telemetry] Failed to patch domain stat %s for %s: %v", domain, userID, patchErr)
	}
}

func observeDomain(userID, domain, network string, port int, serverID, serverIP, remoteAddr string, now time.Time) {
	if userID == "" || domain == "" {
		return
	}

	domainKey := userID + "|" + domain
	shouldRecordDomain := false

	domainTouchMu.Lock()
	lastTouch, ok := lastDomainTouch[domainKey]
	if !ok || now.Sub(lastTouch) >= vlessDomainMinInterval {
		lastDomainTouch[domainKey] = now
		shouldRecordDomain = true
	}
	domainTouchMu.Unlock()

	if shouldRecordDomain {
		upsertDomainStat(userID, domain, network, port, serverID, serverIP, remoteAddr, now)
	}
}

func resolveReverseDomain(ip string) string {
	now := time.Now().UTC()

	reverseDNSMu.Lock()
	cached, ok := reverseDNSCache[ip]
	if ok && now.Before(cached.expiresAt) {
		reverseDNSMu.Unlock()
		return cached.value
	}
	reverseDNSMu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	names, err := net.DefaultResolver.LookupAddr(ctx, ip)
	value := ""
	if err == nil && len(names) > 0 {
		value = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(names[0])), ".")
	}

	reverseDNSMu.Lock()
	reverseDNSCache[ip] = reverseDNSCacheEntry{
		value:     value,
		expiresAt: now.Add(30 * time.Minute),
	}
	reverseDNSMu.Unlock()

	return value
}

func sanitizeIPKey(ip string) string {
	replacer := strings.NewReplacer(".", "-", ":", "-")
	return replacer.Replace(strings.TrimSpace(ip))
}

func maxInt(v, floor int) int {
	if v < floor {
		return floor
	}
	return v
}
