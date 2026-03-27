package telemetry

import (
	"context"
	"log"
	"sync"
	"sync/atomic"
	"time"

	voidorm "github.com/Nopass0/void_go"

	"hysteria_server/db"
)

const (
	sessionsCollection      = "vpn_sessions"
	userProtocolCollection  = "vpn_user_protocol_stats"
	flushInterval           = 5 * time.Second
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

var (
	hysteriaActive atomic.Int64
	vlessActive    atomic.Int64

	loadCbMu sync.RWMutex
	loadCb   func()

	vlessMu       sync.Mutex
	lastVLESSByUser = map[string]vlessSnapshot{}
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

func maxInt(v, floor int) int {
	if v < floor {
		return floor
	}
	return v
}
