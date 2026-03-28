//go:build !linux

package telemetry

import "time"

func StartVLESSTrafficSniffer(publicIP string) {}

func RegisterPendingVLESSFlow(
	userID,
	serverID,
	serverIP,
	remoteAddr,
	network,
	destIP string,
	port int,
	now time.Time,
) {
}
