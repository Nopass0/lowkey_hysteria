//go:build linux

package telemetry

import (
	"log"
	"net"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/afpacket"
	"github.com/google/gopacket/layers"
)

const (
	pendingVLESSFlowTTL     = 12 * time.Second
	establishedVLESSFlowTTL = 10 * time.Minute
)

type pendingVLESSFlow struct {
	userID     string
	serverID   string
	serverIP   string
	remoteAddr string
	network    string
	destIP     string
	port       int
	createdAt  time.Time
}

type establishedVLESSFlow struct {
	userID     string
	serverID   string
	serverIP   string
	remoteAddr string
	network    string
	domain     string
	port       int
	lastSeenAt time.Time
}

var (
	vlessSnifferOnce sync.Once

	localVLESSIPMu sync.RWMutex
	localVLESSIPs  = map[string]struct{}{}

	pendingVLESSFlowMu sync.Mutex
	pendingVLESSFlows  = map[string][]pendingVLESSFlow{}

	establishedVLESSFlowMu sync.Mutex
	establishedVLESSFlows  = map[string]establishedVLESSFlow{}
)

func StartVLESSTrafficSniffer(publicIP string) {
	vlessSnifferOnce.Do(func() {
		setLocalVLESSIPs(publicIP)

		ifaceName := detectVLESSSnifferInterface(publicIP)
		if ifaceName == "" {
			log.Printf("[Telemetry] VLESS flow sniffer disabled: no capture interface found")
			return
		}

		go cleanupVLESSFlowState()
		go runVLESSTrafficSniffer(ifaceName)
	})
}

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
	if userID == "" || destIP == "" || port <= 0 {
		return
	}
	if net.ParseIP(destIP) == nil {
		return
	}

	key := pendingVLESSFlowKey(destIP, port)
	flow := pendingVLESSFlow{
		userID:     userID,
		serverID:   serverID,
		serverIP:   serverIP,
		remoteAddr: remoteAddr,
		network:    strings.ToLower(strings.TrimSpace(network)),
		destIP:     destIP,
		port:       port,
		createdAt:  now,
	}

	pendingVLESSFlowMu.Lock()
	flows := append(filterPendingVLESSFlowsLocked(pendingVLESSFlows[key], now), flow)
	if len(flows) > 12 {
		flows = flows[len(flows)-12:]
	}
	pendingVLESSFlows[key] = flows
	pendingVLESSFlowMu.Unlock()
}

func runVLESSTrafficSniffer(ifaceName string) {
	handle, err := afpacket.NewTPacket(
		afpacket.OptInterface(ifaceName),
		afpacket.OptFrameSize(1<<16),
		afpacket.OptBlockSize(1<<20),
		afpacket.OptNumBlocks(8),
		afpacket.OptPollTimeout(500*time.Millisecond),
	)
	if err != nil {
		log.Printf("[Telemetry] Failed to start VLESS flow sniffer on %s: %v", ifaceName, err)
		return
	}
	defer handle.Close()

	var (
		eth layers.Ethernet
		ip4 layers.IPv4
		ip6 layers.IPv6
		tcp layers.TCP
		udp layers.UDP
		sll layers.LinuxSLL
	)

	parser := gopacket.NewDecodingLayerParser(
		layers.LayerTypeEthernet,
		&eth,
		&ip4,
		&ip6,
		&tcp,
		&udp,
		&sll,
	)
	parser.IgnoreUnsupported = true

	decoded := make([]gopacket.LayerType, 0, 8)
	log.Printf("[Telemetry] VLESS flow sniffer listening on %s", ifaceName)

	for {
		data, _, err := handle.ZeroCopyReadPacketData()
		if err != nil {
			if strings.Contains(err.Error(), "timeout") {
				continue
			}
			log.Printf("[Telemetry] VLESS flow sniffer read error: %v", err)
			time.Sleep(time.Second)
			continue
		}

		decoded = decoded[:0]
		if err := parser.DecodeLayers(data, &decoded); err != nil {
			continue
		}

		var (
			srcIP   string
			dstIP   string
			srcPort int
			dstPort int
			payload []byte
		)

		for _, layerType := range decoded {
			switch layerType {
			case layers.LayerTypeIPv4:
				srcIP = ip4.SrcIP.String()
				dstIP = ip4.DstIP.String()
			case layers.LayerTypeIPv6:
				srcIP = ip6.SrcIP.String()
				dstIP = ip6.DstIP.String()
			case layers.LayerTypeTCP:
				srcPort = int(tcp.SrcPort)
				dstPort = int(tcp.DstPort)
				payload = tcp.Payload
			}
		}

		if srcIP == "" || dstIP == "" || srcPort <= 0 || dstPort <= 0 {
			continue
		}

		handleCapturedVLESSTCPPacket(srcIP, srcPort, dstIP, dstPort, payload, time.Now().UTC())
	}
}

func handleCapturedVLESSTCPPacket(
	srcIP string,
	srcPort int,
	dstIP string,
	dstPort int,
	payload []byte,
	now time.Time,
) {
	if flow, ok := lookupEstablishedVLESSFlow(srcIP, srcPort, dstIP, dstPort, now); ok {
		observeDomain(
			flow.userID,
			flow.domain,
			flow.network,
			flow.port,
			flow.serverID,
			flow.serverIP,
			flow.remoteAddr,
			now,
		)
		return
	}

	if !isLocalVLESSIP(srcIP) {
		return
	}

	pending, ok := takePendingVLESSFlow(dstIP, dstPort, now)
	if !ok {
		return
	}

	domain := ""
	network := pending.network

	if parsed := ExtractHTTPHost(payload); parsed != "" {
		domain = parsed
		network = "http-sniff"
	} else if parsed := ExtractTLSServerName(payload); parsed != "" {
		domain = parsed
		network = "tls-sniff"
	}

	if domain == "" {
		if resolved := resolveReverseDomain(dstIP); resolved != "" {
			domain = resolved
			network = strings.TrimSuffix(network, "+ip") + "+ptr"
		} else {
			domain = "ip-" + sanitizeIPKey(dstIP)
			network = strings.TrimSuffix(network, "+ip") + "+ip"
		}
	}

	rememberEstablishedVLESSFlow(srcIP, srcPort, dstIP, dstPort, establishedVLESSFlow{
		userID:     pending.userID,
		serverID:   pending.serverID,
		serverIP:   pending.serverIP,
		remoteAddr: pending.remoteAddr,
		network:    network,
		domain:     domain,
		port:       dstPort,
		lastSeenAt: now,
	})

	observeDomain(
		pending.userID,
		domain,
		network,
		dstPort,
		pending.serverID,
		pending.serverIP,
		pending.remoteAddr,
		now,
	)
}

func pendingVLESSFlowKey(destIP string, port int) string {
	return strings.ToLower(strings.TrimSpace(destIP)) + "|" + strconv.Itoa(port)
}

func establishedVLESSFlowKey(srcIP string, srcPort int, dstIP string, dstPort int) string {
	return srcIP + "|" + strconv.Itoa(srcPort) + "|" + dstIP + "|" + strconv.Itoa(dstPort)
}

func takePendingVLESSFlow(destIP string, port int, now time.Time) (pendingVLESSFlow, bool) {
	key := pendingVLESSFlowKey(destIP, port)

	pendingVLESSFlowMu.Lock()
	defer pendingVLESSFlowMu.Unlock()

	flows := filterPendingVLESSFlowsLocked(pendingVLESSFlows[key], now)
	if len(flows) == 0 {
		delete(pendingVLESSFlows, key)
		return pendingVLESSFlow{}, false
	}

	latestByUser := map[string]pendingVLESSFlow{}
	for _, flow := range flows {
		latestByUser[flow.userID] = flow
	}
	if len(latestByUser) != 1 {
		pendingVLESSFlows[key] = flows
		return pendingVLESSFlow{}, false
	}

	var selected pendingVLESSFlow
	for _, flow := range latestByUser {
		selected = flow
	}

	remaining := make([]pendingVLESSFlow, 0, len(flows))
	for _, flow := range flows {
		if flow.userID == selected.userID &&
			flow.destIP == selected.destIP &&
			flow.port == selected.port &&
			flow.createdAt.Equal(selected.createdAt) {
			continue
		}
		remaining = append(remaining, flow)
	}

	if len(remaining) == 0 {
		delete(pendingVLESSFlows, key)
	} else {
		pendingVLESSFlows[key] = remaining
	}

	return selected, true
}

func filterPendingVLESSFlowsLocked(flows []pendingVLESSFlow, now time.Time) []pendingVLESSFlow {
	if len(flows) == 0 {
		return nil
	}

	filtered := make([]pendingVLESSFlow, 0, len(flows))
	for _, flow := range flows {
		if now.Sub(flow.createdAt) <= pendingVLESSFlowTTL {
			filtered = append(filtered, flow)
		}
	}
	return filtered
}

func rememberEstablishedVLESSFlow(
	srcIP string,
	srcPort int,
	dstIP string,
	dstPort int,
	flow establishedVLESSFlow,
) {
	establishedVLESSFlowMu.Lock()
	defer establishedVLESSFlowMu.Unlock()

	flow.lastSeenAt = time.Now().UTC()
	forward := establishedVLESSFlowKey(srcIP, srcPort, dstIP, dstPort)
	reverse := establishedVLESSFlowKey(dstIP, dstPort, srcIP, srcPort)
	establishedVLESSFlows[forward] = flow
	establishedVLESSFlows[reverse] = flow
}

func lookupEstablishedVLESSFlow(
	srcIP string,
	srcPort int,
	dstIP string,
	dstPort int,
	now time.Time,
) (establishedVLESSFlow, bool) {
	key := establishedVLESSFlowKey(srcIP, srcPort, dstIP, dstPort)

	establishedVLESSFlowMu.Lock()
	defer establishedVLESSFlowMu.Unlock()

	flow, ok := establishedVLESSFlows[key]
	if !ok {
		return establishedVLESSFlow{}, false
	}
	if now.Sub(flow.lastSeenAt) > establishedVLESSFlowTTL {
		delete(establishedVLESSFlows, key)
		return establishedVLESSFlow{}, false
	}

	flow.lastSeenAt = now
	establishedVLESSFlows[key] = flow
	return flow, true
}

func cleanupVLESSFlowState() {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()

	for now := range ticker.C {
		ts := now.UTC()

		pendingVLESSFlowMu.Lock()
		for key, flows := range pendingVLESSFlows {
			filtered := filterPendingVLESSFlowsLocked(flows, ts)
			if len(filtered) == 0 {
				delete(pendingVLESSFlows, key)
				continue
			}
			pendingVLESSFlows[key] = filtered
		}
		pendingVLESSFlowMu.Unlock()

		establishedVLESSFlowMu.Lock()
		for key, flow := range establishedVLESSFlows {
			if ts.Sub(flow.lastSeenAt) > establishedVLESSFlowTTL {
				delete(establishedVLESSFlows, key)
			}
		}
		establishedVLESSFlowMu.Unlock()
	}
}

func setLocalVLESSIPs(publicIP string) {
	localVLESSIPMu.Lock()
	defer localVLESSIPMu.Unlock()

	localVLESSIPs = map[string]struct{}{}
	if publicIP != "" {
		localVLESSIPs[strings.TrimSpace(publicIP)] = struct{}{}
	}

	ifaces, err := net.Interfaces()
	if err != nil {
		return
	}
	for _, iface := range ifaces {
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			switch value := addr.(type) {
			case *net.IPNet:
				localVLESSIPs[value.IP.String()] = struct{}{}
			case *net.IPAddr:
				localVLESSIPs[value.IP.String()] = struct{}{}
			}
		}
	}
}

func isLocalVLESSIP(ip string) bool {
	localVLESSIPMu.RLock()
	defer localVLESSIPMu.RUnlock()
	_, ok := localVLESSIPs[ip]
	return ok
}

func detectVLESSSnifferInterface(publicIP string) string {
	ifaces, err := net.Interfaces()
	if err == nil {
		for _, iface := range ifaces {
			if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
				continue
			}

			addrs, addrErr := iface.Addrs()
			if addrErr != nil {
				continue
			}
			for _, addr := range addrs {
				switch value := addr.(type) {
				case *net.IPNet:
					if value.IP.String() == publicIP {
						return iface.Name
					}
				case *net.IPAddr:
					if value.IP.String() == publicIP {
						return iface.Name
					}
				}
			}
		}
	}

	out, routeErr := exec.Command(
		"sh",
		"-lc",
		`ip route get 1.1.1.1 2>/dev/null | awk '{for (i=1;i<=NF;i++) if ($i=="dev") { print $(i+1); exit }}'`,
	).Output()
	if routeErr == nil {
		ifaceName := strings.TrimSpace(string(out))
		if ifaceName != "" {
			return ifaceName
		}
	}

	if err != nil {
		return ""
	}

	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp != 0 && iface.Flags&net.FlagLoopback == 0 {
			return iface.Name
		}
	}

	return ""
}
