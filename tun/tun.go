// Package tun manages the Linux TUN virtual network interface used to route
// VPN traffic between the QUIC layer (connected clients) and the internet.
//
// The TUN device (e.g. tun0) forwards decapsulated IP packets from the server
// to the internet and returns replies to the originating QUIC connection.
package tun

import (
	"log"
	"net"
	"os/exec"
	"sync"

	"github.com/quic-go/quic-go"
	"github.com/songgao/water"
)

// Device is the active TUN interface. Nil when running on non-Linux hosts.
var Device *water.Interface

// clients maps a virtual IP address (e.g. "172.20.0.2") to the QUIC
// connection object for that client.
var (
	clients   = make(map[string]*quic.Conn)
	clientsMu sync.RWMutex
)

// Init creates and configures the TUN interface.
// On non-Linux systems (or when privileges are missing) the TUN step is
// skipped and the server operates in auth-only mode.
//
// @returns nil on success, error otherwise (non-fatal — logged internally)
func Init() {
	iface, err := water.New(water.Config{DeviceType: water.TUN})
	if err != nil {
		log.Printf("[TUN] Could not create TUN device: %v — running in auth-only mode.", err)
		return
	}
	Device = iface
	name := iface.Name()
	log.Printf("[TUN] Interface created: %s", name)

	// Configure the interface (Linux-specific iproute2 commands).
	// 172.20.0.1/24 is the VPN subnet gateway.
	_ = exec.Command("ip", "addr", "add", "172.20.0.1/24", "dev", name).Run()
	_ = exec.Command("ip", "link", "set", "dev", name, "mtu", "1350").Run()
	_ = exec.Command("ip", "link", "set", name, "up").Run()

	// Enable NAT so VPN clients can reach the internet.
	_ = exec.Command("iptables", "-t", "nat", "-A", "POSTROUTING", "-s", "172.20.0.0/24", "-j", "MASQUERADE").Run()
	_ = exec.Command("sysctl", "-w", "net.ipv4.ip_forward=1").Run()

	// Start the TUN → QUIC forwarding goroutine.
	go forwardTUNToQUIC()
}

// RegisterClient adds a client's virtual IP → QUIC connection mapping so that
// packets from the internet can be routed back to the correct client.
//
// @param vip  - virtual IP assigned to the client (e.g. "172.20.0.5")
// @param conn - the client's QUIC connection
func RegisterClient(vip string, conn *quic.Conn) {
	clientsMu.Lock()
	clients[vip] = conn
	clientsMu.Unlock()
}

// UnregisterClient removes the mapping when a client disconnects.
//
// @param vip - virtual IP that was assigned to the client
func UnregisterClient(vip string) {
	clientsMu.Lock()
	delete(clients, vip)
	clientsMu.Unlock()
}

// forwardTUNToQUIC reads raw IP packets from the TUN interface and routes
// each packet to the QUIC connection of the destination IP, if known.
func forwardTUNToQUIC() {
	buf := make([]byte, 2000)
	for {
		n, err := Device.Read(buf)
		if err != nil {
			log.Printf("[TUN] Read error: %v", err)
			break
		}
		packet := buf[:n]
		if len(packet) < 20 {
			continue // too short to be a valid IPv4 packet
		}

		// Bytes 16-19 of an IPv4 header are the destination IP address.
		destIP := net.IP(packet[16:20]).String()

		clientsMu.RLock()
		conn, ok := clients[destIP]
		clientsMu.RUnlock()

		if ok {
			// Send via QUIC Datagram (unreliable, low-latency channel).
			if err = conn.SendDatagram(packet); err != nil {
				log.Printf("[TUN→QUIC] Send error to %s: %v", destIP, err)
			}
		}
	}
}
