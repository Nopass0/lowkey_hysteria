// Package tun manages the Linux TUN virtual network interface used to route
// VPN traffic between the QUIC layer (connected clients) and the internet.
//
// The TUN device (e.g. tun0) forwards decapsulated IP packets from the server
// to the internet and returns replies to the originating QUIC connection.
package tun

import (
	"io"
	"log"
	"net"
	"os/exec"
	"sync"

	"github.com/songgao/water"
)

// Device is the active TUN interface. Nil when running on non-Linux hosts.
var Device *water.Interface

// clients maps a virtual IP address (e.g. "172.20.0.2") to the client connection.
var (
	udpClients    = make(map[string]*net.UDPAddr)
	streamClients = make(map[string]io.Writer)
	clientsMu     sync.RWMutex
)

// ServerConn is the shared UDP socket (fallback).
var ServerConn *net.UDPConn

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
	// 10.0.0.1/8 is the VPN subnet gateway.
	if err := exec.Command("ip", "addr", "add", "10.0.0.1/8", "dev", name).Run(); err != nil {
		log.Printf("[TUN] Error adding IP address: %v", err)
	}
	if err := exec.Command("ip", "link", "set", "dev", name, "mtu", "1350").Run(); err != nil {
		log.Printf("[TUN] Error setting MTU: %v", err)
	}
	if err := exec.Command("ip", "link", "set", name, "up").Run(); err != nil {
		log.Printf("[TUN] Error setting interface UP: %v", err)
	}

	// Enable NAT so VPN clients can reach the internet.
	// Note: Root privileges required.
	if err := exec.Command("iptables", "-t", "nat", "-A", "POSTROUTING", "-s", "10.0.0.0/8", "-j", "MASQUERADE").Run(); err != nil {
		log.Printf("[TUN] Warning: iptables MASQUERADE failed: %v", err)
	}
	if err := exec.Command("sysctl", "-w", "net.ipv4.ip_forward=1").Run(); err != nil {
		log.Printf("[TUN] Warning: sysctl ip_forward failed: %v", err)
	}

	// Start the TUN → QUIC forwarding goroutine.
	go forwardTUNToQUIC()
}


// RegisterStreamClient adds a client's virtual IP → io.Writer mapping (for HTTP/3).
func RegisterStreamClient(vip string, w io.Writer) {
	clientsMu.Lock()
	streamClients[vip] = w
	clientsMu.Unlock()
}

// UnregisterClient removes the mapping for all protocol types.
func UnregisterClient(vip string) {
	clientsMu.Lock()
	delete(udpClients, vip)
	delete(streamClients, vip)
	clientsMu.Unlock()
}

// forwardTUNToQUIC reads raw IP packets from the TUN interface and routes
// each packet to the UDP connection of the destination IP, if known.
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
		uAddr, isUDP  := udpClients[destIP]
		sWriter, isStream := streamClients[destIP]
		clientsMu.RUnlock()

		if isStream {
			// Send via Stream (HTTP/3)
			if _, err := sWriter.Write(packet); err != nil {
				log.Printf("[TUN→Stream] Write error to %s: %v", destIP, err)
			}
		} else if isUDP && ServerConn != nil {
			// Fallback to UDP
			if _, err = ServerConn.WriteToUDP(packet, uAddr); err != nil {
				log.Printf("[TUN→UDP] Send error to %s: %v", destIP, err)
			}
		}
	}
}
