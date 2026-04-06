package vpn

import (
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"strings"

	"hysteria_server/blocklist"
	"hysteria_server/telemetry"
)

const (
	tcpFlagFin = 0x01
	tcpFlagRst = 0x04
	tcpFlagPsh = 0x08
	tcpFlagAck = 0x10
)

func maybeHandleBlockedPacket(writer io.Writer, packet []byte, bl *blocklist.Manager) bool {
	if bl == nil || len(packet) < 40 || packet[0]>>4 != 4 || packet[9] != 6 {
		return false
	}

	ipHeaderLen := int(packet[0]&0x0F) * 4
	if ipHeaderLen < 20 || len(packet) < ipHeaderLen+20 {
		return false
	}

	tcpPacket := packet[ipHeaderLen:]
	tcpHeaderLen := int(tcpPacket[12]>>4) * 4
	if tcpHeaderLen < 20 || len(tcpPacket) < tcpHeaderLen {
		return false
	}

	payload := tcpPacket[tcpHeaderLen:]
	if len(payload) == 0 {
		return false
	}

	srcIP := net.IP(packet[12:16]).To4()
	dstIP := net.IP(packet[16:20]).To4()
	if srcIP == nil || dstIP == nil {
		return false
	}

	srcPort := binary.BigEndian.Uint16(tcpPacket[0:2])
	dstPort := binary.BigEndian.Uint16(tcpPacket[2:4])
	seq := binary.BigEndian.Uint32(tcpPacket[4:8])
	ack := binary.BigEndian.Uint32(tcpPacket[8:12])

	var host string
	switch dstPort {
	case 80, 8080, 8000:
		host = telemetry.ExtractHTTPHost(payload)
	case 443, 8443:
		host = telemetry.ExtractTLSServerName(payload)
	default:
		return false
	}
	if host == "" {
		return false
	}

	entry, blocked := bl.MatchHost(host)
	if !blocked {
		return false
	}

	if dstPort == 80 || dstPort == 8080 || dstPort == 8000 {
		redirectURL := bl.RedirectURL(entry, host)
		response := buildHTTPRedirectPacket(
			srcIP,
			dstIP,
			srcPort,
			dstPort,
			seq,
			ack,
			payload,
			redirectURL,
		)
		if len(response) == 0 {
			return false
		}
		if _, err := writer.Write(response); err != nil {
			log.Printf("[Blocklist] Failed to send redirect packet for %s: %v", host, err)
		} else {
			log.Printf("[Blocklist] Redirected blocked HTTP host=%s to %s", host, redirectURL)
		}
		return true
	}

	rst := buildTCPResetPacket(srcIP, dstIP, srcPort, dstPort, seq, ack, payload)
	if len(rst) == 0 {
		return false
	}
	if _, err := writer.Write(rst); err != nil {
		log.Printf("[Blocklist] Failed to send reset packet for %s: %v", host, err)
	} else {
		log.Printf("[Blocklist] Dropped blocked TLS host=%s", host)
	}
	return true
}

func buildHTTPRedirectPacket(
	clientIP net.IP,
	targetIP net.IP,
	clientPort uint16,
	targetPort uint16,
	clientSeq uint32,
	serverSeq uint32,
	requestPayload []byte,
	redirectURL string,
) []byte {
	body := []byte(
		"<!DOCTYPE html><html><head><meta charset=\"utf-8\">" +
			"<meta http-equiv=\"refresh\" content=\"0; url=" + htmlEscape(redirectURL) + "\"></head>" +
			"<body>Redirecting to <a href=\"" + htmlEscape(redirectURL) + "\">" + htmlEscape(redirectURL) + "</a></body></html>",
	)
	responsePayload := []byte(
		fmt.Sprintf(
			"HTTP/1.1 302 Found\r\nLocation: %s\r\nContent-Type: text/html; charset=utf-8\r\nCache-Control: no-store\r\nConnection: close\r\nContent-Length: %d\r\n\r\n%s",
			redirectURL,
			len(body),
			body,
		),
	)

	return buildTCPPacket(
		targetIP,
		clientIP,
		targetPort,
		clientPort,
		serverSeq,
		clientSeq+uint32(len(requestPayload)),
		tcpFlagAck|tcpFlagPsh|tcpFlagFin,
		responsePayload,
	)
}

func buildTCPResetPacket(
	clientIP net.IP,
	targetIP net.IP,
	clientPort uint16,
	targetPort uint16,
	clientSeq uint32,
	serverSeq uint32,
	requestPayload []byte,
) []byte {
	return buildTCPPacket(
		targetIP,
		clientIP,
		targetPort,
		clientPort,
		serverSeq,
		clientSeq+uint32(len(requestPayload)),
		tcpFlagAck|tcpFlagRst,
		nil,
	)
}

func buildTCPPacket(
	srcIP net.IP,
	dstIP net.IP,
	srcPort uint16,
	dstPort uint16,
	seq uint32,
	ack uint32,
	flags byte,
	payload []byte,
) []byte {
	const ipHeaderLen = 20
	const tcpHeaderLen = 20

	totalLen := ipHeaderLen + tcpHeaderLen + len(payload)
	packet := make([]byte, totalLen)

	packet[0] = 0x45
	packet[1] = 0
	binary.BigEndian.PutUint16(packet[2:4], uint16(totalLen))
	binary.BigEndian.PutUint16(packet[4:6], 0)
	binary.BigEndian.PutUint16(packet[6:8], 0)
	packet[8] = 64
	packet[9] = 6
	copy(packet[12:16], srcIP.To4())
	copy(packet[16:20], dstIP.To4())
	binary.BigEndian.PutUint16(packet[10:12], ipv4Checksum(packet[:ipHeaderLen]))

	tcpHeader := packet[ipHeaderLen : ipHeaderLen+tcpHeaderLen]
	binary.BigEndian.PutUint16(tcpHeader[0:2], srcPort)
	binary.BigEndian.PutUint16(tcpHeader[2:4], dstPort)
	binary.BigEndian.PutUint32(tcpHeader[4:8], seq)
	binary.BigEndian.PutUint32(tcpHeader[8:12], ack)
	tcpHeader[12] = byte(tcpHeaderLen / 4 << 4)
	tcpHeader[13] = flags
	binary.BigEndian.PutUint16(tcpHeader[14:16], 65535)
	binary.BigEndian.PutUint16(tcpHeader[16:18], 0)
	binary.BigEndian.PutUint16(tcpHeader[18:20], 0)

	copy(packet[ipHeaderLen+tcpHeaderLen:], payload)
	binary.BigEndian.PutUint16(tcpHeader[16:18], tcpChecksum(srcIP.To4(), dstIP.To4(), tcpHeader, payload))

	return packet
}

func ipv4Checksum(header []byte) uint16 {
	var sum uint32
	for i := 0; i < len(header); i += 2 {
		if i == 10 {
			continue
		}
		sum += uint32(binary.BigEndian.Uint16(header[i : i+2]))
	}
	for sum > 0xFFFF {
		sum = (sum >> 16) + (sum & 0xFFFF)
	}
	return ^uint16(sum)
}

func tcpChecksum(srcIP net.IP, dstIP net.IP, header []byte, payload []byte) uint16 {
	var sum uint32

	addBytes := func(data []byte) {
		for i := 0; i+1 < len(data); i += 2 {
			sum += uint32(binary.BigEndian.Uint16(data[i : i+2]))
		}
		if len(data)%2 == 1 {
			sum += uint32(data[len(data)-1]) << 8
		}
	}

	addBytes(srcIP)
	addBytes(dstIP)
	sum += uint32(6)
	sum += uint32(len(header) + len(payload))

	headerCopy := append([]byte(nil), header...)
	headerCopy[16] = 0
	headerCopy[17] = 0

	addBytes(headerCopy)
	addBytes(payload)

	for sum > 0xFFFF {
		sum = (sum >> 16) + (sum & 0xFFFF)
	}
	return ^uint16(sum)
}

func htmlEscape(value string) string {
	replacer := strings.NewReplacer(
		"&", "&amp;",
		"<", "&lt;",
		">", "&gt;",
		"\"", "&quot;",
		"'", "&#39;",
	)
	return replacer.Replace(value)
}
