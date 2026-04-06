package telemetry

import (
	"bytes"
	"encoding/binary"
	"strings"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

func ObserveHysteriaPacket(userID, serverID, serverIP, remoteAddr string, packet []byte) {
	if userID == "" || len(packet) < 20 || packet[0]>>4 != 4 {
		return
	}

	headerLen := int(packet[0]&0x0F) * 4
	if headerLen < 20 || len(packet) < headerLen {
		return
	}

	now := time.Now().UTC()
	switch packet[9] {
	case 17:
		observeHysteriaUDPPacket(userID, serverID, serverIP, remoteAddr, packet[headerLen:], now)
	case 6:
		observeHysteriaTCPPacket(userID, serverID, serverIP, remoteAddr, packet[headerLen:], now)
	}
}

func observeHysteriaUDPPacket(userID, serverID, serverIP, remoteAddr string, packet []byte, now time.Time) {
	if len(packet) < 8 {
		return
	}

	dstPort := int(binary.BigEndian.Uint16(packet[2:4]))
	if dstPort != 53 {
		return
	}

	domain := ExtractDNSQueryName(packet[8:])
	if domain == "" {
		return
	}

	observeDomain(userID, domain, "dns", dstPort, serverID, serverIP, remoteAddr, now)
}

func observeHysteriaTCPPacket(userID, serverID, serverIP, remoteAddr string, packet []byte, now time.Time) {
	if len(packet) < 20 {
		return
	}

	dstPort := int(binary.BigEndian.Uint16(packet[2:4]))
	dataOffset := int(packet[12]>>4) * 4
	if dataOffset < 20 || len(packet) < dataOffset {
		return
	}

	payload := packet[dataOffset:]
	if len(payload) == 0 {
		return
	}

	switch dstPort {
	case 80, 8080, 8000:
		if domain := ExtractHTTPHost(payload); domain != "" {
			observeDomain(userID, domain, "http", dstPort, serverID, serverIP, remoteAddr, now)
		}
	case 443, 8443:
		if domain := ExtractTLSServerName(payload); domain != "" {
			observeDomain(userID, domain, "tls", dstPort, serverID, serverIP, remoteAddr, now)
		}
	}
}

func ExtractDNSQueryName(message []byte) string {
	var parser dnsmessage.Parser
	if _, err := parser.Start(message); err != nil {
		return ""
	}

	question, err := parser.Question()
	if err != nil {
		return ""
	}

	return strings.TrimSuffix(strings.ToLower(question.Name.String()), ".")
}

func ExtractHTTPHost(payload []byte) string {
	if len(payload) == 0 {
		return ""
	}

	headerEnd := bytes.Index(payload, []byte("\r\n\r\n"))
	if headerEnd == -1 {
		headerEnd = len(payload)
	}
	if headerEnd > 4096 {
		headerEnd = 4096
	}

	text := string(payload[:headerEnd])
	if !strings.Contains(text, "HTTP/") {
		return ""
	}

	for _, line := range strings.Split(text, "\r\n") {
		if len(line) < 5 {
			continue
		}
		if strings.EqualFold(line[:5], "host:") {
			return strings.Trim(strings.ToLower(strings.TrimSpace(line[5:])), ".")
		}
	}

	return ""
}

func ExtractTLSServerName(payload []byte) string {
	if len(payload) < 5 || payload[0] != 0x16 {
		return ""
	}

	recordLen := int(binary.BigEndian.Uint16(payload[3:5]))
	if recordLen <= 0 || len(payload) < 5+recordLen {
		return ""
	}

	record := payload[5 : 5+recordLen]
	if len(record) < 4 || record[0] != 0x01 {
		return ""
	}

	helloLen := int(record[1])<<16 | int(record[2])<<8 | int(record[3])
	if helloLen <= 0 || len(record) < 4+helloLen {
		return ""
	}

	hello := record[4 : 4+helloLen]
	if len(hello) < 34 {
		return ""
	}

	offset := 34
	if offset >= len(hello) {
		return ""
	}

	sessionIDLen := int(hello[offset])
	offset++
	if offset+sessionIDLen > len(hello) {
		return ""
	}
	offset += sessionIDLen

	if offset+2 > len(hello) {
		return ""
	}
	cipherSuiteLen := int(binary.BigEndian.Uint16(hello[offset : offset+2]))
	offset += 2
	if offset+cipherSuiteLen > len(hello) {
		return ""
	}
	offset += cipherSuiteLen

	if offset >= len(hello) {
		return ""
	}
	compressionLen := int(hello[offset])
	offset++
	if offset+compressionLen > len(hello) {
		return ""
	}
	offset += compressionLen

	if offset+2 > len(hello) {
		return ""
	}
	extensionsLen := int(binary.BigEndian.Uint16(hello[offset : offset+2]))
	offset += 2
	if offset+extensionsLen > len(hello) {
		return ""
	}

	extensions := hello[offset : offset+extensionsLen]
	for len(extensions) >= 4 {
		extType := binary.BigEndian.Uint16(extensions[:2])
		extLen := int(binary.BigEndian.Uint16(extensions[2:4]))
		extensions = extensions[4:]
		if extLen > len(extensions) {
			return ""
		}

		extData := extensions[:extLen]
		extensions = extensions[extLen:]
		if extType != 0x0000 {
			continue
		}

		if len(extData) < 2 {
			return ""
		}
		serverNameListLen := int(binary.BigEndian.Uint16(extData[:2]))
		if len(extData) < 2+serverNameListLen {
			return ""
		}

		serverNames := extData[2 : 2+serverNameListLen]
		for len(serverNames) >= 3 {
			nameType := serverNames[0]
			nameLen := int(binary.BigEndian.Uint16(serverNames[1:3]))
			serverNames = serverNames[3:]
			if nameLen > len(serverNames) {
				return ""
			}
			name := serverNames[:nameLen]
			serverNames = serverNames[nameLen:]
			if nameType == 0 {
				return strings.Trim(strings.ToLower(string(name)), ".")
			}
		}
	}

	return ""
}
