package types

import (
	"fmt"
	"net"
	"time"
)

// XDCPacketType represents the type of XDC packet
type XDCPacketType string

const (
	Unknown         XDCPacketType = "Unknown"
	DevP2PHandshake               = "DevP2PHandshake"
	DiscV4                        = "DiscV4"
	DiscV5                        = "DiscV5"
	EncryptedRLPx                 = "EncryptedRLPx"
)

// XDCPacketInfo contains information about an XDC packet
type XDCPacketInfo struct {
	Type     XDCPacketType
	Details  string
	PeerIP   string
	PeerPort string
	PeerID   string // only populated if cryptographically verifiable
}

// PeerActivity tracks activity for a specific peer
type PeerActivity struct {
	IP             string
	PeerID         string
	LastSeen       time.Time
	Connections    int
	Handshakes     int
	DiscoveryCount int
	DataCount      int
	BytesSent      int64
	BytesReceived  int64
	Active         bool
	Score          float64
}

// parseIntPort converts a port string to an integer
func ParseIntPort(portStr string) int {
	var port int
	fmt.Sscanf(portStr, "%d", &port)
	return port
}

var cgnatBlock = mustCIDR("100.64.0.0/10")

// IsLocalIP checks if an IP address is a private/local address
func IsLocalIP(ipAddr string) bool {
	ip := net.ParseIP(ipAddr)
	if ip == nil {
		return false
	}

	// Check if it's a private/reserved/local IP address
	if ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return true
	}
	if cgnatBlock.Contains(ip) {
		return true
	}
	return false
}
func mustCIDR(c string) *net.IPNet {
	_, block, err := net.ParseCIDR(c)
	if err != nil {
		panic(err)
	}
	return block
}

// LooksLikeDevP2PHandshake checks if the payload looks like a DevP2P handshake
func LooksLikeDevP2PHandshake(b []byte) bool {
	// ECIES auth / ack sizes are predictable
	// Raw Auth ≈ 194 bytes, Raw Ack ≈ 97 bytes
	// Encrypted Auth ≈ 307 bytes, Encrypted Ack ≈ 210 bytes (with ECIES overhead)
	// We should accept a range that covers both raw and encrypted handshake packets
	if len(b) < 50 || len(b) > 500 {
		return false
	}

	// For now, we'll use size as a primary indicator but acknowledge that
	// encrypted handshake packets are larger due to ECIES overhead
	// Additional checks could be added later for more accuracy
	return true
}

// LooksLikeDiscV5 checks if the payload looks like a DiscV5 packet
func LooksLikeDiscV5(b []byte) bool {
	// DiscV5: 32-byte hash + signature + packet-type
	if len(b) < 63 {
		return false
	}
	return IsValidDiscV5PacketType(b[32])
}

// LooksLikeDiscV4 checks if the payload looks like a DiscV4 packet
func LooksLikeDiscV4(b []byte) bool {
	// DiscV4 packets are signed
	if len(b) < 98 {
		return false
	}
	// Without entropy check, we rely on size alone for now
	// Could add other heuristics later if needed
	return true
}

// IsValidDiscV5PacketType checks if a byte represents a valid DiscV5 packet type
func IsValidDiscV5PacketType(t byte) bool {
	switch t {
	case 0x01, 0x02, 0x03, 0x04, 0x05:
		return true
	default:
		return false
	}
}

// PeerStat holds peer statistics for sorting
type PeerStat struct {
	IP    string
	Stats *PeerActivity
}
