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
	IP            string
	LastSeen      time.Time
	Connections   int
	Handshakes    int
	BytesSent     int64
	BytesReceived int64
	Active        bool
}

// parseIntPort converts a port string to an integer
func ParseIntPort(portStr string) int {
	var port int
	fmt.Sscanf(portStr, "%d", &port)
	return port
}

// IsLocalIP checks if an IP address belongs to any of the local network interfaces
func IsLocalIP(ipAddr string) bool {
	// Parse the IP address
	ip := net.ParseIP(ipAddr)
	if ip == nil {
		return false
	}

	// Get all network interfaces
	interfaces, err := net.Interfaces()
	if err != nil {
		return false
	}

	// Check each interface
	for _, iface := range interfaces {
		// Skip down interfaces
		if iface.Flags&net.FlagUp == 0 {
			continue
		}

		// Get addresses for this interface
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}

		// Check each address
		for _, addr := range addrs {
			switch v := addr.(type) {
			case *net.IPNet:
				if v.Contains(ip) {
					return true
				}
			case *net.IPAddr:
				if v.IP.Equal(ip) {
					return true
				}
			}
		}
	}

	return false
}

// LooksLikeDevP2PHandshake checks if the payload looks like a DevP2P handshake
func LooksLikeDevP2PHandshake(b []byte) bool {
	// ECIES auth / ack sizes are predictable-ish
	// Auth ≈ 194 bytes, Ack ≈ 97 bytes (varies slightly)
	if len(b) < 90 || len(b) > 300 {
		return false
	}

	// Without entropy check, we rely on size alone for now
	// Could add other heuristics later if needed
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
