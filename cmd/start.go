package cmd

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/spf13/cobra"
)

var startCmd = &cobra.Command{
	Use:   "start",
	Short: "Start monitoring XDC network traffic",
	Long:  `Starts the XDC network traffic monitor.`,
	Run: func(cmd *cobra.Command, args []string) {
		if err := ensurePeerdDir(); err != nil {
			fmt.Printf("Error creating .peerd directory: %v\n", err)
			return
		}

		xdcOnly, _ := cmd.Flags().GetBool("xdc-only")

		startMonitoring(xdcOnly)
	},
}

func init() {
	startCmd.Flags().Bool("xdc-only", false, "Log only XDC traffic")
	rootCmd.AddCommand(startCmd)
}

func startMonitoring(xdcOnly bool) {
	// Open the device for packet capture on any interface
	handle, err := pcap.OpenLive("any", 1600, true, pcap.BlockForever)
	if err != nil {
		log.Fatal("Failed to open device any: ", err)
	}
	defer handle.Close()

	// Capture all traffic
	err = handle.SetBPFFilter("tcp or udp")
	if err != nil {
		log.Fatal("Failed to set BPF filter: ", err)
	}

	fmt.Printf("Starting XDC packet capture on any interface...\n")
	if xdcOnly {
		fmt.Println("Monitoring only XDC traffic...")
	} else {
		fmt.Println("Monitoring all TCP/UDP traffic...")
	}

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	// Initialize peer data map
	peerData := make(map[string]interface{})

	for packet := range packetSource.Packets() {
		// Parse layers
		var srcIP, dstIP string
		var srcPort, dstPort string
		var protocol string

		networkLayer := packet.NetworkLayer()
		if networkLayer != nil {
			switch layer := networkLayer.(type) {
			case *layers.IPv4:
				srcIP = layer.SrcIP.String()
				dstIP = layer.DstIP.String()
			case *layers.IPv6:
				srcIP = layer.SrcIP.String()
				dstIP = layer.DstIP.String()
			}
		}

		transportLayer := packet.TransportLayer()
		if transportLayer != nil {
			switch layer := transportLayer.(type) {
			case *layers.TCP:
				srcPort = layer.SrcPort.String()
				dstPort = layer.DstPort.String()
				protocol = "TCP"
			case *layers.UDP:
				srcPort = layer.SrcPort.String()
				dstPort = layer.DstPort.String()
				protocol = "UDP"
			}
		}

		// Extract payload data if available
		var data string
		var resp XDCPacketInfo
		var isXDCResult bool
		appLayer := packet.ApplicationLayer()
		if appLayer != nil {
			payload := appLayer.Payload()
			if len(payload) > 0 {
				// Store raw hex data
				data = hex.EncodeToString(payload)

				// Analyze XDC payload to detect traffic and decode
				// The function will check both srcPort and dstPort for XDC range (30000-65535)
				// It will also consider localhost connections when determining XDC traffic
				isXDCResult, resp = analyzeXDCPayloadSafe(payload, srcIP, dstIP, srcPort, dstPort, protocol)

				// Skip non-XDC traffic if xdc-only is enabled
				if !isXDCResult {
					continue
				}

				if len(data) > 100 {
					data = data[:100] + "... (truncated)"
				}
			}
		}

		// Create a packet info structure
		packetInfo := map[string]interface{}{
			"timestamp": packet.Metadata().Timestamp,
			"src_ip":    srcIP,
			"dst_ip":    dstIP,
			"src_port":  srcPort,
			"dst_port":  dstPort,
			"protocol":  protocol,
			"is_xdc":    isXDCResult,
			"details":   resp.Details,
			"type":      resp.Type,
			"data":      data,
			"size":      len(packet.Data()),
		}

		// Log the packet info as JSON
		jsonData, err := json.Marshal(packetInfo)
		if err != nil {
			log.Printf("Error marshaling packet info: %v", err)
			continue
		}

		if xdcOnly {
			if isXDCResult {
				fmt.Println(string(jsonData))
			}
		} else {
			fmt.Println(string(jsonData))
		}

		// Update peer data for storage
		updatePeerData(&peerData, srcIP, dstIP, protocol, resp.Details)

		// Save peer data to file periodically
		savePeerDataToFile(peerData)
	}
}

// updatePeerData updates the peer data map with new information
func updatePeerData(peerData *map[string]interface{}, srcIP, dstIP, protocol, decodedData string) {
	// Update both source and destination IPs
	updateSinglePeer(peerData, srcIP, protocol, decodedData)
	updateSinglePeer(peerData, dstIP, protocol, decodedData)
}

// updateSinglePeer updates data for a single peer
func updateSinglePeer(peerData *map[string]interface{}, ip, protocol, decodedData string) {
	if ip == "" {
		return
	}

	// Get or create peer info
	peerInfo, exists := (*peerData)[ip]
	if !exists {
		peerInfo = make(map[string]interface{})
		(*peerData)[ip] = peerInfo
	}

	peerMap := peerInfo.(map[string]interface{})

	// Update last seen timestamp
	peerMap["last_seen"] = time.Now()

	// Update message count
	count, ok := peerMap["total_messages"].(int)
	if !ok {
		count = 0
	}
	peerMap["total_messages"] = count + 1

	// Update protocol count
	protocolCounts, ok := peerMap["protocols"].(map[string]int)
	if !ok {
		protocolCounts = make(map[string]int)
		peerMap["protocols"] = protocolCounts
	}
	protocolCounts[protocol]++

	// Update message type count if we have decoded data
	if decodedData != "" {
		messageTypes, ok := peerMap["message_types"].(map[string]int)
		if !ok {
			messageTypes = make(map[string]int)
			peerMap["message_types"] = messageTypes
		}
		messageTypes[decodedData]++
	}
}

// savePeerDataToFile saves the peer data to the file
func savePeerDataToFile(peerData map[string]interface{}) {
	peerdDir, err := getPeerdDir()
	if err != nil {
		log.Printf("Error getting .peerd directory: %v", err)
		return
	}

	dataFile := filepath.Join(peerdDir, "peer-data.json")

	// Marshal the data
	jsonData, err := json.MarshalIndent(peerData, "", "  ")
	if err != nil {
		log.Printf("Error marshaling peer data: %v", err)
		return
	}

	// Write to file
	if err := os.WriteFile(dataFile, jsonData, 0644); err != nil {
		log.Printf("Error writing peer data to file: %v", err)
	}
}

type XDCPacketType string

const (
	Unknown         XDCPacketType = "Unknown"
	DevP2PHandshake               = "DevP2PHandshake"
	DiscV4                        = "DiscV4"
	DiscV5                        = "DiscV5"
	EncryptedRLPx                 = "EncryptedRLPx"
)

type XDCPacketInfo struct {
	Type     XDCPacketType
	Details  string
	PeerIP   string
	PeerPort string
	PeerID   string // only populated if cryptographically verifiable
}

func analyzeXDCPayloadSafe(
	payload []byte,
	srcIP string,
	dstIP string,
	srcPort string,
	dstPort string,
	protocol string,
) (bool, XDCPacketInfo) {

	if len(payload) == 0 {
		return false, XDCPacketInfo{Type: Unknown, Details: "empty payload"}
	}

	// Parse the source and destination ports to integers
	srcPortInt := parseIntPort(srcPort)
	dstPortInt := parseIntPort(dstPort)

	// Check if either endpoint is a local IP
	isSrcLocal := isLocalIP(srcIP)
	isDstLocal := isLocalIP(dstIP)

	// Check if either port is in XDC range (30000-65535)
	var isInXDPortRange bool

	if isSrcLocal {
		// If source is local, only check destination port
		isInXDPortRange = dstPortInt >= 30000 && dstPortInt <= 65535
	} else if isDstLocal {
		// If destination is local, only check source port
		isInXDPortRange = srcPortInt >= 30000 && srcPortInt <= 65535
	} else {
		// Both endpoints are external, check both ports
		isInXDPortRange = (srcPortInt >= 30000 && srcPortInt <= 65535) ||
			(dstPortInt >= 30000 && dstPortInt <= 65535)
	}

	// If not in XDC port range, return false early
	if !isInXDPortRange {
		return false, XDCPacketInfo{Type: Unknown, Details: "port not in XDC range (30000-65535)"}
	}

	// --- 1. DevP2P ECIES handshake (unencrypted) ---
	// Auth / Ack packets are fixed-size-ish and NOT random
	// They always begin with ECIES data, not ASCII or RLP
	if looksLikeDevP2PHandshake(payload) {
		return true, XDCPacketInfo{
			Type:     DevP2PHandshake,
			Details:  "DevP2P ECIES handshake",
			PeerIP:   srcIP,
			PeerPort: srcPort,
			PeerID:   "",
		}
	}

	// --- 2. Discovery v5 (cryptographically signed UDP packets) ---
	if looksLikeDiscV5(payload) {
		return true, XDCPacketInfo{
			Type:     DiscV5,
			Details:  "Discovery v5 packet",
			PeerIP:   srcIP,
			PeerPort: srcPort,
			PeerID:   "",
		}
	}

	// --- 3. Discovery v4 ---
	if looksLikeDiscV4(payload) {
		return true, XDCPacketInfo{
			Type:     DiscV4,
			Details:  "Discovery v4 packet",
			PeerIP:   srcIP,
			PeerPort: srcPort,
			PeerID:   "",
		}
	}

	// --- 4. Everything else is encrypted RLPx ---
	// We DO NOT attempt to decode it

	return protocol == "TCP", XDCPacketInfo{
		Type:     EncryptedRLPx,
		Details:  "Encrypted RLPx frame (opaque)",
		PeerIP:   srcIP,
		PeerPort: srcPort,
		PeerID:   "",
	}
}

func looksLikeDevP2PHandshake(b []byte) bool {
	// ECIES auth / ack sizes are predictable-ish
	// Auth ≈ 194 bytes, Ack ≈ 97 bytes (varies slightly)
	if len(b) < 90 || len(b) > 300 {
		return false
	}

	// Without entropy check, we rely on size alone for now
	// Could add other heuristics later if needed
	return true
}

func looksLikeDiscV5(b []byte) bool {
	// DiscV5: 32-byte hash + signature + packet-type
	if len(b) < 63 {
		return false
	}
	return isValidDiscV5PacketType(b[32])
}

func looksLikeDiscV4(b []byte) bool {
	// DiscV4 packets are signed
	if len(b) < 98 {
		return false
	}
	// Without entropy check, we rely on size alone for now
	// Could add other heuristics later if needed
	return true
}

func isValidDiscV5PacketType(t byte) bool {
	switch t {
	case 0x01, 0x02, 0x03, 0x04, 0x05:
		return true
	default:
		return false
	}
}

// parseIntPort converts a port string to an integer
func parseIntPort(portStr string) int {
	var port int
	fmt.Sscanf(portStr, "%d", &port)
	return port
}

// isLocalIP checks if an IP address belongs to any of the local network interfaces
func isLocalIP(ipAddr string) bool {
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
