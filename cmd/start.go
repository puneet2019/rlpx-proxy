package cmd

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
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
		var srcIP, dstIP, srcPort, dstPort string
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
				srcPort = fmt.Sprintf("%d", layer.SrcPort)
				dstPort = fmt.Sprintf("%d", layer.DstPort)
				protocol = "TCP"
			case *layers.UDP:
				srcPort = fmt.Sprintf("%d", layer.SrcPort)
				dstPort = fmt.Sprintf("%d", layer.DstPort)
				protocol = "UDP"
			}
		}

		// Extract payload data if available
		var data string
		var decodedData string
		var isXDCResult bool
		appLayer := packet.ApplicationLayer()
		if appLayer != nil {
			payload := appLayer.Payload()
			if len(payload) > 0 {
				// Store raw hex data
				data = hex.EncodeToString(payload)

				// Analyze XDC payload to detect traffic and decode
				isXDCResult, _, decoded := analyzeXDCPayload(payload)

				// Skip non-XDC traffic if xdc-only is enabled
				if xdcOnly && !isXDCResult {
					continue
				}

				if decoded != "" {
					decodedData = decoded
				}

				if len(data) > 100 {
					data = data[:100] + "... (truncated)"
				}
			}
		} else {
			// If no application layer, check if xdcOnly is enabled
			if xdcOnly {
				continue // Skip if no payload to check
			}
		}

		// Create a packet info structure
		packetInfo := map[string]interface{}{
			"timestamp":    packet.Metadata().Timestamp,
			"src_ip":       srcIP,
			"dst_ip":       dstIP,
			"src_port":     srcPort,
			"dst_port":     dstPort,
			"protocol":     protocol,
			"is_xdc":       isXDCResult,
			"data":         data,
			"decoded_data": decodedData,
			"size":         len(packet.Data()),
		}

		// Log the packet info as JSON
		jsonData, err := json.Marshal(packetInfo)
		if err != nil {
			log.Printf("Error marshaling packet info: %v", err)
			continue
		}

		fmt.Println(string(jsonData))

		// Update peer data for storage
		updatePeerData(&peerData, srcIP, dstIP, protocol, decodedData)

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


// XDCPacketType represents the type of XDC packet
type XDCPacketType string

const (
	ConnectionRequest XDCPacketType = "connection_request"
	Disconnect        XDCPacketType = "disconnect"
	MessagePassing    XDCPacketType = "message_passing"
	PingPong          XDCPacketType = "ping_pong"
	Unknown           XDCPacketType = "unknown"
)

// XDCPacketInfo contains information about the XDC packet
type XDCPacketInfo struct {
	Type    XDCPacketType
	Details string
}

// analyzeXDCPayload analyzes the payload data to detect XDC traffic and decode it
func analyzeXDCPayload(payload []byte) (bool, XDCPacketInfo, string) {
	if len(payload) == 0 {
		return false, XDCPacketInfo{Type: Unknown, Details: "Empty payload"}, ""
	}

	// Check for devp2p handshake (starts with 0x22 - Hello message length)
	if len(payload) >= 1 && payload[0] == 0x22 {
		return true, XDCPacketInfo{Type: ConnectionRequest, Details: "DevP2P Hello Message"}, "DevP2P Hello Message"
	}

	// Check for RLP-encoded data (common in Ethereum protocols)
	if len(payload) >= 1 {
		firstByte := payload[0]
		// RLP length prefixes: 0x80-0xbf for strings/lists
		if firstByte >= 0x80 && firstByte <= 0xbf {
			// Check for common XDC protocol message types
			if len(payload) >= 2 {
				secondByte := payload[1]
				switch secondByte {
				case 0x00: // Hello
					return true, XDCPacketInfo{Type: ConnectionRequest, Details: "Hello Message"}, "XDC Hello Message"
				case 0x01: // Disconnect
					return true, XDCPacketInfo{Type: Disconnect, Details: "Disconnect Message"}, "XDC Disconnect Message"
				case 0x02: // Ping
					return true, XDCPacketInfo{Type: PingPong, Details: "Ping Message"}, "XDC Ping Message"
				case 0x03: // Pong
					return true, XDCPacketInfo{Type: PingPong, Details: "Pong Message"}, "XDC Pong Message"
				case 0x0a: // Transactions
					return true, XDCPacketInfo{Type: MessagePassing, Details: "Transaction Message"}, "XDC Transaction Message"
				case 0x0b: // GetBlockHashes
					return true, XDCPacketInfo{Type: MessagePassing, Details: "GetBlockHashes Message"}, "XDC GetBlockHashes Message"
				case 0x0c: // BlockHashes
					return true, XDCPacketInfo{Type: MessagePassing, Details: "BlockHashes Message"}, "XDC BlockHashes Message"
				case 0x0d: // GetBlocks
					return true, XDCPacketInfo{Type: MessagePassing, Details: "GetBlocks Message"}, "XDC GetBlocks Message"
				case 0x0e: // Blocks
					return true, XDCPacketInfo{Type: MessagePassing, Details: "Blocks Message"}, "XDC Blocks Message"
				case 0x10: // NewBlock
					return true, XDCPacketInfo{Type: MessagePassing, Details: "NewBlock Message"}, "XDC NewBlock Message"
				case 0x11: // NewBlockHashes
					return true, XDCPacketInfo{Type: MessagePassing, Details: "NewBlockHashes Message"}, "XDC NewBlockHashes Message"
				}
			}
			return true, XDCPacketInfo{Type: MessagePassing, Details: "RLP Encoded Data"}, "RLP Encoded Data"
		}
	}

	// Check for common protocol IDs in XDC
	if len(payload) >= 3 {
		// Look for common protocol identifiers
		if string(payload[:3]) == "ETH" || string(payload[:3]) == "XDC" {
			return true, XDCPacketInfo{Type: MessagePassing, Details: "XDC Protocol Data"}, "XDC Protocol Data"
		}
	}

	// Check for readable strings that might be XDC-related
	payloadStr := string(payload)
	if strings.Contains(strings.ToLower(payloadStr), "xdc") ||
		strings.Contains(strings.ToLower(payloadStr), "xinfin") ||
		strings.Contains(payloadStr, "enode://") {
		return true, XDCPacketInfo{Type: MessagePassing, Details: "XDC Protocol String Data"}, "XDC Protocol String Data"
	}

	// Check for DiscV5 discovery protocol signatures (used by XDC)
	if len(payload) >= 65 { // Minimum size for a DiscV5 packet
		// DiscV5 packets have a 32-byte signature followed by packet type
		// The signature is ECDSA over the packet data
		// Common packet types: PING (0x01), PONG (0x02), FINDNODE (0x03), NODES (0x04)
		packetType := payload[32]
		switch packetType {
		case 0x01:
			return true, XDCPacketInfo{Type: PingPong, Details: "DiscV5 PING Message"}, "DiscV5 PING Message"
		case 0x02:
			return true, XDCPacketInfo{Type: PingPong, Details: "DiscV5 PONG Message"}, "DiscV5 PONG Message"
		case 0x03:
			return true, XDCPacketInfo{Type: MessagePassing, Details: "DiscV5 FINDNODE Message"}, "DiscV5 FINDNODE Message"
		case 0x04:
			return true, XDCPacketInfo{Type: MessagePassing, Details: "DiscV5 NODES Message"}, "DiscV5 NODES Message"
		}
	}

	// Check for hex patterns that might indicate blockchain data
	// This is a heuristic approach
	hexCount := 0
	for _, b := range payload {
		if (b >= '0' && b <= '9') || (b >= 'a' && b <= 'f') || (b >= 'A' && b <= 'F') {
			hexCount++
		}
	}

	// If a high percentage of the payload looks like hex, it might be blockchain data
	if float32(hexCount)/float32(len(payload)) > 0.7 {
		return true, XDCPacketInfo{Type: MessagePassing, Details: "Hex-encoded Blockchain Data"}, "Hex-encoded Blockchain Data"
	}

	return false, XDCPacketInfo{Type: Unknown, Details: "Not XDC traffic"}, ""
}
