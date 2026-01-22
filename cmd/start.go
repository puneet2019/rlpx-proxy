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

	// Define XDC ports
	xdcPorts := []string{"30303", "30304", "30305", "30306", "30307", "30308", "30309", "30310", "30311", "30312", "30313"}

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

		// Check if this is XDC traffic by checking ports
		isXDC := isXDCPort(dstPort, xdcPorts) || isXDCPort(srcPort, xdcPorts)
		if xdcOnly && !isXDC {
			continue // Skip non-XDC traffic if xdc-only is enabled
		}

		// Extract payload data if available
		var data string
		var decodedData string
		appLayer := packet.ApplicationLayer()
		if appLayer != nil {
			payload := appLayer.Payload()
			if len(payload) > 0 {
				// Store raw hex data
				data = hex.EncodeToString(payload)

				// Attempt to decode XDC/Ethereum-style RLP data
				decoded := decodeXDCData(payload)
				if decoded != "" {
					decodedData = decoded
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
			"is_xdc":    isXDC,
			"data":      data,
			"decoded_data": decodedData,
			"size":      len(packet.Data()),
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

func isXDCPort(port string, xdcPorts []string) bool {
	for _, xdcPort := range xdcPorts {
		if port == xdcPort {
			return true
		}
	}
	return false
}

// decodeXDCData attempts to decode XDC/Ethereum-style data
func decodeXDCData(data []byte) string {
	if len(data) == 0 {
		return ""
	}

	// Check for common Ethereum/XDC protocol signatures
	// This is a simplified decoder - in reality, you'd need more sophisticated parsing

	// Check for devp2p handshake (starts with 0x22 - Hello message length)
	if len(data) >= 1 && data[0] == 0x22 {
		return "DevP2P Hello Message"
	}

	// Check for RLP-encoded data (common in Ethereum protocols)
	if len(data) >= 1 {
		firstByte := data[0]
		// RLP length prefixes: 0x80-0xb7 for short data, 0xb8-0xbf for long data
		if (firstByte >= 0x80 && firstByte <= 0xb7) || (firstByte >= 0xb8 && firstByte <= 0xbf) {
			return "RLP Encoded Data"
		}
	}

	// Check for common protocol IDs in XDC
	if len(data) >= 3 {
		// Look for common protocol identifiers
		if string(data[:3]) == "ETH" || string(data[:3]) == "XDC" {
			return "XDC Protocol Data"
		}
	}

	// Check for readable strings that might be XDC-related
	dataStr := string(data)
	if strings.Contains(strings.ToLower(dataStr), "xdc") ||
	   strings.Contains(strings.ToLower(dataStr), "xinfin") ||
	   strings.Contains(dataStr, "enode://") {
		return "XDC Protocol String Data"
	}

	return ""
}