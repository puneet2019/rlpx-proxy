package cmd

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"

	"peer-sniffer/pkg/logger"
	"peer-sniffer/pkg/sessiontracker"
	"peer-sniffer/pkg/types"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/spf13/cobra"
)

var start2Cmd = &cobra.Command{
	Use:   "start2",
	Short: "Start monitoring XDC network traffic with enhanced features",
	Long:  `Starts the XDC network traffic monitor with improved performance and additional features.`,
	Run: func(cmd *cobra.Command, args []string) {
		if err := ensurePeerdDir(); err != nil {
			fmt.Printf("Error creating .peerd directory: %v\n", err)
			return
		}

		outputFormat, _ := cmd.Flags().GetString("output")
		filter, _ := cmd.Flags().GetString("filter")
		trackHandshakes, _ := cmd.Flags().GetBool("track-handshakes")

		startMonitoringEnhanced(outputFormat, filter, trackHandshakes)
	},
}

func init() {
	start2Cmd.Flags().String("output", "json", "Output format: json, text, csv")
	start2Cmd.Flags().String("filter", "tcp or udp", "BPF filter for packet capture")
	start2Cmd.Flags().Bool("track-handshakes", true, "Track handshake information for peer identification")
	rootCmd.AddCommand(start2Cmd)
}

func startMonitoringEnhanced(outputFormat string, filter string, trackHandshakes bool) {
	// Open the device for packet capture - always use "any" interface
	handle, err := pcap.OpenLive("any", 1600, true, pcap.BlockForever)
	if err != nil {
		log.Fatal(fmt.Sprintf("Failed to open device any: %v", err))
	}
	defer handle.Close()

	// Apply the BPF filter
	err = handle.SetBPFFilter(filter)
	if err != nil {
		log.Fatal("Failed to set BPF filter: ", err)
	}

	fmt.Printf("Starting XDC packet capture on any interface with filter '%s'...\n", filter)
	fmt.Println("Monitoring all traffic (XDC and non-XDC)...")

	// Print information about handshake tracking
	if trackHandshakes {
		fmt.Println("Tracking handshake information for peer identification and activity monitoring...")
	}

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	// Initialize peer data map with thread safety
	var peerData sync.Map

	// Create logger instance
	loggerInstance := logger.NewLogger(outputFormat)

	// Initialize the TCP stream processor (for handshake reconstruction)
	if err := sessiontracker.InitStreamProcessor(); err != nil {
		log.Printf("Warning: failed to initialize stream processor: %v", err)
	}

	// Channel to receive processed packets
	packetChan := make(chan map[string]interface{}, 1000)

	// Goroutine to handle output formatting
	go func() {
		for packetInfo := range packetChan {
			// Only log XDC traffic, discard non-XDC traffic, hence we use LogXDCPacket
			loggerInstance.LogXDCPacket(packetInfo)

		}
	}()

	// Create a ticker for periodic saving of peer data (every 10 seconds)
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	// Create a ticker for periodic decryption and logging (every 5 seconds)
	decryptTicker := time.NewTicker(5 * time.Second)
	defer decryptTicker.Stop()

	// Goroutine to periodically save peer data
	go func() {
		for range ticker.C {
			savePeerDataToFileEnhanced(&peerData)
		}
	}()

	// Goroutine to periodically report established sessions and traffic types
	go func() {
		for range decryptTicker.C {
			// Get all sessions from the session tracker
			sessions := sessiontracker.GetAllSessions()

			establishedCount := 0
			handshakeCount := 0
			dataTransferCount := 0

			for sessionID, session := range sessions {
				if session.P2PSession != nil {
					if session.P2PSession.Established {
						log.Printf("Active session: %s with peer %s", sessionID, session.P2PSession.PeerID)
						establishedCount++
						dataTransferCount++
					} else {
						// Check if this session has handshake data but is not yet established
						hasAuth := session.P2PSession.AuthRespHash != nil
						hasAck := session.P2PSession.AckHash != nil
						if hasAuth || hasAck {
							status := "Partial handshake"
							if hasAuth && hasAck {
								status = "Handshake complete (no frame keys — passive sniffing/PFS)"
							} else if hasAuth {
								log.Printf("Auth packet captured: %s (awaiting Ack)", sessionID)
							} else if hasAck {
								log.Printf("Ack packet captured: %s (awaiting Auth)", sessionID)
							}
							log.Printf("%s: %s", status, sessionID)
							handshakeCount++
						}
					}
				}
			}

			log.Printf("Summary - Established: %d, Handshakes: %d, Data Transfers: %d",
				establishedCount, handshakeCount, dataTransferCount)
		}
	}()

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

		// Skip local-to-local traffic
		if types.IsLocalIP(srcIP) && types.IsLocalIP(dstIP) {
			continue // Skip local-to-local traffic completely
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
		var resp types.XDCPacketInfo
		var isXDCResult bool
		appLayer := packet.ApplicationLayer()
		if appLayer != nil {
			payload := appLayer.Payload()
			if len(payload) > 0 {
				// Store raw hex data
				data = hex.EncodeToString(payload)

				// Determine if this is XDC traffic based on port ranges
				isXDCResult = isXDCTraffic(srcIP, dstIP, srcPort, dstPort)

				// Create response object based on packet type if it's XDC traffic
				if isXDCResult {
					resp = classifyPacketType(payload, srcIP, dstIP, srcPort, dstPort, protocol)
				} else {
					// For non-XDC traffic, just mark as unknown
					resp = types.XDCPacketInfo{
						Type:     types.Unknown,
						Details:  "Non-XDC traffic",
						PeerIP:   srcIP,
						PeerPort: srcPort,
						PeerID:   "",
					}
				}

				if len(data) > 100 {
					data = data[:100] + "... (truncated)"
				}
			}
		}

		// Create a canonical session ID that is the same for both directions of a connection
		sessionID := sessiontracker.CreateCanonicalSessionID(srcIP, srcPort, dstIP, dstPort)

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

		// Attempt to decrypt encrypted packets if we have an established session
		currentAppLayer := packet.ApplicationLayer()
		if currentAppLayer != nil && resp.Type == types.EncryptedRLPx {
			payload := currentAppLayer.Payload()
			if len(payload) > 0 {
				decryptedData, err := sessiontracker.DecryptAndLogPlaintext(sessionID, payload)
				if err != nil {
					// Log decryption errors for debugging
					log.Printf("Decryption failed for session %s: %v", sessionID, err)
				} else if len(decryptedData) > 0 {
					// Add decrypted message to packet info
					packetInfo["decrypted_msg"] = string(decryptedData)
					log.Printf("Successfully decrypted message for session %s: %d bytes", sessionID, len(decryptedData))
				} else {
					log.Printf("Decryption succeeded but returned empty data for session %s", sessionID)
				}
			}
		}

		// Only send XDC packets to output goroutine, discard non-XDC traffic
		if isXDCResult {
			select {
			case packetChan <- packetInfo:
			default:
				// Drop packet if channel is full to prevent blocking
				log.Printf("Dropping XDC packet due to full channel buffer")
			}
		}

		// Process the packet with session tracker to extract handshake info and derive session keys
		if err := sessiontracker.ProcessPacket(packet); err != nil {
			// Log error but continue processing other packets
			log.Printf("Error processing packet with session tracker: %v", err)
		}

		// Update peer data for storage (thread-safe)
		packetSize := len(packet.Data())
		updatePeerDataEnhanced(&peerData, srcIP, dstIP, protocol, resp.Details, packetSize)
	}

	// Save peer data one final time before exiting
	savePeerDataToFileEnhanced(&peerData)
	close(packetChan)
}

// updatePeerDataEnhanced updates the peer data map with new information (thread-safe)
func updatePeerDataEnhanced(peerData *sync.Map, srcIP, dstIP, protocol, decodedData string, packetSize int) {
	// Update both source and destination IPs
	updateSinglePeerEnhanced(peerData, srcIP, protocol, decodedData, packetSize, true) // src is sender
	updateSinglePeerEnhanced(peerData, dstIP, protocol, decodedData, 0, false)         // dst is receiver
}

// updateSinglePeerEnhanced updates data for a single peer (thread-safe)
func updateSinglePeerEnhanced(peerData *sync.Map, ip, protocol, decodedData string, packetSize int, isSender bool) {
	if ip == "" {
		return
	}

	// Load or store peer info
	peerInfo, _ := peerData.LoadOrStore(ip, make(map[string]interface{}))

	peerMap := peerInfo.(map[string]interface{})

	// Update last seen timestamp
	peerMap["last_seen"] = time.Now()

	// Update message count
	count, ok := peerMap["total_messages"].(int)
	if !ok {
		count = 0
	}
	peerMap["total_messages"] = count + 1

	// Update total bytes
	totalBytes, ok := peerMap["total_bytes"].(int64)
	if !ok {
		totalBytes = 0
	}
	totalBytes += int64(packetSize)
	peerMap["total_bytes"] = totalBytes

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

// savePeerDataToFileEnhanced saves the peer data to the file (thread-safe)
func savePeerDataToFileEnhanced(peerData *sync.Map) {
	peerdDir, err := getPeerdDir()
	if err != nil {
		log.Printf("Error getting .peerd directory: %v", err)
		return
	}

	dataFile := filepath.Join(peerdDir, "peer-data-enhanced.json")

	// Convert sync.Map to regular map for JSON marshaling
	result := make(map[string]interface{})
	peerData.Range(func(key, value interface{}) bool {
		result[key.(string)] = value
		return true
	})

	// Marshal the data
	jsonData, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		log.Printf("Error marshaling peer data: %v", err)
		return
	}

	// Write to file
	if err := os.WriteFile(dataFile, jsonData, 0644); err != nil {
		log.Printf("Error writing peer data to file: %v", err)
	}
}

// isXDCTraffic determines if traffic is XDC based on port ranges and local IP considerations
func isXDCTraffic(srcIP string, dstIP string, srcPort string, dstPort string) bool {
	// Parse the source and destination ports to integers
	srcPortInt := types.ParseIntPort(srcPort)
	dstPortInt := types.ParseIntPort(dstPort)

	// Check if either endpoint is a local IP
	isSrcLocal := types.IsLocalIP(srcIP)
	isDstLocal := types.IsLocalIP(dstIP)

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

	return isInXDPortRange
}

// classifyPacketType classifies packets as handshake, ping/pong, or block messages
func classifyPacketType(
	payload []byte,
	srcIP string,
	dstIP string,
	srcPort string,
	dstPort string,
	protocol string,
) types.XDCPacketInfo {
	// Protocol-aware classification to avoid mislabeling UDP discovery as DevP2P handshake
	if protocol == "TCP" {
		if types.LooksLikeDevP2PHandshake(payload) {
			return types.XDCPacketInfo{
				Type:     types.DevP2PHandshake,
				Details:  "DevP2P ECIES handshake",
				PeerIP:   srcIP,
				PeerPort: srcPort,
				PeerID:   "",
			}
		}
		// Other TCP encrypted traffic assumed to be RLPx frames
		return types.XDCPacketInfo{
			Type:     types.EncryptedRLPx,
			Details:  "Encrypted RLPx frame (requires decryption)",
			PeerIP:   srcIP,
			PeerPort: srcPort,
			PeerID:   "",
		}
	}

	// UDP path — handle Discovery protocols first
	if protocol == "UDP" {
		if types.LooksLikeDiscV5(payload) {
			return types.XDCPacketInfo{
				Type:     types.DiscV5,
				Details:  "Discovery v5 packet",
				PeerIP:   srcIP,
				PeerPort: srcPort,
				PeerID:   "",
			}
		}
		if types.LooksLikeDiscV4(payload) {
			return types.XDCPacketInfo{
				Type:     types.DiscV4,
				Details:  "Discovery v4 packet",
				PeerIP:   srcIP,
				PeerPort: srcPort,
				PeerID:   "",
			}
		}
	}

	// Fallback
	return types.XDCPacketInfo{
		Type:     types.Unknown,
		Details:  "Non-XDC or unrecognized packet",
		PeerIP:   srcIP,
		PeerPort: srcPort,
		PeerID:   "",
	}
}
