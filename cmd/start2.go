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

	"peer-sniffer/pkg/types"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/spf13/cobra"
)

// Import the PeerStat type from types package instead of duplicating
// (already imported via "peer-sniffer/pkg/types")

var start2Cmd = &cobra.Command{
	Use:   "start2",
	Short: "Start monitoring XDC network traffic with enhanced features",
	Long:  `Starts the XDC network traffic monitor with improved performance and additional features.`,
	Run: func(cmd *cobra.Command, args []string) {
		if err := ensurePeerdDir(); err != nil {
			fmt.Printf("Error creating .peerd directory: %v\n", err)
			return
		}

		xdcOnly, _ := cmd.Flags().GetBool("xdc-only")
		outputFormat, _ := cmd.Flags().GetString("output")
		filter, _ := cmd.Flags().GetString("filter")
		trackHandshakes, _ := cmd.Flags().GetBool("track-handshakes")

		startMonitoringEnhanced(xdcOnly, outputFormat, filter, trackHandshakes)
	},
}

func init() {
	start2Cmd.Flags().Bool("xdc-only", true, "Log only XDC traffic (default true)")
	start2Cmd.Flags().String("output", "json", "Output format: json, text, csv")
	start2Cmd.Flags().String("filter", "tcp or udp", "BPF filter for packet capture")
	start2Cmd.Flags().Bool("track-handshakes", true, "Track handshake information for peer identification")
	rootCmd.AddCommand(start2Cmd)
}

func startMonitoringEnhanced(xdcOnly bool, outputFormat string, filter string, trackHandshakes bool) {
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
	if xdcOnly {
		fmt.Println("Monitoring only XDC traffic...")
	}

	// Print information about handshake tracking
	if trackHandshakes {
		fmt.Println("Tracking handshake information for peer identification and activity monitoring...")
	}

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	// Initialize peer data map with thread safety
	var peerData sync.Map

	// Channel to receive processed packets
	packetChan := make(chan map[string]interface{}, 100)

	// Goroutine to handle output formatting
	go func() {
		for packetInfo := range packetChan {
			printPacket(outputFormat, packetInfo)
		}
	}()

	// Track handshake attempts to identify peers early
	handshakeTracker := make(map[string]*types.PeerActivity)

	// Create a ticker for periodic saving of peer data (every 30 seconds)
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	// Goroutine to periodically save peer data
	go func() {
		for range ticker.C {
			savePeerDataToFileEnhanced(&peerData)
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

				// Analyze XDC payload to detect traffic and decode
				isXDCResult, resp = analyzeXDCPayloadSafe(payload, srcIP, dstIP, srcPort, dstPort, protocol)

				// Skip non-XDC traffic if xdc-only is enabled
				if xdcOnly && !isXDCResult {
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

		// Send packet to output goroutine
		select {
		case packetChan <- packetInfo:
		default:
			// Drop packet if channel is full to prevent blocking
			log.Printf("Dropping packet due to full channel buffer")
		}

		// Track handshake information for peer identification
		if trackHandshakes && resp.Type == types.DevP2PHandshake {
			trackHandshake(handshakeTracker, srcIP, dstIP, resp)

			// Periodically output peer statistics
			if len(handshakeTracker)%10 == 0 { // Every 10 handshakes
				outputPeerStats(handshakeTracker)
			}
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

// printPacket formats and prints the packet based on the output format
func printPacket(format string, packetInfo map[string]interface{}) {
	switch format {
	case "text":
		fmt.Printf("[%s] %s:%s -> %s:%s (%s) | Type: %s | Size: %d bytes\n",
			packetInfo["timestamp"],
			packetInfo["src_ip"], packetInfo["src_port"],
			packetInfo["dst_ip"], packetInfo["dst_port"],
			packetInfo["protocol"],
			packetInfo["type"],
			packetInfo["size"])
	case "csv":
		fmt.Printf("%s,%s,%s,%s,%s,%s,%s,%s,%d\n",
			packetInfo["timestamp"],
			packetInfo["src_ip"], packetInfo["src_port"],
			packetInfo["dst_ip"], packetInfo["dst_port"],
			packetInfo["protocol"],
			packetInfo["type"],
			packetInfo["details"],
			packetInfo["size"])
	default: // json
		jsonData, err := json.Marshal(packetInfo)
		if err != nil {
			log.Printf("Error marshaling packet info: %v", err)
			return
		}
		fmt.Println(string(jsonData))
	}
}

// trackHandshake records handshake information for peer identification
func trackHandshake(tracker map[string]*types.PeerActivity, srcIP, dstIP string, handshakeInfo types.XDCPacketInfo) {
	// Track source IP
	if _, exists := tracker[srcIP]; !exists {
		tracker[srcIP] = &types.PeerActivity{
			IP:            srcIP,
			LastSeen:      time.Now(),
			Connections:   0,
			Handshakes:    0,
			BytesSent:     0,
			BytesReceived: 0,
			Active:        true,
		}
	}
	tracker[srcIP].Handshakes++
	tracker[srcIP].LastSeen = time.Now()

	// Track destination IP
	if _, exists := tracker[dstIP]; !exists {
		tracker[dstIP] = &types.PeerActivity{
			IP:            dstIP,
			LastSeen:      time.Now(),
			Connections:   0,
			Handshakes:    0,
			BytesSent:     0,
			BytesReceived: 0,
			Active:        true,
		}
	}
	tracker[dstIP].Connections++
	tracker[dstIP].LastSeen = time.Now()
}

// outputPeerStats outputs peer statistics to help identify good and bad peers
func outputPeerStats(tracker map[string]*types.PeerActivity) {
	fmt.Println("\n=== PEER ACTIVITY STATISTICS ===")

	// Sort peers by handshake count to identify most active
	var sortedPeers []types.PeerStat
	for ip, stats := range tracker {
		sortedPeers = append(sortedPeers, types.PeerStat{IP: ip, Stats: stats})
	}

	// Simple bubble sort by handshake count (descending)
	for i := 0; i < len(sortedPeers)-1; i++ {
		for j := 0; j < len(sortedPeers)-i-1; j++ {
			if sortedPeers[j].Stats.Handshakes < sortedPeers[j+1].Stats.Handshakes {
				sortedPeers[j], sortedPeers[j+1] = sortedPeers[j+1], sortedPeers[j]
			}
		}
	}

	// Output top 10 most active peers
	topN := len(sortedPeers)
	if topN > 10 {
		topN = 10
	}

	fmt.Printf("Top %d most active peers:\n", topN)
	fmt.Println("IP Address\t\tHandshakes\tConnections\tLast Seen")
	fmt.Println("----------\t\t----------\t-----------\t---------")

	for i := 0; i < topN; i++ {
		peer := sortedPeers[i]
		fmt.Printf("%-20s\t%d\t\t%d\t\t%s\n",
			peer.IP,
			peer.Stats.Handshakes,
			peer.Stats.Connections,
			peer.Stats.LastSeen.Format("15:04:05"))
	}

	fmt.Println("==================================")

	// Save top peers to file for XDC node static peer list
	peerdDir, err := getPeerdDir()
	if err != nil {
		log.Printf("Error getting .peerd directory: %v", err)
		return
	}

	peersFile := filepath.Join(peerdDir, "top-peers.json")

	// Prepare data for JSON output
	type PeerInfo struct {
		IP          string    `json:"ip"`
		Handshakes  int       `json:"handshakes"`
		Connections int       `json:"connections"`
		LastSeen    time.Time `json:"last_seen"`
		Score       float64   `json:"score"` // A composite score based on activity
	}

	var topPeers []PeerInfo
	for i := 0; i < topN; i++ {
		peer := sortedPeers[i]

		// Calculate a simple score based on handshakes and recency
		score := float64(peer.Stats.Handshakes)*0.7 +
			float64(peer.Stats.Connections)*0.3

		// Boost score for recently active peers
		timeSinceLastSeen := time.Since(peer.Stats.LastSeen).Minutes()
		if timeSinceLastSeen < 10 { // Active in last 10 minutes
			score *= 1.2
		} else if timeSinceLastSeen < 30 { // Active in last 30 minutes
			score *= 1.1
		}

		topPeers = append(topPeers, PeerInfo{
			IP:          peer.IP,
			Handshakes:  peer.Stats.Handshakes,
			Connections: peer.Stats.Connections,
			LastSeen:    peer.Stats.LastSeen,
			Score:       score,
		})
	}

	// Marshal the data
	jsonData, marshalErr := json.MarshalIndent(topPeers, "", "  ")
	if marshalErr != nil {
		log.Printf("Error marshaling top peers: %v", marshalErr)
		return
	}

	// Write to file
	if writeErr := os.WriteFile(peersFile, jsonData, 0644); writeErr != nil {
		log.Printf("Error writing top peers to file: %v", writeErr)
		return
	}

	log.Printf("Saved top %d peers to %s", len(topPeers), peersFile)
}

// analyzeXDCPayloadSafe analyzes the payload to determine if it's XDC traffic
func analyzeXDCPayloadSafe(
	payload []byte,
	srcIP string,
	dstIP string,
	srcPort string,
	dstPort string,
	protocol string,
) (bool, types.XDCPacketInfo) {

	if len(payload) == 0 {
		return false, types.XDCPacketInfo{Type: types.Unknown, Details: "empty payload"}
	}

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

	// If not in XDC port range, return false early
	if !isInXDPortRange {
		return false, types.XDCPacketInfo{Type: types.Unknown, Details: "port not in XDC range (30000-65535)"}
	}

	// --- 1. DevP2P ECIES handshake (unencrypted) ---
	// Auth / Ack packets are fixed-size-ish and NOT random
	// They always begin with ECIES data, not ASCII or RLP
	if types.LooksLikeDevP2PHandshake(payload) {
		return true, types.XDCPacketInfo{
			Type:     types.DevP2PHandshake,
			Details:  "DevP2P ECIES handshake",
			PeerIP:   srcIP,
			PeerPort: srcPort,
			PeerID:   "",
		}
	}

	// --- 2. Discovery v5 (cryptographically signed UDP packets) ---
	if types.LooksLikeDiscV5(payload) {
		return true, types.XDCPacketInfo{
			Type:     types.DiscV5,
			Details:  "Discovery v5 packet",
			PeerIP:   srcIP,
			PeerPort: srcPort,
			PeerID:   "",
		}
	}

	// --- 3. Discovery v4 ---
	if types.LooksLikeDiscV4(payload) {
		return true, types.XDCPacketInfo{
			Type:     types.DiscV4,
			Details:  "Discovery v4 packet",
			PeerIP:   srcIP,
			PeerPort: srcPort,
			PeerID:   "",
		}
	}

	// --- 4. Everything else is encrypted RLPx ---
	// We DO NOT attempt to decode it

	return protocol == "TCP", types.XDCPacketInfo{
		Type:     types.EncryptedRLPx,
		Details:  "Encrypted RLPx frame (opaque)",
		PeerIP:   srcIP,
		PeerPort: srcPort,
		PeerID:   "",
	}
}
