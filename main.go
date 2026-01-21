package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

func main() {
	// Open the device for packet capture - capture ALL traffic
	handle, err := pcap.OpenLive("en0", 1600, true, pcap.BlockForever)
	if err != nil {
		log.Fatal("Failed to open device en0: ", err)
	}
	defer handle.Close()

	// Capture all traffic
	err = handle.SetBPFFilter("tcp or udp")
	if err != nil {
		log.Fatal("Failed to set BPF filter: ", err)
	}

	fmt.Println("Starting packet capture on en0...")
	fmt.Println("Logging all TCP/UDP traffic...")

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

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
		appLayer := packet.ApplicationLayer()
		if appLayer != nil {
			payload := appLayer.Payload()
			if len(payload) > 0 {
				// Store raw hex data
				data = hex.EncodeToString(payload)[:min(100, len(hex.EncodeToString(payload)))]
				if len(hex.EncodeToString(payload)) > 100 {
					data += "... (truncated)"
				}
			}
		}

		// Create a simple packet info structure
		packetInfo := map[string]interface{}{
			"timestamp": packet.Metadata().Timestamp,
			"src_ip":    srcIP,
			"dst_ip":    dstIP,
			"src_port":  srcPort,
			"dst_port":  dstPort,
			"protocol":  protocol,
			"data":      data,
			"size":      len(packet.Data()),
		}

		// Log the packet info as JSON
		jsonData, err := json.Marshal(packetInfo)
		if err != nil {
			log.Printf("Error marshaling packet info: %v", err)
			continue
		}
		fmt.Println(string(jsonData))

	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
