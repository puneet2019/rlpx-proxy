package cmd

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"

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

		interfaceName, _ := cmd.Flags().GetString("interface")
		xdcOnly, _ := cmd.Flags().GetBool("xdc-only")

		startMonitoring(interfaceName, xdcOnly)
	},
}

func init() {
	startCmd.Flags().String("interface", "en0", "Network interface to capture from")
	startCmd.Flags().Bool("xdc-only", false, "Log only XDC traffic")
	rootCmd.AddCommand(startCmd)
}

func startMonitoring(interfaceName string, xdcOnly bool) {
	// Open the device for packet capture
	handle, err := pcap.OpenLive(interfaceName, 1600, true, pcap.BlockForever)
	if err != nil {
		log.Fatal("Failed to open device ", interfaceName, ": ", err)
	}
	defer handle.Close()

	// Capture all traffic
	err = handle.SetBPFFilter("tcp or udp")
	if err != nil {
		log.Fatal("Failed to set BPF filter: ", err)
	}

	fmt.Printf("Starting XDC packet capture on interface %s...\n", interfaceName)
	if xdcOnly {
		fmt.Println("Monitoring only XDC traffic...")
	} else {
		fmt.Println("Monitoring all TCP/UDP traffic...")
	}

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	// Define XDC ports
	xdcPorts := []string{"30303", "30304", "30305", "30306", "30307", "30308", "30309", "30310", "30311", "30312", "30313"}

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
		appLayer := packet.ApplicationLayer()
		if appLayer != nil {
			payload := appLayer.Payload()
			if len(payload) > 0 {
				// Store raw hex data
				data = hex.EncodeToString(payload)
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

func isXDCPort(port string, xdcPorts []string) bool {
	for _, xdcPort := range xdcPorts {
		if port == xdcPort {
			return true
		}
	}
	return false
}