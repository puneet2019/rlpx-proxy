package cmd

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"text/tabwriter"

	"github.com/spf13/cobra"
)

var showCmd = &cobra.Command{
	Use:   "show",
	Short: "Show peer statistics and data",
	Long:  `Displays collected peer statistics and network data.`,
	Run: func(cmd *cobra.Command, args []string) {
		format, _ := cmd.Flags().GetString("format")
		showPeerData(format)
	},
}

func init() {
	showCmd.Flags().String("format", "table", "Output format (table or json)")
	rootCmd.AddCommand(showCmd)
}

func showPeerData(format string) {
	peerdDir, err := getPeerdDir()
	if err != nil {
		fmt.Printf("Error getting .peerd directory: %v\n", err)
		return
	}

	dataFile := filepath.Join(peerdDir, "peer-data.json")
	
	// Read the data file
	data, err := ioutil.ReadFile(dataFile)
	if err != nil {
		fmt.Printf("No peer data found at %s\n", dataFile)
		fmt.Println("Run 'peer-sniffer start' first to collect data")
		return
	}
	
	if format == "json" {
		fmt.Println(string(data))
		return
	}
	
	// Parse and display as table
	var peerData map[string]interface{}
	if err := json.Unmarshal(data, &peerData); err != nil {
		fmt.Printf("Error parsing peer data: %v\n", err)
		return
	}
	
	displayPeerTable(peerData)
}

func displayPeerTable(peerData map[string]interface{}) {
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "Peer IP\tLast Seen\tTotal Msgs\tIncoming\tOutgoing\tActive")
	fmt.Fprintln(w, "-------\t---------\t----------\t--------\t--------\t------")
	
	for peerIP, data := range peerData {
		if peerInfo, ok := data.(map[string]interface{}); ok {
			lastSeen := peerInfo["last_seen"]
			totalMsgs := peerInfo["total_messages"]
			incoming := peerInfo["incoming_messages"]
			outgoing := peerInfo["outgoing_messages"]
			
			fmt.Fprintf(w, "%s\t%v\t%v\t%v\t%v\tYes\n", 
				peerIP, lastSeen, totalMsgs, incoming, outgoing)
		}
	}
	
	w.Flush()
}