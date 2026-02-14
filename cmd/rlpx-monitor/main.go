package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
)

// logEvent mirrors the proxy's JSON log format.
type logEvent struct {
	Timestamp  string `json:"ts"`
	Event      string `json:"event"`
	Direction  string `json:"direction"`
	Peer       string `json:"peer"`
	PeerID     string `json:"peer_id"`
	ClientName string `json:"client"`
	MsgCode    uint64 `json:"msg_code"`
	Size       int    `json:"size"`
}

// peerRecord is persisted to disk — lifetime stats for a peer.
type peerRecord struct {
	Enode      string         `json:"enode"`
	PeerID     string         `json:"peer_id"`
	Addr       string         `json:"addr"`
	ClientName string         `json:"client"`
	MsgCounts  map[string]int `json:"msg_counts"`
	TotalMsgs  int            `json:"total_msgs"`
	TotalBytes int            `json:"total_bytes"`
	InMsgs     int            `json:"in_msgs"`
	OutMsgs    int            `json:"out_msgs"`
	Sessions   int            `json:"sessions"`
	FirstSeen  time.Time      `json:"first_seen"`
	LastSeen   time.Time      `json:"last_seen"`
	LastActive time.Time      `json:"last_active"` // last non-ping/pong
	Score      float64        `json:"score"`
}

func (p *peerRecord) computeScore() {
	// Score based on: protocol message diversity, volume, and recency.
	// Higher = better peer.
	protocolMsgs := 0
	uniqueProtocol := 0
	for name, count := range p.MsgCounts {
		if name != "Ping" && name != "Pong" && name != "Hello" && name != "Disconnect" {
			protocolMsgs += count
			uniqueProtocol++
		}
	}

	// Volume component (log scale, capped).
	volume := 0.0
	if protocolMsgs > 0 {
		volume = min64(float64(protocolMsgs)/100.0, 10.0)
	}

	// Diversity component: more unique message types = better.
	diversity := float64(uniqueProtocol) * 2.0

	// Recency component: recent activity scores higher.
	recency := 0.0
	if !p.LastActive.IsZero() {
		hoursSince := time.Since(p.LastActive).Hours()
		if hoursSince < 1 {
			recency = 10.0
		} else if hoursSince < 24 {
			recency = 5.0
		} else if hoursSince < 168 { // 1 week
			recency = 2.0
		}
	}

	// Session count bonus.
	sessionBonus := min64(float64(p.Sessions)*0.5, 3.0)

	p.Score = volume + diversity + recency + sessionBonus
}

func (p *peerRecord) status() string {
	if p.LastActive.IsZero() {
		return "IDLE"
	}
	if time.Since(p.LastActive) < 60*time.Second {
		return "ACTIVE"
	}
	if time.Since(p.LastSeen) < 60*time.Second {
		return "KEEPALIVE"
	}
	return "STALE"
}

func min64(a, b float64) float64 {
	if a < b {
		return a
	}
	return b
}

var msgNames = map[uint64]string{
	0x00: "Hello",
	0x01: "Disconnect",
	0x02: "Ping",
	0x03: "Pong",
	0x10: "Status",
	0x11: "NewBlockHashes",
	0x12: "Txns",
	0x13: "GetHeaders",
	0x14: "Headers",
	0x15: "GetBodies",
	0x16: "Bodies",
	0x17: "NewBlock",
	0xF0: "XDPoS/Vote",
	0xF1: "XDPoS/Timeout",
}

func msgName(code uint64) string {
	if name, ok := msgNames[code]; ok {
		return name
	}
	return fmt.Sprintf("0x%02x", code)
}

func isProtocolMsg(code uint64) bool {
	return code != 0x02 && code != 0x03
}

var (
	mu    sync.Mutex
	peers = make(map[string]*peerRecord) // key = peer addr
)

func main() {
	dbPath := flag.String("db", "peers.json", "Path to peer database file")
	exportPath := flag.String("export", "", "Export good peers as static-nodes.json and exit")
	minScore := flag.Float64("min-score", 5.0, "Minimum score for export")
	refresh := flag.Duration("refresh", 5*time.Second, "Dashboard refresh interval")
	flag.Parse()

	// Load existing peer database.
	loadDB(*dbPath)

	// Export mode: just write the good peers and exit.
	if *exportPath != "" {
		exportGoodPeers(*exportPath, *minScore)
		return
	}

	// Live mode: read stdin, update dashboard, persist periodically.
	go readInput()

	saveTicker := time.NewTicker(30 * time.Second)
	defer saveTicker.Stop()

	displayTicker := time.NewTicker(*refresh)
	defer displayTicker.Stop()

	for {
		select {
		case <-displayTicker.C:
			printDashboard()
		case <-saveTicker.C:
			saveDB(*dbPath)
		}
	}
}

func readInput() {
	scanner := bufio.NewScanner(os.Stdin)
	scanner.Buffer(make([]byte, 0, 1024*1024), 1024*1024)

	for scanner.Scan() {
		line := scanner.Text()
		idx := strings.Index(line, "{")
		if idx == -1 {
			continue
		}
		var ev logEvent
		if err := json.Unmarshal([]byte(line[idx:]), &ev); err != nil {
			continue
		}
		if ev.Peer == "" {
			continue
		}

		ts, _ := time.Parse(time.RFC3339Nano, ev.Timestamp)

		mu.Lock()
		p, ok := peers[ev.Peer]
		if !ok {
			p = &peerRecord{
				Addr:      ev.Peer,
				MsgCounts: make(map[string]int),
				FirstSeen: ts,
			}
			peers[ev.Peer] = p
		}

		switch ev.Event {
		case "connect", "probe_connect":
			p.PeerID = ev.PeerID
			p.ClientName = ev.ClientName
			p.Enode = fmt.Sprintf("enode://%s@%s", ev.PeerID, ev.Peer)
			p.Sessions++
			p.LastSeen = ts
		case "disconnect", "probe_disconnect":
			p.LastSeen = ts
		case "msg", "probe_msg", "":
			name := msgName(ev.MsgCode)
			p.MsgCounts[name]++
			p.TotalMsgs++
			p.TotalBytes += ev.Size
			p.LastSeen = ts
			if ev.Direction == "peer→node" {
				p.InMsgs++
			} else {
				p.OutMsgs++
			}
			if isProtocolMsg(ev.MsgCode) {
				p.LastActive = ts
			}
		}
		p.computeScore()
		mu.Unlock()
	}
}

func loadDB(path string) {
	data, err := os.ReadFile(path)
	if err != nil {
		return // no existing DB, that's fine
	}
	var records []*peerRecord
	if err := json.Unmarshal(data, &records); err != nil {
		fmt.Fprintf(os.Stderr, "warning: could not parse %s: %v\n", path, err)
		return
	}
	mu.Lock()
	for _, r := range records {
		if r.Addr != "" {
			r.computeScore()
			peers[r.Addr] = r
		}
	}
	mu.Unlock()
	fmt.Fprintf(os.Stderr, "loaded %d peers from %s\n", len(records), path)
}

func saveDB(path string) {
	mu.Lock()
	records := make([]*peerRecord, 0, len(peers))
	for _, p := range peers {
		records = append(records, p)
	}
	mu.Unlock()

	sort.Slice(records, func(i, j int) bool { return records[i].Score > records[j].Score })

	data, err := json.MarshalIndent(records, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "save error: %v\n", err)
		return
	}
	if err := os.WriteFile(path, data, 0644); err != nil {
		fmt.Fprintf(os.Stderr, "save error: %v\n", err)
	}
}

func exportGoodPeers(path string, minScore float64) {
	mu.Lock()
	defer mu.Unlock()

	var enodes []string
	var exported int
	records := make([]*peerRecord, 0, len(peers))
	for _, p := range peers {
		records = append(records, p)
	}
	sort.Slice(records, func(i, j int) bool { return records[i].Score > records[j].Score })

	for _, p := range records {
		if p.Score >= minScore && p.Enode != "" {
			enodes = append(enodes, p.Enode)
			exported++
		}
	}

	data, err := json.MarshalIndent(enodes, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "export error: %v\n", err)
		os.Exit(1)
	}
	if err := os.WriteFile(path, data, 0644); err != nil {
		fmt.Fprintf(os.Stderr, "export error: %v\n", err)
		os.Exit(1)
	}
	fmt.Fprintf(os.Stderr, "exported %d good peers (score >= %.1f) to %s\n", exported, minScore, path)

	// Also print summary to stdout.
	fmt.Printf("%-50s %8s %8s %s\n", "ENODE", "SCORE", "MSGS", "CLIENT")
	fmt.Println(strings.Repeat("─", 100))
	for _, p := range records {
		if p.Score >= minScore && p.Enode != "" {
			short := p.Enode
			if len(short) > 50 {
				short = short[:47] + "..."
			}
			fmt.Printf("%-50s %8.1f %8d %s\n", short, p.Score, p.TotalMsgs, p.ClientName)
		}
	}
}

func printDashboard() {
	mu.Lock()
	defer mu.Unlock()

	fmt.Print("\033[2J\033[H")
	fmt.Printf("=== RLPx Peer Monitor === %s\n\n", time.Now().Format("15:04:05"))

	if len(peers) == 0 {
		fmt.Println("No peers yet. Pipe proxy logs: docker compose logs -f rlpx-proxy | ./build/rlpx-monitor")
		return
	}

	sorted := make([]*peerRecord, 0, len(peers))
	for _, p := range peers {
		sorted = append(sorted, p)
	}
	sort.Slice(sorted, func(i, j int) bool {
		si, sj := sorted[i].status(), sorted[j].status()
		if si != sj {
			order := map[string]int{"ACTIVE": 0, "KEEPALIVE": 1, "STALE": 2, "IDLE": 3}
			return order[si] < order[sj]
		}
		return sorted[i].Score > sorted[j].Score
	})

	var totalMsgs, totalBytes, activePeers, knownPeers int
	for _, p := range sorted {
		totalMsgs += p.TotalMsgs
		totalBytes += p.TotalBytes
		if p.status() == "ACTIVE" {
			activePeers++
		}
		if p.Enode != "" {
			knownPeers++
		}
	}
	fmt.Printf("Peers: %d total, %d known enodes, %d active  |  Messages: %d  |  Data: %s\n\n",
		len(sorted), knownPeers, activePeers, totalMsgs, humanBytes(totalBytes))

	// Per-peer table.
	fmt.Printf("%-28s %6s %9s %7s %7s %7s %-10s  %s\n",
		"PEER", "SCORE", "STATUS", "IN", "OUT", "TOTAL", "DATA", "TOP MESSAGES")
	fmt.Println(strings.Repeat("─", 130))

	for _, p := range sorted {
		breakdown := topMessages(p.MsgCounts, 4)
		fmt.Printf("%-28s %6.1f %9s %7d %7d %7d %-10s  %s\n",
			p.Addr,
			p.Score,
			colorStatus(p.status()),
			p.InMsgs,
			p.OutMsgs,
			p.TotalMsgs,
			humanBytes(p.TotalBytes),
			breakdown,
		)
		if p.ClientName != "" {
			fmt.Printf("  %-26s %s  (sessions: %d)\n", "", p.ClientName, p.Sessions)
		}
	}

	// Global message summary.
	fmt.Printf("\n%s\n", strings.Repeat("─", 130))
	fmt.Println("Global message breakdown:")
	globalCounts := make(map[string]int)
	for _, p := range sorted {
		for name, count := range p.MsgCounts {
			globalCounts[name] += count
		}
	}
	names := make([]string, 0, len(globalCounts))
	for name := range globalCounts {
		names = append(names, name)
	}
	sort.Slice(names, func(i, j int) bool { return globalCounts[names[i]] > globalCounts[names[j]] })
	maxCount := 1
	if len(names) > 0 {
		maxCount = globalCounts[names[0]]
	}
	for _, name := range names {
		count := globalCounts[name]
		barLen := count * 40 / maxCount
		if barLen < 1 && count > 0 {
			barLen = 1
		}
		bar := strings.Repeat("█", barLen)
		fmt.Printf("  %-16s %6d  %s\n", name, count, bar)
	}
}

func topMessages(counts map[string]int, n int) string {
	type kv struct {
		name  string
		count int
	}
	var items []kv
	for name, count := range counts {
		items = append(items, kv{name, count})
	}
	sort.Slice(items, func(i, j int) bool { return items[i].count > items[j].count })

	var parts []string
	for i, item := range items {
		if i >= n {
			parts = append(parts, "...")
			break
		}
		parts = append(parts, fmt.Sprintf("%s:%d", item.name, item.count))
	}
	return strings.Join(parts, " ")
}

func colorStatus(status string) string {
	switch status {
	case "ACTIVE":
		return "\033[32m" + status + "\033[0m"
	case "KEEPALIVE":
		return "\033[33m" + status + "\033[0m"
	case "IDLE":
		return "\033[90m" + status + "\033[0m"
	case "STALE":
		return "\033[31m" + status + "\033[0m"
	}
	return status
}

func humanBytes(b int) string {
	switch {
	case b >= 1<<30:
		return fmt.Sprintf("%.1f GB", float64(b)/(1<<30))
	case b >= 1<<20:
		return fmt.Sprintf("%.1f MB", float64(b)/(1<<20))
	case b >= 1<<10:
		return fmt.Sprintf("%.1f KB", float64(b)/(1<<10))
	default:
		return fmt.Sprintf("%d B", b)
	}
}
