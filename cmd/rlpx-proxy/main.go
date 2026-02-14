package main

import (
	"context"
	"encoding/json"
	"log"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/p2p/enode"
	"github.com/puneetmahajan/rlpx-proxy/proxy"
)

func main() {
	log.SetFlags(log.Ldate | log.Ltime | log.Lmicroseconds | log.LUTC)

	// Load the real node's private key from env.
	nodeKeyHex := os.Getenv("NODE_PRIVATE_KEY")
	if nodeKeyHex == "" {
		log.Fatal("NODE_PRIVATE_KEY env var is required")
	}
	nodeKey, err := crypto.HexToECDSA(nodeKeyHex)
	if err != nil {
		log.Fatalf("invalid NODE_PRIVATE_KEY: %v", err)
	}
	log.Printf("node pubkey: %x", crypto.FromECDSAPub(&nodeKey.PublicKey)[1:])

	// Generate a random proxy key for the upstream side.
	proxyKey, err := crypto.GenerateKey()
	if err != nil {
		log.Fatalf("generate proxy key: %v", err)
	}

	// Upstream is now optional (standalone monitor mode).
	upstreamHost := os.Getenv("UPSTREAM_HOST")
	upstreamPort := envOrDefault("UPSTREAM_PORT", "30303")
	listenPort := envOrDefault("LISTEN_PORT", "30303")

	var upstreamAddr string
	if upstreamHost != "" {
		upstreamAddr = upstreamHost + ":" + upstreamPort
	}

	// Load outbound peers from PEERS_FILE (JSON array of enode URLs).
	var peers []*proxy.Peer
	if peersFile := os.Getenv("PEERS_FILE"); peersFile != "" {
		peers, err = loadPeersFile(peersFile)
		if err != nil {
			log.Fatalf("load peers file: %v", err)
		}
		log.Printf("loaded %d outbound peers from %s", len(peers), peersFile)
	}

	maxOutbound := 100
	if v := os.Getenv("MAX_OUTBOUND"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			maxOutbound = n
		}
	}

	// Optional: explicit bootnodes for discovery.
	var bootnodes = proxy.ParseBootnodes(splitNonEmpty(os.Getenv("BOOTNODES"), ","))
	if bnFile := os.Getenv("BOOTNODES_FILE"); bnFile != "" {
		fileNodes, err := loadBootnodesFile(bnFile)
		if err != nil {
			log.Fatalf("load bootnodes file: %v", err)
		}
		bootnodes = append(bootnodes, fileNodes...)
	}
	if len(bootnodes) > 0 {
		log.Printf("loaded %d bootnodes", len(bootnodes))
	}

	discoveryAddr := envOrDefault("DISCOVERY_ADDR", ":30301")

	// Monitor mode config.
	propagate := true
	if v := os.Getenv("PROPAGATE"); v != "" {
		propagate = v == "true" || v == "1" || v == "yes"
	}

	apiAddr := envOrDefault("API_ADDR", ":8080")

	upstreamRPC := os.Getenv("UPSTREAM_RPC")
	if upstreamRPC == "" && upstreamHost != "" {
		upstreamRPC = "http://" + upstreamHost + ":8545"
	}

	cfg := proxy.Config{
		ListenAddr:    ":" + listenPort,
		UpstreamAddr:  upstreamAddr,
		NodeKey:       nodeKey,
		ProxyKey:      proxyKey,
		Peers:         peers,
		MaxOutbound:   maxOutbound,
		DiscoveryAddr: discoveryAddr,
		Bootnodes:     bootnodes,
		Propagate:     propagate,
		APIAddr:       apiAddr,
		UpstreamRPC:   upstreamRPC,
	}

	srv := proxy.NewServer(cfg)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Graceful shutdown on SIGINT/SIGTERM.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		sig := <-sigCh
		log.Printf("received %v, shutting down…", sig)
		cancel()
	}()

	if err := srv.ListenAndServe(ctx); err != nil {
		log.Fatalf("server: %v", err)
	}
}

func loadPeersFile(path string) ([]*proxy.Peer, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var enodes []string
	if err := json.Unmarshal(data, &enodes); err != nil {
		return nil, err
	}
	var peers []*proxy.Peer
	for _, e := range enodes {
		p, err := proxy.ParseEnode(e)
		if err != nil {
			log.Printf("skipping invalid enode: %v", err)
			continue
		}
		peers = append(peers, p)
	}
	return peers, nil
}

func envOrDefault(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func loadBootnodesFile(path string) ([]*enode.Node, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var enodes []string
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line != "" && !strings.HasPrefix(line, "#") {
			enodes = append(enodes, line)
		}
	}
	nodes := proxy.ParseBootnodes(enodes)
	log.Printf("loaded %d bootnodes from %s", len(nodes), path)
	return nodes, nil
}

func splitNonEmpty(s, sep string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, sep)
	out := parts[:0]
	for _, p := range parts {
		if t := strings.TrimSpace(p); t != "" {
			out = append(out, t)
		}
	}
	return out
}
