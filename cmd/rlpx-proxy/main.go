package main

import (
	"context"
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

	// Load the node's private key from env.
	nodeKeyHex := os.Getenv("NODE_PRIVATE_KEY")
	if nodeKeyHex == "" {
		log.Fatal("NODE_PRIVATE_KEY env var is required")
	}
	nodeKey, err := crypto.HexToECDSA(nodeKeyHex)
	if err != nil {
		log.Fatalf("invalid NODE_PRIVATE_KEY: %v", err)
	}
	log.Printf("node pubkey: %x", crypto.FromECDSAPub(&nodeKey.PublicKey)[1:])

	// Load bootnodes for discovery.
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

	maxOutbound := 100
	if v := os.Getenv("MAX_OUTBOUND"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			maxOutbound = n
		}
	}

	discoveryAddr := envOrDefault("DISCOVERY_ADDR", ":30301")
	discoveryV5Addr := envOrDefault("DISCOVERY_V5_ADDR", ":30302")
	apiAddr := envOrDefault("API_ADDR", ":8080")

	cfg := proxy.Config{
		NodeKey:         nodeKey,
		MaxOutbound:     maxOutbound,
		DiscoveryAddr:   discoveryAddr,
		DiscoveryV5Addr: discoveryV5Addr,
		Bootnodes:       bootnodes,
		APIAddr:         apiAddr,
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
