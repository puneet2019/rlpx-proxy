package main

import (
	"context"
	"encoding/json"
	"log"
	"os"
	"os/signal"
	"strconv"
	"syscall"

	"github.com/ethereum/go-ethereum/crypto"
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
	log.Printf("proxy pubkey: %x", crypto.FromECDSAPub(&proxyKey.PublicKey)[1:])

	upstreamHost := envOrDefault("UPSTREAM_HOST", "xdc-node")
	upstreamPort := envOrDefault("UPSTREAM_PORT", "30303")
	listenPort := envOrDefault("LISTEN_PORT", "30303")

	// Load outbound peers from PEERS_FILE (JSON array of enode URLs).
	var peers []*proxy.Peer
	if peersFile := os.Getenv("PEERS_FILE"); peersFile != "" {
		peers, err = loadPeersFile(peersFile)
		if err != nil {
			log.Fatalf("load peers file: %v", err)
		}
		log.Printf("loaded %d outbound peers from %s", len(peers), peersFile)
	}

	maxOutbound := 10
	if v := os.Getenv("MAX_OUTBOUND"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			maxOutbound = n
		}
	}

	cfg := proxy.Config{
		ListenAddr:   ":" + listenPort,
		UpstreamAddr: upstreamHost + ":" + upstreamPort,
		NodeKey:      nodeKey,
		ProxyKey:     proxyKey,
		Peers:        peers,
		MaxOutbound:  maxOutbound,
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
