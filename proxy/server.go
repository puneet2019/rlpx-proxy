package proxy

import (
	"context"
	"crypto/ecdsa"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/p2p/enode"
)

// Config holds the server configuration.
type Config struct {
	NodeKey *ecdsa.PrivateKey // node's P2P identity key

	// Discovery
	DiscoveryAddr   string        // UDP listen address for discv4 (e.g. ":30301")
	DiscoveryV5Addr string        // UDP listen address for discv5 (e.g. ":30302")
	Bootnodes       []*enode.Node // bootstrap nodes

	// Monitor
	MaxOutbound int    // max concurrent outbound connections (default 100)
	APIAddr     string // HTTP API listen address (e.g. ":8080")
}

// Server is the RLPx peer health monitor and gossip bridge.
type Server struct {
	cfg         Config
	wg          sync.WaitGroup
	discovery   *Discovery
	store       *PeerStore
	cache       *BlockCache
	broadcaster *Broadcaster
}

// NewServer creates a new server with the given config.
func NewServer(cfg Config) *Server {
	return &Server{
		cfg:         cfg,
		store:       NewPeerStore(),
		cache:       NewBlockCache(),
		broadcaster: NewBroadcaster(),
	}
}

// ListenAndServe starts discovery, the monitor pool, and the HTTP API.
func (s *Server) ListenAndServe(ctx context.Context) error {
	// Start HTTP API.
	apiAddr := s.cfg.APIAddr
	if apiAddr == "" {
		apiAddr = ":8080"
	}
	log.Printf("[api] starting HTTP API on %s", apiAddr)
	StartAPI(apiAddr, s)

	// Start discovery + monitor pool.
	bootnodes := s.cfg.Bootnodes
	if len(bootnodes) > 0 {
		v4Addr := s.cfg.DiscoveryAddr
		if v4Addr == "" {
			v4Addr = ":30301"
		}
		v5Addr := s.cfg.DiscoveryV5Addr
		if v5Addr == "" {
			v5Addr = ":30302"
		}
		disc, err := NewDiscovery(s.cfg.NodeKey, v4Addr, v5Addr, bootnodes)
		if err != nil {
			return fmt.Errorf("discovery: %w", err)
		}
		s.discovery = disc
		peerCh := make(chan *enode.Node, 256)
		go disc.Run(ctx, peerCh)
		go s.runMonitorPool(ctx, peerCh)

		// Seed bootnode IPs directly (handles XDC's shared-key bootnodes).
		go s.seedBootnodes(ctx, bootnodes, peerCh)

		go func() {
			<-ctx.Done()
			disc.Close()
		}()
	}

	log.Printf("running in standalone monitor mode")
	<-ctx.Done()
	s.wg.Wait()
	return nil
}

// seedBootnodes pushes all bootnode IPs directly to the peer channel,
// bypassing discovery's dedup. This is critical for networks like XDC where
// many bootnodes share a single key — DHT dedup would collapse them to 1.
func (s *Server) seedBootnodes(ctx context.Context, nodes []*enode.Node, peerCh chan<- *enode.Node) {
	const reseedInterval = 5 * time.Minute

	for {
		log.Printf("[monitor] seeding %d bootnode IPs directly", len(nodes))
		for _, n := range nodes {
			select {
			case peerCh <- n:
			case <-ctx.Done():
				return
			}
		}

		timer := time.NewTimer(reseedInterval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
	}
}
