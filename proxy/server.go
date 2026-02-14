package proxy

import (
	"context"
	"crypto/ecdsa"
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/p2p/enode"
)

// Config holds the proxy server configuration.
type Config struct {
	ListenAddr   string            // e.g. ":30303"
	UpstreamAddr string            // e.g. "xdc-node:30303" (optional for monitor mode)
	NodeKey      *ecdsa.PrivateKey // real node's private key (external side)
	ProxyKey     *ecdsa.PrivateKey // random key (internal/upstream side)
	Peers        []*Peer           // outbound peers to actively connect to
	MaxOutbound  int               // max concurrent outbound/monitor connections (default 100)

	// Discovery
	DiscoveryAddr   string        // UDP listen address for discv4 (e.g. ":30301")
	DiscoveryV5Addr string        // UDP listen address for discv5 (e.g. ":30302")
	Bootnodes       []*enode.Node // bootstrap nodes

	// Monitor mode (replaces probe tier)
	Propagate bool   // forward NewBlock/NewBlockHashes/Txns between peers
	APIAddr   string // HTTP API listen address (e.g. ":8080")

	// Legacy (only used if UpstreamAddr is set)
	UpstreamRPC string // HTTP RPC URL of upstream node
}

// Server is the RLPx peer health monitor and optional MitM proxy.
type Server struct {
	cfg         Config
	listener    net.Listener
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

// ListenAndServe starts the monitor, optional proxy listener, and API.
func (s *Server) ListenAndServe(ctx context.Context) error {
	// Start HTTP API.
	apiAddr := s.cfg.APIAddr
	if apiAddr == "" {
		apiAddr = ":8080"
	}
	log.Printf("[api] starting HTTP API on %s", apiAddr)
	StartAPI(apiAddr, s)

	// Start outbound relay connections if peers and upstream are configured.
	if len(s.cfg.Peers) > 0 && s.cfg.UpstreamAddr != "" {
		log.Printf("starting outbound relay connections to %d peers", len(s.cfg.Peers))
		s.connectOutbound(ctx, s.cfg.Peers)
	}

	// Start discovery + monitor pool.
	bootnodes := s.cfg.Bootnodes
	if len(bootnodes) == 0 && s.cfg.UpstreamAddr != "" {
		upNode, err := UpstreamBootnode(s.cfg.NodeKey, s.cfg.UpstreamAddr)
		if err != nil {
			log.Printf("[discovery] auto-bootstrap failed: %v (set BOOTNODES_FILE to override)", err)
		} else {
			bootnodes = []*enode.Node{upNode}
			log.Printf("[discovery] auto-bootstrapping from upstream node: %s", upNode.URLv4())
		}
	}
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

	// Only start TCP listener if upstream is configured (proxy mode).
	if s.cfg.UpstreamAddr != "" {
		var err error
		s.listener, err = net.Listen("tcp", s.cfg.ListenAddr)
		if err != nil {
			return err
		}
		log.Printf("listening on %s, upstream %s", s.cfg.ListenAddr, s.cfg.UpstreamAddr)

		go func() {
			<-ctx.Done()
			s.listener.Close()
		}()

		for {
			conn, err := s.listener.Accept()
			if err != nil {
				select {
				case <-ctx.Done():
					s.wg.Wait()
					return nil
				default:
					log.Printf("accept error: %v", err)
					continue
				}
			}
			s.wg.Add(1)
			go func() {
				defer s.wg.Done()
				sess := &session{
					extConn:      conn,
					upstreamAddr: s.cfg.UpstreamAddr,
					nodeKey:      s.cfg.NodeKey,
					proxyKey:     s.cfg.ProxyKey,
				}
				sess.run(ctx)
			}()
		}
	}

	// Monitor-only mode: block until context is done.
	log.Printf("running in standalone monitor mode (no upstream)")
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
