package proxy

import (
	"context"
	"crypto/ecdsa"
	"log"
	"net"
	"sync"
)

// Config holds the proxy server configuration.
type Config struct {
	ListenAddr   string             // e.g. ":30303"
	UpstreamAddr string             // e.g. "xdc-node:30303"
	NodeKey      *ecdsa.PrivateKey  // real node's private key (external side)
	ProxyKey     *ecdsa.PrivateKey  // random key (internal/upstream side)
	Peers        []*Peer            // outbound peers to actively connect to
	MaxOutbound  int                // max concurrent outbound connections (default 10)
}

// Server is the RLPx MitM proxy TCP server.
type Server struct {
	cfg      Config
	listener net.Listener
	wg       sync.WaitGroup
}

// ListenAndServe starts accepting TCP connections and proxying them.
// It also starts outbound connections to configured peers.
// It blocks until ctx is cancelled, then drains active sessions.
func (s *Server) ListenAndServe(ctx context.Context) error {
	var err error
	s.listener, err = net.Listen("tcp", s.cfg.ListenAddr)
	if err != nil {
		return err
	}
	log.Printf("listening on %s, upstream %s", s.cfg.ListenAddr, s.cfg.UpstreamAddr)

	// Start outbound connections if peers are configured.
	if len(s.cfg.Peers) > 0 {
		log.Printf("starting outbound connections to %d peers", len(s.cfg.Peers))
		s.connectOutbound(ctx, s.cfg.Peers)
	}

	// Close listener when context is cancelled.
	go func() {
		<-ctx.Done()
		s.listener.Close()
	}()

	for {
		conn, err := s.listener.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				// Expected shutdown.
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

// NewServer creates a new proxy server with the given config.
func NewServer(cfg Config) *Server {
	return &Server{cfg: cfg}
}
