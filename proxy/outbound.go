package proxy

import (
	"context"
	"crypto/ecdsa"
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/p2p/rlpx"
	"github.com/ethereum/go-ethereum/rlp"
)

// Peer represents a parsed enode URL.
type Peer struct {
	Pubkey *ecdsa.PublicKey
	Addr   string // ip:port
}

// ParseEnode parses an enode URL into a Peer.
// Format: enode://<hex-pubkey>@<ip>:<port>
func ParseEnode(url string) (*Peer, error) {
	url = strings.TrimSpace(url)
	if !strings.HasPrefix(url, "enode://") {
		return nil, fmt.Errorf("invalid enode URL: %s", url)
	}
	url = strings.TrimPrefix(url, "enode://")
	parts := strings.SplitN(url, "@", 2)
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid enode URL: missing @")
	}
	pubBytes, err := hex.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("invalid pubkey hex: %w", err)
	}
	if len(pubBytes) != 64 {
		return nil, fmt.Errorf("invalid pubkey length: %d (expected 64)", len(pubBytes))
	}
	fullPub := append([]byte{0x04}, pubBytes...)
	pub, err := crypto.UnmarshalPubkey(fullPub)
	if err != nil {
		return nil, fmt.Errorf("invalid pubkey: %w", err)
	}
	return &Peer{Pubkey: pub, Addr: parts[1]}, nil
}

const (
	outboundRetryDelay    = 30 * time.Second
	outboundMaxRetryDelay = 5 * time.Minute
)

var disconnectReasons = map[uint]string{
	0x00: "requested",
	0x01: "TCP error",
	0x02: "protocol breach",
	0x03: "useless peer",
	0x04: "too many peers",
	0x05: "already connected",
	0x06: "incompatible p2p version",
	0x07: "invalid node identity",
	0x08: "client quitting",
	0x09: "unexpected identity",
	0x0a: "connected to self",
	0x0b: "read timeout",
	0x10: "subprotocol error",
}

func decodeDisconnectReason(data []byte) string {
	var reasons []uint
	if err := rlp.DecodeBytes(data, &reasons); err == nil && len(reasons) > 0 {
		if name, ok := disconnectReasons[reasons[0]]; ok {
			return name
		}
		return fmt.Sprintf("unknown(%d)", reasons[0])
	}
	if len(data) == 1 {
		if name, ok := disconnectReasons[uint(data[0])]; ok {
			return name
		}
	}
	return fmt.Sprintf("raw:%x", data)
}

// connectOutbound manages outbound connections to a list of peers with a
// concurrency limit controlled by maxOutbound.
func (s *Server) connectOutbound(ctx context.Context, peers []*Peer) {
	maxOutbound := s.cfg.MaxOutbound
	if maxOutbound <= 0 {
		maxOutbound = 10
	}
	sem := make(chan struct{}, maxOutbound)

	for _, p := range peers {
		s.wg.Add(1)
		go func(target *Peer) {
			defer s.wg.Done()
			// Acquire semaphore slot before dialing.
			select {
			case sem <- struct{}{}:
			case <-ctx.Done():
				return
			}
			s.outboundLoop(ctx, target, sem)
		}(p)
	}
}

func (s *Server) outboundLoop(ctx context.Context, target *Peer, sem chan struct{}) {
	targetID := fmt.Sprintf("%x", crypto.FromECDSAPub(target.Pubkey)[1:])
	delay := outboundRetryDelay

	for {
		select {
		case <-ctx.Done():
			<-sem
			return
		default:
		}

		sess := &session{
			upstreamAddr: s.cfg.UpstreamAddr,
			nodeKey:      s.cfg.NodeKey,
			proxyKey:     s.cfg.ProxyKey,
		}
		relayed := sess.runOutbound(ctx, target)

		select {
		case <-ctx.Done():
			<-sem
			return
		default:
		}

		if relayed {
			// Connection was successful and relayed traffic. Reset delay.
			delay = outboundRetryDelay
		}

		log.Printf("[outbound→%s] reconnecting in %v", targetID[:16], delay)

		// Release semaphore while waiting for retry.
		<-sem

		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}

		// Back off, capped at max.
		delay = delay * 3 / 2
		if delay > outboundMaxRetryDelay {
			delay = outboundMaxRetryDelay
		}

		// Re-acquire semaphore for next attempt.
		select {
		case sem <- struct{}{}:
		case <-ctx.Done():
			return
		}
	}
}

// runOutbound connects to a target peer and the upstream node, then relays.
// Returns true if traffic was successfully relayed (reached Phase 4).
func (s *session) runOutbound(ctx context.Context, target *Peer) bool {
	targetID := fmt.Sprintf("%x", crypto.FromECDSAPub(target.Pubkey)[1:])
	log.Printf("[outbound→%s] connecting to %s", targetID[:16], target.Addr)

	// Phase 1: Connect to target peer and handshake (initiator mode).
	peerTCP, err := net.DialTimeout("tcp", target.Addr, handshakeTimeout)
	if err != nil {
		log.Printf("[outbound→%s] dial failed: %v", targetID[:16], err)
		return false
	}
	defer peerTCP.Close()

	peerRLPx := rlpx.NewConn(peerTCP, target.Pubkey)
	peerTCP.SetDeadline(time.Now().Add(handshakeTimeout))
	remotePub, err := peerRLPx.Handshake(s.nodeKey)
	if err != nil {
		log.Printf("[outbound→%s] peer handshake failed: %v", targetID[:16], err)
		return false
	}
	peerTCP.SetDeadline(time.Time{})
	remoteID := fmt.Sprintf("%x", crypto.FromECDSAPub(remotePub)[1:])
	log.Printf("[outbound→%s] peer handshake OK, remote=%s…", targetID[:16], remoteID[:16])

	// Phase 2: Connect to upstream XDC node and handshake (initiator mode).
	upTCP, err := net.DialTimeout("tcp", s.upstreamAddr, handshakeTimeout)
	if err != nil {
		log.Printf("[outbound→%s] upstream dial failed: %v", targetID[:16], err)
		return false
	}
	defer upTCP.Close()

	upPub := s.upstreamPubKey
	if upPub == nil {
		upPub = &s.nodeKey.PublicKey
	}
	upRLPx := rlpx.NewConn(upTCP, upPub)
	upTCP.SetDeadline(time.Now().Add(handshakeTimeout))
	nodePub, err := upRLPx.Handshake(s.proxyKey)
	if err != nil {
		log.Printf("[outbound→%s] upstream handshake failed: %v", targetID[:16], err)
		return false
	}
	upTCP.SetDeadline(time.Time{})
	nodeID := fmt.Sprintf("%x", crypto.FromECDSAPub(nodePub)[1:])
	log.Printf("[outbound→%s] upstream handshake OK, node=%s…", targetID[:16], nodeID[:16])

	// Phase 3: Hello exchange.
	peerHello := &Hello{
		Version:    5,
		Name:       "rlpx-proxy",
		Caps:       defaultXDCCaps(),
		ListenPort: 0,
		ID:         crypto.FromECDSAPub(&s.nodeKey.PublicKey)[1:],
	}
	peerHelloBytes, err := encodeHello(peerHello)
	if err != nil {
		log.Printf("[outbound→%s] encode peerHello: %v", targetID[:16], err)
		return false
	}

	upHello := &Hello{
		Version:    5,
		Name:       "rlpx-proxy",
		Caps:       defaultXDCCaps(),
		ListenPort: 0,
		ID:         crypto.FromECDSAPub(&s.proxyKey.PublicKey)[1:],
	}
	upHelloBytes, err := encodeHello(upHello)
	if err != nil {
		log.Printf("[outbound→%s] encode upHello: %v", targetID[:16], err)
		return false
	}

	type helloResult struct {
		hello *Hello
		err   error
	}
	peerHelloCh := make(chan helloResult, 1)
	upHelloCh := make(chan helloResult, 1)

	go func() {
		if _, err := peerRLPx.Write(HandshakeMsg, peerHelloBytes); err != nil {
			peerHelloCh <- helloResult{err: fmt.Errorf("write: %w", err)}
			return
		}
		code, data, _, err := peerRLPx.Read()
		if err != nil {
			peerHelloCh <- helloResult{err: fmt.Errorf("read: %w", err)}
			return
		}
		if code == DiscMsg {
			reason := decodeDisconnectReason(data)
			peerHelloCh <- helloResult{err: fmt.Errorf("peer disconnected: %s", reason)}
			return
		}
		if code != HandshakeMsg {
			peerHelloCh <- helloResult{err: fmt.Errorf("expected hello (0x00), got 0x%02x", code)}
			return
		}
		h, err := decodeHello(data)
		if err != nil {
			peerHelloCh <- helloResult{err: fmt.Errorf("decode: %w", err)}
			return
		}
		peerHelloCh <- helloResult{hello: h}
	}()

	go func() {
		if _, err := upRLPx.Write(HandshakeMsg, upHelloBytes); err != nil {
			upHelloCh <- helloResult{err: fmt.Errorf("write: %w", err)}
			return
		}
		code, data, _, err := upRLPx.Read()
		if err != nil {
			upHelloCh <- helloResult{err: fmt.Errorf("read: %w", err)}
			return
		}
		if code == DiscMsg {
			reason := decodeDisconnectReason(data)
			upHelloCh <- helloResult{err: fmt.Errorf("node disconnected: %s", reason)}
			return
		}
		if code != HandshakeMsg {
			upHelloCh <- helloResult{err: fmt.Errorf("expected hello (0x00), got 0x%02x", code)}
			return
		}
		h, err := decodeHello(data)
		if err != nil {
			upHelloCh <- helloResult{err: fmt.Errorf("decode: %w", err)}
			return
		}
		upHelloCh <- helloResult{hello: h}
	}()

	peerHelloRes := <-peerHelloCh
	if peerHelloRes.err != nil {
		log.Printf("[outbound→%s] peer hello: %v", targetID[:16], peerHelloRes.err)
		return false
	}
	nodeHelloRes := <-upHelloCh
	if nodeHelloRes.err != nil {
		log.Printf("[outbound→%s] upstream hello: %v", targetID[:16], nodeHelloRes.err)
		return false
	}

	peerH := peerHelloRes.hello
	nodeH := nodeHelloRes.hello
	log.Printf("[outbound→%s] hello exchange done: peer=%q caps=%v, node=%q caps=%v",
		targetID[:16], peerH.Name, peerH.Caps, nodeH.Name, nodeH.Caps)

	// Emit connect event with peer identity.
	logConnect(target.Addr, remoteID, peerH.Name)
	defer logDisconnect(target.Addr, remoteID)

	peerRLPx.SetSnappy(peerH.Version >= 5)
	upRLPx.SetSnappy(nodeH.Version >= 5)

	// Phase 4: Bidirectional relay.
	peerAddr := target.Addr
	done := make(chan struct{}, 2)

	go func() {
		defer func() { done <- struct{}{} }()
		s.relay(ctx, peerRLPx, upRLPx, "peer→node", peerAddr)
	}()

	go func() {
		defer func() { done <- struct{}{} }()
		s.relay(ctx, upRLPx, peerRLPx, "node→peer", peerAddr)
	}()

	<-done
	peerRLPx.Close()
	upRLPx.Close()
	<-done

	log.Printf("[outbound→%s] session ended", targetID[:16])
	return true
}
