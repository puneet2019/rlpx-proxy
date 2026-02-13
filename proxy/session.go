package proxy

import (
	"context"
	"crypto/ecdsa"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/p2p/rlpx"
)

const (
	handshakeTimeout = 10 * time.Second
	readTimeout      = 30 * time.Second
	writeTimeout     = 20 * time.Second
)

// session handles a single proxied peer connection.
type session struct {
	extConn        net.Conn           // raw TCP from external peer
	upstreamAddr   string             // address of the real XDC node
	nodeKey        *ecdsa.PrivateKey  // node's real key (external side)
	proxyKey       *ecdsa.PrivateKey  // proxy's random key (internal side)
	upstreamPubKey *ecdsa.PublicKey   // expected upstream node pubkey (nil = use nodeKey.PublicKey)
}

// logEvent is a JSON log line written to stdout.
// For message events: Event="msg", MsgCode/Size/DataHex are set.
// For session events: Event="connect"/"disconnect", PeerID/ClientName are set.
type logEvent struct {
	Timestamp  string `json:"ts"`
	Event      string `json:"event"`
	Peer       string `json:"peer"`
	PeerID     string `json:"peer_id,omitempty"`
	ClientName string `json:"client,omitempty"`
	Direction  string `json:"direction,omitempty"`
	MsgCode    uint64 `json:"msg_code,omitempty"`
	Size       int    `json:"size,omitempty"`
	DataHex    string `json:"data_hex,omitempty"`
}

var (
	jsonEncoder  = json.NewEncoder(os.Stdout)
	encoderMutex sync.Mutex
)

func emitJSON(e *logEvent) {
	encoderMutex.Lock()
	defer encoderMutex.Unlock()
	if err := jsonEncoder.Encode(e); err != nil {
		log.Printf("log encode error: %v", err)
	}
}

func logMessage(direction, peer string, code uint64, data []byte, size int) {
	emitJSON(&logEvent{
		Timestamp: time.Now().UTC().Format(time.RFC3339Nano),
		Event:     "msg",
		Peer:      peer,
		Direction: direction,
		MsgCode:   code,
		Size:      size,
		DataHex:   hex.EncodeToString(data),
	})
}

func logConnect(peer, peerID, clientName string) {
	emitJSON(&logEvent{
		Timestamp:  time.Now().UTC().Format(time.RFC3339Nano),
		Event:      "connect",
		Peer:       peer,
		PeerID:     peerID,
		ClientName: clientName,
	})
}

func logDisconnect(peer, peerID string) {
	emitJSON(&logEvent{
		Timestamp: time.Now().UTC().Format(time.RFC3339Nano),
		Event:     "disconnect",
		Peer:      peer,
		PeerID:    peerID,
	})
}

func pubkeyHex(pub *ecdsa.PublicKey) string {
	return fmt.Sprintf("%x", crypto.FromECDSAPub(pub)[1:])
}

func (s *session) run(ctx context.Context) {
	peerAddr := s.extConn.RemoteAddr().String()
	log.Printf("new connection from %s", peerAddr)
	defer s.extConn.Close()

	// Phase 1: External RLPx handshake (responder mode).
	extRLPx := rlpx.NewConn(s.extConn, nil)
	s.extConn.SetDeadline(time.Now().Add(handshakeTimeout))
	remotePub, err := extRLPx.Handshake(s.nodeKey)
	if err != nil {
		log.Printf("[%s] external handshake failed: %v", peerAddr, err)
		return
	}
	s.extConn.SetDeadline(time.Time{}) // clear deadline
	remoteID := pubkeyHex(remotePub)
	log.Printf("[%s] external handshake OK, remote=%s…", peerAddr, remoteID[:16])

	// Phase 2: Connect to upstream XDC node and handshake (initiator mode).
	upTCP, err := net.DialTimeout("tcp", s.upstreamAddr, handshakeTimeout)
	if err != nil {
		log.Printf("[%s] upstream dial failed: %v", peerAddr, err)
		return
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
		log.Printf("[%s] upstream handshake failed: %v", peerAddr, err)
		return
	}
	upTCP.SetDeadline(time.Time{})
	nodeID := pubkeyHex(nodePub)
	log.Printf("[%s] upstream handshake OK, node=%s…", peerAddr, nodeID[:16])

	// Phase 3: Hello exchange.
	extHello := &Hello{
		Version:    5,
		Name:       "rlpx-proxy",
		Caps:       defaultXDCCaps(),
		ListenPort: 0,
		ID:         crypto.FromECDSAPub(&s.nodeKey.PublicKey)[1:],
	}
	extHelloBytes, err := encodeHello(extHello)
	if err != nil {
		log.Printf("[%s] encode extHello: %v", peerAddr, err)
		return
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
		log.Printf("[%s] encode upHello: %v", peerAddr, err)
		return
	}

	type helloResult struct {
		hello *Hello
		err   error
	}
	extHelloCh := make(chan helloResult, 1)
	upHelloCh := make(chan helloResult, 1)

	go func() {
		if _, err := extRLPx.Write(HandshakeMsg, extHelloBytes); err != nil {
			extHelloCh <- helloResult{err: fmt.Errorf("write: %w", err)}
			return
		}
		code, data, _, err := extRLPx.Read()
		if err != nil {
			extHelloCh <- helloResult{err: fmt.Errorf("read: %w", err)}
			return
		}
		if code != HandshakeMsg {
			extHelloCh <- helloResult{err: fmt.Errorf("expected hello (0x00), got 0x%02x", code)}
			return
		}
		h, err := decodeHello(data)
		if err != nil {
			extHelloCh <- helloResult{err: fmt.Errorf("decode: %w", err)}
			return
		}
		extHelloCh <- helloResult{hello: h}
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

	peerHelloRes := <-extHelloCh
	if peerHelloRes.err != nil {
		log.Printf("[%s] external hello: %v", peerAddr, peerHelloRes.err)
		return
	}
	nodeHelloRes := <-upHelloCh
	if nodeHelloRes.err != nil {
		log.Printf("[%s] upstream hello: %v", peerAddr, nodeHelloRes.err)
		return
	}

	peerHello := peerHelloRes.hello
	nodeHello := nodeHelloRes.hello
	log.Printf("[%s] hello exchange done: peer=%q caps=%v, node=%q caps=%v",
		peerAddr, peerHello.Name, peerHello.Caps, nodeHello.Name, nodeHello.Caps)

	// Emit connect event.
	logConnect(peerAddr, remoteID, peerHello.Name)
	defer logDisconnect(peerAddr, remoteID)

	// Enable snappy compression after Hello exchange.
	extRLPx.SetSnappy(peerHello.Version >= 5)
	upRLPx.SetSnappy(nodeHello.Version >= 5)

	// Phase 4: Bidirectional relay.
	done := make(chan struct{}, 2)

	go func() {
		defer func() { done <- struct{}{} }()
		s.relay(ctx, extRLPx, upRLPx, "peer→node", peerAddr)
	}()

	go func() {
		defer func() { done <- struct{}{} }()
		s.relay(ctx, upRLPx, extRLPx, "node→peer", peerAddr)
	}()

	<-done
	extRLPx.Close()
	upRLPx.Close()
	<-done

	log.Printf("[%s] session ended", peerAddr)
}

func (s *session) relay(ctx context.Context, src, dst *rlpx.Conn, direction, peer string) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		src.SetReadDeadline(time.Now().Add(readTimeout))
		code, data, wireSize, err := src.Read()
		if err != nil {
			log.Printf("[%s] %s read error: %v", peer, direction, err)
			return
		}

		logMessage(direction, peer, code, data, wireSize)

		dst.SetWriteDeadline(time.Now().Add(writeTimeout))
		if _, err := dst.Write(code, data); err != nil {
			log.Printf("[%s] %s write error: %v", peer, direction, err)
			return
		}
	}
}
