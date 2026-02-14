package proxy

import (
	"context"
	"crypto/ecdsa"
	"fmt"
	"log"
	"net"
	"strconv"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/p2p/enode"
	"github.com/ethereum/go-ethereum/p2p/rlpx"
	"github.com/ethereum/go-ethereum/rlp"
)

// monitorSession manages a persistent connection to a single peer.
// It performs RLPx + Hello + Status exchange, then enters a keep-alive
// message loop that responds to protocol messages and broadcasts data.
type monitorSession struct {
	nodeKey     *ecdsa.PrivateKey
	store       *PeerStore
	cache       *BlockCache
	broadcaster *Broadcaster
	propagate   bool
}

// runMonitorPool consumes discovered nodes and maintains persistent
// connections, replacing the old probe pool.
func (s *Server) runMonitorPool(ctx context.Context, peerCh <-chan *enode.Node) {
	maxOutbound := s.cfg.MaxOutbound
	if maxOutbound <= 0 {
		maxOutbound = 100
	}
	sem := make(chan struct{}, maxOutbound)

	// Track which addresses we've already launched a session for.
	seen := make(map[string]bool)

	for {
		select {
		case <-ctx.Done():
			return
		case node := <-peerCh:
			ip := node.IP().String()
			port := node.TCP()
			addr := net.JoinHostPort(ip, strconv.Itoa(port))

			if seen[addr] {
				continue
			}
			seen[addr] = true

			// Extract public key.
			var key enode.Secp256k1
			if err := node.Load(&key); err != nil {
				log.Printf("[monitor] cannot load pubkey for %s: %v", addr, err)
				continue
			}
			pubkey := (*ecdsa.PublicKey)(&key)

			select {
			case sem <- struct{}{}:
			case <-ctx.Done():
				return
			}

			s.wg.Add(1)
			go func(pubkey *ecdsa.PublicKey, addr string, enodePort int) {
				defer s.wg.Done()
				ms := &monitorSession{
					nodeKey:     s.cfg.NodeKey,
					store:       s.store,
					cache:       s.cache,
					broadcaster: s.broadcaster,
					propagate:   s.cfg.Propagate,
				}
				ms.connectLoop(ctx, pubkey, addr, enodePort, sem)
			}(pubkey, addr, port)
		}
	}
}

// connectLoop reconnects to a peer with exponential backoff.
func (ms *monitorSession) connectLoop(ctx context.Context, pubkey *ecdsa.PublicKey, addr string, enodePort int, sem chan struct{}) {
	delay := outboundRetryDelay
	ip, _, _ := net.SplitHostPort(addr)

	// Build port fallback list.
	ports := []int{enodePort}
	for _, fb := range []int{30303, 30304} {
		if fb != enodePort {
			ports = append(ports, fb)
		}
	}

	for {
		select {
		case <-ctx.Done():
			<-sem
			return
		default:
		}

		var connected bool
		for _, port := range ports {
			target := net.JoinHostPort(ip, strconv.Itoa(port))
			if ms.runSession(ctx, pubkey, target) {
				connected = true
				break
			}
		}

		select {
		case <-ctx.Done():
			<-sem
			return
		default:
		}

		if connected {
			delay = outboundRetryDelay
		}

		// Release semaphore while waiting.
		<-sem

		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}

		delay = delay * 3 / 2
		if delay > outboundMaxRetryDelay {
			delay = outboundMaxRetryDelay
		}

		// Re-acquire semaphore.
		select {
		case sem <- struct{}{}:
		case <-ctx.Done():
			return
		}
	}
}

// runSession performs a single connection to a peer: RLPx handshake, Hello,
// Status exchange, then message loop. Returns true if the session was useful.
func (ms *monitorSession) runSession(ctx context.Context, pubkey *ecdsa.PublicKey, addr string) bool {
	// Phase 1: Dial TCP.
	tcp, err := net.DialTimeout("tcp", addr, handshakeTimeout)
	if err != nil {
		log.Printf("[monitor→%s] dial failed: %v", addr, err)
		return false
	}
	defer tcp.Close()

	// Phase 2: RLPx encryption handshake.
	conn := rlpx.NewConn(tcp, pubkey)
	tcp.SetDeadline(time.Now().Add(handshakeTimeout))
	remotePub, err := conn.Handshake(ms.nodeKey)
	if err != nil {
		log.Printf("[monitor→%s] handshake failed: %v", addr, err)
		return false
	}
	tcp.SetDeadline(time.Time{})

	peerID := fmt.Sprintf("%x", crypto.FromECDSAPub(remotePub)[1:])

	// Phase 3: Hello exchange.
	hello := &Hello{
		Version:    5,
		Name:       "xdc-monitor/1.0",
		Caps:       allCaps(),
		ListenPort: 0,
		ID:         crypto.FromECDSAPub(&ms.nodeKey.PublicKey)[1:],
	}
	helloBytes, err := encodeHello(hello)
	if err != nil {
		log.Printf("[monitor→%s] encode hello: %v", addr, err)
		return false
	}

	if _, err := conn.Write(HandshakeMsg, helloBytes); err != nil {
		log.Printf("[monitor→%s] write hello: %v", addr, err)
		return false
	}

	code, data, _, err := conn.Read()
	if err != nil {
		log.Printf("[monitor→%s] read hello: %v", addr, err)
		return false
	}
	if code == DiscMsg {
		reason := decodeDisconnectReason(data)
		log.Printf("[monitor→%s] disconnected during hello: %s", addr, reason)
		return false
	}
	if code != HandshakeMsg {
		log.Printf("[monitor→%s] expected hello, got 0x%02x", addr, code)
		return false
	}

	peerHello, err := decodeHello(data)
	if err != nil {
		log.Printf("[monitor→%s] decode hello: %v", addr, err)
		return false
	}

	conn.SetSnappy(peerHello.Version >= 5)

	// Record connection.
	ms.store.RecordConnect(addr, peerID, peerHello.Name, peerHello.Caps)
	defer ms.store.RecordDisconnect(addr)

	log.Printf("[monitor→%s] connected: client=%q caps=%v", addr, peerHello.Name, peerHello.Caps)

	// Phase 4: Status exchange.
	// Always read the peer's Status first, then mirror their chain state
	// so they treat us as a synced node and broadcast new blocks.
	// The peer sends Status asynchronously (goroutine), so this won't deadlock.
	ethVersion := negotiateEthVersion(peerHello.Caps)

	conn.SetReadDeadline(time.Now().Add(handshakeTimeout))
	code, data, _, err = conn.Read()
	if err != nil {
		log.Printf("[monitor→%s] read status: %v", addr, err)
		return false
	}

	if code == DiscMsg {
		reason := decodeDisconnectReason(data)
		log.Printf("[monitor→%s] disconnected during status: %s", addr, reason)
		return false
	}

	var peerStatus *EthStatus
	if code == StatusMsg {
		peerStatus, err = decodeStatus(data)
		if err != nil {
			log.Printf("[monitor→%s] decode status: %v", addr, err)
			return false
		}
		setGenesis(peerStatus.Genesis)
		log.Printf("[monitor→%s] status: net=%d td=%s genesis=%s", addr,
			peerStatus.NetworkID, peerStatus.TD, peerStatus.Genesis.Hex()[:10])
	}
	if peerStatus == nil {
		log.Printf("[monitor→%s] expected status, got 0x%02x", addr, code)
		return false
	}

	// Send our Status mirroring the peer's chain state.
	status := makeStatus(ethVersion, peerStatus)
	statusBytes, err := encodeStatus(status)
	if err != nil {
		log.Printf("[monitor→%s] encode status: %v", addr, err)
		return false
	}
	conn.SetWriteDeadline(time.Now().Add(writeTimeout))
	if _, err := conn.Write(StatusMsg, statusBytes); err != nil {
		log.Printf("[monitor→%s] write status: %v", addr, err)
		return false
	}

	// Register with broadcaster for propagation.
	var broadcastCh chan BroadcastMsg
	if ms.propagate && ms.broadcaster != nil {
		broadcastCh = ms.broadcaster.Register(addr)
		defer ms.broadcaster.Unregister(addr)
	}

	// Phase 5: Message loop.
	return ms.messageLoop(ctx, conn, addr, peerID, broadcastCh)
}

// messageLoop handles the persistent connection message loop.
func (ms *monitorSession) messageLoop(ctx context.Context, conn *rlpx.Conn, addr, peerID string, broadcastCh chan BroadcastMsg) bool {
	useful := false
	pingTicker := time.NewTicker(15 * time.Second)
	defer pingTicker.Stop()

	var pingStart time.Time

	for {
		select {
		case <-ctx.Done():
			return useful
		case msg, ok := <-broadcastCh:
			if !ok {
				return useful
			}
			conn.SetWriteDeadline(time.Now().Add(writeTimeout))
			if _, err := conn.Write(msg.Code, msg.Data); err != nil {
				return useful
			}
		case <-pingTicker.C:
			// Send periodic Ping for keep-alive and latency measurement.
			pingStart = time.Now()
			conn.SetWriteDeadline(time.Now().Add(writeTimeout))
			if _, err := conn.Write(PingMsg, nil); err != nil {
				return useful
			}
		default:
		}

		// Non-blocking read with timeout.
		conn.SetReadDeadline(time.Now().Add(1 * time.Second))
		code, data, _, err := conn.Read()
		if err != nil {
			if isTimeout(err) {
				continue
			}
			return useful
		}

		ms.store.RecordMessage(addr)

		switch code {
		case PingMsg:
			conn.SetWriteDeadline(time.Now().Add(writeTimeout))
			conn.Write(PongMsg, nil)

		case PongMsg:
			if !pingStart.IsZero() {
				ms.store.RecordLatency(addr, time.Since(pingStart))
				pingStart = time.Time{}
			}

		case DiscMsg:
			reason := decodeDisconnectReason(data)
			log.Printf("[monitor→%s] peer disconnected: %s", addr, reason)
			return useful

		case StatusMsg:
			// Late Status (some peers send it twice).
			if peerStatus, err := decodeStatus(data); err == nil {
				setGenesis(peerStatus.Genesis)
			}

		case NewBlockMsg:
			useful = true
			blockNum, blockHash, cached := ms.cache.AddNewBlock(data)
			if cached {
				ms.store.RecordHead(addr, blockNum, blockHash)
				log.Printf("[monitor→%s] new block #%d %s", addr, blockNum, blockHash.Hex()[:10])
			}
			// Propagate to other peers.
			if ms.propagate && ms.broadcaster != nil {
				ms.broadcaster.Broadcast(BroadcastMsg{
					Code: NewBlockMsg, Data: data, Sender: addr,
				})
			}

		case NewBlockHashesMsg:
			useful = true
			// Parse block number from NewBlockHashes: [[hash, number], ...]
			if blockNum, hash, ok := parseNewBlockHashes(data); ok {
				ms.store.RecordHead(addr, blockNum, hash)
			}
			if ms.propagate && ms.broadcaster != nil {
				ms.broadcaster.Broadcast(BroadcastMsg{
					Code: NewBlockHashesMsg, Data: data, Sender: addr,
				})
			}

		case TxMsg:
			useful = true
			if ms.propagate && ms.broadcaster != nil {
				ms.broadcaster.Broadcast(BroadcastMsg{
					Code: TxMsg, Data: data, Sender: addr,
				})
			}

		case GetBlockHeadersMsg:
			// Respond with headers from cache, or empty.
			resp := ms.handleGetHeaders(data)
			conn.SetWriteDeadline(time.Now().Add(writeTimeout))
			conn.Write(BlockHeadersMsg, resp)

		case GetBlockBodiesMsg:
			// Respond with bodies from cache, or empty.
			resp := ms.handleGetBodies(data)
			conn.SetWriteDeadline(time.Now().Add(writeTimeout))
			conn.Write(BlockBodiesMsg, resp)

		case XDPoSVoteMsg:
			// XDPoS v2 consensus Vote — extract block number for head tracking.
			useful = true
			if blockNum, blockHash, ok := decodeVoteBlockNumber(data); ok {
				ms.store.RecordHead(addr, blockNum, blockHash)
			}

		case XDPoSTimeoutMsg:
			// XDPoS v2 consensus Timeout — peer is active.
			useful = true
		}
	}
}

// handleGetHeaders tries to serve headers from cache, falls back to empty.
func (ms *monitorSession) handleGetHeaders(data []byte) []byte {
	// GetBlockHeaders can be: {Origin: {Hash or Number}, Amount, Skip, Reverse}
	// For simplicity, try to parse the hash-based variant.
	var req struct {
		Origin  common.Hash
		Amount  uint64
		Skip    uint64
		Reverse bool
	}
	if err := rlp.DecodeBytes(data, &req); err == nil && req.Amount == 1 {
		if headerRLP, ok := ms.cache.GetHeaderByHash(req.Origin); ok {
			resp, _ := rlp.EncodeToBytes([]rlp.RawValue{rlp.RawValue(headerRLP)})
			return resp
		}
	}
	// Return empty headers.
	resp, _ := encodeEmptyHeaders()
	return resp
}

// handleGetBodies tries to serve bodies from cache, falls back to empty.
func (ms *monitorSession) handleGetBodies(data []byte) []byte {
	var hashes []common.Hash
	if err := rlp.DecodeBytes(data, &hashes); err == nil {
		var bodies []rlp.RawValue
		for _, h := range hashes {
			if bodyRLP, ok := ms.cache.GetBodyByHash(h); ok {
				bodies = append(bodies, rlp.RawValue(bodyRLP))
			}
		}
		if len(bodies) > 0 {
			resp, _ := rlp.EncodeToBytes(bodies)
			return resp
		}
	}
	resp, _ := encodeEmptyBodies()
	return resp
}

// parseNewBlockHashes extracts the highest block number and hash from
// a NewBlockHashes message: [[hash, number], ...]
func parseNewBlockHashes(data []byte) (uint64, common.Hash, bool) {
	var entries []struct {
		Hash   common.Hash
		Number uint64
	}
	if err := rlp.DecodeBytes(data, &entries); err != nil || len(entries) == 0 {
		return 0, common.Hash{}, false
	}
	// Return the highest block number.
	best := entries[0]
	for _, e := range entries[1:] {
		if e.Number > best.Number {
			best = e
		}
	}
	return best.Number, best.Hash, true
}

// isTimeout returns true if the error is a network timeout.
func isTimeout(err error) bool {
	if ne, ok := err.(net.Error); ok {
		return ne.Timeout()
	}
	return false
}
