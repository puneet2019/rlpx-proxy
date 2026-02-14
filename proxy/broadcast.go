package proxy

import (
	"encoding/binary"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

const (
	// dedup TTL: how long we remember a hash to avoid re-broadcasting.
	dedupTTL = 30 * time.Second
	// Max pending messages per peer before dropping.
	peerWriteBuffer = 64
)

// BroadcastMsg is a message to be broadcast to peers.
type BroadcastMsg struct {
	Code   uint64
	Data   []byte
	Sender string // addr of the peer that sent this message (excluded from broadcast)
}

// Broadcaster fans out NewBlock, NewBlockHashes, and Txns to all connected peers.
type Broadcaster struct {
	mu    sync.RWMutex
	peers map[string]chan BroadcastMsg // addr → write channel

	dedupMu sync.Mutex
	seen    map[common.Hash]time.Time // recently seen hashes for dedup
}

// NewBroadcaster creates a new Broadcaster.
func NewBroadcaster() *Broadcaster {
	b := &Broadcaster{
		peers: make(map[string]chan BroadcastMsg),
		seen:  make(map[common.Hash]time.Time),
	}
	go b.cleanupLoop()
	return b
}

// Register adds a peer's write channel for broadcasting.
// Returns the channel the monitor session should read from.
func (b *Broadcaster) Register(addr string) chan BroadcastMsg {
	ch := make(chan BroadcastMsg, peerWriteBuffer)
	b.mu.Lock()
	b.peers[addr] = ch
	b.mu.Unlock()
	return ch
}

// Unregister removes a peer from the broadcast group.
func (b *Broadcaster) Unregister(addr string) {
	b.mu.Lock()
	if ch, ok := b.peers[addr]; ok {
		close(ch)
		delete(b.peers, addr)
	}
	b.mu.Unlock()
}

// Broadcast sends a message to all connected peers except the sender.
// Returns false if the message was already seen (deduped).
func (b *Broadcaster) Broadcast(msg BroadcastMsg) bool {
	// Dedup by hashing the message code + data.
	var prefix [8]byte
	binary.BigEndian.PutUint64(prefix[:], msg.Code)
	hash := common.BytesToHash(crypto.Keccak256(prefix[:], msg.Data))

	b.dedupMu.Lock()
	if _, ok := b.seen[hash]; ok {
		b.dedupMu.Unlock()
		return false
	}
	b.seen[hash] = time.Now()
	b.dedupMu.Unlock()

	b.mu.RLock()
	defer b.mu.RUnlock()

	for addr, ch := range b.peers {
		if addr == msg.Sender {
			continue
		}
		select {
		case ch <- msg:
		default:
			// Peer write buffer full, drop message.
		}
	}
	return true
}

// PeerCount returns the number of registered peers.
func (b *Broadcaster) PeerCount() int {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return len(b.peers)
}

// cleanupLoop periodically removes expired dedup entries.
func (b *Broadcaster) cleanupLoop() {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		b.dedupMu.Lock()
		now := time.Now()
		for h, t := range b.seen {
			if now.Sub(t) > dedupTTL {
				delete(b.seen, h)
			}
		}
		b.dedupMu.Unlock()
	}
}
