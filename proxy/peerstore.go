package proxy

import (
	"fmt"
	"math"
	"sort"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/common"
)

// PeerRecord holds live and historical stats for a single peer.
type PeerRecord struct {
	Addr       string      `json:"addr"`
	PeerID     string      `json:"peer_id,omitempty"`
	ClientName string      `json:"client,omitempty"`
	Caps       []Cap       `json:"caps,omitempty"`
	Enode      string      `json:"enode,omitempty"`
	HeadBlock  uint64      `json:"head_block"`
	HeadHash   common.Hash `json:"head_hash,omitempty"`
	LatencyMs  int64       `json:"latency_ms,omitempty"`
	Connected  bool        `json:"connected"`
	Sessions   int         `json:"sessions"`
	MsgCount   int         `json:"msg_count"`
	FirstSeen  time.Time   `json:"first_seen"`
	LastSeen   time.Time   `json:"last_seen"`
	Score      float64     `json:"score"`
}

// computeScore calculates a quality score based on chain head freshness,
// latency, uptime, and reliability.
func (p *PeerRecord) computeScore(bestBlock uint64) {
	score := 0.0

	// Chain head freshness (highest weight): 0-40 points.
	// Peers at the best known block get full points.
	if bestBlock > 0 && p.HeadBlock > 0 {
		lag := bestBlock - p.HeadBlock
		if p.HeadBlock > bestBlock {
			lag = 0 // peer is ahead, that's fine
		}
		switch {
		case lag == 0:
			score += 40
		case lag < 10:
			score += 30
		case lag < 100:
			score += 20
		case lag < 1000:
			score += 10
		}
	}

	// Latency: 0-20 points.
	if p.LatencyMs > 0 {
		switch {
		case p.LatencyMs < 100:
			score += 20
		case p.LatencyMs < 300:
			score += 15
		case p.LatencyMs < 1000:
			score += 10
		case p.LatencyMs < 3000:
			score += 5
		}
	}

	// Uptime/recency: 0-20 points.
	if !p.LastSeen.IsZero() {
		since := time.Since(p.LastSeen).Minutes()
		switch {
		case since < 1:
			score += 20
		case since < 5:
			score += 15
		case since < 30:
			score += 10
		case since < 60:
			score += 5
		}
	}

	// Reliability: sessions and message count, 0-20 points.
	sessionScore := math.Min(float64(p.Sessions)*2, 10)
	msgScore := math.Min(float64(p.MsgCount)/100, 10)
	score += sessionScore + msgScore

	p.Score = score
}

// PeerStore is a thread-safe in-memory store for peer records.
type PeerStore struct {
	mu        sync.RWMutex
	peers     map[string]*PeerRecord // keyed by addr (ip:port)
	bestBlock uint64
}

// NewPeerStore creates a new empty PeerStore.
func NewPeerStore() *PeerStore {
	return &PeerStore{
		peers: make(map[string]*PeerRecord),
	}
}

// RecordConnect records a peer connection event.
func (s *PeerStore) RecordConnect(addr, peerID, clientName string, caps []Cap) {
	s.mu.Lock()
	defer s.mu.Unlock()

	p := s.getOrCreate(addr)
	p.PeerID = peerID
	p.ClientName = clientName
	p.Caps = caps
	p.Connected = true
	p.Sessions++
	p.LastSeen = time.Now()
	if peerID != "" {
		p.Enode = fmt.Sprintf("enode://%s@%s", peerID, addr)
	}
	p.computeScore(s.bestBlock)
}

// RecordDisconnect records a peer disconnection event.
func (s *PeerStore) RecordDisconnect(addr string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if p, ok := s.peers[addr]; ok {
		p.Connected = false
		p.LastSeen = time.Now()
		p.computeScore(s.bestBlock)
	}
}

// RecordMessage records that a message was received from a peer.
func (s *PeerStore) RecordMessage(addr string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if p, ok := s.peers[addr]; ok {
		p.MsgCount++
		p.LastSeen = time.Now()
	}
}

// RecordHead updates a peer's reported chain head.
func (s *PeerStore) RecordHead(addr string, block uint64, hash common.Hash) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if p, ok := s.peers[addr]; ok {
		if block > p.HeadBlock {
			p.HeadBlock = block
			p.HeadHash = hash
		}
		if block > s.bestBlock {
			s.bestBlock = block
		}
		p.computeScore(s.bestBlock)
	}
}

// RecordLatency updates a peer's measured RTT latency.
func (s *PeerStore) RecordLatency(addr string, latency time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if p, ok := s.peers[addr]; ok {
		p.LatencyMs = latency.Milliseconds()
		p.computeScore(s.bestBlock)
	}
}

// BestBlock returns the highest block number seen across all peers.
func (s *PeerStore) BestBlock() uint64 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.bestBlock
}

// ConnectedCount returns the number of currently connected peers.
func (s *PeerStore) ConnectedCount() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	count := 0
	for _, p := range s.peers {
		if p.Connected {
			count++
		}
	}
	return count
}

// AllPeers returns a snapshot of all peer records, sorted by score descending.
func (s *PeerStore) AllPeers() []*PeerRecord {
	s.mu.RLock()
	defer s.mu.RUnlock()

	result := make([]*PeerRecord, 0, len(s.peers))
	for _, p := range s.peers {
		// Copy the record to avoid races.
		cp := *p
		result = append(result, &cp)
	}

	sort.Slice(result, func(i, j int) bool {
		return result[i].Score > result[j].Score
	})
	return result
}

// TotalCount returns the total number of known peers.
func (s *PeerStore) TotalCount() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.peers)
}

func (s *PeerStore) getOrCreate(addr string) *PeerRecord {
	p, ok := s.peers[addr]
	if !ok {
		p = &PeerRecord{
			Addr:      addr,
			FirstSeen: time.Now(),
		}
		s.peers[addr] = p
	}
	return p
}
