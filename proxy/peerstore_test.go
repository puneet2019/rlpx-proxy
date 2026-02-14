package proxy

import (
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
)

func TestPeerStoreRecordConnect(t *testing.T) {
	s := NewPeerStore()
	caps := []Cap{{Name: "eth", Version: 100}}
	s.RecordConnect("1.2.3.4:30303", "abc123", "XDC/v2.6.8", caps)

	if s.TotalCount() != 1 {
		t.Fatalf("expected 1 peer, got %d", s.TotalCount())
	}
	if s.ConnectedCount() != 1 {
		t.Fatalf("expected 1 connected, got %d", s.ConnectedCount())
	}

	peers := s.AllPeers()
	if len(peers) != 1 {
		t.Fatalf("expected 1 peer, got %d", len(peers))
	}
	p := peers[0]
	if p.Addr != "1.2.3.4:30303" {
		t.Errorf("addr = %q, want 1.2.3.4:30303", p.Addr)
	}
	if p.PeerID != "abc123" {
		t.Errorf("peer_id = %q, want abc123", p.PeerID)
	}
	if p.ClientName != "XDC/v2.6.8" {
		t.Errorf("client = %q, want XDC/v2.6.8", p.ClientName)
	}
	if !p.Connected {
		t.Error("expected connected=true")
	}
	if p.Sessions != 1 {
		t.Errorf("sessions = %d, want 1", p.Sessions)
	}
	if p.Enode != "enode://abc123@1.2.3.4:30303" {
		t.Errorf("enode = %q", p.Enode)
	}
}

func TestPeerStoreDisconnect(t *testing.T) {
	s := NewPeerStore()
	s.RecordConnect("1.2.3.4:30303", "abc", "test", nil)
	s.RecordDisconnect("1.2.3.4:30303")

	if s.ConnectedCount() != 0 {
		t.Fatalf("expected 0 connected, got %d", s.ConnectedCount())
	}
	if s.TotalCount() != 1 {
		t.Fatal("peer should still exist after disconnect")
	}
}

func TestPeerStoreRecordHead(t *testing.T) {
	s := NewPeerStore()
	s.RecordConnect("1.2.3.4:30303", "abc", "test", nil)

	hash := common.HexToHash("0xdeadbeef")
	s.RecordHead("1.2.3.4:30303", 1000, hash)

	if s.BestBlock() != 1000 {
		t.Errorf("best block = %d, want 1000", s.BestBlock())
	}
	peers := s.AllPeers()
	if peers[0].HeadBlock != 1000 {
		t.Errorf("head block = %d, want 1000", peers[0].HeadBlock)
	}
	if peers[0].HeadHash != hash {
		t.Errorf("head hash mismatch")
	}
}

func TestPeerStoreHeadOnlyAdvances(t *testing.T) {
	s := NewPeerStore()
	s.RecordConnect("1.2.3.4:30303", "abc", "test", nil)

	s.RecordHead("1.2.3.4:30303", 1000, common.Hash{})
	s.RecordHead("1.2.3.4:30303", 500, common.Hash{}) // should not go backwards

	peers := s.AllPeers()
	if peers[0].HeadBlock != 1000 {
		t.Errorf("head block regressed to %d, want 1000", peers[0].HeadBlock)
	}
}

func TestPeerStoreRecordLatency(t *testing.T) {
	s := NewPeerStore()
	s.RecordConnect("1.2.3.4:30303", "abc", "test", nil)
	s.RecordLatency("1.2.3.4:30303", 150*time.Millisecond)

	peers := s.AllPeers()
	if peers[0].LatencyMs != 150 {
		t.Errorf("latency = %d, want 150", peers[0].LatencyMs)
	}
}

func TestPeerStoreRecordMessage(t *testing.T) {
	s := NewPeerStore()
	s.RecordConnect("1.2.3.4:30303", "abc", "test", nil)
	s.RecordMessage("1.2.3.4:30303")
	s.RecordMessage("1.2.3.4:30303")
	s.RecordMessage("1.2.3.4:30303")

	peers := s.AllPeers()
	if peers[0].MsgCount != 3 {
		t.Errorf("msg_count = %d, want 3", peers[0].MsgCount)
	}
}

func TestPeerStoreMultipleSessions(t *testing.T) {
	s := NewPeerStore()
	s.RecordConnect("1.2.3.4:30303", "abc", "test", nil)
	s.RecordDisconnect("1.2.3.4:30303")
	s.RecordConnect("1.2.3.4:30303", "abc", "test", nil)

	peers := s.AllPeers()
	if peers[0].Sessions != 2 {
		t.Errorf("sessions = %d, want 2", peers[0].Sessions)
	}
}

func TestPeerStoreSortedByScore(t *testing.T) {
	s := NewPeerStore()
	s.RecordConnect("slow:30303", "a", "test", nil)
	s.RecordConnect("fast:30303", "b", "test", nil)

	// Give "fast" better latency and block head.
	s.RecordLatency("fast:30303", 50*time.Millisecond)
	s.RecordHead("fast:30303", 1000, common.Hash{})

	s.RecordLatency("slow:30303", 5*time.Second)

	peers := s.AllPeers()
	if len(peers) != 2 {
		t.Fatalf("expected 2 peers, got %d", len(peers))
	}
	if peers[0].Addr != "fast:30303" {
		t.Errorf("expected fast peer first, got %s", peers[0].Addr)
	}
}

func TestPeerScoreChainHead(t *testing.T) {
	s := NewPeerStore()
	s.RecordConnect("peer1:30303", "a", "test", nil)
	s.RecordConnect("peer2:30303", "b", "test", nil)

	s.RecordHead("peer1:30303", 1000, common.Hash{})
	s.RecordHead("peer2:30303", 1000, common.Hash{})

	// Both at best block → both should get 40 points for chain head.
	peers := s.AllPeers()
	for _, p := range peers {
		if p.Score < 40 {
			t.Errorf("peer %s: score=%.1f, expected >= 40 (at best block)", p.Addr, p.Score)
		}
	}
}
