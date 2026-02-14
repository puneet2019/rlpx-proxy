package proxy

import (
	"testing"
	"time"
)

func TestBroadcasterRegisterUnregister(t *testing.T) {
	b := NewBroadcaster()

	ch := b.Register("peer1")
	if b.PeerCount() != 1 {
		t.Fatalf("expected 1 peer, got %d", b.PeerCount())
	}
	if ch == nil {
		t.Fatal("expected non-nil channel")
	}

	b.Unregister("peer1")
	if b.PeerCount() != 0 {
		t.Fatalf("expected 0 peers, got %d", b.PeerCount())
	}
}

func TestBroadcasterFanout(t *testing.T) {
	b := NewBroadcaster()

	ch1 := b.Register("peer1")
	ch2 := b.Register("peer2")
	ch3 := b.Register("peer3")

	// Broadcast from peer1 — should reach peer2 and peer3 but not peer1.
	ok := b.Broadcast(BroadcastMsg{
		Code:   NewBlockMsg,
		Data:   []byte("block-data"),
		Sender: "peer1",
	})
	if !ok {
		t.Fatal("expected broadcast to succeed (not deduped)")
	}

	// peer1 should NOT receive it (it's the sender).
	select {
	case <-ch1:
		t.Error("peer1 should not receive its own broadcast")
	case <-time.After(50 * time.Millisecond):
		// good
	}

	// peer2 and peer3 should receive it.
	select {
	case msg := <-ch2:
		if msg.Code != NewBlockMsg {
			t.Errorf("peer2: code = 0x%02x, want 0x%02x", msg.Code, NewBlockMsg)
		}
	case <-time.After(time.Second):
		t.Fatal("peer2: timeout waiting for broadcast")
	}

	select {
	case msg := <-ch3:
		if string(msg.Data) != "block-data" {
			t.Errorf("peer3: data = %q, want 'block-data'", msg.Data)
		}
	case <-time.After(time.Second):
		t.Fatal("peer3: timeout waiting for broadcast")
	}
}

func TestBroadcasterDedup(t *testing.T) {
	b := NewBroadcaster()
	b.Register("peer1")
	b.Register("peer2")

	msg := BroadcastMsg{
		Code:   NewBlockMsg,
		Data:   []byte("same-block"),
		Sender: "peer1",
	}

	first := b.Broadcast(msg)
	if !first {
		t.Error("first broadcast should not be deduped")
	}

	second := b.Broadcast(msg)
	if second {
		t.Error("duplicate broadcast should be deduped")
	}
}

func TestBroadcasterFullBuffer(t *testing.T) {
	b := NewBroadcaster()
	b.Register("slow-peer")

	// Fill the buffer.
	for i := 0; i < peerWriteBuffer+10; i++ {
		b.Broadcast(BroadcastMsg{
			Code:   TxMsg,
			Data:   []byte{byte(i)},
			Sender: "other",
		})
	}
	// Should not panic — messages are dropped when buffer is full.
}
