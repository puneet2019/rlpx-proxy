package proxy

import (
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/rlp"
)

func TestStatusRoundTrip(t *testing.T) {
	original := &EthStatus{
		ProtocolVersion: 100,
		NetworkID:       50,
		TD:              big.NewInt(999999),
		Head:            common.HexToHash("0xabcdef"),
		Genesis:         common.HexToHash("0x112233"),
	}

	data, err := encodeStatus(original)
	if err != nil {
		t.Fatalf("encodeStatus: %v", err)
	}

	decoded, err := decodeStatus(data)
	if err != nil {
		t.Fatalf("decodeStatus: %v", err)
	}

	if decoded.ProtocolVersion != original.ProtocolVersion {
		t.Errorf("ProtocolVersion = %d, want %d", decoded.ProtocolVersion, original.ProtocolVersion)
	}
	if decoded.NetworkID != original.NetworkID {
		t.Errorf("NetworkID = %d, want %d", decoded.NetworkID, original.NetworkID)
	}
	if decoded.TD.Cmp(original.TD) != 0 {
		t.Errorf("TD = %s, want %s", decoded.TD, original.TD)
	}
	if decoded.Head != original.Head {
		t.Errorf("Head = %s, want %s", decoded.Head, original.Head)
	}
	if decoded.Genesis != original.Genesis {
		t.Errorf("Genesis = %s, want %s", decoded.Genesis, original.Genesis)
	}
}

func TestMakeStatusMirrorsPeer(t *testing.T) {
	// Reset global chain state for this test.
	resetChainState()

	peer := &EthStatus{
		ProtocolVersion: 100,
		NetworkID:       50,
		TD:              big.NewInt(123456),
		Head:            common.HexToHash("0xaabbcc"),
		Genesis:         common.HexToHash("0x112233"),
	}

	// No chain state learned yet — should mirror peer.
	ours := makeStatus(100, peer)

	if ours.ProtocolVersion != 100 {
		t.Errorf("ProtocolVersion = %d, want 100", ours.ProtocolVersion)
	}
	if ours.NetworkID != peer.NetworkID {
		t.Errorf("NetworkID = %d, want %d", ours.NetworkID, peer.NetworkID)
	}
	if ours.TD.Cmp(peer.TD) != 0 {
		t.Errorf("TD = %s, want %s", ours.TD, peer.TD)
	}
	if ours.Head != peer.Head {
		t.Errorf("Head mismatch")
	}
	if ours.Genesis != peer.Genesis {
		t.Errorf("Genesis mismatch")
	}
}

func TestMakeStatusUsesBestChainState(t *testing.T) {
	resetChainState()

	// Learn chain state from a "good" peer.
	good := &EthStatus{
		ProtocolVersion: 100,
		NetworkID:       50,
		TD:              big.NewInt(999999),
		Head:            common.HexToHash("0xbesthead"),
		Genesis:         common.HexToHash("0x112233"),
	}
	updateChainState(good)

	// Now connect to a peer with lower TD.
	weaker := &EthStatus{
		ProtocolVersion: 100,
		NetworkID:       50,
		TD:              big.NewInt(100000),
		Head:            common.HexToHash("0xoldhead"),
		Genesis:         common.HexToHash("0x112233"),
	}

	ours := makeStatus(100, weaker)

	// Should use the best known state, not the weaker peer's.
	if ours.TD.Cmp(good.TD) != 0 {
		t.Errorf("TD = %s, want %s (best known)", ours.TD, good.TD)
	}
	if ours.Head != good.Head {
		t.Errorf("Head = %s, want %s (best known)", ours.Head, good.Head)
	}
	// NetworkID should come from the peer we're connecting to.
	if ours.NetworkID != weaker.NetworkID {
		t.Errorf("NetworkID = %d, want %d", ours.NetworkID, weaker.NetworkID)
	}
}

func TestDecodeVoteBlockNumber(t *testing.T) {
	vote := xdposVote{
		ProposedBlockInfo: xdposBlockInfo{
			Hash:   common.HexToHash("0xdeadbeef"),
			Round:  42,
			Number: big.NewInt(99000000),
		},
		Signature: []byte("sig"),
		GapNumber: 100,
	}

	data, err := rlp.EncodeToBytes(vote)
	if err != nil {
		t.Fatal(err)
	}

	num, hash, ok := decodeVoteBlockNumber(data)
	if !ok {
		t.Fatal("decodeVoteBlockNumber returned false")
	}
	if num != 99000000 {
		t.Errorf("block number = %d, want 99000000", num)
	}
	if hash != common.HexToHash("0xdeadbeef") {
		t.Errorf("hash mismatch")
	}
}

func TestDecodeVoteBlockNumberInvalid(t *testing.T) {
	_, _, ok := decodeVoteBlockNumber([]byte("garbage"))
	if ok {
		t.Error("expected false for garbage data")
	}

	_, _, ok = decodeVoteBlockNumber(nil)
	if ok {
		t.Error("expected false for nil data")
	}
}

func TestEncodeEmptyResponses(t *testing.T) {
	headers, err := encodeEmptyHeaders()
	if err != nil {
		t.Fatalf("encodeEmptyHeaders: %v", err)
	}
	if len(headers) == 0 {
		t.Error("expected non-empty bytes")
	}

	bodies, err := encodeEmptyBodies()
	if err != nil {
		t.Fatalf("encodeEmptyBodies: %v", err)
	}
	if len(bodies) == 0 {
		t.Error("expected non-empty bytes")
	}
}
