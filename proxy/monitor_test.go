package proxy

import (
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/rlp"
)

func TestParseNewBlockHashes(t *testing.T) {
	entries := []struct {
		Hash   common.Hash
		Number uint64
	}{
		{common.HexToHash("0xaaa"), 100},
		{common.HexToHash("0xbbb"), 200},
		{common.HexToHash("0xccc"), 150},
	}

	data, err := rlp.EncodeToBytes(entries)
	if err != nil {
		t.Fatal(err)
	}

	num, hash, ok := parseNewBlockHashes(data)
	if !ok {
		t.Fatal("parseNewBlockHashes returned false")
	}
	if num != 200 {
		t.Errorf("block number = %d, want 200 (highest)", num)
	}
	if hash != common.HexToHash("0xbbb") {
		t.Errorf("hash mismatch")
	}
}

func TestParseNewBlockHashesSingle(t *testing.T) {
	entries := []struct {
		Hash   common.Hash
		Number uint64
	}{
		{common.HexToHash("0xfff"), 42},
	}

	data, _ := rlp.EncodeToBytes(entries)
	num, _, ok := parseNewBlockHashes(data)
	if !ok {
		t.Fatal("expected ok")
	}
	if num != 42 {
		t.Errorf("block number = %d, want 42", num)
	}
}

func TestParseNewBlockHashesInvalid(t *testing.T) {
	_, _, ok := parseNewBlockHashes([]byte("garbage"))
	if ok {
		t.Error("expected false for garbage data")
	}

	_, _, ok = parseNewBlockHashes(nil)
	if ok {
		t.Error("expected false for nil data")
	}
}

func TestIsTimeout(t *testing.T) {
	if isTimeout(nil) {
		t.Error("nil error should not be timeout")
	}
}

func TestDecodeDisconnectReason(t *testing.T) {
	// Encode a disconnect reason: "too many peers" = 0x04
	data, _ := rlp.EncodeToBytes([]uint{0x04})
	reason := decodeDisconnectReason(data)
	if reason != "too many peers" {
		t.Errorf("reason = %q, want 'too many peers'", reason)
	}
}
