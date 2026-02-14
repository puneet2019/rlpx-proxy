package proxy

import (
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/rlp"
)

// makeNewBlockRLP builds a minimal NewBlock message: [[header, txs, uncles], td]
func makeNewBlockRLP(t *testing.T, blockNum uint64) []byte {
	t.Helper()

	header := blockHeader{
		ParentHash: common.HexToHash("0x01"),
		Number:     big.NewInt(int64(blockNum)).Bytes(),
		Time:       1000,
	}
	headerRLP, err := rlp.EncodeToBytes(header)
	if err != nil {
		t.Fatal(err)
	}

	// Empty txs and uncles.
	txsRLP, _ := rlp.EncodeToBytes([]interface{}{})
	unclesRLP, _ := rlp.EncodeToBytes([]interface{}{})

	block, _ := rlp.EncodeToBytes([]rlp.RawValue{
		rlp.RawValue(headerRLP),
		rlp.RawValue(txsRLP),
		rlp.RawValue(unclesRLP),
	})

	td, _ := rlp.EncodeToBytes(big.NewInt(100))

	outer, _ := rlp.EncodeToBytes([]rlp.RawValue{
		rlp.RawValue(block),
		rlp.RawValue(td),
	})
	return outer
}

func TestBlockCacheAddAndRetrieve(t *testing.T) {
	c := NewBlockCache()
	data := makeNewBlockRLP(t, 42)

	blockNum, hash, ok := c.AddNewBlock(data)
	if !ok {
		t.Fatal("AddNewBlock returned false")
	}
	if blockNum != 42 {
		t.Errorf("block number = %d, want 42", blockNum)
	}
	if hash == (common.Hash{}) {
		t.Error("hash should not be zero")
	}

	// Retrieve by hash.
	headerRLP, ok := c.GetHeaderByHash(hash)
	if !ok {
		t.Fatal("GetHeaderByHash returned false")
	}
	if len(headerRLP) == 0 {
		t.Error("header RLP is empty")
	}

	bodyRLP, ok := c.GetBodyByHash(hash)
	if !ok {
		t.Fatal("GetBodyByHash returned false")
	}
	if len(bodyRLP) == 0 {
		t.Error("body RLP is empty")
	}
}

func TestBlockCacheBest(t *testing.T) {
	c := NewBlockCache()

	c.AddNewBlock(makeNewBlockRLP(t, 10))
	c.AddNewBlock(makeNewBlockRLP(t, 50))
	c.AddNewBlock(makeNewBlockRLP(t, 30))

	if c.Best() != 50 {
		t.Errorf("best = %d, want 50", c.Best())
	}
}

func TestBlockCacheMiss(t *testing.T) {
	c := NewBlockCache()

	_, ok := c.GetHeaderByHash(common.HexToHash("0xdead"))
	if ok {
		t.Error("expected miss for unknown hash")
	}

	_, ok = c.GetBodyByHash(common.HexToHash("0xdead"))
	if ok {
		t.Error("expected miss for unknown hash")
	}
}

func TestBlockCacheEviction(t *testing.T) {
	c := NewBlockCache()

	// Add more than maxCachedBlocks.
	for i := uint64(1); i <= maxCachedBlocks+10; i++ {
		c.AddNewBlock(makeNewBlockRLP(t, i))
	}

	c.mu.RLock()
	count := len(c.blocks)
	c.mu.RUnlock()

	if count > maxCachedBlocks {
		t.Errorf("cache has %d blocks, expected <= %d", count, maxCachedBlocks)
	}
}

func TestBlockCacheInvalidData(t *testing.T) {
	c := NewBlockCache()

	_, _, ok := c.AddNewBlock([]byte("garbage"))
	if ok {
		t.Error("expected AddNewBlock to fail on garbage data")
	}

	_, _, ok = c.AddNewBlock(nil)
	if ok {
		t.Error("expected AddNewBlock to fail on nil data")
	}
}
