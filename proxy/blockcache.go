package proxy

import (
	"sync"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/rlp"
)

const maxCachedBlocks = 256

// CachedBlock holds raw RLP-encoded header and body for a block.
type CachedBlock struct {
	Number    uint64
	Hash      common.Hash
	HeaderRLP []byte // raw RLP of the block header
	BodyRLP   []byte // raw RLP of the block body (txs + uncles)
}

// BlockCache is a rolling in-memory cache of recent blocks.
// Populated from NewBlock messages received from peers.
type BlockCache struct {
	mu     sync.RWMutex
	blocks map[uint64]*CachedBlock // by block number
	hashes map[common.Hash]uint64  // hash → block number
	best   uint64
}

// NewBlockCache creates a new empty block cache.
func NewBlockCache() *BlockCache {
	return &BlockCache{
		blocks: make(map[uint64]*CachedBlock),
		hashes: make(map[common.Hash]uint64),
	}
}

// blockHeader is a minimal decode of just the fields we need from a block header.
type blockHeader struct {
	ParentHash  common.Hash
	UncleHash   common.Hash
	Coinbase    common.Address
	Root        common.Hash
	TxHash      common.Hash
	ReceiptHash common.Hash
	Bloom       [256]byte
	Difficulty  []byte // raw big.Int
	Number      []byte // raw big.Int
	GasLimit    uint64
	GasUsed     uint64
	Time        uint64
	Extra       []byte
	MixDigest   common.Hash
	Nonce       [8]byte
}

// AddNewBlock parses a NewBlock message and caches the block.
// Returns the block number and hash if successfully cached.
func (c *BlockCache) AddNewBlock(data []byte) (uint64, common.Hash, bool) {
	// NewBlock is encoded as: [[header, txs, uncles], td]
	var outer []rlp.RawValue
	if err := rlp.DecodeBytes(data, &outer); err != nil || len(outer) < 1 {
		return 0, common.Hash{}, false
	}

	// Decode the block envelope [header, txs, uncles]
	var blockParts []rlp.RawValue
	if err := rlp.DecodeBytes(outer[0], &blockParts); err != nil || len(blockParts) < 3 {
		return 0, common.Hash{}, false
	}

	headerRLP := []byte(blockParts[0])

	// Decode just enough of the header to get the block number.
	var hdr blockHeader
	if err := rlp.DecodeBytes(headerRLP, &hdr); err != nil {
		return 0, common.Hash{}, false
	}

	// Block number from raw big.Int bytes.
	blockNum := uint64(0)
	for _, b := range hdr.Number {
		blockNum = (blockNum << 8) | uint64(b)
	}

	// Hash is the keccak256 of the RLP-encoded header.
	blockHash := common.BytesToHash(crypto.Keccak256(headerRLP))

	// Build the body RLP: [txs, uncles]
	bodyRLP, err := rlp.EncodeToBytes([]rlp.RawValue{blockParts[1], blockParts[2]})
	if err != nil {
		return 0, common.Hash{}, false
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	c.blocks[blockNum] = &CachedBlock{
		Number:    blockNum,
		Hash:      blockHash,
		HeaderRLP: headerRLP,
		BodyRLP:   bodyRLP,
	}
	c.hashes[blockHash] = blockNum

	if blockNum > c.best {
		c.best = blockNum
	}

	// Evict old blocks.
	if len(c.blocks) > maxCachedBlocks {
		c.evictOldest()
	}

	return blockNum, blockHash, true
}

// GetHeaderByHash returns the raw RLP header for a given block hash.
func (c *BlockCache) GetHeaderByHash(hash common.Hash) ([]byte, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	num, ok := c.hashes[hash]
	if !ok {
		return nil, false
	}
	block, ok := c.blocks[num]
	if !ok {
		return nil, false
	}
	return block.HeaderRLP, true
}

// GetBodyByHash returns the raw RLP body for a given block hash.
func (c *BlockCache) GetBodyByHash(hash common.Hash) ([]byte, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	num, ok := c.hashes[hash]
	if !ok {
		return nil, false
	}
	block, ok := c.blocks[num]
	if !ok {
		return nil, false
	}
	return block.BodyRLP, true
}

// Best returns the highest cached block number.
func (c *BlockCache) Best() uint64 {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.best
}

func (c *BlockCache) evictOldest() {
	minNum := c.best
	for num := range c.blocks {
		if num < minNum {
			minNum = num
		}
	}
	if block, ok := c.blocks[minNum]; ok {
		delete(c.hashes, block.Hash)
		delete(c.blocks, minNum)
	}
}
