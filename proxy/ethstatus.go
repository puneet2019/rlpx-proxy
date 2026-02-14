package proxy

import (
	"math/big"
	"sync"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/rlp"
)

// EthStatus is the eth/6x Status message exchanged after Hello.
// Fields match XDC's old eth/62-63 Status format.
type EthStatus struct {
	ProtocolVersion uint32
	NetworkID       uint64
	TD              *big.Int
	Head            common.Hash
	Genesis         common.Hash
}

// encodeStatus RLP-encodes a Status message (without the message-code prefix).
func encodeStatus(s *EthStatus) ([]byte, error) {
	return rlp.EncodeToBytes(s)
}

// decodeStatus RLP-decodes a Status message from raw bytes.
func decodeStatus(data []byte) (*EthStatus, error) {
	var s EthStatus
	if err := rlp.DecodeBytes(data, &s); err != nil {
		return nil, err
	}
	return &s, nil
}

// genesisState holds the genesis hash learned from the first peer.
var (
	genesisHash   common.Hash
	genesisMu     sync.Mutex
	genesisLearnt bool
)

// setGenesis records the genesis hash from the first peer's Status.
func setGenesis(h common.Hash) {
	genesisMu.Lock()
	defer genesisMu.Unlock()
	if !genesisLearnt {
		genesisHash = h
		genesisLearnt = true
	}
}

// getGenesis returns the genesis hash if learned, or zero hash.
func getGenesis() common.Hash {
	genesisMu.Lock()
	defer genesisMu.Unlock()
	return genesisHash
}

// makeStatus builds a Status message that mirrors the peer's chain state.
// This makes the peer treat us as a synced node and broadcast new blocks.
func makeStatus(protoVersion uint32, peerStatus *EthStatus) *EthStatus {
	td := peerStatus.TD
	head := peerStatus.Head
	genesis := peerStatus.Genesis
	return &EthStatus{
		ProtocolVersion: protoVersion,
		NetworkID:       peerStatus.NetworkID,
		TD:              td,
		Head:            head,
		Genesis:         genesis,
	}
}

// xdposBlockInfo is the ProposedBlockInfo inside an XDPoS v2 Vote message.
type xdposBlockInfo struct {
	Hash   common.Hash
	Round  uint64
	Number *big.Int
}

// xdposVote is the XDPoS v2 Vote message (subprotocol code 0xe0, raw 0xf0).
type xdposVote struct {
	ProposedBlockInfo xdposBlockInfo
	Signature         []byte
	GapNumber         uint64
}

// decodeVoteBlockNumber extracts the block number from an XDPoS Vote message.
func decodeVoteBlockNumber(data []byte) (uint64, common.Hash, bool) {
	var v xdposVote
	if err := rlp.DecodeBytes(data, &v); err != nil {
		return 0, common.Hash{}, false
	}
	if v.ProposedBlockInfo.Number == nil {
		return 0, common.Hash{}, false
	}
	return v.ProposedBlockInfo.Number.Uint64(), v.ProposedBlockInfo.Hash, true
}

// encodeEmptyHeaders returns an RLP-encoded empty block headers response.
func encodeEmptyHeaders() ([]byte, error) {
	return rlp.EncodeToBytes([]interface{}{})
}

// encodeEmptyBodies returns an RLP-encoded empty block bodies response.
func encodeEmptyBodies() ([]byte, error) {
	return rlp.EncodeToBytes([]interface{}{})
}
