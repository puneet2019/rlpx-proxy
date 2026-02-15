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

// bestChainState tracks the best known chain state across all peers.
// Updated from Status messages and NewBlock announcements so we can
// advertise up-to-date state to every peer we connect to.
var (
	chainMu      sync.Mutex
	chainGenesis common.Hash
	chainNet     uint64
	chainTD      *big.Int
	chainHead    common.Hash
	chainLearnt  bool
)

// updateChainState updates the best known chain state if the given Status
// has a higher TD than what we've seen so far.
func updateChainState(s *EthStatus) {
	chainMu.Lock()
	defer chainMu.Unlock()
	if !chainLearnt {
		chainGenesis = s.Genesis
		chainNet = s.NetworkID
		chainTD = new(big.Int).Set(s.TD)
		chainHead = s.Head
		chainLearnt = true
		return
	}
	if s.TD.Cmp(chainTD) > 0 {
		chainTD.Set(s.TD)
		chainHead = s.Head
	}
}

// updateChainHead updates the best head hash when we learn about a new block
// from NewBlock messages. Only updates when we have a concrete TD to compare.
func updateChainHead(head common.Hash, td *big.Int) {
	if td == nil {
		return
	}
	chainMu.Lock()
	defer chainMu.Unlock()
	if !chainLearnt {
		return
	}
	if td.Cmp(chainTD) > 0 {
		chainTD.Set(td)
		chainHead = head
	}
}

// getGenesis returns the genesis hash if learned, or zero hash.
func getGenesis() common.Hash {
	chainMu.Lock()
	defer chainMu.Unlock()
	return chainGenesis
}

// makeStatus builds a Status message using the best known chain state.
// If we've already learned chain state from other peers, we advertise that
// (making us look synced). Otherwise we fall back to mirroring the peer.
func makeStatus(protoVersion uint32, peerStatus *EthStatus) *EthStatus {
	chainMu.Lock()
	best := chainLearnt
	var td *big.Int
	var head common.Hash
	var genesis common.Hash
	if best {
		td = new(big.Int).Set(chainTD)
		head = chainHead
		genesis = chainGenesis
	}
	chainMu.Unlock()

	if best && td.Cmp(peerStatus.TD) >= 0 {
		return &EthStatus{
			ProtocolVersion: protoVersion,
			NetworkID:       peerStatus.NetworkID,
			TD:              td,
			Head:            head,
			Genesis:         genesis,
		}
	}
	return &EthStatus{
		ProtocolVersion: protoVersion,
		NetworkID:       peerStatus.NetworkID,
		TD:              peerStatus.TD,
		Head:            peerStatus.Head,
		Genesis:         peerStatus.Genesis,
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

// resetChainState resets the global chain state (for testing).
func resetChainState() {
	chainMu.Lock()
	defer chainMu.Unlock()
	chainGenesis = common.Hash{}
	chainNet = 0
	chainTD = nil
	chainHead = common.Hash{}
	chainLearnt = false
}

// encodeEmptyHeaders returns an RLP-encoded empty block headers response.
func encodeEmptyHeaders() ([]byte, error) {
	return rlp.EncodeToBytes([]interface{}{})
}

// encodeEmptyBodies returns an RLP-encoded empty block bodies response.
func encodeEmptyBodies() ([]byte, error) {
	return rlp.EncodeToBytes([]interface{}{})
}
