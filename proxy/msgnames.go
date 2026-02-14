package proxy

import "fmt"

// Eth sub-protocol message codes (offset 0x10 from base devp2p).
const (
	StatusMsg         = 0x10
	NewBlockHashesMsg = 0x11
	TxMsg             = 0x12
	GetBlockHeadersMsg = 0x13
	BlockHeadersMsg   = 0x14
	GetBlockBodiesMsg = 0x15
	BlockBodiesMsg    = 0x16
	NewBlockMsg       = 0x17
)

// XDPoS consensus message codes.
const (
	XDPoSVoteMsg    = 0xF0
	XDPoSTimeoutMsg = 0xF1
)

var msgNames = map[uint64]string{
	HandshakeMsg:       "Hello",
	DiscMsg:            "Disconnect",
	PingMsg:            "Ping",
	PongMsg:            "Pong",
	StatusMsg:          "Status",
	NewBlockHashesMsg:  "NewBlockHashes",
	TxMsg:              "Txns",
	GetBlockHeadersMsg: "GetHeaders",
	BlockHeadersMsg:    "Headers",
	GetBlockBodiesMsg:  "GetBodies",
	BlockBodiesMsg:     "Bodies",
	NewBlockMsg:        "NewBlock",
	XDPoSVoteMsg:       "XDPoS/Vote",
	XDPoSTimeoutMsg:    "XDPoS/Timeout",
}

// MsgName returns a human-readable name for a devp2p/eth message code.
func MsgName(code uint64) string {
	if name, ok := msgNames[code]; ok {
		return name
	}
	return fmt.Sprintf("0x%02x", code)
}

// IsProtocolMsg returns true for eth sub-protocol messages (not Ping/Pong).
func IsProtocolMsg(code uint64) bool {
	return code >= StatusMsg
}
