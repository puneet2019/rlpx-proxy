package proxy

import "github.com/ethereum/go-ethereum/rlp"

// DevP2P base protocol message codes.
const (
	HandshakeMsg = 0x00
	DiscMsg      = 0x01
	PingMsg      = 0x02
	PongMsg      = 0x03
)

// Cap represents a peer capability (sub-protocol name + version).
type Cap struct {
	Name    string
	Version uint
}

// Hello is the devp2p handshake message exchanged right after the RLPx
// encryption handshake completes.
type Hello struct {
	Version    uint64
	Name       string
	Caps       []Cap
	ListenPort uint64
	ID         []byte // 64-byte uncompressed pubkey (without 0x04 prefix)
	Rest       []rlp.RawValue `rlp:"tail"`
}

// encodeHello RLP-encodes a Hello message (without the message-code prefix).
func encodeHello(h *Hello) ([]byte, error) {
	return rlp.EncodeToBytes(h)
}

// decodeHello RLP-decodes a Hello message from raw bytes.
func decodeHello(data []byte) (*Hello, error) {
	var h Hello
	if err := rlp.DecodeBytes(data, &h); err != nil {
		return nil, err
	}
	return &h, nil
}

// defaultXDCCaps returns the capability set advertised by XDC nodes.
func defaultXDCCaps() []Cap {
	return []Cap{
		{Name: "eth", Version: 62},
		{Name: "eth", Version: 63},
		{Name: "eth", Version: 100},
	}
}

// defaultEthCaps returns the capability set for modern Ethereum nodes.
func defaultEthCaps() []Cap {
	return []Cap{
		{Name: "eth", Version: 67},
		{Name: "eth", Version: 68},
		{Name: "snap", Version: 1},
	}
}

// allCaps returns a combined capability set that works with both XDC and
// Ethereum nodes. The remote peer negotiates to the highest common version.
func allCaps() []Cap {
	return []Cap{
		{Name: "eth", Version: 62},
		{Name: "eth", Version: 63},
		{Name: "eth", Version: 67},
		{Name: "eth", Version: 68},
		{Name: "eth", Version: 100},
		{Name: "snap", Version: 1},
	}
}

// negotiateEthVersion returns the highest common eth protocol version
// between our caps and the peer's caps.
func negotiateEthVersion(peerCaps []Cap) uint32 {
	ours := make(map[uint]bool)
	for _, c := range allCaps() {
		if c.Name == "eth" {
			ours[c.Version] = true
		}
	}
	var best uint
	for _, c := range peerCaps {
		if c.Name == "eth" && ours[c.Version] && c.Version > best {
			best = c.Version
		}
	}
	if best == 0 {
		return 63 // fallback
	}
	return uint32(best)
}
