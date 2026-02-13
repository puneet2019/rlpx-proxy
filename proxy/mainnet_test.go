package proxy

import (
	"context"
	"crypto/ecdsa"
	"encoding/hex"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/p2p/rlpx"
)

// TestMainnetBootnodeHandshake connects the proxy to a real XDC mainnet
// bootnode and validates that:
//  1. The proxy successfully completes an RLPx handshake with the bootnode
//  2. An external "peer" can handshake with the proxy
//  3. Hello messages are exchanged through the proxy
//  4. At least one application message is relayed (the bootnode will likely
//     send a Status message or disconnect)
//
// This test requires internet access and a reachable bootnode.
func TestMainnetBootnodeHandshake(t *testing.T) {
	// XDC mainnet bootnodes (try multiple in case one is down).
	bootnodes := []struct {
		pubkey string
		addr   string
	}{
		{
			pubkey: "e5567ad0fab8f95880de949d1a50b384bef98a661084a9d9506eb936bef60c178b1d6311dc106230c032185db3b4ef358ad340a8e54fcf1a77e47f10ff9f09c1",
			addr:   "45.10.162.64:30303",
		},
		{
			pubkey: "ffad9467921f0189ff30cbce9b38005866b7a7fa321a5c53e9a04d4ae6495e49679930ddcd10c0d915efcc25dfd70e1da786d61463f6b8aa456eb5cd2d40ed69",
			addr:   "62.171.129.255:30303",
		},
		{
			pubkey: "be0a8b1198ff3c6f8561504c97202d142e67880e195c6a3b581f5b0f052276da9f5d4dd9646d9eb18e6e01accb3725434aa2afbe74e6fd1bfc25db25a8aca4a3",
			addr:   "209.145.54.70:30303",
		},
	}

	// Use a fresh key as the "node" key (external identity) and proxy key.
	nodeKey := genKey(t)
	proxyKey := genKey(t)
	peerKey := genKey(t)

	// Try bootnodes until one is TCP-reachable.
	var bootnodeAddr string
	var bootnodePubKey *ecdsa.PublicKey
	for _, bn := range bootnodes {
		conn, err := net.DialTimeout("tcp", bn.addr, 5*time.Second)
		if err != nil {
			t.Logf("bootnode %s unreachable: %v", bn.addr, err)
			continue
		}
		conn.Close()

		// Parse bootnode's public key.
		pubBytes, err := hex.DecodeString(bn.pubkey)
		if err != nil {
			t.Fatalf("bad pubkey hex: %v", err)
		}
		pub, err := crypto.UnmarshalPubkey(append([]byte{0x04}, pubBytes...))
		if err != nil {
			t.Fatalf("bad pubkey: %v", err)
		}
		bootnodePubKey = pub
		bootnodeAddr = bn.addr
		t.Logf("using bootnode %s (pubkey %s…)", bootnodeAddr, bn.pubkey[:16])
		break
	}
	if bootnodeAddr == "" {
		t.Skip("no reachable XDC bootnode found")
	}

	// Start proxy pointing at the bootnode as upstream.
	cfg := Config{
		ListenAddr:   "127.0.0.1:0",
		UpstreamAddr: bootnodeAddr,
		NodeKey:      nodeKey,
		ProxyKey:     proxyKey,
	}
	srv := NewServer(cfg)
	proxyListener, err := net.Listen("tcp", cfg.ListenAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer proxyListener.Close()
	srv.listener = proxyListener
	proxyAddr := proxyListener.Addr().String()
	t.Logf("proxy listening on %s → upstream %s", proxyAddr, bootnodeAddr)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Run proxy accept loop. Pass the bootnode's actual pubkey so the
	// upstream handshake targets the correct identity.
	go func() {
		for {
			conn, err := srv.listener.Accept()
			if err != nil {
				return
			}
			srv.wg.Add(1)
			go func() {
				defer srv.wg.Done()
				sess := &session{
					extConn:        conn,
					upstreamAddr:   srv.cfg.UpstreamAddr,
					nodeKey:        srv.cfg.NodeKey,
					proxyKey:       srv.cfg.ProxyKey,
					upstreamPubKey: bootnodePubKey,
				}
				sess.run(ctx)
			}()
		}
	}()

	// Connect as external peer.
	peerConn, err := net.DialTimeout("tcp", proxyAddr, 5*time.Second)
	if err != nil {
		t.Fatalf("peer dial proxy: %v", err)
	}
	defer peerConn.Close()

	pc := rlpx.NewConn(peerConn, &nodeKey.PublicKey)
	peerConn.SetDeadline(time.Now().Add(15 * time.Second))
	remotePub, err := pc.Handshake(peerKey)
	if err != nil {
		t.Fatalf("peer handshake with proxy: %v", err)
	}
	peerConn.SetDeadline(time.Time{})

	// Verify proxy presented node's key.
	remoteID := fmt.Sprintf("%x", crypto.FromECDSAPub(remotePub)[1:])
	nodeID := fmt.Sprintf("%x", crypto.FromECDSAPub(&nodeKey.PublicKey)[1:])
	if remoteID != nodeID {
		t.Fatalf("expected node pubkey, got %s…", remoteID[:16])
	}
	t.Log("PASS: external handshake succeeded, proxy presented correct node key")

	// Send Hello.
	peerHello := &Hello{
		Version:    5,
		Name:       "test-peer",
		Caps:       defaultXDCCaps(),
		ListenPort: 0,
		ID:         crypto.FromECDSAPub(&peerKey.PublicKey)[1:],
	}
	helloBytes, _ := encodeHello(peerHello)
	if _, err := pc.Write(HandshakeMsg, helloBytes); err != nil {
		t.Fatalf("peer write hello: %v", err)
	}

	// Read Hello from proxy (which relays the bootnode's Hello).
	code, data, _, err := pc.Read()
	if err != nil {
		t.Fatalf("peer read hello: %v", err)
	}
	if code != HandshakeMsg {
		t.Fatalf("expected hello (0x00), got 0x%02x", code)
	}
	h, err := decodeHello(data)
	if err != nil {
		t.Fatalf("decode hello: %v", err)
	}
	t.Logf("PASS: got Hello via proxy: name=%q version=%d caps=%v",
		h.Name, h.Version, h.Caps)

	// Verify Hello.ID matches node key (proxy replaces it with node identity).
	helloID := fmt.Sprintf("%x", h.ID)
	if helloID != nodeID {
		t.Fatalf("Hello.ID mismatch: got %s…, want %s…", helloID[:16], nodeID[:16])
	}
	t.Log("PASS: Hello.ID matches node key")

	// Enable snappy.
	pc.SetSnappy(h.Version >= 5)

	// Try to read at least one more message (bootnode will likely send a
	// Status message or disconnect us since we don't send a proper Status).
	peerConn.SetReadDeadline(time.Now().Add(10 * time.Second))
	code, data, wireSize, err := pc.Read()
	if err != nil {
		// A disconnect is expected — bootnode will drop us because we
		// haven't sent an eth Status message. The important thing is
		// both handshakes and Hello exchange worked through the proxy.
		t.Logf("post-hello read (expected disconnect): %v", err)
	} else {
		t.Logf("PASS: received relayed message from bootnode: code=0x%02x size=%d data_preview=%x",
			code, wireSize, truncate(data, 64))
	}

	cancel()
	proxyListener.Close()
	t.Log("mainnet bootnode test completed successfully")
}

func truncate(b []byte, max int) []byte {
	if len(b) > max {
		return b[:max]
	}
	return b
}
