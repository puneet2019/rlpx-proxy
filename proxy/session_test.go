package proxy

import (
	"context"
	"crypto/ecdsa"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/p2p/rlpx"
)

// TestE2EProxyRelay starts a fake upstream "node", the proxy in front of it,
// and a fake "external peer" that connects through the proxy.  It validates:
//   - Both RLPx handshakes succeed (external ↔ proxy, proxy ↔ upstream)
//   - Hello messages are exchanged on both sides
//   - Application messages are relayed bidirectionally with correct data
func TestE2EProxyRelay(t *testing.T) {
	// Generate three key pairs: node, proxy, external peer.
	nodeKey := genKey(t)
	proxyKey := genKey(t)
	peerKey := genKey(t)

	// ----- Start fake upstream "node" -----
	upListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer upListener.Close()
	upstreamAddr := upListener.Addr().String()
	t.Logf("fake upstream listening on %s", upstreamAddr)

	// Channel to receive messages the upstream "node" reads from the proxy.
	type msg struct {
		code uint64
		data []byte
	}
	nodeGot := make(chan msg, 10)
	peerGot := make(chan msg, 10)

	var wg sync.WaitGroup

	// Upstream node goroutine: accept one connection, handshake, Hello, relay.
	wg.Add(1)
	go func() {
		defer wg.Done()
		conn, err := upListener.Accept()
		if err != nil {
			t.Errorf("upstream accept: %v", err)
			return
		}
		defer conn.Close()

		// The proxy connects as initiator with dialDest = nodeKey.PublicKey.
		// We are the responder (dialDest=nil) using nodeKey.
		rc := rlpx.NewConn(conn, nil)
		conn.SetDeadline(time.Now().Add(10 * time.Second))
		remotePub, err := rc.Handshake(nodeKey)
		if err != nil {
			t.Errorf("upstream handshake: %v", err)
			return
		}
		conn.SetDeadline(time.Time{})
		t.Logf("upstream: handshake OK, remote=%x…", crypto.FromECDSAPub(remotePub)[1:5])

		// Read Hello from proxy.
		code, data, _, err := rc.Read()
		if err != nil {
			t.Errorf("upstream read hello: %v", err)
			return
		}
		if code != HandshakeMsg {
			t.Errorf("upstream: expected hello code 0x00, got 0x%02x", code)
			return
		}
		h, err := decodeHello(data)
		if err != nil {
			t.Errorf("upstream decode hello: %v", err)
			return
		}
		t.Logf("upstream: got Hello from proxy: %q caps=%v", h.Name, h.Caps)

		// Send our Hello back.
		nodeHello := &Hello{
			Version:    5,
			Name:       "fake-node",
			Caps:       defaultXDCCaps(),
			ListenPort: 0,
			ID:         crypto.FromECDSAPub(&nodeKey.PublicKey)[1:],
		}
		helloBytes, _ := encodeHello(nodeHello)
		if _, err := rc.Write(HandshakeMsg, helloBytes); err != nil {
			t.Errorf("upstream write hello: %v", err)
			return
		}

		// Enable snappy after hello.
		rc.SetSnappy(true)

		// Send a test message to the proxy (should be relayed to peer).
		testMsg := []byte("hello-from-node")
		if _, err := rc.Write(0x10, testMsg); err != nil {
			t.Errorf("upstream write test msg: %v", err)
			return
		}
		t.Logf("upstream: sent test message code=0x10")

		// Read a message from the proxy (should be relayed from peer).
		code, data, _, err = rc.Read()
		if err != nil {
			t.Errorf("upstream read relayed msg: %v", err)
			return
		}
		nodeGot <- msg{code, append([]byte{}, data...)}
		t.Logf("upstream: received relayed msg code=0x%02x data=%q", code, data)
	}()

	// ----- Start the proxy -----
	cfg := Config{
		ListenAddr:   "127.0.0.1:0",
		UpstreamAddr: upstreamAddr,
		NodeKey:      nodeKey,
		ProxyKey:     proxyKey,
	}
	srv := NewServer(cfg)
	proxyListener, err := net.Listen("tcp", cfg.ListenAddr)
	if err != nil {
		t.Fatal(err)
	}
	// Assign the actual listener so the server uses it.
	srv.listener = proxyListener
	proxyAddr := proxyListener.Addr().String()
	t.Logf("proxy listening on %s", proxyAddr)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Run proxy accept loop in background.
	wg.Add(1)
	go func() {
		defer wg.Done()
		// Accept loop.
		for {
			conn, err := srv.listener.Accept()
			if err != nil {
				return
			}
			srv.wg.Add(1)
			go func() {
				defer srv.wg.Done()
				sess := &session{
					extConn:      conn,
					upstreamAddr: srv.cfg.UpstreamAddr,
					nodeKey:      srv.cfg.NodeKey,
					proxyKey:     srv.cfg.ProxyKey,
				}
				sess.run(ctx)
			}()
		}
	}()

	// ----- External peer connects to proxy -----
	peerConn, err := net.DialTimeout("tcp", proxyAddr, 5*time.Second)
	if err != nil {
		t.Fatalf("peer dial: %v", err)
	}
	defer peerConn.Close()

	// Peer is the initiator, targeting node's pubkey (proxy presents this).
	pc := rlpx.NewConn(peerConn, &nodeKey.PublicKey)
	peerConn.SetDeadline(time.Now().Add(10 * time.Second))
	remotePub, err := pc.Handshake(peerKey)
	if err != nil {
		t.Fatalf("peer handshake: %v", err)
	}
	peerConn.SetDeadline(time.Time{})

	// Verify the proxy presented the node's public key.
	remoteID := fmt.Sprintf("%x", crypto.FromECDSAPub(remotePub)[1:])
	nodeID := fmt.Sprintf("%x", crypto.FromECDSAPub(&nodeKey.PublicKey)[1:])
	if remoteID != nodeID {
		t.Fatalf("peer: expected node pubkey, got %s…", remoteID[:16])
	}
	t.Logf("peer: handshake OK, remote matches node key")

	// Send Hello to proxy.
	peerHello := &Hello{
		Version:    5,
		Name:       "fake-peer",
		Caps:       defaultXDCCaps(),
		ListenPort: 0,
		ID:         crypto.FromECDSAPub(&peerKey.PublicKey)[1:],
	}
	helloBytes, _ := encodeHello(peerHello)
	if _, err := pc.Write(HandshakeMsg, helloBytes); err != nil {
		t.Fatalf("peer write hello: %v", err)
	}

	// Read Hello from proxy.
	code, data, _, err := pc.Read()
	if err != nil {
		t.Fatalf("peer read hello: %v", err)
	}
	if code != HandshakeMsg {
		t.Fatalf("peer: expected hello code 0x00, got 0x%02x", code)
	}
	h, err := decodeHello(data)
	if err != nil {
		t.Fatalf("peer decode hello: %v", err)
	}
	t.Logf("peer: got Hello from proxy: %q caps=%v", h.Name, h.Caps)

	// Verify Hello.ID matches node's pubkey.
	helloID := fmt.Sprintf("%x", h.ID)
	if helloID != nodeID {
		t.Fatalf("peer: Hello.ID mismatch: got %s…, want %s…", helloID[:16], nodeID[:16])
	}
	t.Logf("peer: Hello.ID correctly matches node key")

	// Enable snappy.
	pc.SetSnappy(true)

	// Read the test message sent by upstream node (relayed through proxy).
	code, data, _, err = pc.Read()
	if err != nil {
		t.Fatalf("peer read relayed msg: %v", err)
	}
	peerGot <- msg{code, append([]byte{}, data...)}
	t.Logf("peer: received relayed msg code=0x%02x data=%q", code, data)

	// Send a test message to proxy (should be relayed to upstream node).
	testMsg := []byte("hello-from-peer")
	if _, err := pc.Write(0x11, testMsg); err != nil {
		t.Fatalf("peer write test msg: %v", err)
	}
	t.Logf("peer: sent test message code=0x11")

	// ----- Verify results -----
	// Check message relayed from node → peer.
	select {
	case m := <-peerGot:
		if m.code != 0x10 {
			t.Errorf("peer: expected code 0x10, got 0x%02x", m.code)
		}
		if string(m.data) != "hello-from-node" {
			t.Errorf("peer: expected 'hello-from-node', got %q", m.data)
		}
		t.Logf("PASS: node→peer relay: code=0x%02x data=%q", m.code, m.data)
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for node→peer message")
	}

	// Check message relayed from peer → node.
	select {
	case m := <-nodeGot:
		if m.code != 0x11 {
			t.Errorf("node: expected code 0x11, got 0x%02x", m.code)
		}
		if string(m.data) != "hello-from-peer" {
			t.Errorf("node: expected 'hello-from-peer', got %q", m.data)
		}
		t.Logf("PASS: peer→node relay: code=0x%02x data=%q", m.code, m.data)
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for peer→node message")
	}

	// Cleanup.
	cancel()
	proxyListener.Close()
	wg.Wait()
	t.Log("all goroutines stopped cleanly")
}

func genKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	return k
}
