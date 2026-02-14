package proxy

import (
	"context"
	"crypto/ecdsa"
	"fmt"
	"log"
	"net"
	"strconv"
	"sync"

	"github.com/ethereum/go-ethereum/p2p/discover"
	"github.com/ethereum/go-ethereum/p2p/enode"
)

// Discovery manages discv4 + discv5 DHT peer discovery.
type Discovery struct {
	v4 *discover.UDPv4
	v5 *discover.UDPv5 // nil if v5 listen fails (non-fatal)

	localNode *enode.LocalNode
	db        *enode.DB

	mu   sync.Mutex
	pool map[enode.ID]*enode.Node // all discovered nodes
}

// NewDiscovery creates discv4 and discv5 discovery listeners.
// discv4 listens on v4Addr, discv5 on v5Addr. Both share the same
// node identity and bootnode list. discv5 failure is non-fatal.
func NewDiscovery(key *ecdsa.PrivateKey, v4Addr, v5Addr string, bootnodes []*enode.Node) (*Discovery, error) {
	db, err := enode.OpenDB("")
	if err != nil {
		return nil, err
	}
	ln := enode.NewLocalNode(db, key)

	cfg := discover.Config{
		PrivateKey: key,
		Bootnodes:  bootnodes,
	}

	// Start discv4.
	udp4, err := listenUDP(v4Addr)
	if err != nil {
		db.Close()
		return nil, fmt.Errorf("discv4 listen: %w", err)
	}
	v4, err := discover.ListenV4(udp4, ln, cfg)
	if err != nil {
		udp4.Close()
		db.Close()
		return nil, fmt.Errorf("discv4: %w", err)
	}
	log.Printf("[discovery] discv4 listening on %s with %d bootnodes", v4Addr, len(bootnodes))

	// Start discv5 (non-fatal if it fails).
	var v5 *discover.UDPv5
	if v5Addr != "" {
		udp5, err := listenUDP(v5Addr)
		if err != nil {
			log.Printf("[discovery] discv5 listen on %s failed: %v (continuing with v4 only)", v5Addr, err)
		} else {
			v5, err = discover.ListenV5(udp5, ln, cfg)
			if err != nil {
				udp5.Close()
				log.Printf("[discovery] discv5 start failed: %v (continuing with v4 only)", err)
			} else {
				log.Printf("[discovery] discv5 listening on %s", v5Addr)
			}
		}
	}

	return &Discovery{
		v4:        v4,
		v5:        v5,
		localNode: ln,
		db:        db,
		pool:      make(map[enode.ID]*enode.Node),
	}, nil
}

func listenUDP(addr string) (*net.UDPConn, error) {
	a, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, err
	}
	return net.ListenUDP("udp", a)
}

// Run continuously walks both DHTs and sends newly discovered nodes to peerCh.
// It blocks until ctx is cancelled.
func (d *Discovery) Run(ctx context.Context, peerCh chan<- *enode.Node) {
	var wg sync.WaitGroup

	// Run discv4 iterator.
	wg.Add(1)
	go func() {
		defer wg.Done()
		d.runIterator(ctx, d.v4.RandomNodes(), "v4", peerCh)
	}()

	// Run discv5 iterator if available.
	if d.v5 != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			d.runIterator(ctx, d.v5.RandomNodes(), "v5", peerCh)
		}()
	}

	wg.Wait()
}

// runIterator consumes a single discovery iterator and deduplicates into peerCh.
func (d *Discovery) runIterator(ctx context.Context, iter enode.Iterator, tag string, peerCh chan<- *enode.Node) {
	defer iter.Close()

	for iter.Next() {
		select {
		case <-ctx.Done():
			return
		default:
		}

		node := iter.Node()
		if node.TCP() == 0 {
			continue
		}

		d.mu.Lock()
		_, seen := d.pool[node.ID()]
		if !seen {
			d.pool[node.ID()] = node
		}
		d.mu.Unlock()

		if seen {
			continue
		}

		log.Printf("[discovery/%s] new node: %s @ %s:%d (pool size: %d)",
			tag, node.ID().TerminalString(), node.IP(), node.TCP(), d.PoolSize())

		select {
		case peerCh <- node:
		case <-ctx.Done():
			return
		}
	}
}

// Close shuts down all discovery listeners and the database.
func (d *Discovery) Close() {
	d.v4.Close()
	if d.v5 != nil {
		d.v5.Close()
	}
	d.db.Close()
}

// PoolSize returns the number of unique nodes discovered so far.
func (d *Discovery) PoolSize() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return len(d.pool)
}

// ParseBootnodes parses a list of enode URL strings into enode.Node objects.
// Invalid entries are logged and skipped.
func ParseBootnodes(enodes []string) []*enode.Node {
	var nodes []*enode.Node
	for _, raw := range enodes {
		node, err := enode.Parse(enode.ValidSchemes, raw)
		if err != nil {
			log.Printf("[discovery] skipping invalid bootnode %q: %v", raw, err)
			continue
		}
		nodes = append(nodes, node)
	}
	return nodes
}

// UpstreamBootnode constructs an enode.Node from the upstream node's public key
// and address, for use as a discovery bootstrap node.
func UpstreamBootnode(nodeKey *ecdsa.PrivateKey, upstreamAddr string) (*enode.Node, error) {
	host, portStr, err := net.SplitHostPort(upstreamAddr)
	if err != nil {
		return nil, fmt.Errorf("split upstream addr: %w", err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return nil, fmt.Errorf("parse port: %w", err)
	}

	ips, err := net.LookupIP(host)
	if err != nil {
		return nil, fmt.Errorf("resolve %s: %w", host, err)
	}
	var ip net.IP
	for _, addr := range ips {
		if v4 := addr.To4(); v4 != nil {
			ip = v4
			break
		}
	}
	if ip == nil && len(ips) > 0 {
		ip = ips[0]
	}
	if ip == nil {
		return nil, fmt.Errorf("no IP addresses for %s", host)
	}

	return enode.NewV4(&nodeKey.PublicKey, ip, port, port), nil
}
