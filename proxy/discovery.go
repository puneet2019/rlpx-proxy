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

// Discovery manages discv4 DHT peer discovery.
type Discovery struct {
	disc      *discover.UDPv4
	localNode *enode.LocalNode
	db        *enode.DB

	mu   sync.Mutex
	pool map[enode.ID]*enode.Node // all discovered nodes
}

// NewDiscovery creates a new discv4 discovery instance that listens for
// UDP packets on listenAddr and bootstraps from the given bootnodes.
func NewDiscovery(key *ecdsa.PrivateKey, listenAddr string, bootnodes []*enode.Node) (*Discovery, error) {
	db, err := enode.OpenDB("")
	if err != nil {
		return nil, err
	}
	ln := enode.NewLocalNode(db, key)

	addr, err := net.ResolveUDPAddr("udp", listenAddr)
	if err != nil {
		db.Close()
		return nil, err
	}
	udpConn, err := net.ListenUDP("udp", addr)
	if err != nil {
		db.Close()
		return nil, err
	}

	cfg := discover.Config{
		PrivateKey: key,
		Bootnodes:  bootnodes,
	}
	disc, err := discover.ListenV4(udpConn, ln, cfg)
	if err != nil {
		udpConn.Close()
		db.Close()
		return nil, err
	}

	log.Printf("[discovery] listening on %s with %d bootnodes", listenAddr, len(bootnodes))

	return &Discovery{
		disc:      disc,
		localNode: ln,
		db:        db,
		pool:      make(map[enode.ID]*enode.Node),
	}, nil
}

// Run continuously walks the DHT and sends newly discovered nodes to peerCh.
// It blocks until ctx is cancelled.
func (d *Discovery) Run(ctx context.Context, peerCh chan<- *enode.Node) {
	iter := d.disc.RandomNodes()
	defer iter.Close()

	for iter.Next() {
		select {
		case <-ctx.Done():
			return
		default:
		}

		node := iter.Node()
		if node.TCP() == 0 {
			continue // skip nodes without a TCP port
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

		log.Printf("[discovery] new node: %s @ %s:%d (pool size: %d)",
			node.ID().TerminalString(), node.IP(), node.TCP(), d.PoolSize())

		select {
		case peerCh <- node:
		case <-ctx.Done():
			return
		}
	}
}

// Close shuts down the discovery listener and database.
func (d *Discovery) Close() {
	d.disc.Close()
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
// and address, for use as a discv4 bootstrap node. This lets discovery
// auto-bootstrap from the upstream XDC node without any explicit bootnode config.
func UpstreamBootnode(nodeKey *ecdsa.PrivateKey, upstreamAddr string) (*enode.Node, error) {
	host, portStr, err := net.SplitHostPort(upstreamAddr)
	if err != nil {
		return nil, fmt.Errorf("split upstream addr: %w", err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return nil, fmt.Errorf("parse port: %w", err)
	}

	// Resolve hostname to IP (handles docker hostnames, etc.).
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
		ip = ips[0] // fallback to IPv6
	}
	if ip == nil {
		return nil, fmt.Errorf("no IP addresses for %s", host)
	}

	// The upstream XDC node uses nodeKey's public key as its identity.
	// TCP and UDP ports are the same for standard Ethereum/XDC nodes.
	return enode.NewV4(&nodeKey.PublicKey, ip, port, port), nil
}
