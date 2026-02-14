# rlpx-proxy

A standalone P2P gossip layer for the [XDC Network](https://xinfin.org). It speaks the RLPx/devp2p protocol natively — no XDC node required — to discover, connect to, and monitor every reachable peer on the network. It extends gossip across the protocol by relaying blocks, transactions, and consensus messages between peers, without storing any chain data.

```
                         ┌─────────────────────────────────────────┐
                         │              rlpx-proxy                 │
                         │                                         │
  ┌───────────┐   discv4 │  ┌───────────┐      ┌───────────────┐  │
  │ XDC Peers │◄────────►│  │ Discovery │─────►│ Monitor Pool  │  │
  │ (network) │   discv5 │  │ v4 + v5   │      │ (100 conns)   │  │
  │           │◄────────►│  └───────────┘      └───────┬───────┘  │
  │           │          │                             │          │
  │           │◄─ RLPx ─►│  ┌─────────────┐    ┌──────┴───────┐  │
  │           │  (TCP)   │  │ Broadcaster │◄──►│  PeerStore   │  │
  │           │          │  │ (fan-out)   │    │  (scoring)   │  │
  └───────────┘          │  └─────────────┘    └──────┬───────┘  │
                         │                            │          │
                         │                     ┌──────┴───────┐  │
                         │                     │  HTTP API    │  │
                         │                     │  :8080       │  │
                         │                     └──────────────┘  │
                         └─────────────────────────────────────────┘
```

## What It Does

XDC network nodes often max out their peer slots, making it difficult for new nodes to join. A bootnode list tells you *where* peers are, but not *whether they're healthy or have room*. rlpx-proxy solves this by building a live **nodebook** — a scored directory of every reachable peer with quality ratings.

**Key capabilities:**

- **Peer Discovery** — Crawls the network using both discv4 and discv5 DHT protocols simultaneously, starting from 235 known XDC mainnet bootnodes.
- **Persistent Monitoring** — Maintains up to 100 concurrent encrypted RLPx connections. Each connection performs a full handshake, protocol negotiation (eth/62, eth/63, eth/100), and Status exchange.
- **Gossip Extension** — Relays `NewBlock`, `NewBlockHashes`, and transaction messages between connected peers. Peers that can't directly reach each other stay in sync through the proxy.
- **Consensus Tracking** — Decodes XDPoS v2 `Vote` and `Timeout` consensus messages to track the chain head per peer — XDC uses these instead of traditional `NewBlock` for block propagation.
- **Peer Scoring** — Rates each peer 0–100 based on chain head freshness, latency, uptime, and reliability.
- **HTTP API** — Exposes network stats, full peer list, and filtered enode export.

**What it is NOT:**

- Not a full node — stores zero chain data (only a rolling 256-block header/body cache for protocol compliance)
- Not a bootnode list — it includes quality/health ratings, not just addresses
- Not a block explorer — it tracks the chain head for scoring purposes only

## Architecture

The system has five main components that run concurrently:

```
Bootnode List (.txt)
       │
       ▼
┌─────────────┐     ┌──────────────┐     ┌─────────────┐
│  Discovery   │────►│ Monitor Pool │────►│  PeerStore   │
│  (discv4+v5) │     │ (RLPx conns) │     │  (scoring)   │
└─────────────┘     └──────┬───────┘     └──────┬──────┘
                           │                     │
                    ┌──────┴───────┐      ┌──────┴──────┐
                    │ Broadcaster  │      │  HTTP API   │
                    │ (block relay)│      │  /stats     │
                    │              │      │  /peers     │
                    └──────────────┘      │  /peers/    │
                                          │   export    │
                                          └─────────────┘
```

### Flow

1. **Discovery** finds peers via UDP DHT (discv4 on `:30301`, discv5 on `:30302`)
2. **Bootnode seeder** pushes known bootnode IPs directly (bypasses DHT key dedup for networks like XDC where bootnodes share keys)
3. **Monitor Pool** picks up discovered nodes and opens persistent RLPx connections (bounded by semaphore to `MAX_OUTBOUND`)
4. Each **monitor session** does: TCP dial → RLPx encryption handshake → Hello exchange → Status exchange (mirrors peer's chain state so they treat us as synced) → message loop
5. The **message loop** handles: ping/pong keep-alive, block/tx propagation, XDPoS Vote/Timeout tracking, GetHeaders/GetBodies responses from cache
6. **Broadcaster** fans out NewBlock/NewBlockHashes/Txs to all connected peers with dedup (30s TTL)
7. **PeerStore** records every event (connect, disconnect, head update, latency, messages) and computes quality scores
8. **HTTP API** serves the data as JSON

### Adaptive Retry

When a peer disconnects, the retry strategy adapts:

| Result | Retry Delay | Rationale |
|--------|-------------|-----------|
| Connected (useful/brief) | 10s | Was alive, retry quickly |
| "Too many peers" | 10s flat | Alive but full — slots churn frequently |
| Dead (dial fail, handshake fail) | 30s → 45s → ... → 2min | Exponential backoff with 1.5x multiplier |

Port fallback: if the enode port fails, also tries `:30303` and `:30304`.

## Quick Start

### Docker (recommended)

```bash
cd example
cp .env.example .env

# Generate a P2P key (or use an existing one):
echo "NODE_P2P_KEY=$(openssl rand -hex 32)" > .env

# Start:
docker compose up -d --build

# Check:
curl -s localhost:8080/stats | jq .
curl -s localhost:8080/peers | jq .
```

### Local Binary

```bash
# Build:
make build

# Run:
NODE_PRIVATE_KEY=$(openssl rand -hex 32) \
BOOTNODES_FILE=example/xdc-bootnodes.txt \
  ./build/rlpx-proxy
```

### Docker Buildx (multi-platform)

```bash
# Build and push for amd64 + arm64:
make docker-buildx IMAGE=yourregistry/rlpx-proxy TAG=latest
```

## Configuration

All configuration is via environment variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `NODE_PRIVATE_KEY` | (required) | Hex-encoded secp256k1 private key (no `0x` prefix). This is the node's P2P identity. |
| `BOOTNODES_FILE` | — | Path to a file with enode URLs (one per line). Ships with 235 XDC mainnet bootnodes. |
| `BOOTNODES` | — | Comma-separated enode URLs (alternative to file). |
| `DISCOVERY_ADDR` | `:30301` | UDP listen address for discv4. |
| `DISCOVERY_V5_ADDR` | `:30302` | UDP listen address for discv5. |
| `MAX_OUTBOUND` | `100` | Max concurrent outbound RLPx connections. |
| `API_ADDR` | `:8080` | HTTP API listen address. |

## HTTP API

### `GET /stats`

Network summary.

```json
{
  "total_peers": 54,
  "connected_peers": 2,
  "best_block": 99319952,
  "dht_pool_size": 54
}
```

### `GET /peers`

Full peer list sorted by score (descending).

```json
[
  {
    "addr": "62.146.231.239:30303",
    "peer_id": "784670fa...",
    "client": "XDC/v2.6.8-stable/linux-amd64/go1.23.12",
    "caps": [{"Name": "eth", "Version": 100}, ...],
    "enode": "enode://784670fa...@62.146.231.239:30303",
    "head_block": 99319952,
    "head_hash": "0x4bd667...",
    "latency_ms": 206,
    "connected": true,
    "sessions": 4,
    "msg_count": 5211,
    "first_seen": "2026-02-14T21:03:26Z",
    "last_seen": "2026-02-14T21:05:43Z",
    "score": 93
  }
]
```

### `GET /peers/export?min_score=N`

Export enode URLs of peers above a quality threshold.

```json
[
  "enode://784670fa...@62.146.231.239:30303",
  "enode://6ec1ac63...@75.119.143.96:30303"
]
```

## Peer Scoring

Each peer is scored 0–100 across four dimensions:

| Dimension | Points | Criteria |
|-----------|--------|----------|
| **Chain head freshness** | 0–40 | At best block: 40. Lag < 10: 30. Lag < 100: 20. Lag < 1000: 10. |
| **Latency** | 0–20 | < 100ms: 20. < 300ms: 15. < 1s: 10. < 3s: 5. |
| **Recency** | 0–20 | Last seen < 1min: 20. < 5min: 15. < 30min: 10. < 1hr: 5. |
| **Reliability** | 0–20 | Sessions (2pts each, max 10) + messages (1pt per 100, max 10). |

## Project Structure

```
rlpx-proxy/
├── cmd/
│   └── rlpx-proxy/
│       └── main.go              # Entry point, env var parsing, signal handling
│
├── proxy/
│   ├── server.go                # Server struct, Config, ListenAndServe orchestration
│   ├── discovery.go             # discv4 + discv5 DHT peer discovery (parallel iterators)
│   ├── monitor.go               # Monitor pool, session lifecycle, message loop
│   ├── peerstore.go             # Thread-safe peer database with quality scoring
│   ├── blockcache.go            # Rolling 256-block LRU cache (headers + bodies)
│   ├── broadcast.go             # Fan-out message relay with hash-based dedup
│   ├── devp2p.go                # Hello/Cap structs, capability negotiation
│   ├── ethstatus.go             # Status encode/decode, genesis learning, XDPoS Vote decoder
│   ├── msgnames.go              # Message code constants and human-readable names
│   ├── api.go                   # HTTP API handlers (/stats, /peers, /peers/export)
│   │
│   ├── peerstore_test.go        # PeerStore scoring, connect/disconnect, head tracking
│   ├── blockcache_test.go       # Cache add/retrieve, eviction, invalid data
│   ├── broadcast_test.go        # Fan-out, sender exclusion, dedup, buffer overflow
│   ├── devp2p_test.go           # Eth version negotiation, Hello RLP round-trip
│   ├── ethstatus_test.go        # Status round-trip, Vote decoding
│   ├── msgnames_test.go         # Message name lookup, protocol classification
│   └── monitor_test.go          # NewBlockHashes parsing, disconnect reasons
│
├── example/
│   ├── docker-compose.yml       # Docker Compose for standalone deployment
│   ├── .env.example             # Template environment file
│   └── xdc-bootnodes.txt        # 235 XDC mainnet bootnode enode URLs
│
├── Dockerfile                   # Multi-platform build (amd64 + arm64)
├── Makefile                     # Build, test, docker, compose, API helpers
├── .dockerignore
├── .gitignore
├── go.mod
└── go.sum
```

### File Details

| File | Purpose |
|------|---------|
| `server.go` | Top-level orchestration. Creates all subsystems, starts discovery, monitor pool, and API. Handles bootnode seeding (reseed every 5 min). |
| `discovery.go` | Manages two parallel UDP listeners (discv4 + discv5). Both feed a shared `peerCh` channel with deduplication by node ID. Falls back gracefully if discv5 fails. |
| `monitor.go` | Core of the system. `runMonitorPool` manages a bounded pool of goroutines. `connectLoop` handles adaptive retry. `runSession` does dial → handshake → hello → status → message loop. Handles all eth and XDPoS message types. |
| `peerstore.go` | Thread-safe `map[addr]*PeerRecord` with methods for recording events and computing scores. `AllPeers()` returns a snapshot sorted by score. |
| `blockcache.go` | Caches the last 256 blocks from `NewBlock` messages. Serves `GetBlockHeaders` and `GetBlockBodies` requests from cache so peers don't disconnect us for not responding. |
| `broadcast.go` | Register/Unregister pattern. Each peer gets a buffered channel. `Broadcast()` sends to all except sender, with hash-based dedup (30s TTL). Drops messages if a peer's buffer is full. |
| `devp2p.go` | RLP encode/decode for Hello messages. `allCaps()` advertises eth/62, eth/63, eth/67, eth/68, eth/100, snap/1. `negotiateEthVersion()` picks the highest common version. Includes `decodeDisconnectReason()` for parsing peer disconnect messages. |
| `ethstatus.go` | Status message handling. `makeStatus()` mirrors the peer's TD/Head/Genesis so they treat us as a synced node. Includes XDPoS Vote struct decoder for extracting block numbers from consensus messages. |

## Protocol Details

The XDC network is an old Ethereum fork. Its P2P stack is unchanged go-ethereum code, but with some XDC-specific additions:

- **eth/100**: XDC's custom protocol version (in addition to eth/62, eth/63)
- **XDPoS Vote (0xF0)**: Consensus message containing `{ProposedBlockInfo: {Hash, Round, Number}, Signature, GapNumber}` — this is how block numbers propagate in XDPoS v2
- **XDPoS Timeout (0xF1)**: Consensus timeout message — indicates an active peer
- **Status mirroring**: We read the peer's Status first, then send ours mirroring their TD/Head/Genesis. This makes the peer treat us as a synced node and broadcast new blocks to us.

## Testing

```bash
# Run all tests:
make test

# Run with verbose output:
go test -v ./...

# Run only unit tests (skip network tests):
go test -short ./...
```

Test coverage:
- **Unit tests**: PeerStore, BlockCache, Broadcaster, devp2p negotiation, RLP encode/decode, XDPoS Vote parsing, message names, disconnect reason decoding

## Makefile Targets

```
make build         # Build binary to ./build/rlpx-proxy
make clean         # Remove build artifacts
make test          # Run go vet + go test

make docker-build  # Build Docker image
make docker-push   # Build + push Docker image
make docker-buildx # Multi-platform build + push (amd64 + arm64)

make up            # docker compose up (from example/)
make down          # docker compose down
make logs          # Tail all container logs
make logs-proxy    # Tail proxy logs only
make rebuild       # Rebuild + restart proxy container

make stats         # curl /stats
make peers         # curl /peers
make export        # curl /peers/export?min_score=20
```

## Network Observations

From testing against XDC mainnet (Feb 2026):

- **235 bootnodes** in the shipped list
- **~54 unique nodes** discovered via discv4 + discv5 combined (discv5 finds ~2.5x more)
- **~22 nodes** respond "too many peers" — genuine network congestion
- **~20 nodes** drop TCP with EOF during handshake (likely also congested)
- **2–5 nodes** typically accept connections at any given time
- **Block tracking** works via XDPoS Vote messages (not traditional NewBlock)
- **Best block** advances in real-time through consensus message decoding

---

Built with assistance from Claude (Anthropic) and Qwen (Alibaba).
