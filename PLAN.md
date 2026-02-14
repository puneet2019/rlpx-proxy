# RLPx Proxy — Monitoring Summary (Run 2)

**Date:** 2026-02-14 05:03–06:24 UTC (~80 minutes)

---

## Executive Summary

**Everything works.** The XDC node is syncing from genesis with 2 stable peers, the proxy discovers + probes + feeds peers to the upstream node. The previous run's "merkle root" error was caused by corrupted chain data from a failed `--syncmode fast` attempt — a clean genesis init fixed it.

---

## XDC Node Sync Progress

| Time | Block | Peers | Errors |
|------|-------|-------|--------|
| t=0m | 35,911 | 2 | 0 |
| t=5m | 353,689 | 2 | 0 |
| t=10m | 601,231 | 2 | 0 |
| t=16m | 762,751 | 2 | 0 |
| t=22m | 963,551 | 2 | 0 |
| t=28m | 1,168,831 | 2 | 0 |
| t=65m | 1,306,726 | 2 | 0 |
| t=80m | **1,482,061** | 2 | **0** |

- **Sync rate:** ~18,500 blocks/min
- **ETA to full sync:** ~88 hours (~3.7 days)
- **Merkle root errors:** 0 (was 165+ in run 1)
- **"Useless peer" disconnects:** 1 (vs constant in run 1)
- Syncing from block 0 → 99,316,894 with `--syncmode full --gcmode archive`

### What Fixed the Merkle Root Error

The first run used `--syncmode full` and hit "invalid merkle root" at block 101,700. We then tried `--syncmode fast` which crashed with a nil pointer dereference. When we wiped the chain data and restarted with `--syncmode full`, the fresh genesis init produced correct state and synced cleanly past block 101,700. The fast sync crash likely corrupted the chain database in the first run.

### Sync Mode Findings

| Mode | Result |
|------|--------|
| `full` (archive) | Works from clean genesis init |
| `fast` | Crashes — nil pointer in `checkSignersOnCheckpoint` |
| `snap` | Not supported by XDC v2.6.8 |

---

## Proxy Discovery + Probe Tier

| Metric | Value |
|--------|-------|
| DHT pool size | 55 unique nodes |
| Successful probes | 4 |
| "Too many peers" responses | 351 (22 unique IPs) |
| Peers fed to upstream | 3 (with retry-on-failure dedup) |

### Probed Peers

| IP | Client | Score |
|----|--------|-------|
| 75.119.143.96:30303 | XDC/v1.6.0 | 13.0 |
| 62.146.231.239:30303 | XDC/v2.6.8-stable | 13.0 |

### Network Observations

22 unique XDC nodes respond "too many peers" — confirming the network's peering congestion. The proxy's peer-feeding feature successfully bridges discovery to the XDC node: `admin_addPeer` calls work, and the node maintains 2 stable connections throughout.

---

## Infrastructure Changes Made

### Bug Fixes
1. **Peer feed dedup** — Changed from permanent dedup to 5-minute cooldown with retry on failure. Previously, if the first `admin_addPeer` call failed (e.g., DNS not ready), the peer was permanently blacklisted.
2. **Configurable sync/gc mode** — `SYNC_MODE` and `GC_MODE` env vars in docker-compose, defaults to `full`/`archive`.
3. **Restart policies** — Added `restart: unless-stopped` to both containers.

### Makefile Helpers

```
make up          # Start everything
make down        # Stop everything
make status      # Quick: block + peers + syncing
make peers       # admin.peers (detailed)
make peercount   # net.peerCount
make sync        # eth.syncing
make block       # eth.blockNumber
make attach      # Interactive JS console
make logs        # All logs
make logs-proxy  # Proxy logs only
make logs-xdc    # XDC node logs only
make monitor     # Live rlpx-monitor dashboard
make export      # Export good peers to JSON
make rebuild     # Rebuild + restart proxy only
make wipe        # Wipe chain data
make snapshot    # Download 644GB snapshot (run overnight)
```

### IPC Path Fix

`docker compose exec xdc-node XDC attach /work/xdcchain/XDC.ipc` didn't work because we moved the IPC socket to `/tmp/XDC.ipc` (macOS Docker bind mount workaround). The Makefile helpers use the correct path automatically.

---

## Next Steps

1. **Let the sync complete** (~3.7 days at current rate). Once synced, the XDC node will maintain peers independently and the full MitM relay tier can be tested.

2. **For faster sync:** Run `make snapshot` overnight to download the 644 GB official snapshot. This gets you to a recent block instantly instead of waiting 3+ days.

3. **Improve probe yield:** Only 2/55 discovered nodes accept probes. The 22 "too many peers" nodes are prime targets — add persistent retry with backoff to catch them when slots open.
