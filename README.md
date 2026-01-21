# XDC Peer Sniffer

A Go application that captures and analyzes peer-to-peer traffic on the XDC network with peer scoring capabilities.

## Overview

This tool captures network packets on your machine and analyzes peer-to-peer traffic on the XDC (XinFin) network. It monitors specific ports used by XDC nodes, decodes protocol data, and provides peer scoring with a configurable sliding window.

## Prerequisites

### macOS
```bash
# Install libpcap development libraries
brew install libpcap
```

### Linux (Ubuntu/Debian)
```bash
sudo apt-get update
sudo apt-get install libpcap-dev
```

### Linux (CentOS/RHEL/Fedora)
```bash
sudo yum install libpcap-devel
# or for newer versions
sudo dnf install libpcap-devel
```

## Installation

1. Clone or download this repository
2. Navigate to the project directory
3. Install Go dependencies:
```bash
go mod tidy
```

## Usage

### Commands

The application uses a command-line interface with multiple subcommands:

#### Initialize
```bash
# Initialize the .peerd directory with default config and .env
peer-sniffer init
```

#### Start Monitoring
```bash
# Start monitoring XDC network traffic
peer-sniffer start

# Specify network interface directly
peer-sniffer start --interface en0

# Log only XDC traffic
peer-sniffer start --xdc-only

# Use specific interface
peer-sniffer start --interface en0 --xdc-only
```

#### Show Peer Data
```bash
# Show collected peer statistics in table format
peer-sniffer show

# Show collected peer statistics in JSON format
peer-sniffer show --format json
```

#### Help
```bash
# Show help
peer-sniffer --help

# Show help for a specific command
peer-sniffer start --help
peer-sniffer show --help
```

### Configuration

The application stores configuration and data in `~/.peerd/` directory:
- `config.json` - Configuration file
- `peer-data.json` - Collected peer statistics
- `.env` - Environment variables

The default configuration includes:

```json
{
  "interface": "en0",
  "log_xdc_only": false,
  "xdc_nodes": [],
  "xdc_ports": [
    "30303",
    "30304", 
    "30305",
    "30306",
    "30307",
    "30308",
    "30309",
    "30310",
    "30311",
    "30312",
    "30313"
  ],
  "buffer_size": 1600,
  "promiscuous_mode": true
}
```

### Network Interface Selection

The application defaults to monitoring `en0` interface. To see available interfaces:

#### On macOS:
```bash
networksetup -listallhardwareports
# or
ifconfig
```

#### On Linux:
```bash
ip link show
# or
ifconfig -a
```

## OS-Level Configuration

### macOS

On macOS, you need to grant special permissions for packet capture:

1. **Run with sudo** (recommended for development):
```bash
sudo peer-sniffer start
```

2. **Or create a privileged helper** (for production):
   - macOS requires special entitlements for raw socket access
   - Consider building a signed application with appropriate entitlements
   - The application will need the `com.apple.security.network.socket` entitlement

### Linux

On Linux, you need to run with appropriate privileges:

1. **Run with sudo**:
```bash
sudo peer-sniffer start
```

## Environment Variables

For handling encrypted data, set the XDC private key:

```bash
export XDC_PRIVATE_KEY="your_private_key_here"
```

## Output Format

The application outputs JSON-formatted records for each captured packet:

```json
{
  "timestamp": "2023-10-01T12:34:56.789Z",
  "src_ip": "192.168.1.100",
  "dst_ip": "172.217.164.14",
  "src_port": "54321",
  "dst_port": "30303",
  "protocol": "TCP",
  "data": "hex_encoded_payload",
  "is_xdc": true,
  "size": 1234
}
```

## Peer Scoring System

The application includes an automatic peer scoring system with a configurable sliding window (default 100 seconds) that tracks:

- **Message Direction**: Distinguishes between outgoing (from our node) and incoming (to our node) messages
- **Message Types**: Tracks different types of XDC protocol messages (transactions, blocks, pings, etc.)
- **Peer Statistics**: Maintains statistics for each peer including:
  - Last seen timestamp
  - Total message count
  - Incoming vs outgoing message counts
  - Message type distribution
- **Stale Peer Detection**: Identifies peers that are no longer active or frequently disconnecting

The system helps identify:
- **Good Peers**: Active in propagating transactions and blocks
- **Bad Peers**: Frequently disconnecting or inactive

### Statistics Storage

Peer statistics are automatically saved to `~/.peerd/peer-data.json` and can be viewed with:
```bash
peer-sniffer show
```

## Building

To build a standalone executable:

```bash
make build
```

Then run:
```bash
sudo ./build/peer-sniffer start [options]
```

## Installing

To install the binary to your Go bin directory:

```bash
make install-go
```

This will install the binary to `~/go/bin/peer-sniffer`.

## Decoding Capabilities

The application attempts to decode various types of XDC network data:

- DevP2P protocol messages (Hello, Ping, Pong, etc.)
- RLP-encoded data structures
- XDC-specific protocol identifiers
- Potentially encrypted data (with private key provided)

## Troubleshooting

- If you get "Permission denied" errors, try running with `sudo`
- If no packets are captured, verify the correct network interface is selected
- On macOS, if you get libpcap errors, ensure Xcode command line tools are installed: `xcode-select --install`
- Check `~/.peerd/peer-data.json` for collected peer statistics
- If using a VPN, traffic may be routed through the VPN interface instead of the physical interface