# Peer Sniffer

A Go application that captures and analyzes network traffic with focus on XDC (XinFin) protocol detection and peer analysis.

## Overview

This tool captures network packets on your machine and analyzes traffic to identify XDC (XinFin) network communications. It uses port-based filtering (30000-65535) and protocol analysis to detect XDC traffic, with enhanced local/external connection handling.

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
# Initialize the .peerd directory with default config
peer-sniffer init
```

#### Start Monitoring (requires sudo)
```bash
# Start monitoring XDC network traffic
peer-sniffer start

# Log only XDC traffic (filtered by port range 30000-65535)
peer-sniffer start --xdc-only
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

### Network Interface Selection

The application monitors all interfaces by default. The tool automatically detects local machine IP addresses and applies intelligent filtering based on connection type.

## OS-Level Configuration

### macOS

On macOS, you need to grant special permissions for packet capture:

**Run with sudo** (required):
```bash
sudo peer-sniffer start
```

### Linux

On Linux, you need to run with appropriate privileges:

**Run with sudo**:
```bash
sudo peer-sniffer start
```

## Features

### Port-Based Filtering
- Filters traffic in the XDC port range (30000-65535)
- Intelligent handling of local vs external connections
- When one endpoint is local, only checks the external machine's port
- When both endpoints are external, checks both ports

### Local/External Connection Handling
- Automatically detects local machine IP addresses across all network interfaces
- Properly identifies 192.168.x.x, 10.x.x.x, 172.16-31.x.x, and other local address ranges
- Optimizes filtering based on connection direction

### Protocol Analysis
- Detects DevP2P handshakes
- Identifies Discovery V4/V5 packets
- Recognizes encrypted RLPx frames
- Analyzes XDC-specific protocol structures

### Output Format

The application outputs JSON-formatted records for each captured packet:

```json
{
  "timestamp": "2023-10-01T12:34:56.789Z",
  "src_ip": "192.168.1.100",
  "dst_ip": "172.217.164.14",
  "src_port": "54321",
  "dst_port": "30303",
  "protocol": "TCP",
  "is_xdc": true,
  "details": "DevP2P ECIES handshake",
  "type": "DevP2PHandshake",
  "data": "hex_encoded_payload",
  "size": 1234
}
```

### Peer Data Collection

Peer statistics are automatically saved to `~/.peerd/peer-data.json` and include:
- Last seen timestamp
- Total message count
- Protocol distribution
- Message type breakdown

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

## Troubleshooting

- If you get "Permission denied" errors, try running with `sudo`
- If no packets are captured, ensure you're running with appropriate privileges
- On macOS, if you get libpcap errors, ensure Xcode command line tools are installed: `xcode-select --install`
- Check `~/.peerd/peer-data.json` for collected peer statistics
- If using a VPN, traffic may be routed through the VPN interface