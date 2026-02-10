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

#### Start2 Enhanced Monitoring (requires sudo)
```bash
# Start enhanced monitoring with peer tracking and statistics
peer-sniffer start2

# Enhanced monitoring with handshake tracking (default behavior)
peer-sniffer start2 --track-handshakes

# Different output formats
peer-sniffer start2 --output json
peer-sniffer start2 --output text
peer-sniffer start2 --output csv

# Custom filter
peer-sniffer start2 --filter "tcp port 30303"
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

## Docker Compose Setup

The project includes a Docker Compose setup for running the peer sniffer alongside an XDC node:

```yaml
version: '3.8'

services:
  xdc-peer-sniffer:
    build:
      context: .
      dockerfile: Dockerfile
    container_name: xdc-peer-sniffer
    command: ["./peer-sniffer", "start2", "--track-handshakes=true", "--output=json"]
    network_mode: "host"  # Allows the container to access host network interfaces
    volumes:
      - ./peerd-data:/root/.peerd  # Mount volume to persist peer data
    privileged: true  # Required for network packet capture
    restart: unless-stopped
    environment:
      - HOME=/root
    logging:
      driver: "json-file"
      options:
        max-size: "10m"
        max-file: "3"

  xdc-node:  # Placeholder for your XDC node service
    image: your-xdc-node-image:latest  # Replace with your actual XDC node image
    container_name: xdc-node
    ports:
      - "30303:30303/tcp"
      - "30303:30303/udp"
      - "8545:8545"  # RPC port
      - "8546:8546"  # WebSocket port
    volumes:
      - ./xdc-data:/root/.xdc  # Mount for XDC node data
      - ./peerd-data:/root/.peerd  # Share peer data with sniffer
    restart: unless-stopped
    depends_on:
      - xdc-peer-sniffer
    logging:
      driver: "json-file"
      options:
        max-size: "10m"
        max-file: "3"
```

### Running with Docker Compose

1. Build and start the services:
```bash
docker-compose up -d
```

2. View logs:
```bash
docker-compose logs -f xdc-peer-sniffer
```

3. The peer sniffer will generate statistics and save top peers to `/peerd-data/top-peers.json` inside the container, which can be accessed from the host at `./peerd-data/top-peers.json`.

## Use Case: Dynamic Peer Management

The `start2` command is specifically designed to work with XDC nodes in a Docker Compose setup to:

- Monitor handshakes from the beginning to identify peer IDs
- Track peer activity levels to determine which peers are active
- Generate a list of top-performing peers that can be used to update static peer lists
- Help maintain healthy connections by identifying and promoting good peers while demoting inactive ones

## Advanced Features

### Top Peers Tracking
The `start2` command generates a `top-peers.json` file that contains the most active peers based on handshake activity and connection frequency. This file can be used to maintain an optimized list of reliable peers for your XDC node.

### Real-time Statistics
During monitoring, the `start2` command provides real-time statistics showing the most active peers with information about:
- Number of handshakes initiated
- Number of connections made
- Last seen timestamp
- Activity score based on engagement level

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