#!/bin/bash
# Custom XDC mainnet start script.
# Based on the upstream cicd/mainnet/start.sh, with fixes for:
#   - IPC socket on macOS Docker bind mounts (--ipcpath /tmp/XDC.ipc)
#   - P2P node key from env var (--nodekeyhex $XDC_NODEKEYHEX)

set -e

DATADIR=/work/xdcchain

# First run: import account and init genesis.
if [ ! -d "$DATADIR/XDC/chaindata" ]; then
  if [ -z "$PRIVATE_KEY" ]; then
    echo "PRIVATE_KEY environment variable has not been set."
    exit 1
  fi
  echo "$PRIVATE_KEY" > /tmp/key
  wallet=$(XDC account import --password .pwd --datadir "$DATADIR" /tmp/key | awk -F '[{}]' '{print $2}')
  rm -f /tmp/key
  XDC --datadir "$DATADIR" init /work/genesis.json
else
  wallet=$(XDC account list --datadir "$DATADIR" | head -n 1 | awk -F '[{}]' '{print $2}')
fi

# Read bootnodes from file.
bootnodes=""
if [ -f /work/bootnodes.list ]; then
  while IFS= read -r line || [ -n "$line" ]; do
    line=$(echo "$line" | tr -d '[:space:]')
    [ -z "$line" ] && continue
    if [ -z "$bootnodes" ]; then
      bootnodes="$line"
    else
      bootnodes="${bootnodes},${line}"
    fi
  done < /work/bootnodes.list
fi

log_level=${LOG_LEVEL:-4}
port=${PORT:-30303}
rpc_port=${RPC_PORT:-8545}
ws_port=${WS_PORT:-8555}
sync_mode=${SYNC_MODE:-snap}
gc_mode=${GC_MODE:-full}

# Detect external IP for NAT traversal.
INSTANCE_IP=$(curl -s --max-time 5 https://checkip.amazonaws.com || echo "")
if [ -n "$INSTANCE_IP" ]; then
  echo "Detected external IP: $INSTANCE_IP"
  nat_flag="--nat extip:${INSTANCE_IP}"
else
  echo "Could not detect external IP, using --nat any"
  nat_flag="--nat any"
fi

# Build optional flags.
extra_flags=""
if [ -n "$XDC_NODEKEYHEX" ]; then
  extra_flags="$extra_flags --nodekeyhex $XDC_NODEKEYHEX"
  echo "Using P2P node key from XDC_NODEKEYHEX"
fi

echo "Running node with wallet: ${wallet}"
echo "Bootnodes: ${bootnodes:-(none)}"

echo "Sync mode: $sync_mode | GC mode: $gc_mode"

exec XDC \
  --gcmode "$gc_mode" \
  $nat_flag \
  --bootnodes "$bootnodes" \
  --syncmode "$sync_mode" \
  --datadir "$DATADIR" \
  --networkid 50 \
  --port "$port" \
  --http --http-corsdomain "*" --http-addr 0.0.0.0 \
  --http-port "$rpc_port" \
  --http-api admin,db,eth,debug,net,shh,txpool,personal,web3,XDPoS \
  --http-vhosts "*" \
  --unlock "$wallet" --password /work/.pwd --mine \
  --miner-gasprice "1" --miner-gaslimit "420000000" \
  --verbosity "$log_level" \
  --debugdatadir "$DATADIR" \
  --store-reward \
  --ws --ws-addr=0.0.0.0 --ws-port "$ws_port" --ws-origins "*" \
  --ipcpath /tmp/XDC.ipc \
  $extra_flags \
  2>&1 | tee -a "$DATADIR/xdc.log"
