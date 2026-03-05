#!/usr/bin/env bash
# Start bitcoind and web server in the ITE-449 project root.
# Uses PHP built-in server so .php files (e.g. beacon.php) work.

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PORT="${PORT:-80}"
CONF="$SCRIPT_DIR/bitcoin.conf"

cd "$SCRIPT_DIR"

# Start bitcoind in the background if present in project root (use project bitcoin.conf)
BITCOIND_PID=""
if [[ -x "$SCRIPT_DIR/bitcoind" ]]; then
    echo "Starting bitcoind..."
    mkdir -p "$SCRIPT_DIR/.bitcoin"
    "$SCRIPT_DIR/bitcoind" -conf="$CONF" &
    BITCOIND_PID=$!
    trap 'kill $BITCOIND_PID 2>/dev/null' EXIT
elif command -v bitcoind &>/dev/null; then
    echo "Starting bitcoind..."
    mkdir -p "$SCRIPT_DIR/.bitcoin"
    bitcoind -conf="$CONF" &
    BITCOIND_PID=$!
    trap 'kill $BITCOIND_PID 2>/dev/null' EXIT
fi

# Wait until bitcoind is accepting RPC (so beacon can get addresses)
if [[ -n "$BITCOIND_PID" ]] && [[ -f "$CONF" ]]; then
    echo "Waiting for bitcoind to be ready..."
    if [[ -x "$SCRIPT_DIR/bitcoin-cli" ]]; then
        CLI=("$SCRIPT_DIR/bitcoin-cli" -conf="$CONF")
    else
        CLI=(bitcoin-cli -conf="$CONF")
    fi
    for i in {1..30}; do
        if "${CLI[@]}" getblockcount &>/dev/null; then
            echo "Bitcoind is ready."
            # Ensure a wallet exists for getnewaddress (Bitcoin Core 0.21+ has no default wallet)
            "${CLI[@]}" createwallet "beacon" 2>/dev/null || true
            break
        fi
        if ! kill -0 "$BITCOIND_PID" 2>/dev/null; then
            echo "Warning: bitcoind exited early." >&2
            break
        fi
        sleep 1
    done
fi

echo "Serving project root at http://127.0.0.1:$PORT"
echo "Press Ctrl+C to stop."
php -S "127.0.0.1:$PORT"
