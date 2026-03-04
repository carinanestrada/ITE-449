#!/usr/bin/env bash
# Start bitcoind and web server in the ITE-449 project root.
# Uses PHP built-in server so .php files (e.g. beacon.php) work.

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PORT="${PORT:-80}"

cd "$SCRIPT_DIR"

# Start bitcoind in the background if present in project root (use project bitcoin.conf)
BITCOIND_PID=""
if [[ -x "$SCRIPT_DIR/bitcoind" ]]; then
    echo "Starting bitcoind..."
    mkdir -p "$SCRIPT_DIR/.bitcoin"
    "$SCRIPT_DIR/bitcoind" -conf="$SCRIPT_DIR/bitcoin.conf" &
    BITCOIND_PID=$!
    trap 'kill $BITCOIND_PID 2>/dev/null' EXIT
elif command -v bitcoind &>/dev/null; then
    echo "Starting bitcoind..."
    mkdir -p "$SCRIPT_DIR/.bitcoin"
    bitcoind -conf="$SCRIPT_DIR/bitcoin.conf" &
    BITCOIND_PID=$!
    trap 'kill $BITCOIND_PID 2>/dev/null' EXIT
fi

echo "Serving project root at http://127.0.0.1:$PORT"
echo "Press Ctrl+C to stop."
php -S "127.0.0.1:$PORT"
