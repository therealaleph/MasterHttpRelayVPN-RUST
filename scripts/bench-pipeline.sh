#!/usr/bin/env bash
#
# bench-pipeline.sh — compare throughput: serial (depth=1) vs pipelined (depth=10)
#
# Builds mhrv-rs twice (patching the INFLIGHT_ACTIVE constant), runs each
# as a local SOCKS5 proxy, downloads through the full tunnel, reports.
#
# Usage:
#   ./scripts/bench-pipeline.sh [CONFIG_FILE]
#
# Default: config.json

set -euo pipefail

CONFIG="${1:-config.json}"
RUNS=3
SOCKS_PORT=18088
HTTP_PORT=18087
TEST_URL="https://speed.cloudflare.com/__down?bytes=5000000"
SRC="src/tunnel_client.rs"
TMPDIR_BENCH=$(mktemp -d)

cleanup() {
    rm -rf "$TMPDIR_BENCH"
    kill $PROXY_PID 2>/dev/null || true
    # Restore original constant
    sed -i '' "s/^const INFLIGHT_ACTIVE: usize = [0-9]*/const INFLIGHT_ACTIVE: usize = 10/" "$SRC" 2>/dev/null || true
}
trap cleanup EXIT

if [ ! -f "$CONFIG" ]; then
    echo "ERROR: Config not found: $CONFIG"
    exit 1
fi

echo "╔══════════════════════════════════════════════╗"
echo "║     Pipeline Throughput Benchmark            ║"
echo "╠══════════════════════════════════════════════╣"
echo "║ Config:    $CONFIG"
echo "║ Test URL:  $TEST_URL"
echo "║ Runs:      $RUNS per mode"
echo "╚══════════════════════════════════════════════╝"
echo ""

# Write a temp config with our ports
TEMP_CONFIG="$TMPDIR_BENCH/config.json"
python3 -c "
import json
with open('$CONFIG') as f:
    c = json.load(f)
c['listen_port'] = $HTTP_PORT
c['socks5_port'] = $SOCKS_PORT
c['log_level'] = 'warn'
with open('$TEMP_CONFIG', 'w') as f:
    json.dump(c, f)
"

run_test() {
    local label="$1"
    local binary="$2"
    echo "━━━ $label ━━━"

    $binary -c "$TEMP_CONFIG" &
    PROXY_PID=$!
    sleep 3

    if ! kill -0 $PROXY_PID 2>/dev/null; then
        echo "  ERROR: Proxy failed to start"
        return
    fi

    # Wait for proxy
    for attempt in $(seq 1 15); do
        if curl -s --socks5-hostname localhost:$SOCKS_PORT --connect-timeout 5 -o /dev/null https://www.google.com 2>/dev/null; then
            break
        fi
        sleep 1
    done

    local total_bytes=0
    local total_time=0

    for i in $(seq 1 $RUNS); do
        local result
        result=$(curl -s --socks5-hostname localhost:$SOCKS_PORT \
            -o /dev/null \
            -w '%{size_download} %{time_total} %{speed_download}' \
            --connect-timeout 30 \
            --max-time 90 \
            "$TEST_URL" 2>/dev/null || echo "0 999 0")

        local bytes time_s speed
        bytes=$(echo "$result" | awk '{print $1}')
        time_s=$(echo "$result" | awk '{print $2}')
        speed=$(echo "$result" | awk '{printf "%.0f", $3/1024}')

        total_bytes=$((total_bytes + ${bytes%.*}))
        total_time=$(echo "$total_time + $time_s" | bc)

        printf "  Run %d: %.1fs  %s KB/s\n" "$i" "$time_s" "$speed"
    done

    local avg_speed avg_time
    avg_speed=$(echo "scale=1; $total_bytes / $total_time / 1024" | bc 2>/dev/null || echo "0")
    avg_time=$(echo "scale=1; $total_time / $RUNS" | bc 2>/dev/null || echo "0")
    printf "  ➜ Average: %s KB/s  (%.1fs per download)\n\n" "$avg_speed" "$avg_time"

    kill $PROXY_PID 2>/dev/null || true
    wait $PROXY_PID 2>/dev/null || true
    sleep 1

    echo "$label|$avg_speed|$avg_time" >> "$TMPDIR_BENCH/results.txt"
}

# Build serial (depth=1)
echo "Building serial mode (INFLIGHT_ACTIVE=1)..."
sed -i '' "s/^const INFLIGHT_ACTIVE: usize = [0-9]*/const INFLIGHT_ACTIVE: usize = 1/" "$SRC"
cargo build --release 2>&1 | tail -1
cp target/release/mhrv-rs "$TMPDIR_BENCH/mhrv-serial"

# Build pipelined (depth=10)
echo "Building pipelined mode (INFLIGHT_ACTIVE=10)..."
sed -i '' "s/^const INFLIGHT_ACTIVE: usize = [0-9]*/const INFLIGHT_ACTIVE: usize = 10/" "$SRC"
cargo build --release 2>&1 | tail -1
cp target/release/mhrv-rs "$TMPDIR_BENCH/mhrv-pipelined"

echo ""

# Run tests
run_test "Serial (depth=1)" "$TMPDIR_BENCH/mhrv-serial"
run_test "Pipelined (depth=10)" "$TMPDIR_BENCH/mhrv-pipelined"

# Summary
echo "╔══════════════════════════════════════════════╗"
echo "║               RESULTS                       ║"
echo "╠══════════════════════════════════════════════╣"
while IFS='|' read -r label speed time; do
    printf "║  %-25s %6s KB/s  %5ss\n" "$label" "$speed" "$time"
done < "$TMPDIR_BENCH/results.txt"
echo "╚══════════════════════════════════════════════╝"
