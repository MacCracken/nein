#!/usr/bin/env bash
set -euo pipefail

# Run criterion benchmarks and append a timestamped summary to the
# historical record. Stores raw criterion output alongside a compact
# TSV log for easy diffing across versions.
#
# Usage:
#   ./scripts/bench-track.sh              # run and record
#   ./scripts/bench-track.sh --compare    # show last two entries side-by-side

BENCH_DIR="benchmarks"
HISTORY_FILE="$BENCH_DIR/history.tsv"
LATEST_DIR="$BENCH_DIR/latest"

mkdir -p "$BENCH_DIR" "$LATEST_DIR"

if [[ "${1:-}" == "--compare" ]]; then
    if [[ ! -f "$HISTORY_FILE" ]]; then
        echo "No history file found at $HISTORY_FILE"
        exit 1
    fi
    echo "=== Benchmark History ==="
    echo ""
    column -t -s $'\t' "$HISTORY_FILE" | tail -40
    exit 0
fi

VERSION=$(cat VERSION 2>/dev/null | tr -d '[:space:]' || echo "unknown")
COMMIT=$(git rev-parse --short HEAD 2>/dev/null || echo "unknown")
TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
RUN_ID="${VERSION}_${COMMIT}_${TIMESTAMP}"

echo "Running benchmarks for $VERSION ($COMMIT)..."

# Run criterion benchmarks, capture output
BENCH_OUTPUT=$(cargo bench --features full --bench benchmarks 2>&1)

# Save raw criterion output
RAW_FILE="$BENCH_DIR/${VERSION}_${COMMIT}.txt"
echo "$BENCH_OUTPUT" > "$RAW_FILE"

# Copy criterion results for baseline comparison
if [[ -d "target/criterion" ]]; then
    rm -rf "$LATEST_DIR"
    cp -r target/criterion "$LATEST_DIR"
fi

# Write header if history file is new
if [[ ! -f "$HISTORY_FILE" ]]; then
    printf "timestamp\tversion\tcommit\tbenchmark\ttime_ns\n" > "$HISTORY_FILE"
fi

# Parse criterion output and append to history
echo "$BENCH_OUTPUT" | grep "time:" | while IFS= read -r line; do
    # Extract benchmark name from preceding "Benchmarking <name>" line
    # Criterion output format: "benchmark_name   time:   [low mid high]"
    name=$(echo "$line" | sed -E 's/^([a-zA-Z_0-9]+)\s+time:.*/\1/' | tr -d ' ')

    # Skip lines that don't start with a benchmark name (indented continuation lines)
    if [[ -z "$name" || "$name" == "time:"* ]]; then
        continue
    fi

    # Extract median time (middle value in [low median high])
    median=$(echo "$line" | sed -E 's/.*time:\s+\[.*\s+(.*)\s+.+\]/\1/' | tr -d ' ')

    if [[ -n "$median" && "$median" != *"time"* ]]; then
        printf "%s\t%s\t%s\t%s\t%s\n" "$TIMESTAMP" "$VERSION" "$COMMIT" "$name" "$median" >> "$HISTORY_FILE"
    fi
done

echo ""
echo "Results saved to $RAW_FILE"
echo "History appended to $HISTORY_FILE"
echo ""
echo "Recent results:"
tail -25 "$HISTORY_FILE" | column -t -s $'\t'
