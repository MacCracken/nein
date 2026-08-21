#!/usr/bin/env bash
set -euo pipefail

# Run the Cyrius benchmark suite and append a timestamped baseline to
# docs/benchmarks/history.csv — the record scripts/bench-regression.sh
# gates against, and the CSV history CLAUDE.md calls "the proof".
#
# Replaces the Rust-era script (criterion via `cargo bench`, writing
# benchmarks/history.tsv), retired at 1.6.5. That directory moved under
# rust-old/ at 1.6.5 and was deleted with it at 1.6.8 — the criterion archive
# lives in git history only.
#
# Baselines ride in on release commits. Recording one mid-cycle moves the
# floor bench-regression.sh compares against, so record deliberately.
#
# Usage:
#   ./scripts/bench-track.sh              # run and append a baseline
#   ./scripts/bench-track.sh --dry-run    # run and print, append nothing
#   ./scripts/bench-track.sh --compare    # last two baselines side by side

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

HISTORY="docs/benchmarks/history.csv"
BENCH_SRC="tests/nein.bcyr"
MODE="${1:-record}"

# --- --compare ---------------------------------------------------------
if [[ "$MODE" == "--compare" ]]; then
    [ -f "$HISTORY" ] || { echo "no history at $HISTORY" >&2; exit 1; }
    # Baselines are grouped by timestamp; take the two most recent.
    mapfile -t STAMPS < <(awk -F, 'NR>1 {print $1}' "$HISTORY" | sort -u | tail -2)
    if [ "${#STAMPS[@]}" -lt 2 ]; then
        echo "only one baseline recorded — nothing to compare" >&2
        exit 1
    fi
    PREV="${STAMPS[0]}"; CURR="${STAMPS[1]}"
    echo "=== $PREV  ->  $CURR ==="
    awk -F, -v prev="$PREV" -v curr="$CURR" '
        NR == 1 { next }
        $1 == prev { p[$4] = $5; pv = $2 }
        $1 == curr { c[$4] = $5; cv = $2; order[++n] = $4 }
        END {
            printf "%-32s %12s %12s %9s\n", "benchmark", pv, cv, "delta%"
            printf "%-32s %12s %12s %9s\n", "---------", "----", "----", "------"
            for (i = 1; i <= n; i++) {
                b = order[i]
                if (!(b in p)) { printf "%-32s %12s %12d %9s\n", b, "-", c[b], "new"; continue }
                d = (p[b] == 0) ? 0 : (c[b] - p[b]) * 100.0 / p[b]
                printf "%-32s %12d %12d %8.1f%%\n", b, p[b], c[b], d
            }
        }' "$HISTORY"
    exit 0
fi

if [[ "$MODE" != "record" && "$MODE" != "--dry-run" ]]; then
    echo "Usage: $0 [--dry-run|--compare]" >&2
    exit 1
fi

# --- run ---------------------------------------------------------------
VERSION=$(tr -d '[:space:]' < VERSION)
COMMIT=$(git rev-parse --short HEAD 2>/dev/null || echo "unknown")
TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

echo "running benchmarks for $VERSION ($COMMIT)..."
BENCH_OUT=$(CYRIUS_NO_WARN_SHADOW_LIB=1 cyrius bench "$BENCH_SRC" 2>&1)

if ! echo "$BENCH_OUT" | grep -q "passed, 0 failed"; then
    echo "FAIL: benchmark run did not pass — not recording" >&2
    echo "$BENCH_OUT" | tail -20 >&2
    exit 1
fi

# `cyrius bench` prints e.g. "  validate_family: 53ns avg (min=... max=...)"
# with ns/us/ms units and optional decimals. Normalize every value to whole
# nanoseconds so the CSV stays in one unit across toolchain versions.
ROWS=$(echo "$BENCH_OUT" | awk -v ts="$TIMESTAMP" -v ver="$VERSION" -v commit="$COMMIT" '
    match($0, /^[[:space:]]*[A-Za-z_/0-9]+:[[:space:]]*[0-9.]+(ns|us|ms)[[:space:]]+avg/) {
        line = $0
        sub(/^[[:space:]]+/, "", line)
        colon = index(line, ":")
        name  = substr(line, 1, colon - 1)
        rest  = substr(line, colon + 1)
        sub(/^[[:space:]]+/, "", rest)
        val  = rest + 0                       # leading float
        unit = "ns"
        if (rest ~ /^[0-9.]+us/) unit = "us"
        if (rest ~ /^[0-9.]+ms/) unit = "ms"
        if (unit == "us") val *= 1000
        if (unit == "ms") val *= 1000000
        printf "%s,%s,%s,%s,%d\n", ts, ver, commit, name, (val + 0.5)
    }')

COUNT=$(echo "$ROWS" | grep -c . || true)
if [ "$COUNT" -eq 0 ]; then
    echo "FAIL: parsed 0 benchmarks from the run — output shape changed?" >&2
    echo "$BENCH_OUT" | tail -20 >&2
    exit 1
fi

echo "$BENCH_OUT" | grep -E "^[[:space:]]+[A-Za-z_/0-9]+:.*avg"

if [[ "$MODE" == "--dry-run" ]]; then
    echo ""
    echo "--dry-run: $COUNT rows parsed, nothing written to $HISTORY"
    exit 0
fi

if [ ! -f "$HISTORY" ]; then
    mkdir -p "$(dirname "$HISTORY")"
    echo "timestamp,version,commit,benchmark,time_ns" > "$HISTORY"
fi

echo "$ROWS" >> "$HISTORY"
echo ""
echo "appended $COUNT rows to $HISTORY ($VERSION / $COMMIT / $TIMESTAMP)"
echo "compare against the previous baseline: $0 --compare"
