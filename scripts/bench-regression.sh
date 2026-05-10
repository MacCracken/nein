#!/usr/bin/env bash
# Compare current cyrius bench run against the most recent committed
# baseline in docs/benchmarks/history.csv. Fail on per-bench slowdown
# beyond threshold unless the HEAD commit message carries
# `[bench-regression-ack]`.
#
# Pattern lifted from agnostik scripts/bench-regression.sh. Threshold
# shape tuned for cyrius's whole-µs rounding + GitHub-runner load:
#
#   baseline <  1000ns (ns-precision):
#     fires on delta% > NS_THRESHOLD (default 50%) AND
#             abs delta > NS_FLOOR_NS (default 50)
#     Tiny baselines (sub-100ns ops) amplify CPU jitter into percent
#     movements; the absolute floor avoids false positives.
#
#   baseline >= 1000ns (us-bracketed, rounding-noisy):
#     fires on delta% > US_THRESHOLD (default 80%) AND
#             abs delta >= US_BUCKET_FLOOR_NS (default 2000; ≥2 µs)
#     cyrius bench rounds avg to whole µs — `1us → 2us` could be just
#     1.999µs → 2.0µs (0.05% real shift reported as 100%).
#
# Usage:
#   scripts/bench-regression.sh         # default thresholds
#   scripts/bench-regression.sh 30 50   # tighter percent thresholds

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
HISTORY="$REPO_ROOT/docs/benchmarks/history.csv"

NS_THRESHOLD="${1:-50}"
US_THRESHOLD="${2:-80}"
NS_FLOOR_NS=50
US_BUCKET_FLOOR_NS=2000

# Skip the gate if the HEAD commit message carries the ack tag.
COMMIT_MSG=$(git log -1 --format=%B 2>/dev/null || echo "")
if echo "$COMMIT_MSG" | grep -qE '\[bench-regression-ack\]'; then
    echo "bench-regression: skipped (HEAD carries [bench-regression-ack])"
    exit 0
fi

echo "running benchmarks..."
BENCH_OUT=$(CYRIUS_NO_WARN_SHADOW_LIB=1 cyrius bench "$REPO_ROOT/tests/nein.bcyr" 2>&1)

# Parse current run into name=ns map (normalize us/ms to ns).
declare -A CURRENT
while IFS= read -r line; do
    if [[ "$line" =~ ^[[:space:]]*([a-zA-Z_/0-9]+):[[:space:]]*([0-9]+)(ns|us|ms)[[:space:]]+avg ]]; then
        val="${BASH_REMATCH[2]}"
        case "${BASH_REMATCH[3]}" in
            ns) ;;
            us) val=$((val * 1000)) ;;
            ms) val=$((val * 1000000)) ;;
        esac
        CURRENT["${BASH_REMATCH[1]}"]="$val"
    fi
done <<< "$BENCH_OUT"

if [ ${#CURRENT[@]} -eq 0 ]; then
    echo "bench-regression: ERROR — no benchmarks parsed from output"
    exit 2
fi

# Build baseline map from the most recent row per benchmark in history.csv.
declare -A BASELINE
while IFS='=' read -r name ns; do
    BASELINE["$name"]="$ns"
done < <(awk -F, 'NR>1 { last[$4] = $5 } END { for (k in last) print k "=" last[k] }' "$HISTORY")

if [ ${#BASELINE[@]} -eq 0 ]; then
    echo "bench-regression: WARN — no baseline in $HISTORY; skipping gate"
    exit 0
fi

fail=0; new=0; checked=0
TABLE=$(mktemp)
trap 'rm -f "$TABLE"' EXIT
for name in "${!CURRENT[@]}"; do
    cur="${CURRENT[$name]}"
    base="${BASELINE[$name]:-}"
    if [ -z "$base" ]; then
        printf "%-32s %10s %10s %8s %8s\n" "$name" "(new)" "$cur" "-" "-" >> "$TABLE"
        new=$((new + 1))
        continue
    fi
    delta=$(awk -v c="$cur" -v b="$base" 'BEGIN { printf "%.1f", (c - b) * 100.0 / b }')
    abs_delta=$((cur - base))
    if [ "$base" -ge 1000 ]; then
        thresh="$US_THRESHOLD"
        is_regression=$(awk -v d="$delta" -v t="$thresh" -v ad="$abs_delta" -v floor="$US_BUCKET_FLOOR_NS" \
            'BEGIN { print (d > t && ad >= floor) ? 1 : 0 }')
    else
        thresh="$NS_THRESHOLD"
        is_regression=$(awk -v d="$delta" -v t="$thresh" -v ad="$abs_delta" -v floor="$NS_FLOOR_NS" \
            'BEGIN { print (d > t && ad > floor) ? 1 : 0 }')
    fi
    if [ "$is_regression" = "1" ]; then
        printf "%-32s %10s %10s %8s%% %7s%% **FAIL**\n" "$name" "$base" "$cur" "$delta" "$thresh" >> "$TABLE"
        fail=$((fail + 1))
    else
        printf "%-32s %10s %10s %8s%% %7s%%\n" "$name" "$base" "$cur" "$delta" "$thresh" >> "$TABLE"
    fi
    checked=$((checked + 1))
done

printf "%-32s %10s %10s %8s %8s\n" "benchmark" "baseline" "current" "delta%" "threshold"
printf '%.0s-' {1..72}; echo
sort "$TABLE"

echo
echo "summary: $checked checked, $new new, $fail regressions"

if [ "$fail" -gt 0 ]; then
    echo
    echo "BREAKING: $fail benchmark(s) regressed beyond threshold."
    echo "Either optimize, or ack with [bench-regression-ack] in the commit message."
    echo "(Baseline updates ride into docs/benchmarks/history.csv on each release tag.)"
    exit 1
fi

echo "ok: no regressions"
