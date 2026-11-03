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
#     fires on delta% > NS_THRESHOLD (default 90%) AND
#             abs delta > NS_FLOOR_NS (default 50)
#     Tiny baselines (sub-100ns ops) amplify CPU jitter into percent
#     movements; the absolute floor avoids false positives.
#
#     The 90% default (was 50% through 1.6.7) accounts for a structural
#     apples-to-oranges comparison: baselines are recorded by
#     scripts/bench-track.sh on whatever machine cuts the release, and the
#     gate then runs them on a shared GitHub runner. On the 1.6.8 baseline
#     the runner measured EVERY ns-bracket benchmark 21-58% slower (median
#     ~34%) — a uniform machine shift, not a regression in any one of them.
#     At 50% that left `nein_ok` sitting at exactly 50.0% and four more
#     within ten points, so the gate was one jittery run from firing on
#     something that had not changed. 90% keeps ~1.5x headroom over the
#     worst observed shift while still catching a micro-benchmark that
#     genuinely doubles.
#
#     Since 1.8.2 every delta is ALSO normalized against the run's machine
#     factor (see "Machine factor" below), so the cross-machine offset no
#     longer has to fit inside the threshold at all.
#
#   baseline >= 1000ns (us-bracketed):
#     fires on delta% > US_THRESHOLD (default 80%) AND
#             abs delta >= US_BUCKET_FLOOR_NS (default 2000; ≥2 µs)
#     Written when cyrius bench rounded avg to whole µs, so `1us → 2us`
#     could be 1.999µs → 2.0µs. It now prints fractional µs / ms
#     (`1.028us`, `1.270ms`); the floor stays as an absolute noise guard.
#
# Every benchmark in the latest baseline must appear in the current run.
# Through 1.8.0 the parser matched whole numbers only, so every fractional
# µs / ms result (27 of 48 benches, every large-ruleset one) was dropped
# from the run and never compared — and nothing said so, because the
# comparison loop walks the current run. A baseline bench the run does not
# produce is now a failure, so the next output-format change cannot shrink
# the gate silently. Retiring a bench means recording a new baseline
# (scripts/bench-track.sh) or acking the commit.
#
# Usage:
#   scripts/bench-regression.sh         # default thresholds
#   scripts/bench-regression.sh 30 50   # tighter percent thresholds

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
HISTORY="$REPO_ROOT/docs/benchmarks/history.csv"

NS_THRESHOLD="${1:-90}"
US_THRESHOLD="${2:-80}"
NS_FLOOR_NS=50
US_BUCKET_FLOOR_NS=2000

# Per-benchmark ns-bracket threshold overrides, for benches whose run-to-run
# spread on CI is wider than the rest of the ns bracket. An entry here says
# "this one is known-noisy", which is a different claim from "the whole
# bracket shifted" — keep the list short and justify each addition, or the
# gate quietly stops gating.
#
# validate_iface: the widest spread of any ns bench across 1.6.5-1.6.8
# baselines (112 -> 101 -> 102 locally) and the single worst CI shift
# observed on the 1.6.8 baseline (102 -> 161, +57.8%) — it topped the
# distribution even though every other bench moved with it. 1.6.8.
declare -A BENCH_NS_THRESHOLD=(
    [validate_iface]=120
)

# Skip the gate if the HEAD commit message carries the ack tag.
COMMIT_MSG=$(git log -1 --format=%B 2>/dev/null || echo "")
if echo "$COMMIT_MSG" | grep -qE '\[bench-regression-ack\]'; then
    echo "bench-regression: skipped (HEAD carries [bench-regression-ack])"
    exit 0
fi

echo "running benchmarks..."
BENCH_OUT=$(CYRIUS_NO_WARN_SHADOW_LIB=1 cyrius bench "$REPO_ROOT/tests/nein.bcyr" 2>&1)

# Parse current run into name=ns map. Values may be fractional (`1.028us`,
# `1.270ms`); bash arithmetic is integer-only, so awk normalizes to whole ns,
# rounding to nearest — the same normalization scripts/bench-track.sh applies
# when it records the baseline.
declare -A CURRENT
while IFS= read -r line; do
    if [[ "$line" =~ ^[[:space:]]*([a-zA-Z_/0-9]+):[[:space:]]*([0-9]+(\.[0-9]+)?)(ns|us|ms)[[:space:]]+avg ]]; then
        val=$(awk -v v="${BASH_REMATCH[2]}" -v u="${BASH_REMATCH[4]}" \
            'BEGIN { m = (u == "ms") ? 1000000 : (u == "us") ? 1000 : 1; printf "%d", v * m + 0.5 }')
        CURRENT["${BASH_REMATCH[1]}"]="$val"
    fi
done <<< "$BENCH_OUT"

if [ ${#CURRENT[@]} -eq 0 ]; then
    echo "bench-regression: ERROR — no benchmarks parsed from output"
    exit 2
fi

# Build baseline map from the most recent baseline in history.csv — every row
# carrying its latest timestamp. (Not "last row per name across all history":
# a bench retired long ago would then stay in the baseline and, with the
# missing-bench check below, fail every run forever.)
declare -A BASELINE
while IFS='=' read -r name ns; do
    BASELINE["$name"]="$ns"
done < <(awk -F, 'NR>1 { ts[NR] = $1; nm[NR] = $4; v[NR] = $5; if ($1 > latest) latest = $1 }
                  END { for (i in ts) if (ts[i] == latest) print nm[i] "=" v[i] }' "$HISTORY")

if [ ${#BASELINE[@]} -eq 0 ]; then
    echo "bench-regression: WARN — no baseline in $HISTORY; skipping gate"
    exit 0
fi

# --- Machine factor (1.8.2) -------------------------------------------
# Baselines are recorded on the release machine (scripts/bench-track.sh); CI
# runs this on a shared GitHub runner that is uniformly slower. The 1.8.2
# release run measured EVERY benchmark 1.23x-1.82x slower than its baseline
# (median 1.43x), and `geoip_10_countries_to_firewall` at +81.4% failed the
# 80% threshold — a machine difference, not a regression: against the run's
# own median it is +27%. So each benchmark is judged against
# `baseline x factor`, where the factor is the MEDIAN current/baseline ratio of
# this run. A uniform machine shift cancels; a single benchmark that doubled
# still stands out by ~2x the factor.
#
# What the median cannot see is a regression that hits MOST benchmarks at
# once (a slower allocator, say). The factor is printed on every run, and a
# factor above MAX_MACHINE_FACTOR fails the gate outright: the whole suite
# more than 2x slower is either a very different class of machine or a global
# regression, and both need a human. Locally (same machine as the baseline)
# the factor sits near 1.0, so a global regression shows up there directly.
MAX_MACHINE_FACTOR="${BENCH_MAX_MACHINE_FACTOR:-2.0}"
MACHINE=$(for name in "${!CURRENT[@]}"; do
        b="${BASELINE[$name]:-}"
        if [ -n "$b" ] && [ "$b" -gt 0 ]; then
            awk -v c="${CURRENT[$name]}" -v b="$b" 'BEGIN { printf "%.6f\n", c / b }'
        fi
    done | sort -g | awk 'NF { a[++n] = $1 }
        END { if (n == 0) { print 1; exit }
              if (n % 2) { print a[(n + 1) / 2] } else { print (a[n / 2] + a[n / 2 + 1]) / 2 } }')

fail=0; new=0; checked=0
TABLE=$(mktemp)
trap 'rm -f "$TABLE"' EXIT
for name in "${!CURRENT[@]}"; do
    cur="${CURRENT[$name]}"
    base="${BASELINE[$name]:-}"
    if [ -z "$base" ]; then
        printf "%-32s %10s %10s %9s %9s %8s\n" "$name" "(new)" "$cur" "-" "-" "-" >> "$TABLE"
        new=$((new + 1))
        continue
    fi
    # raw: against the baseline as recorded; delta: against baseline x factor,
    # which is what the thresholds and floors judge.
    raw=$(awk -v c="$cur" -v b="$base" 'BEGIN { printf "%.1f", (c - b) * 100.0 / b }')
    delta=$(awk -v c="$cur" -v b="$base" -v m="$MACHINE" 'BEGIN { e = b * m; printf "%.1f", (c - e) * 100.0 / e }')
    abs_delta=$(awk -v c="$cur" -v b="$base" -v m="$MACHINE" 'BEGIN { printf "%.0f", c - b * m }')
    if [ "$base" -ge 1000 ]; then
        thresh="$US_THRESHOLD"
        is_regression=$(awk -v d="$delta" -v t="$thresh" -v ad="$abs_delta" -v floor="$US_BUCKET_FLOOR_NS" \
            'BEGIN { print (d > t && ad >= floor) ? 1 : 0 }')
    else
        # Per-bench override wins over the bracket default when present.
        thresh="${BENCH_NS_THRESHOLD[$name]:-$NS_THRESHOLD}"
        is_regression=$(awk -v d="$delta" -v t="$thresh" -v ad="$abs_delta" -v floor="$NS_FLOOR_NS" \
            'BEGIN { print (d > t && ad > floor) ? 1 : 0 }')
    fi
    if [ "$is_regression" = "1" ]; then
        printf "%-32s %10s %10s %8s%% %8s%% %7s%% **FAIL**\n" "$name" "$base" "$cur" "$raw" "$delta" "$thresh" >> "$TABLE"
        fail=$((fail + 1))
    else
        printf "%-32s %10s %10s %8s%% %8s%% %7s%%\n" "$name" "$base" "$cur" "$raw" "$delta" "$thresh" >> "$TABLE"
    fi
    checked=$((checked + 1))
done

# A baseline bench the run did not produce was never compared. Fail rather
# than let the checked count shrink unnoticed (see the header).
missing=0
for name in "${!BASELINE[@]}"; do
    if [ -z "${CURRENT[$name]:-}" ]; then
        printf "%-32s %10s %10s %9s %9s %8s **MISSING**\n" "$name" "${BASELINE[$name]}" "-" "-" "-" "-" >> "$TABLE"
        missing=$((missing + 1))
    fi
done

echo "machine factor: ${MACHINE}x (median current/baseline; each delta below is against baseline x factor)"
printf "%-32s %10s %10s %9s %9s %8s\n" "benchmark" "baseline" "current" "raw%" "delta%" "threshold"
printf '%.0s-' {1..72}; echo
sort "$TABLE"

echo
echo "summary: $checked checked of ${#BASELINE[@]} in the baseline, $new new, $missing missing, $fail regressions"

if [ "$missing" -gt 0 ]; then
    echo
    echo "BREAKING: $missing baseline benchmark(s) missing from this run — never compared."
    echo "If the bench output format changed, fix the parser above. If a bench was"
    echo "retired on purpose, record a new baseline or ack with [bench-regression-ack]."
fi
if [ "$fail" -gt 0 ]; then
    echo
    echo "BREAKING: $fail benchmark(s) regressed beyond threshold."
    echo "Either optimize, or ack with [bench-regression-ack] in the commit message."
    echo "(Baseline updates ride into docs/benchmarks/history.csv on each release tag.)"
fi
machine_over=$(awk -v m="$MACHINE" -v x="$MAX_MACHINE_FACTOR" 'BEGIN { print (m > x) ? 1 : 0 }')
if [ "$machine_over" = "1" ]; then
    echo
    echo "BREAKING: the whole suite runs ${MACHINE}x the baseline (limit ${MAX_MACHINE_FACTOR}x)."
    echo "Normalizing that away could hide a global regression: either this is a very"
    echo "different class of machine, or most benchmarks got slower at once. Investigate."
fi
if [ "$missing" -gt 0 ] || [ "$fail" -gt 0 ] || [ "$machine_over" = "1" ]; then
    exit 1
fi

echo "ok: no regressions"
