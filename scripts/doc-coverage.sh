#!/usr/bin/env bash
set -euo pipefail

# Doc-coverage gate: what fraction of nein's public fns carry a doc comment.
#
# Wraps `cyrius doc --check`, which does the analysis but CANNOT gate: it
# reports "N documented, M undocumented" and then exits 0 regardless — verified
# at 6.5.33 against a file with 3/3 undocumented fns. So the toolchain supplies
# the numbers and this script supplies the exit code.
#
# It also only ever examines the ONE file it is handed, so it has to be run per
# module and summed; pointing it at src/main.cyr alone reports "1 total" and
# tells you nothing about the other 390 public fns.
#
# THRESHOLD IS A RATCHET, NOT A TARGET. The floor below is the measured figure
# at the time it was last raised. It exists to stop the number sliding
# backwards, not to assert the number is good. Raise it when you improve
# coverage; never lower it to make a build pass.
#
# Why the number is what it is: nein's public surface is accessor-heavy —
# `fn table_name(t: i64): i64 { return load64(t); }` and ~200 siblings. The
# modules carrying real logic are already at or near 100% (config 17/17,
# validate 8/8, error 3/3); the deficit is almost entirely one-line accessors
# grouped under a section comment rather than commented individually.
#
# No --list: `cyrius doc --check` emits per-fn "undocumented: NAME" lines for
# some inputs (src/main.cyr, a standalone file) but not for the src/lib/
# modules, where it prints the summary line only. Rather than ship a flag that
# silently returns nothing for 20 of 22 modules, this reports counts. To see
# names for one module: `cyrius doc --check src/lib/<mod>.cyr`.
#
# Usage:
#   scripts/doc-coverage.sh              # gate at the recorded floor
#   scripts/doc-coverage.sh --min 25     # gate at an explicit percentage

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

# Measured floor. 1.6.9: 68/391 = 17%.
MIN_PCT=17

while [ $# -gt 0 ]; do
    case "$1" in
        --min) MIN_PCT="$2"; shift 2 ;;
        *) echo "Usage: $0 [--min PCT]" >&2; exit 2 ;;
    esac
done

command -v cyrius >/dev/null 2>&1 || { echo "cyrius not on PATH" >&2; exit 2; }

total_doc=0
total_undoc=0

printf "%-28s %12s %14s\n" "module" "documented" "undocumented"
printf '%.0s-' {1..56}; echo

for f in src/main.cyr src/lib/*.cyr; do
    [ -f "$f" ] || continue
    out=$(cyrius doc --check "$f" 2>/dev/null || true)
    line=$(echo "$out" | grep -E '^[0-9]+ documented' || true)
    if [ -z "$line" ]; then
        printf "%-28s %12s %14s\n" "$(basename "$f")" "?" "?"
        continue
    fi
    d=$(echo "$line" | grep -oE '^[0-9]+')
    u=$(echo "$line" | grep -oE '[0-9]+ undocumented' | grep -oE '^[0-9]+')
    d=${d:-0}; u=${u:-0}
    total_doc=$((total_doc + d))
    total_undoc=$((total_undoc + u))
    printf "%-28s %12s %14s\n" "$(basename "$f")" "$d" "$u"
done

total=$((total_doc + total_undoc))
if [ "$total" -eq 0 ]; then
    echo "doc-coverage: ERROR — no functions found; did the cyrius doc output format change?" >&2
    exit 2
fi

pct=$((total_doc * 100 / total))

echo ""
echo "doc-coverage: $total_doc/$total documented (${pct}%), floor ${MIN_PCT}%"

if [ "$pct" -lt "$MIN_PCT" ]; then
    echo ""
    echo "BREAKING: doc coverage ${pct}% is below the ${MIN_PCT}% floor."
    echo "Add doc comments, or — if the floor is genuinely wrong — change it"
    echo "deliberately in this script with a note saying why. Do not lower it"
    echo "just to make a build pass."
    exit 1
fi

if [ "$pct" -gt "$MIN_PCT" ]; then
    echo "note: coverage is ${pct}%, above the ${MIN_PCT}% floor — consider raising the floor."
fi

echo "ok: doc coverage at or above floor"
