#!/usr/bin/env bash
set -euo pipefail

# Test-coverage gate: what fraction of nein's public API is actually called by
# the test suite.
#
# This is the gate CLAUDE.md's "minimum 80%+ coverage target" was always
# reaching for, and it is NOT what `cyrius coverage` provides — see below.
#
# WHAT IT MEASURES: for every fn in docs/api-surface.snapshot (the same
# definition of "public" that scripts/api-surface.sh gates on), whether any
# .tcyr under tests/ calls it. Comment lines are stripped first so a name
# mentioned only in prose does not count.
#
# WHAT IT DOES NOT MEASURE: line or branch coverage. A fn called once with one
# input counts as covered. This is a FLOOR — it catches "we shipped an API and
# never wrote a test for it", which is the failure this repo actually had (the
# v1.6.7 dry_run bug survived precisely because the behaviour had no test).
# It cannot tell you the tests are good.
#
# WHY NOT `cyrius coverage --min`: that subcommand measures *reference*
# coverage — whether a fn is referenced from an entry point, i.e. a dead-code
# metric, and it says so in its own output ("a floor, not a correctness
# proof"). Worse, on this tree its default mode walks only src/main.cyr and
# reports 1/1 = 100%, so `cyrius coverage --min 80` passes vacuously while
# measuring nothing. A gate that cannot fail is worse than no gate, because it
# makes CLAUDE.md's claim look enforced. `--full` swings the other way and
# reports 63/2634 = 2%, dominated by unreferenced vendored stdlib. Neither
# number is about nein's tests.
#
# THRESHOLD IS A RATCHET. The floor is the measured figure when last raised.
# Raise it as coverage improves; never lower it to make a build pass.
#
# Usage:
#   scripts/test-coverage.sh                # gate at the recorded floor
#   scripts/test-coverage.sh --min 70       # gate at an explicit percentage
#   scripts/test-coverage.sh --list         # list every uncovered fn, by module

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

# Measured floor. 1.6.9: 251/392 = 64% (raised from 63% when the P(-1)
# hardening tests landed — the ratchet working as intended).
MIN_PCT=64
LIST=0

while [ $# -gt 0 ]; do
    case "$1" in
        --min) MIN_PCT="$2"; shift 2 ;;
        --list) LIST=1; shift ;;
        *) echo "Usage: $0 [--min PCT] [--list]" >&2; exit 2 ;;
    esac
done

SNAPSHOT="docs/api-surface.snapshot"
[ -f "$SNAPSHOT" ] || { echo "no $SNAPSHOT — run scripts/api-surface.sh update" >&2; exit 2; }

TESTS=$(cat tests/*.tcyr tests/integration/*.tcyr 2>/dev/null || true)
[ -n "$TESTS" ] || { echo "no .tcyr test files found under tests/" >&2; exit 2; }

# Strip comments: a fn named only in a comment is not exercised by anything.
#
# Materialised to a file rather than kept in a variable and piped per-fn. Two
# reasons: it greps a 100KB file 391 times instead of re-serialising it 391
# times, and — the sharp one — `printf ... | grep -q` is a trap under
# `set -o pipefail`. grep -q exits the instant it matches, printf then dies of
# SIGPIPE (141), and pipefail surfaces that as the pipeline's status, so a
# SUCCESSFUL match reads as a failure. Only fns near the end of the input
# matched. Greping a file has no pipeline and no such hazard.
TEST_CODE_FILE=$(mktemp)
CLEANUP_FILES="$TEST_CODE_FILE"
printf '%s\n' "$TESTS" | sed 's/#.*$//' > "$TEST_CODE_FILE"

total=0
covered=0
UNCOVERED=$(mktemp)
trap 'rm -f "$UNCOVERED" $CLEANUP_FILES' EXIT

while IFS= read -r entry; do
    case "$entry" in *"::"*) ;; *) continue ;; esac
    mod="${entry%%::*}"
    rest="${entry#*::}"
    fn="${rest%%/*}"
    [ -n "$fn" ] || continue
    total=$((total + 1))
    # `name(` — a call, not a substring match against a longer identifier.
    if grep -qE "(^|[^A-Za-z0-9_])${fn}[[:space:]]*\(" "$TEST_CODE_FILE"; then
        covered=$((covered + 1))
    else
        echo "$mod $fn" >> "$UNCOVERED"
    fi
done < "$SNAPSHOT"

if [ "$total" -eq 0 ]; then
    echo "test-coverage: ERROR — parsed 0 fns from $SNAPSHOT" >&2
    exit 2
fi

pct=$((covered * 100 / total))
uncovered=$((total - covered))

printf "%-14s %8s %10s\n" "module" "uncalled" "examples"
printf '%.0s-' {1..60}; echo
if [ -s "$UNCOVERED" ]; then
    awk '{ c[$1]++; if (n[$1] < 4) { ex[$1] = ex[$1] " " $2; n[$1]++ } }
         END { for (m in c) printf "%-14s %8d %s\n", m, c[m], ex[m] }' "$UNCOVERED" | sort -k2 -rn
fi

if [ "$LIST" -eq 1 ] && [ -s "$UNCOVERED" ]; then
    echo ""
    echo "every uncovered fn:"
    sort "$UNCOVERED" | awk '{ printf "  %s::%s\n", $1, $2 }'
fi

echo ""
echo "test-coverage: $covered/$total public fns called by tests (${pct}%), floor ${MIN_PCT}%"
echo "  (reference coverage — a fn called once counts; not line or branch coverage)"

if [ "$pct" -lt "$MIN_PCT" ]; then
    echo ""
    echo "BREAKING: test coverage ${pct}% is below the ${MIN_PCT}% floor."
    echo "$uncovered public fns have no test calling them. Add tests, or — if the"
    echo "floor is genuinely wrong — change it deliberately in this script with a"
    echo "note saying why. Do not lower it just to make a build pass."
    exit 1
fi

if [ "$pct" -gt "$MIN_PCT" ]; then
    echo "note: coverage is ${pct}%, above the ${MIN_PCT}% floor — consider raising the floor."
fi

echo "ok: test coverage at or above floor"
