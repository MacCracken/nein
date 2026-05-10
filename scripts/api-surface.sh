#!/usr/bin/env bash
# Snapshot nein's public-fn surface across src/main.cyr + src/lib/*.cyr.
#
# Note: cyrius_api_surface as of v5.10.x doesn't walk nein's src/lib/
# include tree — it stops at top-level src/ files. Until upstream
# resolves, this script greps `^fn NAME(args)` directly and emits the
# same `<module>::<fn>/<arity>` shape cyrius_api_surface produces, so
# the diff tooling is identical to the agnosys/agnostik convention.
#
# Usage:
#   scripts/api-surface.sh check    # CI gate: regenerate and diff
#   scripts/api-surface.sh update   # Refresh docs/api-surface.snapshot

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SNAPSHOT="$REPO_ROOT/docs/api-surface.snapshot"
LIVE="$(mktemp)"
trap 'rm -f "$LIVE"' EXIT

extract() {
    for f in "$REPO_ROOT"/src/main.cyr "$REPO_ROOT"/src/lib/*.cyr; do
        [ -f "$f" ] || continue
        local module
        module=$(basename "$f" .cyr)
        # Match `fn NAME(args...)`; skip private fns (starting with `_`).
        # sed extracts the fn name + paren block; awk computes arity from
        # comma count (empty arg list → 0).
        grep -E '^fn [a-zA-Z][a-zA-Z0-9_]*\(' "$f" \
          | sed -E 's/^fn ([a-zA-Z][a-zA-Z0-9_]*)\(([^)]*)\).*/\1|\2/' \
          | awk -F'|' -v m="$module" '
              {
                name = $1; args = $2
                gsub(/^[[:space:]]+|[[:space:]]+$/, "", args)
                if (args == "") arity = 0
                else { n = split(args, _, ","); arity = n }
                print m "::" name "/" arity
              }'
    done | LC_ALL=C sort -u
}

cmd="${1:-check}"

case "$cmd" in
  update)
    extract > "$SNAPSHOT"
    echo "snapshot updated: $(wc -l < "$SNAPSHOT") nein public fns"
    ;;
  check)
    extract > "$LIVE"
    if [ ! -f "$SNAPSHOT" ]; then
      echo "BREAKING: snapshot missing at $SNAPSHOT"
      echo "Run: scripts/api-surface.sh update"
      exit 1
    fi
    if diff -q "$SNAPSHOT" "$LIVE" > /dev/null; then
      echo "ok: $(wc -l < "$SNAPSHOT") public fns, surface matches snapshot"
    else
      echo "BREAKING: nein public-fn surface drifted from snapshot:"
      echo "(- = removed since snapshot; + = added since snapshot)"
      diff -u "$SNAPSHOT" "$LIVE" | tail -n +3 | head -200
      echo ""
      echo "If intentional, regenerate:"
      echo "  scripts/api-surface.sh update"
      exit 1
    fi
    ;;
  *)
    echo "Usage: $0 {check|update}"
    exit 2
    ;;
esac
