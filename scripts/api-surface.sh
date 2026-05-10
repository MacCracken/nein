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
        # awk pass: join multi-line `fn NAME(args, ...continuation)` into a
        # single logical line, then extract NAME + arg-list. Multi-line
        # signatures appear when a single-line `fn` declaration would
        # exceed the 120-char lint limit (e.g. nat_dnat_range after
        # v1.2.1's type-annotation expansion).
        awk -v m="$module" '
          /^fn [a-zA-Z][a-zA-Z0-9_]*\(/ {
            # accumulate until the opening paren is balanced by a close
            buf = $0
            opens = gsub(/\(/, "(", buf)
            # awk gsub returns the count; recompute via length diff so the
            # buffer string itself stays intact for matching.
            opens = 0; closes = 0
            for (i = 1; i <= length($0); i++) {
              c = substr($0, i, 1)
              if (c == "(") opens++
              if (c == ")") closes++
            }
            while (opens > closes) {
              if ((getline next_line) <= 0) break
              buf = buf " " next_line
              for (i = 1; i <= length(next_line); i++) {
                c = substr(next_line, i, 1)
                if (c == "(") opens++
                if (c == ")") closes++
              }
            }
            # buf now has the full signature. Extract NAME + args.
            if (match(buf, /^fn ([a-zA-Z][a-zA-Z0-9_]*)\(/)) {
              name_start = RSTART + 3
              name_len = RLENGTH - 4
              name = substr(buf, name_start, name_len)
              paren_open = index(buf, "(")
              # find matching close: scan with nesting depth
              depth = 0; close_at = 0
              for (i = paren_open; i <= length(buf); i++) {
                c = substr(buf, i, 1)
                if (c == "(") depth++
                if (c == ")") { depth--; if (depth == 0) { close_at = i; break } }
              }
              if (close_at > paren_open) {
                args = substr(buf, paren_open + 1, close_at - paren_open - 1)
                gsub(/^[[:space:]]+|[[:space:]]+$/, "", args)
                if (args == "") arity = 0
                else { arity = split(args, _, ",") }
                print m "::" name "/" arity
              }
            }
          }
        ' "$f"
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
