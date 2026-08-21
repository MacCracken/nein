#!/usr/bin/env bash
set -euo pipefail

# Bump nein's version and re-stamp everything that carries it.
#
# `cyrius.cyml` pulls the version through `${file:VERSION}`, so VERSION is
# the single source of truth — but the `dist/*.cyr` bundles bake a version
# banner at generation time, and CI's docs gate wants a dated CHANGELOG
# entry. This script moves VERSION, regenerates the bundles, and reports on
# whatever is still owed.
#
# Replaces the Rust-era script (which `sed`-ed a Cargo.toml that stopped
# existing at the Cyrius port and ran `cargo check`), retired at 1.6.5.
#
# Usage:
#   ./scripts/version-bump.sh 1.6.6          # bump, regenerate, report
#   ./scripts/version-bump.sh 1.6.6 --check  # report only, change nothing

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

NEW_VERSION="${1:?Usage: $0 <new-version> [--check]}"
CHECK_ONLY=0
[[ "${2:-}" == "--check" ]] && CHECK_ONLY=1

if ! echo "$NEW_VERSION" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+$'; then
    echo "FAIL: '$NEW_VERSION' is not semver x.y.z" >&2
    exit 1
fi

OLD_VERSION=$(tr -d '[:space:]' < VERSION)
echo "nein $OLD_VERSION -> $NEW_VERSION"

# cyrius.cyml must interpolate rather than hardcode, or the bump silently
# only half-lands. Release's "Verify version" step enforces the same thing.
# -F (fixed string): in a basic regex `$` is an end-of-line anchor, so an
# unescaped `${file:VERSION}` pattern silently never matches.
if ! grep -qF 'version = "${file:VERSION}"' cyrius.cyml; then
    echo "FAIL: cyrius.cyml [package].version must be \${file:VERSION}" >&2
    exit 1
fi

if [ "$CHECK_ONLY" -eq 1 ]; then
    echo "(--check: no files written)"
else
    echo "$NEW_VERSION" > VERSION
    echo "  VERSION written"

    # dist/*.cyr carry a `# Version: X.Y.Z` banner from generation time, so
    # they go stale on every bump. CI's dist-staleness gate fails the build
    # if they aren't regenerated and committed. Needs ./lib/ populated.
    if [ -d lib ] && [ -n "$(ls -A lib 2>/dev/null)" ]; then
        cyrius distlib     > /dev/null 2>&1 && echo "  dist/nein.cyr regenerated"
        cyrius distlib mcp > /dev/null 2>&1 && echo "  dist/nein-mcp.cyr regenerated"
    else
        echo "  SKIP dist regen — ./lib/ is empty; run 'cyrius lib sync && cyrius deps' then 'cyrius distlib' + 'cyrius distlib mcp'"
    fi
fi

# --- What's still owed -------------------------------------------------
echo ""
echo "Remaining for $NEW_VERSION:"

TODO=0
if grep -qE "^## \[$NEW_VERSION\] — [0-9]{4}-[0-9]{2}-[0-9]{2}" CHANGELOG.md; then
    echo "  ok   CHANGELOG.md has a dated [$NEW_VERSION] entry"
else
    echo "  TODO CHANGELOG.md needs '## [$NEW_VERSION] — $(date -u +%Y-%m-%d)'"
    TODO=1
fi

ROADMAP_DATE=$(grep -oE 'Last refresh: \*?\*?[0-9]{4}-[0-9]{2}-[0-9]{2}' docs/development/roadmap.md \
    | head -1 | grep -oE '[0-9]{4}-[0-9]{2}-[0-9]{2}' || true)
if [ -n "$ROADMAP_DATE" ]; then
    AGE_DAYS=$(( ($(date -u +%s) - $(date -u -d "$ROADMAP_DATE" +%s)) / 86400 ))
    if [ "$AGE_DAYS" -gt 90 ]; then
        echo "  TODO docs/development/roadmap.md last refreshed $ROADMAP_DATE (${AGE_DAYS}d — CI fails past 90)"
        TODO=1
    else
        echo "  ok   roadmap refreshed $ROADMAP_DATE (${AGE_DAYS}d)"
    fi
fi

# Any doc still naming the outgoing version is a candidate for the sweep.
# Skipped when re-running against the current version — every doc naming it
# is then correct, not stale.
STALE=""
if [ "$OLD_VERSION" != "$NEW_VERSION" ]; then
    STALE=$(grep -rlF "$OLD_VERSION" --include="*.md" . 2>/dev/null \
        | grep -vE '^\./(CHANGELOG\.md|rust-old/)' | sort || true)
fi
if [ -n "$STALE" ]; then
    echo "  TODO docs still naming $OLD_VERSION (check each — some refs are historical):"
    echo "$STALE" | sed 's/^/         /'
    TODO=1
fi

echo ""
if [ "$TODO" -eq 0 ]; then
    echo "Ready. Commit, then tag $NEW_VERSION."
else
    echo "Finish the TODOs above, then commit and tag $NEW_VERSION."
fi
echo "Benchmarks: ./scripts/bench-track.sh records a $NEW_VERSION baseline."
