#!/usr/bin/env bash
set -euo pipefail

# Enforce nein's dependency supply-chain policy against cyrius.cyml + cyrius.lock.
#
# This is the Cyrius-side successor to the Rust tree's `deny.toml` (cargo-deny),
# retired with `rust-old/` at 1.6.8. The policy it encoded — allowed licences,
# allowed sources, no wildcards, no unknown registries — is real and outlived
# the Rust tree, but it had nowhere to live: despite the name, `cyrius deny` is
# NOT a supply-chain tool. It is an include-path checker (rejects absolute paths
# and `../` traversal), and `cyrius vet` checks includes resolve under a
# HARDCODED trusted-prefix set. Neither takes an allow-list. So the policy is
# enforced here instead.
#
# What each deny.toml section became:
#
#   [sources]  unknown-git = "deny", allow-git = [...]
#              -> check 2: every [deps.*] git URL must sit under an allowed
#                 source prefix. There is no registry in the Cyrius world, so
#                 `unknown-registry` collapses into the same check.
#   [bans]     wildcards = "deny"
#              -> check 3: every dep must pin an exact immutable tag — no
#                 `branch =`, no `rev =`, no local `path =`.
#              multiple-versions = "warn"
#              -> check 6: a dep name declared twice is an error here, not a
#                 warning; Cyrius resolves single-pass and last-wins, so two
#                 versions of one bundle is a silent-corruption bug, not a
#                 size annoyance.
#   [licenses] allow = [...]
#              -> check 5: every dep's own declared licence must be on the
#                 allow-list. The list below is carried forward verbatim from
#                 deny.toml rather than narrowed to what is used today — every
#                 dep is currently GPL-3.0-only, but narrowing would fail the
#                 first time a legitimately permissive bundle is added, and the
#                 original list was already a deliberate policy decision.
#   [advisories] ignore = []
#              -> not applicable. There is no advisory database for AGNOS
#                 bundles. The nearest equivalent is `cyrius deps --verify`
#                 (sha256 per resolved dep) plus the CI security scan, both of
#                 which already run.
#
# Usage:
#   scripts/supply-chain.sh           # enforce; non-zero exit on violation
#   scripts/supply-chain.sh --print   # print the effective policy, check nothing
#
# Requires `cyrius deps` to have run: check 5 reads each dep's own cyrius.cyml
# out of the resolved clone, rather than trusting a value restated here.

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

MANIFEST="cyrius.cyml"
LOCKFILE="cyrius.lock"
DEPS_CACHE="${CYRIUS_HOME:-$HOME/.cyrius}/deps"

# --- Policy ------------------------------------------------------------
# Sources: first-party AGNOS only. "Own the stack" — if an AGNOS crate wraps
# an external lib, nein depends on the AGNOS crate, never the external one.
ALLOWED_SOURCE_PREFIXES=(
    "https://github.com/MacCracken/"
)

# Licences: carried forward from rust-old/deny.toml [licenses].allow.
# All are GPL-3.0 compatible, which nein (GPL-3.0-only) requires of anything
# it links.
ALLOWED_LICENSES=(
    "MIT"
    "Apache-2.0"
    "Apache-2.0 WITH LLVM-exception"
    "BSD-2-Clause"
    "BSD-3-Clause"
    "ISC"
    "Unicode-3.0"
    "GPL-3.0-only"
    "LGPL-3.0-only"
    "AGPL-3.0-only"
    "MPL-2.0"
    "Zlib"
)

# Transitive stdlib modules that land in ./lib/ without nein declaring them.
# `cyrius lib sync` copies the DECLARED [deps].stdlib subset; `cyrius deps`
# then adds whatever each git dep's `.deps` sidecar requires on top. That
# second set is invisible in cyrius.cyml, so it is recorded here — check 8
# fails on anything that appears in lib/ and is not on one of the lists.
#
# The TLS stack below arrives via majra's sidecar (dist/majra.deps requires
# tls, dynlib, fdlopen, async, sandhi), NOT via bote — nein declares none of
# them and calls none of them, but they are resolved into the tree and
# hash-pinned in cyrius.lock all the same. Recorded rather than removed
# because nein cannot control a dependency's own sidecar; the point of this
# list is that the NEXT arrival fails the build instead of slipping in.
ACCEPTED_TRANSITIVES=(
    "alloc_cx"   # cyrius 6.6.5+: the allocator peer for the cx bytecode
                 # target. `lib/alloc.cyr` includes it unconditionally, so it
                 # lands in lib/ for every consumer; nein reaches none of it
                 # (no cx target). Arrived with the 6.6.2 -> 6.6.6 bump at
                 # 1.6.12 — it does not exist in the 6.6.4 snapshot.
    "sys"        # named by the libro 2.10.3 AND majra 2.9.1 dep sidecars.
                 # Both arrived with 1.6.12's pin bumps. sigil 3.12.18 is the
                 # reason it is load-bearing: its `agnosys_uname` calls
                 # `sys_uname` from lib/sys.cyr rather than a raw syscall(63),
                 # which is also why `duplicate fn 'uname_release'` warns on
                 # units linking both (upstream sigil packaging, harmless).
    "async"
    "boxed"      # cyrius 6.6.0: the boxed Result/Option surface
                 # (tagged_new / boxed_tag / boxed_payload) split out of
                 # tagged.cyr when Result became a register-pair value.
    "hashseed"   # cyrius 6.6.x: per-process randomized hash seeding,
                 # pulled in by hashmap. Closes a hash-flooding DoS.
    "dynlib"
    "fdlopen"
    "mmap"
    "sandhi"
    "test"
    "tls"
    "tls_native"
    "tls_native_conn"
    "tls_native_ctx"
    "tls_native_hs12"
    "tls_native_hs13"
    "tls_native_keysched"
    "tls_native_lowlevel"
)

if [[ "${1:-}" == "--print" ]]; then
    echo "nein dependency supply-chain policy"
    echo ""
    echo "allowed source prefixes:"
    printf '  %s\n' "${ALLOWED_SOURCE_PREFIXES[@]}"
    echo ""
    echo "allowed licences:"
    printf '  %s\n' "${ALLOWED_LICENSES[@]}"
    echo ""
    echo "accepted undeclared transitive stdlib (resolved into lib/ by dep sidecars):"
    printf '  %s\n' "${ACCEPTED_TRANSITIVES[@]}"
    echo ""
    echo "structural rules: exact tag pin required; no path/branch/rev deps;"
    echo "                  every dep commit-pinned in $LOCKFILE; no duplicate names;"
    echo "                  nothing in lib/ outside declared stdlib + dep modules +"
    echo "                  accepted transitives"
    exit 0
fi

FAIL=0
fail() { echo "  FAIL: $*"; FAIL=1; }
ok()   { echo "  ok:   $*"; }

[ -f "$MANIFEST" ] || { echo "no $MANIFEST in $REPO_ROOT" >&2; exit 1; }
[ -f "$LOCKFILE" ] || { echo "no $LOCKFILE — run 'cyrius deps' first" >&2; exit 1; }

# --- Parse [deps.NAME] blocks -----------------------------------------
# Emits one "name<TAB>key<TAB>value" row per field. Section names may contain
# a hyphen (`[deps.bote-core]` since 1.6.6 — the section is named for the
# MODULE it pulls, not the repo, so distlib omits it from the .deps sidecar).
DEPS=$(awk '
    /^\[deps\.[A-Za-z0-9_-]+\]/ {
        name = $0
        sub(/^\[deps\./, "", name)
        sub(/\]$/, "", name)
        next
    }
    /^\[/ { name = "" ; next }
    name != "" && /^[a-z]+ *=/ {
        key = $1
        line = $0
        sub(/^[^=]*= */, "", line)
        gsub(/^"|"$/, "", line)
        print name "\t" key "\t" line
    }
' "$MANIFEST")

DEP_NAMES=$(echo "$DEPS" | cut -f1 | awk '!seen[$0]++')
DEP_COUNT=$(echo "$DEP_NAMES" | grep -c . || true)

echo "=== nein supply-chain policy ==="
echo "$DEP_COUNT git dependencies declared in $MANIFEST"
echo ""

field() { echo "$DEPS" | awk -F'\t' -v n="$1" -v k="$2" '$1==n && $2==k {print $3; exit}'; }

# --- 6: no duplicate declarations -------------------------------------
# Count SECTION HEADERS, not field rows — each dep contributes several rows to
# $DEPS (git / tag / modules), so deduping that would flag every dep.
DUPES=$(grep -oE '^\[deps\.[A-Za-z0-9_-]+\]' "$MANIFEST" | sort | uniq -d || true)
if [ -n "$DUPES" ]; then
    fail "dep declared more than once (single-pass last-wins would silently pick one): $DUPES"
else
    ok "no duplicate dep declarations"
fi

for name in $DEP_NAMES; do
    [ -n "$name" ] || continue
    echo ""
    echo "[deps.$name]"

    url=$(field "$name" git)
    tag=$(field "$name" tag)
    path=$(field "$name" path)
    branch=$(field "$name" branch)
    rev=$(field "$name" rev)

    # --- 1 + 3: structural pinning ------------------------------------
    if [ -n "$path" ]; then
        fail "local path dep ('path = $path') — not reproducible off this machine"
        continue
    fi
    if [ -z "$url" ]; then
        fail "no 'git =' source"
        continue
    fi
    if [ -n "$branch" ]; then
        fail "floating ref 'branch = $branch' — an exact tag is required"
    fi
    if [ -n "$rev" ]; then
        fail "'rev = $rev' — pin by tag, which cyrius.lock then resolves to a sha"
    fi
    if [ -z "$tag" ]; then
        fail "no 'tag =' — exact immutable pin required"
        continue
    fi
    ok "pinned at tag $tag"

    # --- 2: allowed source --------------------------------------------
    src_ok=0
    for prefix in "${ALLOWED_SOURCE_PREFIXES[@]}"; do
        case "$url" in "$prefix"*) src_ok=1 ;; esac
    done
    if [ "$src_ok" -eq 1 ]; then
        ok "source $url"
    else
        fail "source not on the allow-list: $url"
    fi

    # --- 4: commit-pinned in the lockfile -----------------------------
    lock_line=$(awk -F'\t' -v n="$name" '$1=="commit" && $3==n {print; exit}' "$LOCKFILE")
    if [ -z "$lock_line" ]; then
        fail "no commit entry in $LOCKFILE — run 'cyrius deps'"
    else
        lock_sha=$(echo "$lock_line" | cut -f2)
        lock_tag=$(echo "$lock_line" | cut -f5)
        if [ "$lock_tag" != "$tag" ]; then
            fail "lock tag ($lock_tag) != manifest tag ($tag) — re-run 'cyrius deps'"
        elif [ "${#lock_sha}" -ne 40 ]; then
            fail "lock sha is not a 40-char commit id: $lock_sha"
        else
            ok "locked at ${lock_sha:0:12} (tag matches)"
        fi
    fi

    # --- 5: licence ----------------------------------------------------
    # Read the dep's OWN declaration out of the resolved clone rather than
    # trusting a value restated in this script. Clones are keyed by section
    # name; fall back to the repo basename for trees resolved before a
    # section rename.
    repo=$(basename "$url" .git)
    clone=""
    for cand in "$DEPS_CACHE/$name/$tag" "$DEPS_CACHE/$repo/$tag"; do
        [ -f "$cand/cyrius.cyml" ] && { clone="$cand"; break; }
    done

    if [ -z "$clone" ]; then
        fail "no resolved clone for $name@$tag under $DEPS_CACHE — run 'cyrius deps' first"
        continue
    fi

    lic=$(grep -m1 '^license *=' "$clone/cyrius.cyml" | sed 's/^license *= *"\(.*\)"/\1/')
    if [ -z "$lic" ]; then
        fail "no license field in $name@$tag's cyrius.cyml"
        continue
    fi
    lic_ok=0
    for allowed in "${ALLOWED_LICENSES[@]}"; do
        [ "$lic" = "$allowed" ] && lic_ok=1
    done
    if [ "$lic_ok" -eq 1 ]; then
        ok "licence $lic"
    else
        fail "licence '$lic' is not on the allow-list"
    fi
done

# --- 8: no undeclared modules in the resolved tree --------------------
# cargo-deny's [sources] unknown-registry, reinterpreted. There is no
# registry, but there IS a set of modules that arrive in ./lib/ without
# appearing anywhere in cyrius.cyml — pulled by a git dep's own .deps
# sidecar. They are hash-pinned by cyrius.lock, so integrity is covered;
# what is NOT covered is anyone noticing a new one show up. This is that
# check. Arch/platform variants (foo_x86_64_linux, foo_win, ...) collapse
# onto their base module name.
echo ""
echo "resolved tree"
if [ ! -d lib ] || [ -z "$(ls -A lib/*.cyr 2>/dev/null)" ]; then
    fail "./lib/ is empty — run 'cyrius lib sync && cyrius deps' first"
else
    declared_stdlib=$(awk '/^stdlib = \[/,/^\]/' "$MANIFEST" | grep -oE '"[a-z_0-9]+"' | tr -d '"')
    dep_modules=$(grep -oE '"dist/[a-z_0-9-]+\.cyr"' "$MANIFEST" | sed 's|"dist/||; s|\.cyr"||' | sort -u)
    known=$(printf '%s\n%s\n%s\n' "$declared_stdlib" "$dep_modules" "$(printf '%s\n' "${ACCEPTED_TRANSITIVES[@]}")" | sort -u)

    unknown=""
    for f in lib/*.cyr; do
        m=$(basename "$f" .cyr)
        # collapse arch / platform variants onto the base module
        base=$(echo "$m" | sed -E 's/_(x86_64_linux|aarch64_linux|linux_common|x86_64_agnos|windows|macos|agnos|win|fast)$//')
        echo "$known" | grep -qx "$base" || unknown="$unknown $base"
    done
    # `|| true`: with nothing unknown, grep matches nothing and exits 1, which
    # under `set -e` would kill the script on the assignment.
    unknown=$(echo "$unknown" | tr ' ' '\n' | grep -v '^$' | sort -u | tr '\n' ' ' || true)

    lib_count=$(ls lib/*.cyr | wc -l | tr -d ' ')
    if [ -n "$unknown" ]; then
        fail "modules in lib/ that are neither declared nor accepted transitives:$unknown"
        echo "        If legitimate, add them to ACCEPTED_TRANSITIVES in this script"
        echo "        and say which dep sidecar pulls them in docs/development/dependencies.md."
    else
        ok "$lib_count files in lib/, all declared or accepted (${#ACCEPTED_TRANSITIVES[@]} accepted transitives)"
    fi
fi

# --- 7: nein's own licence --------------------------------------------
echo ""
own_lic=$(grep -m1 '^license *=' "$MANIFEST" | sed 's/^license *= *"\(.*\)"/\1/')
own_ok=0
for allowed in "${ALLOWED_LICENSES[@]}"; do
    [ "$own_lic" = "$allowed" ] && own_ok=1
done
if [ "$own_ok" -eq 1 ]; then
    ok "nein's own licence $own_lic"
else
    fail "nein's own licence '$own_lic' is not on the allow-list"
fi

echo ""
if [ "$FAIL" -eq 0 ]; then
    echo "supply-chain: PASS ($DEP_COUNT deps, 0 violations)"
else
    echo "supply-chain: FAIL — see above"
fi
exit $FAIL
