# Doc Health

Currency ledger for nein's prose documentation. Each row tracks the last
refresh against the codebase, the responsible reviewer cadence, and a
status traffic light.

Pattern lifted from agnosys/agnostik 1.2.x. Refresh policy:

- ✅ **Green** — refreshed in the current minor (≤ ~30 days)
- 🟠 **Yellow** — refreshed in the previous minor; due for a read-through
- 🔴 **Red** — multiple minors stale; rewrite candidate

Last refresh of this ledger: **2026-05-10** (post v1.4.0 — apply-layer hardening; T-3 closed; integration scaffold).

## Top-level docs

| Doc | Last refresh | Status | Notes |
|-----|--------------|--------|-------|
| `README.md` | 2026-05-10 | ✅ | Refreshed in v1.4.0: test count 580→585; added `nein_set_nft_path` example for systems with nft outside `/usr/sbin/`; added `tests/integration/` section with permission-denied class doc. |
| `CHANGELOG.md` | 2026-05-10 | ✅ | Updated each release. |
| `CLAUDE.md` | 2026-05-10 | ✅ | Refreshed in v1.1.3: cc3→cc5, pinned cyrius=5.10.34, removed phantom `mcp.cyr` from architecture tree, CI-gate inventory in status line. |
| `CONTRIBUTING.md` | 2026-05-10 | ✅ | Refreshed in v1.1.4: cargo/Makefile/clippy → cyrius CI reproduction recipe, new-module workflow with api-surface update, threat-model coupling. |
| `SECURITY.md` | 2026-05-10 | ✅ | Refreshed in v1.1.4: ties to T-1…T-8, PATH-injection allowlist, symbol-collision audit, lockfile-pinned deps. Supported-versions table updated for v1.1.x baseline. |
| `VERSION` | 2026-05-10 | ✅ | Mechanical. |

## Architecture

| Doc | Last refresh | Status | Notes |
|-----|--------------|--------|-------|
| `docs/architecture/overview.md` | 2026-05-10 | ✅ | Refreshed in v1.1.4: on-disk module map, validate→render→apply data flow, cstring/Str/i64 type-boundary doc, ADR cross-reference. |

## Decisions (ADRs)

ADRs are point-in-time records — they don't decay the way prose docs do.
Each ADR is dated at write-time; superseding ADRs reference the originals.

| ADR | Status | Notes |
|-----|--------|-------|
| 0001 Render-not-execute | ✅ Active | Foundational; still holds. |
| 0002 Validate-before-apply | ✅ Active | Reinforced by v1.1.2 `: cstring` annotation pass on validate.cyr. |
| 0003 Feature-gated modules | ✅ Active | Pattern carried forward; `#ifdef` strategy unchanged. |
| 0004 Raw match escape hatch | ✅ Active | |
| 0005 ChainRule enum | ✅ Active | |
| 0006 Sets in tables | ✅ Active | |
| 0007 Set-based isolation | ✅ Active | |
| 0008 Typed enums over strings | ✅ Active | Aligns with cyrius 5.10.x type-check direction. |
| 0009 Non-exhaustive public structs | ✅ Active | |

## Development

| Doc | Last refresh | Status | Notes |
|-----|--------------|--------|-------|
| `docs/development/roadmap.md` | 2026-05-10 | ✅ | Restructured in v1.1.0; v1.1.1 / v1.1.2 progress folded in. |
| `docs/development/threat-model.md` | 2026-05-10 | ✅ | T-3 hardened in v1.4.0: single pinned absolute path, no fallback chain, runtime override via `nein_set_nft_path` (validated: absolute / ≤ 256 bytes / non-null). Pre-v1.4.0 multi-path race documented in the "Pre-v1.4.0 behavior" subsection. |
| `docs/development/capability-map.md` | 2026-05-10 | ✅ | Subprocess section refreshed in v1.4.0: single pinned `nft` path (default `/usr/sbin/nft`, override via `nein_set_nft_path`) replaces the prior 3-path fallback. |

## Guides

| Doc | Last refresh | Status | Notes |
|-----|--------------|--------|-------|
| `docs/guides/testing.md` | 2026-05-10 | ✅ | Refreshed in v1.1.4: full cargo→cyrius rewrite. Now documents `cyrius test`, the bench-regression flow with threshold semantics, fuzz invocation, and the full CI-reproduction recipe. |

Other integration guides (sutra playbooks, daimon MCP tools) will be
added lazily as those consumers wire nein in — both queued for
v1.4.0+ work.

## Sources

`docs/sources/` is not present and is not required — nein is a systems
library, not a science/math crate, so no academic citations are owed.

## Refresh cadence

Per CLAUDE.md's work-loop, **every minor release** (`x.Y.0`) is expected
to refresh this ledger plus any 🟠/🔴 docs above. Patches (`x.y.Z`) may
update individual rows without a full sweep. Touches to a tracked doc
should bump its row's "Last refresh" date in the same PR.
