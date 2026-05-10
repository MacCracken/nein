# Doc Health

Currency ledger for nein's prose documentation. Each row tracks the last
refresh against the codebase, the responsible reviewer cadence, and a
status traffic light.

Pattern lifted from agnosys/agnostik 1.2.x. Refresh policy:

- ✅ **Green** — refreshed in the current minor (≤ ~30 days)
- 🟠 **Yellow** — refreshed in the previous minor; due for a read-through
- 🔴 **Red** — multiple minors stale; rewrite candidate

Last refresh of this ledger: **2026-05-10** (post v1.1.3 — README + CLAUDE.md refreshed; doc-health and threat-model ✅).

## Top-level docs

| Doc | Last refresh | Status | Notes |
|-----|--------------|--------|-------|
| `README.md` | 2026-05-10 | ✅ | Refreshed in v1.1.3: bumped test/bench counts (541→580, 30→31), removed Rust-syntax `Match::Raw`, added `cyrius deps` + aarch64 build commands, linked the Cyrius-era threat model. |
| `CHANGELOG.md` | 2026-05-10 | ✅ | Updated each release. |
| `CLAUDE.md` | 2026-05-10 | ✅ | Refreshed in v1.1.3: cc3→cc5, pinned cyrius=5.10.34, removed phantom `mcp.cyr` from architecture tree, CI-gate inventory in status line. |
| `CONTRIBUTING.md` | 2026-03-22 | 🟠 | Pre-toolchain-migration. Build/test/bench commands need refresh against `cyrius build` / `cyrius test` shapes. |
| `SECURITY.md` | 2026-04-02 | 🟠 | Disclosure process current; CVE-pattern audit list could fold in v1.1.1 findings (rename collisions, aarch64 pipe). |
| `VERSION` | 2026-05-10 | ✅ | Mechanical. |

## Architecture

| Doc | Last refresh | Status | Notes |
|-----|--------------|--------|-------|
| `docs/architecture/overview.md` | 2026-03-22 | 🟠 | Predates v1.1.x. Design-philosophy section is durable; module list lags (no mention of the agnostik drop or v1.1.1 fn renames). |

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
| `docs/development/threat-model.md` | 2026-05-10 | ✅ | Full Rust-era → Cyrius rewrite in v1.1.2: 8 numbered threats (T-1 through T-8), folds in v1.1.1 findings on PATH-injection allowlist + symbol-collision shadow + supply chain. |

## Guides

`docs/guides/` is currently empty — populated lazily as integration
patterns stabilize (sutra playbooks, daimon MCP tools — both v1.4.0+).

## Sources

`docs/sources/` is not present and is not required — nein is a systems
library, not a science/math crate, so no academic citations are owed.

## Refresh cadence

Per CLAUDE.md's work-loop, **every minor release** (`x.Y.0`) is expected
to refresh this ledger plus any 🟠/🔴 docs above. Patches (`x.y.Z`) may
update individual rows without a full sweep. Touches to a tracked doc
should bump its row's "Last refresh" date in the same PR.
