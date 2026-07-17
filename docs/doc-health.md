# Doc Health

Currency ledger for nein's prose documentation. Each row tracks the last
refresh against the codebase, the responsible reviewer cadence, and a
status traffic light.

Pattern lifted from agnosys/agnostik 1.2.x. Refresh policy:

- ✅ **Green** — refreshed in the current minor (≤ ~30 days)
- 🟠 **Yellow** — refreshed in the previous minor; due for a read-through
- 🔴 **Red** — multiple minors stale; rewrite candidate

Last refresh of this ledger: **2026-07-17** (post v1.6.4 — full doc-currency
sweep across all prose docs after the 1.6.0–1.6.4 line shipped: mcp module
(v1.6.0), sign module (v1.6.1), dist/nein-mcp.cyr bundle + daimon dispatch
adapter (v1.6.2), sigil/patra dep pins (v1.6.3), bote 3.1.4 + libro 2.8.2
bare-err bank (v1.6.4)).

## Top-level docs

| Doc | Last refresh | Status | Notes |
|-----|--------------|--------|-------|
| `README.md` | 2026-07-17 | ✅ | v1.6.4 sweep: module count 19→21 (added `sign`/`mcp` rows), test count 601→664, removed the stale "mcp blocked on bote" bullet, dev recipe gained `cyrius lib sync`, `agnosys`→`agnodrm`. |
| `CHANGELOG.md` | 2026-07-17 | ✅ | Updated each release (entries through v1.6.4). |
| `CLAUDE.md` | 2026-07-17 | ✅ | v1.6.4 sweep: status line → v1.6.4; architecture tree +`firewall`/`sign`/`mcp`; `cc5`/`cc3`→`cycc`; pin `5.10.34`→`6.4.66`; `cyrius.toml`→`cyrius.cyml`; explicit-deps model; `/lib/` gitignore. |
| `CONTRIBUTING.md` | 2026-07-17 | ✅ | v1.6.4 sweep: toolchain `5.10.34`→`6.4.66` install recipe, `cyrius lib sync` step, integration harness shipped, fuzz path `fuzz/*.fcyr`. |
| `SECURITY.md` | 2026-07-17 | ✅ | v1.6.4 sweep: supported versions `1.1.x`→`1.6.x`, cyrius pin, dep set (`agnosys`→libro/majra/bote/sigil/patra/sakshi), T-3 single pinned path. |
| `VERSION` | 2026-07-17 | ✅ | Mechanical (1.6.4). |

## Architecture

| Doc | Last refresh | Status | Notes |
|-----|--------------|--------|-------|
| `docs/architecture/overview.md` | 2026-07-17 | ✅ | v1.6.4 sweep: module map +`diff`/`sign`/`mcp`, fn count 348→383, `mcp` no longer "blocked", consumer + `dist/nein.cyr`/`dist/nein-mcp.cyr` bundle section current, `/usr/sbin/nft` path. |

## Decisions (ADRs)

ADRs are point-in-time records — they don't decay the way prose docs do.
Each ADR is dated at write-time; superseding ADRs reference the originals.

| ADR | Status | Notes |
|-----|--------|-------|
| 0001 Render-not-execute | ✅ Active | Foundational; still holds. |
| 0002 Validate-before-apply | ✅ Active | Reinforced by v1.1.2 `: cstring` annotation pass on validate.cyr. |
| 0003 Feature-gated modules | ✅ Active | Pattern carried forward; `#ifdef` strategy unchanged (mcp/sign are opt-in per this ADR). |
| 0004 Raw match escape hatch | ✅ Active | |
| 0005 ChainRule enum | ✅ Active | |
| 0006 Sets in tables | ✅ Active | |
| 0007 Set-based isolation | ✅ Active | |
| 0008 Typed enums over strings | ✅ Active | Aligns with cyrius 6.4.x type-check direction. |
| 0009 Non-exhaustive public structs | ✅ Active | |

## Development

| Doc | Last refresh | Status | Notes |
|-----|--------------|--------|-------|
| `docs/development/roadmap.md` | 2026-07-17 | ✅ | Bumped to v1.6.4 (toolchain + dep refresh, bare-err bank); current-state module count 20→21. Release history lives in CHANGELOG.md. |
| `docs/development/threat-model.md` | 2026-07-17 | 🟠 | T-8 dep set + toolchain pin brought current. **Gap:** the v1.6.1 `sign` (Ed25519 trust / key management) and v1.6.0 `mcp` (agent tool access-control) surfaces are not yet threat-modeled — a dedicated pass is pending. |
| `docs/development/capability-map.md` | 2026-07-17 | ✅ | v1.6.4 sweep: version block → 1.6.4 / cyrius 6.4.66, Lens-2 single pinned nft path, added `sign` + `mcp` per-module entries (both transitive-only). |

## Guides

| Doc | Last refresh | Status | Notes |
|-----|--------------|--------|-------|
| `docs/guides/testing.md` | 2026-07-17 | ✅ | v1.6.4 sweep: assertion count 580→664, integration harness shipped (16 tests), Fuzzing section rewritten (5 `fuzz/*.fcyr` drivers via `cyrius fuzz`), toolchain `5.10.x`→`6.4.x`. |
| `docs/guides/mcp-host-integration.md` | 2026-07-17 | ✅ | Shipped v1.6.2: daimon MCP host integration — `dist/nein-mcp.cyr` consumption, dispatch adapter, access-control gate. Tag/version refs current at 1.6.4. |

Sutra playbook integration guides remain queued as that consumer wires
nein in. The daimon MCP guide above shipped across v1.6.0–v1.6.2.

## Sources

`docs/sources/` is not present and is not required — nein is a systems
library, not a science/math crate, so no academic citations are owed.

## Refresh cadence

Per CLAUDE.md's work-loop, **every minor release** (`x.Y.0`) is expected
to refresh this ledger plus any 🟠/🔴 docs above. Patches (`x.y.Z`) may
update individual rows without a full sweep. Touches to a tracked doc
should bump its row's "Last refresh" date in the same PR.
