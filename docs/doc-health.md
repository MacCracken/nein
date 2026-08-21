# Doc Health

Currency ledger for nein's prose documentation. Each row tracks the last
refresh against the codebase, the responsible reviewer cadence, and a
status traffic light.

Pattern lifted from agnosys/agnostik 1.2.x. Refresh policy:

- ✅ **Green** — refreshed in the current minor (≤ ~30 days)
- 🟠 **Yellow** — refreshed in the previous minor; due for a read-through
- 🔴 **Red** — multiple minors stale; rewrite candidate

Last refresh of this ledger: **2026-08-21** (post v1.6.6 — the `.deps`
sidecar packaging fix. Targeted, not a sweep: only the docs that made a
now-false claim about the sidecars, or that state the current version, were
touched. The v1.6.5 pass before it updated version/pin/dep-set refs across
every row below and added `docs/development/dependencies.md` as the prose
home for the `[deps]` rationale that used to live in `cyrius.cyml` comments;
the 1.6.4 sweep before that was the full content pass across the
1.6.0–1.6.4 line.)

## Top-level docs

| Doc | Last refresh | Status | Notes |
|-----|--------------|--------|-------|
| `README.md` | 2026-08-21 | ✅ | v1.6.5 re-read: module count (21), test count (664), and dev recipe all still accurate — no edits owed. Prior v1.6.4 sweep: 19→21 modules (added `sign`/`mcp` rows), 601→664 tests, removed the stale "mcp blocked on bote" bullet, `agnosys`→`agnodrm`. |
| `CHANGELOG.md` | 2026-08-21 | ✅ | Updated each release (entries through v1.6.6). |
| `CLAUDE.md` | 2026-08-21 | ✅ | v1.6.6: status line → 1.6.6 (+ sidecar-fix note). v1.6.5: status line → 1.6.5, pin `6.4.66`→`6.5.33`. Prior v1.6.4 sweep: status line → v1.6.4; architecture tree +`firewall`/`sign`/`mcp`; `cc5`/`cc3`→`cycc`; pin `5.10.34`→`6.4.66`; `cyrius.toml`→`cyrius.cyml`; explicit-deps model; `/lib/` gitignore. |
| `CONTRIBUTING.md` | 2026-08-21 | ✅ | v1.6.5: install recipe `6.4.66`→`6.5.33`; CI-repro block rewritten for 6.5.x (`cyrius fmt --check`, not the stdout diff — the old recipe silently rewrites the tree), capacity now a real gate, `cyrius tests`/`fuzz`/`distlib` steps added; new **Cutting a Release** section + `bench-track.sh` baseline guidance. Prior v1.6.4 sweep: toolchain `5.10.34`→`6.4.66` install recipe, `cyrius lib sync` step, integration harness shipped, fuzz path `fuzz/*.fcyr`. |
| `SECURITY.md` | 2026-08-21 | ✅ | v1.6.5: T-8 dep set retagged (libro 2.8.8 / majra 2.6.7 / bote 3.3.2 / sigil 3.12.9 / patra 1.13.9), sakshi noted as no longer a git dep, cyrius pin `6.5.33`, link to `dependencies.md`. Prior v1.6.4 sweep: supported versions `1.1.x`→`1.6.x`, cyrius pin, dep set (`agnosys`→libro/majra/bote/sigil/patra/sakshi), T-3 single pinned path. |
| `VERSION` | 2026-08-21 | ✅ | Mechanical (1.6.6). |

## Architecture

| Doc | Last refresh | Status | Notes |
|-----|--------------|--------|-------|
| `docs/architecture/overview.md` | 2026-08-21 | ✅ | v1.6.5 re-read: module map and fn count (383) still accurate; refresh marker only. Prior v1.6.4 sweep: module map +`diff`/`sign`/`mcp`, fn count 348→383, `mcp` no longer "blocked", consumer + `dist/nein.cyr`/`dist/nein-mcp.cyr` bundle section current, `/usr/sbin/nft` path. |

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
| `docs/development/roadmap.md` | 2026-08-21 | ✅ | v1.6.6: current-state + refresh header → 1.6.6 (sidecar packaging fix). Bumped to v1.6.5 (toolchain 6.5.33 + dep refresh, 6.5.x tooling-behaviour notes, `dependencies.md` pointer). Prior: v1.6.4 (toolchain + dep refresh, bare-err bank); current-state module count 20→21. Release history lives in CHANGELOG.md. |
| `docs/development/threat-model.md` | 2026-08-21 | ✅ | v1.6.5: T-8 pin list retagged (libro 2.8.8 / majra 2.6.7 / bote 3.3.2 / sigil 3.12.9 / patra 1.13.9), sakshi's move out of the git dep set noted, cyrius pin `6.5.33`. Prior v1.6.4 pass — 1.6.x security surfaces modeled: added T-9 (Ed25519 signed-ruleset trust/integrity — key-substitution, tamper, downgrade, replay/keygen residuals), T-10 (MCP destructive-tool access control — fail-closed gate primitive vs. ungated-default fail-open), T-11 (MCP tool-argument injection + output escaping). Scope list +2 surfaces; T-8 pin still current. |
| `docs/development/capability-map.md` | 2026-08-21 | ✅ | v1.6.6: version block → 1.6.6. v1.6.5: version block → 1.6.5 / cyrius 6.5.33. Prior v1.6.4 sweep: Lens-2 single pinned nft path, added `sign` + `mcp` per-module entries (both transitive-only). |
| `docs/development/dependencies.md` | 2026-08-21 | ✅ | v1.6.6: `[deps.*]` table row `bote`→`bote-core`; new section on why the section is named for the module, not the repo (the `distlib` basename==section-name rule that put `bote-core` in both sidecars as a stdlib leaf), and a sidecar rule note — a sidecar may name stdlib leaves only. **New at v1.6.5.** Prose home for the `[deps]` rationale removed from `cyrius.cyml` (the `.cyml` parser mis-resolves deps when comments sit inside the `stdlib` array). Covers the explicit build sequence, per-module justification, pin ordering, the sigil/patra top-level pins, and what was dropped (agnosys, vendored bote-core). |

## Guides

| Doc | Last refresh | Status | Notes |
|-----|--------------|--------|-------|
| `docs/guides/testing.md` | 2026-08-21 | ✅ | v1.6.5 re-read: assertion counts unchanged (664 + 16); refresh marker only. Prior v1.6.4 sweep: assertion count 580→664, integration harness shipped (16 tests), Fuzzing section rewritten (5 `fuzz/*.fcyr` drivers via `cyrius fuzz`), toolchain `5.10.x`→`6.4.x`. |
| `docs/guides/mcp-host-integration.md` | 2026-08-21 | ✅ | v1.6.6: consumer `tag` → 1.6.6 + a pin-1.6.6-or-later warning; **removed a now-false claim** that `dist/nein-mcp.deps` lists `bote-core` (it did, and that was the bug) and a stale cyrius-6.4.x note about `thread`/`thread_local` folding into `std`. v1.6.5: consumer `tag` bumped to 1.6.5. Shipped v1.6.2: daimon MCP host integration — `dist/nein-mcp.cyr` consumption, dispatch adapter, access-control gate. Tag/version refs current at 1.6.6. |

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
