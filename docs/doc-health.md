# Doc Health

Currency ledger for nein's prose documentation. Each row tracks the last
refresh against the codebase, the responsible reviewer cadence, and a
status traffic light.

Pattern lifted from agnosys/agnostik 1.2.x. Refresh policy:

- ✅ **Green** — refreshed in the current minor (≤ ~30 days)
- 🟠 **Yellow** — refreshed in the previous minor; due for a read-through
- 🔴 **Red** — multiple minors stale; rewrite candidate

Last refresh of this ledger: **2026-08-21** (post v1.6.10 — a **full
staleness sweep**, the first since the v1.6.4 content pass. Every checkable
claim in every prose doc was re-verified against the code; 1.6.7–1.6.10 had
shipped four releases' worth of change against docs last content-refreshed at
v1.6.5, so most counts and several behavioural descriptions were stale.

Corrections of note: the threat model's T-7 asserted that a green build implies
zero symbol collisions — false on both halves, and it exposed a real gap in the
type-check gate (the toolchain's `compile …` line has no trailing newline, so
the first warning of every build was invisible to `^warning:`); T-8's "no
floating tags" was untrue of the installer fetch path; `capability-map.md` was
missing the 1.6.10 `rt_sigaction` syscall, which would have made a seccomp
profile built from it kill the first apply, and it wrongly claimed the
read-only MCP tools have no syscall surface; `overview.md` still described
feature-gated modules per the now-superseded ADR-0003; and `testing.md`
documented a fuzz iteration count and timeout that never existed, plus a
`NEIN_INTEGRATION` env gate that no code has ever read.

The prior header of this ledger described v1.6.10 as "the `.deps` sidecar
packaging fix" — that was **v1.6.6**; 1.6.10 closed the P(-1) audit's open
findings.)

## Top-level docs

| Doc | Last refresh | Status | Notes |
|-----|--------------|--------|-------|
| `README.md` | 2026-08-21 | ✅ | v1.6.10 sweep: test count 664→754, benchmarks 31→48, dev recipe now uses `cyrius tests`; the idempotent-apply section rewritten for the 1.6.10 ordered-rebuild diff semantics and the validation/dry-run behaviour. All 47 fns used in the code examples verified against the API snapshot. Prior v1.6.4 sweep: Prior v1.6.4 sweep: 19→21 modules (added `sign`/`mcp` rows), 601→664 tests, removed the stale "mcp blocked on bote" bullet, `agnosys`→`agnodrm`. |
| `CHANGELOG.md` | 2026-08-21 | ✅ | Updated each release (entries through v1.6.10). |
| `CLAUDE.md` | 2026-08-21 | ✅ | v1.6.10: status line → 1.6.10, counts → 754/48/394; the "80%+ coverage target" replaced with the two measured, gated figures. v1.6.6: status line → 1.6.6 (+ sidecar-fix note). v1.6.5: status line → 1.6.5, pin `6.4.66`→`6.5.33`. Prior v1.6.4 sweep: status line → v1.6.4; architecture tree +`firewall`/`sign`/`mcp`; `cc5`/`cc3`→`cycc`; pin `5.10.34`→`6.4.66`; `cyrius.toml`→`cyrius.cyml`; explicit-deps model; `/lib/` gitignore. |
| `CONTRIBUTING.md` | 2026-08-21 | ✅ | v1.6.5: install recipe `6.4.66`→`6.5.33`; CI-repro block rewritten for 6.5.x (`cyrius fmt --check`, not the stdout diff — the old recipe silently rewrites the tree), capacity now a real gate, `cyrius tests`/`fuzz`/`distlib` steps added; new **Cutting a Release** section + `bench-track.sh` baseline guidance. Prior v1.6.4 sweep: toolchain `5.10.34`→`6.4.66` install recipe, `cyrius lib sync` step, integration harness shipped, fuzz path `fuzz/*.fcyr`. |
| `SECURITY.md` | 2026-08-21 | ✅ | v1.6.5: T-8 dep set retagged (libro 2.8.8 / majra 2.6.7 / bote 3.3.2 / sigil 3.12.9 / patra 1.13.9), sakshi noted as no longer a git dep, cyrius pin `6.5.33`, link to `dependencies.md`. Prior v1.6.4 sweep: supported versions `1.1.x`→`1.6.x`, cyrius pin, dep set (`agnosys`→libro/majra/bote/sigil/patra/sakshi), T-3 single pinned path. |
| `VERSION` | 2026-08-21 | ✅ | Mechanical (1.6.10). |

## Architecture

| Doc | Last refresh | Status | Notes |
|-----|--------------|--------|-------|
| `docs/architecture/overview.md` | 2026-08-21 | ✅ | v1.6.10 sweep: refresh marker v1.6.5→v1.6.10, 383→394 fns, 8→9 validators, toolchain 6.4.x→6.5.33, consumer pin 1.6.4→1.6.10 with a "pin at or above 1.6.9" note, and the feature-gated-modules bullet rewritten — ADR-0003 is superseded and there are zero `#ifdef` in the tree. Prior: v1.6.5 re-read: module map and fn count (383) still accurate; refresh marker only. Prior v1.6.4 sweep: module map +`diff`/`sign`/`mcp`, fn count 348→383, `mcp` no longer "blocked", consumer + `dist/nein.cyr`/`dist/nein-mcp.cyr` bundle section current, `/usr/sbin/nft` path. |

## Decisions (ADRs)

ADRs are point-in-time records — they don't decay the way prose docs do.
Each ADR is dated at write-time; superseding ADRs reference the originals.

| ADR | Status | Notes |
|-----|--------|-------|
| 0001 Render-not-execute | ✅ Active | Foundational; still holds. |
| 0002 Validate-before-apply | ✅ Active | Reinforced by v1.1.2 `: cstring` annotation pass on validate.cyr. |
| 0003 Feature-gated modules (**superseded** v1.6.10) | ✅ Active | Pattern carried forward; `#ifdef` strategy unchanged (mcp/sign are opt-in per this ADR). |
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
| `docs/development/capability-map.md` | 2026-08-21 | ✅ | v1.6.10 sweep: added the `rt_sigaction` direct syscall from the SIGPIPE guard to both the apply row and the Lens-2 roll-up (**a seccomp profile built from the older map kills the first apply**); corrected the claim that read-only MCP tools have no syscall surface — `nein_status`/`nein_list` fork+execve nft; noted `diff_compute` is not side-effect-free. v1.6.6: version block → 1.6.6. v1.6.5: version block → 1.6.5 / cyrius 6.5.33. Prior v1.6.4 sweep: Lens-2 single pinned nft path, added `sign` + `mcp` per-module entries (both transitive-only). |
| `docs/development/dependencies.md` | 2026-08-21 | ✅ | v1.6.6: `[deps.*]` table row `bote`→`bote-core`; new section on why the section is named for the module, not the repo (the `distlib` basename==section-name rule that put `bote-core` in both sidecars as a stdlib leaf), and a sidecar rule note — a sidecar may name stdlib leaves only. **New at v1.6.5.** Prose home for the `[deps]` rationale removed from `cyrius.cyml` (the `.cyml` parser mis-resolves deps when comments sit inside the `stdlib` array). Covers the explicit build sequence, per-module justification, pin ordering, the sigil/patra top-level pins, and what was dropped (agnosys, vendored bote-core). |
| `docs/development/supply-chain-policy.md` | 2026-08-21 | ✅ | **New at v1.6.8.** Successor to `rust-old/deny.toml`: allowed sources, pinning rules, the 12-entry SPDX licence allow-list, undeclared-transitive policy, and why `cyrius deny` cannot carry any of it. Enforced by `scripts/supply-chain.sh` as a CI gate. |
| `docs/audit/2026-08-21-audit.md` | 2026-08-21 | ✅ | **New at v1.6.9.** P(-1) scaffold-hardening security audit of v1.6.8: 7 review areas, adversarial verification of every MEDIUM+ finding, 1 CRITICAL + 6 HIGH + 10 MEDIUM + 17 LOW confirmed, 5 CRITICAL/HIGH fixed in 1.6.9; remaining 3 HIGH + 8 MEDIUM + all 6 doc errors fixed in 1.6.10, dispositions recorded in place. Records open findings with severity and fix sketches. |
| `docs/development/port-completeness.md` | 2026-08-21 | ✅ | **New at v1.6.7, amended at v1.6.8** (verdict past-tense; scale-benchmark claim corrected in place; `Cargo.toml` row added). Rust→Cyrius port-completeness audit: method, 172-fn and 22-enum disposition tables, the five intentional drops, the gaps closed at 1.6.7, and the verdict that `rust-old/` can be deleted. |

## Guides

| Doc | Last refresh | Status | Notes |
|-----|--------------|--------|-------|
| `docs/guides/testing.md` | 2026-08-21 | ✅ | v1.6.10 sweep: assertions 664→754, integration 16→18, benchmarks 31→48; Coverage section rewritten for the two 1.6.9 gates (and why `cyrius coverage --min` is deliberately not wired); the fabricated fuzz "500 iterations / 10-second timeout" claim removed; "What CI Runs" now lists all 19 gates, having omitted deny / doc-coverage / test-coverage / supply-chain / deps--verify / fuzz / integration / dist-staleness. Prior v1.6.4 sweep: assertion count 580→664, integration harness shipped (16 tests), Fuzzing section rewritten (5 `fuzz/*.fcyr` drivers via `cyrius fuzz`), toolchain `5.10.x`→`6.4.x`. |
| `docs/guides/mcp-host-integration.md` | 2026-08-21 | ✅ | v1.6.10 sweep: verified clean — the 6-tool table, dispatch/gate signatures, read-only/admin split and sidecar claims all check out against the code; consumer `tag` → 1.6.10. v1.6.6: consumer `tag` → 1.6.6 + a pin-1.6.6-or-later warning; **removed a now-false claim** that `dist/nein-mcp.deps` lists `bote-core` (it did, and that was the bug) and a stale cyrius-6.4.x note about `thread`/`thread_local` folding into `std`. v1.6.5: consumer `tag` bumped to 1.6.5. Shipped v1.6.2: daimon MCP host integration — `dist/nein-mcp.cyr` consumption, dispatch adapter, access-control gate. Tag/version refs current at 1.6.6. |

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
