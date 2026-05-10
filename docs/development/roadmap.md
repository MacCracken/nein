# Roadmap

Last refresh: 2026-05-10 (post v1.4.0 — apply-layer hardening minor).

The arc since v1.0.0 has been catch-up — toolchain 4.5.0 → 5.10.34, agnosys
0.97.2 → 1.2.4, agnostik 0.97.1 → 1.2.1. v1.1.x is the housekeeping shoulder
between that catch-up and the next functional minor (v1.2.0).

## Completed

### v1.0.0 — 2026-04-13
Full Rust → Cyrius port. 18 modules, 580 test assertions, 31 benchmarks,
~3,553 LOC Cyrius (55% reduction across ported modules).

- Core: error, validate, rule, set, nat, chain, table, firewall, builder
- Feature: policy, geoip, mesh, bridge, engine, config, netns, apply, inspect
- Injection-safe validators across 8 input types
- `nft -f -` subprocess execution via fork+pipe+execve (synchronous, blocking)

### v1.1.0 — 2026-05-10
Toolchain + dependency modernization. No source-level API changes.

- Cyrius 4.5.0 → **5.10.34** (declared in `cyrius.cyml`)
- agnosys 0.97.2 → **1.2.4** (`dist/agnosys-core.cyr` profile)
- agnostik 0.97.1 → **1.2.1** (`dist/agnostik.cyr`)
- Manifest: `cyrius.toml` → `cyrius.cyml` with `${file:VERSION}` interpolation
- `cyrius.lock` committed; CI rewritten to versioned-install pattern with
  lockfile hash verification + ELF magic check + version-consistency gate

### v1.1.1 — 2026-05-10
CI gate expansion + portability fixes surfaced by the new gates. aarch64
cross-build green. Binary -21% on x86_64.

- `cyrius fmt` / `cyrius lint` / `cyrius vet` / `cyrius capacity` gates
- aarch64 cross-build + DCE on all builds + security-scan job
- Fixed: `SYS_PIPE` → portable `sys_pipe(...)` (aarch64 portability)
- Fixed: `network_policy_new` / `err_code` collisions with stdlib +
  agnostik (renamed to `nein_*` prefix)
- Removed: agnostik dependency (never actually used in source)

### v1.1.2 — 2026-05-10
Type-check arc + doc currency. Zero nein-side type-check warnings.

- `CYRIUS_TYPE_CHECK=1` CI gate (filters stdlib self-flags + known-tracked
  large-static-data warning)
- `: cstring` / `: i64` annotations on validate.cyr + error.cyr surfaces
- `docs/doc-health.md` currency ledger (✅/🟠/🔴 traffic light per doc)
- `docs/development/threat-model.md` rewritten Rust-era → Cyrius-era,
  8 numbered threats (T-1 through T-8)

### v1.1.3 — 2026-05-10
Surface tracking + annotation pass on the construction surface + prose
refresh.

- `scripts/api-surface.sh` + `docs/api-surface.snapshot` (348 fns)
- `scripts/bench-regression.sh` + `docs/benchmarks/history.csv` baseline
- Currency check (CHANGELOG dated entry + roadmap refresh ≤ 90 days)
- ~55 type annotations across rule.cyr (match/verdict constructors) and
  apply.cyr (full public surface)
- README + CLAUDE.md refresh (both 🟠 → ✅ in doc-health)

---

### v1.1.4 — 2026-05-10
v1.1 minor closeout pass. Prose-doc currency, dead-code audit, clean
build verification — no source-level behavior change.

- `docs/guides/testing.md` rewritten Rust→Cyrius (cargo → cyrius)
- `CONTRIBUTING.md` rewritten Rust→Cyrius (Makefile/clippy → cyrius CI)
- `SECURITY.md` refreshed for v1.1.x (folded T-1…T-8 references)
- `docs/architecture/overview.md` refreshed (module surface + data flow
  + cstring/Str/i64 boundary convention)
- Closeout: dead-code audit, full build from clean, downstream consumers
  surveyed (none actually depend on nein yet)

### v1.2.0 — 2026-05-10
First feature minor since the port. Consumer-bundle shape, audit-trail
story, capability map.

- `dist/nein.cyr` bundle (147 KB, 4621 lines) via `cyrius distlib` from
  new `[lib]` section in `cyrius.cyml`. CI staleness gate.
- Sakshi tracing on `apply.cyr` — `_run_nft_stdin` + `_run_nft_capture`
  wrapped in `sakshi_span_enter` / `sakshi_span_exit`; per-step error
  + warn + info events
- `docs/development/capability-map.md` — per-module syscall / subprocess
  / fs-path footprint with rendering-only vs apply-layer reading lenses
- `cyrius.lock` and `dist/` moved from gitignore to in-tree — supply
  chain hash gate now hard, consumers no longer run distlib themselves
- Scope revision documented: original "split deps by profile" item
  removed (nein's netns is builder-only); OTLP audit-emit deferred (no
  consumer asking, would regress the v1.1.1 agnostik drop)

---

## v1.2.x — Annotation closeout (patches, no API change)

### v1.2.1 — 2026-05-10
Annotation pass on the remaining 14 modules — chain, table, set, nat,
firewall, builder, policy, geoip, mesh, bridge, engine, config, netns,
inspect. ~250 fn signatures. Type-check coverage now end-to-end across
all 18 modules + the apply layer's `Str`/`cstring` boundary. API surface
unchanged.

---

## v1.3.0 — 2026-05-10
Validation-depth minor. Fuzz harness split per-target; idiom audit
documented.

- 5 per-target fuzz drivers under `fuzz/` (validate, config_parse,
  rule, nat, firewall) — replaces `tests/nein.fcyr` smoke harness
- CI `Fuzz` step uses `cyrius fuzz` auto-discovery
- `docs/architecture/overview.md` "Rendering Idioms" section —
  per-module `str_builder` call audit, three legitimate `var buf[N]`
  exceptions, vec-of-pointers pattern documented
- Deferred: packed Result on hot paths (needs measured win to pay for
  caller migration; revisit in v1.4.0); doctest pass (no `///`
  comments yet; v1.3.1 if patching continues)

---

## v1.4.0 — 2026-05-10
Apply-layer hardening minor. Closed threat-model T-3 (PATH-injection
multi-path race), hardened the inspect parser for real-shape nft output,
scaffolded integration tests.

- `nein_set_nft_path` / `nein_nft_path` — single pinned absolute path
  with runtime override; replaces the pre-v1.4.0 3-path fallback chain
- `_parse_ruleset` block-nesting tracker — set/map/flowtable bodies no
  longer count as rules; chain-internal handle annotations skipped
- `tests/integration/apply_smoke.tcyr` scaffold with apply-outcome
  classifier; CI step runs unconditionally
- Deferred to v1.5.0: live-rule diff (`nein diff`); too big without
  splitting v1.4.0's hardening theme

## v1.5.0 — Live-rule diff + idempotent apply (next, feature minor)

- [ ] **`nein diff <target>` module** — compare an in-memory firewall
      plan against the live kernel ruleset (via `list_ruleset_with_handles`)
      and emit the minimal set of `add` / `insert` / `delete` operations
      to converge. Pairs with sutra's idempotent-apply playbook
      semantics. New module `src/lib/diff.cyr`.
- [ ] **Apply transactions** — wrap a diff plan in `nft -f -` atomically
      so partial failures don't leave the ruleset in a half-converged
      state. Builds on the v1.4.0 apply layer.
- [ ] **Doctest pass** — once the diff API is settled, add `///`
      examples to the validate / apply / diff public-fn surface; CI
      `cyrius doctest` gate.
- [ ] Re-evaluate **packed Result** with diff-layer hot paths in mind.

---

## v2.0.0 — Ecosystem integration (major, blocked on upstream)

- [ ] **`mcp` module — Claude MCP tool descriptors.** Blocked on
      [bote](https://github.com/MacCracken/bote) Cyrius port.
      Tools: `nein_render_firewall`, `nein_apply_firewall`,
      `nein_validate_rule`, `nein_inspect_status`, `nein_diff`
- [ ] **Full TOML struct parsing** (sutra-driven). Blocked on richer
      `toml` stdlib parsing (the v1.0 scoped enum-dispatchers in
      `config.cyr` cover today's needs but not nested struct shapes)
- [ ] **Fleet-playbook schema** (sutra-driven). Defines a serializable
      firewall plan independent of the in-memory builder API
- [ ] **Optional rule-set signing** via sigil. Stored ruleset includes
      Ed25519 signature; aegis verifies before apply. Defense-in-depth
      for at-rest plan tampering
- [ ] **daimon firewall MCP tools shipped jointly** (one PR pair)

---

## Blocked on upstream

| Item | Blocked on | Notes |
|------|-----------|-------|
| `mcp` module | bote Cyrius port | Cannot scaffold tool descriptors without bote's runtime |
| Full TOML struct parsing | richer `toml` stdlib | v1.0 enum-dispatchers cover today's needs |
| Sutra playbook schema | sutra design + TOML parsing | Sequenced after the toml unblock |
| `dist/agnosys-system.cyr` netns helpers | none — local | Pull-side change, queued for v1.2.0 |

---

## v1.0 acceptance criteria — kept for reference

- [x] All ported modules pass test + benchmark suites
- [x] Firewall rendering matches Rust output byte-for-byte on tested paths
- [x] Validators reject all known injection patterns
- [x] Documentation: architecture, CHANGELOG, roadmap, README, threat model
- [x] Deferred work documented with explicit upstream blockers
