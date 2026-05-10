# Roadmap

Last refresh: 2026-05-10 (post v1.1.4 — v1.1 minor closeout).

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
- Closeout: dead-code audit (all "dead" warnings are unused stdlib —
  not nein's fault), full build from clean, downstream consumers
  surveyed (none actually depend on nein yet)

---

## v1.2.0 — Profile-aware deps + audit emit (next, feature minor)

The first feature minor since the port. Adopts patterns the broader AGNOS
ecosystem stabilized on between agnosys 1.0.0 and 1.2.x.

- [ ] **Split deps by profile.** `apply.cyr` + `netns.cyr` need the netns
      helpers (`netns_apply_nftables_ruleset`) that live in
      `dist/agnosys-system.cyr`, not `agnosys-core`. Pull both profiles via
      `#ifdef` gates so downstream consumers stay slim (per CLAUDE.md
      "consumers pull only what they need")
- [ ] **Sakshi tracing on apply-layer fns.** CLAUDE.md mandates structured
      logging on syscall sites; today only some apply-layer fns emit
      spans. Audit `apply.cyr`, `inspect.cyr`, `engine.cyr` for full
      coverage; tests assert span emission on success + failure
- [ ] **Optional OTLP audit-emit hook.** Use agnostik 1.2.0's
      `Span_to_otlp_proto` to expose an opt-in audit stream — daimon /
      aegis can consume rule-apply events without a custom format
- [ ] **Capability-map doc** (`docs/development/capability-map.md`) —
      enumerates the syscalls, paths (`/proc/net`, `nft` binary location),
      and capabilities (`CAP_NET_ADMIN`) nein touches. Pattern lifted from
      agnosys 1.2.1 — feeds seccomp-policy authors
- [ ] **`cyrius distlib` bundle.** Ship `dist/nein.cyr` as the canonical
      single-file consumption form for stiva / aegis / sutra (matches
      agnosys / agnostik / darshana convention). Bundle-staleness CI gate
- [ ] **Annotation pass on remaining `src/lib/` modules** (chain, table,
      set, nat, firewall, builder, policy, geoip, mesh, bridge, engine,
      config, netns, inspect) — purely mechanical now that the
      cstring/Str/i64 patterns are settled from v1.1.2 / v1.1.3

---

## v1.3.0 — Validation depth + idiom adoption (minor)

- [ ] **Fuzz harness expansion.** Today `tests/nein.fcyr` is a single
      file. Split per-validator (`fuzz/validate_addr.fcyr`,
      `fuzz/validate_iface.fcyr`, `fuzz/validate_ct_state.fcyr`,
      `fuzz/rule_render.fcyr`, `fuzz/nat_dnat.fcyr`, `fuzz/config_parse.fcyr`)
      so CI can name-tag crashes and the per-harness iteration count can
      scale to the surface size
- [ ] **Packed Result on hot paths.** `error.cyr` returns `i64` with
      bit-63 flag for hot-path fns (validate_*, rule_render, nat_render).
      Heap-allocated `NeinError` stays for cold paths. CLAUDE.md mandates
      this for fallible ops; today only some sites comply
- [ ] **`str_builder` audit.** Manual offset-tracked buffer writes in
      rule.cyr / table.cyr / chain.cyr / nat.cyr replaced with
      `str_builder` per CLAUDE.md — closes a class of off-by-one bugs
      around comment / log-prefix rendering
- [ ] **Vec-of-pointers over hashmap** where indices are known (CLAUDE.md
      idiom). engine.cyr's `_pe_find_index` / `_pe_insert_sorted` are
      already linear-scan; document that as the chosen design
- [ ] **Doctest pass** (`cyrius doctest src/*.cyr`) — public-fn doc
      examples become CI-verified

---

## v1.4.0 — Apply-layer integration (minor, requires root tier)

- [ ] **Real-nftables integration test harness** (`tests/integration/`).
      Gated on `NEIN_INTEGRATION=1` + root; runs in a network namespace
      so it doesn't touch the host ruleset. CI runs under a privileged
      container or skips with a `::warning::` if unavailable
- [ ] **`nft` binary discovery + pinning.** Today apply.cyr's
      `_nft_cmd` builds `["nft", "-f", "-"]` and execve resolves via
      PATH. Validate against a configurable absolute path (default
      `/usr/sbin/nft`) and refuse to apply if mismatch — closes a
      PATH-injection vector
- [ ] **list_ruleset_with_handles parser hardening.** The handle parser
      (`_parse_ruleset` in inspect.cyr) is line-oriented; today it
      passes a smoke test only. Round-trip fuzzing against
      `nft list ruleset` output for representative tables
- [ ] **Live-rule diffing.** `nein diff <target.toml>` — compare an
      in-memory firewall plan against the live kernel ruleset; output
      the minimal set of add/delete operations to converge. Pairs with
      sutra's idempotent-apply playbook semantics

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
