# Roadmap

Last refresh: 2026-05-10 (post v1.5.0 — live-rule diff shipped).

Forward-looking only. The release history (v1.0.0 → v1.5.0) lives in
[`CHANGELOG.md`](../../CHANGELOG.md); the rationale for each shipped
decision is preserved there, not duplicated here. This file tracks
**what's next**.

---

## Current state — v1.5.0

Library is feature-complete for the AGNOS-ecosystem consumers
identified at port time (stiva / daimon / aegis / sutra). 18 modules,
360 public fns, 601 test assertions, 31 benchmarks, 5 per-target fuzz
drivers, integration test scaffold, single-file `dist/nein.cyr`
bundle. Type-check end-to-end clean; aarch64 cross-build green;
zero supply-chain warnings.

What's left is consumer-driven: nothing in nein itself is broken or
incomplete; the next minors land features that a downstream actually
asks for, not speculative additions.

---

## v1.6.0 candidates (no current driver — defer until requested)

These are obvious next steps but nothing downstream is blocking on
them today. They surface here so the design is recoverable when a
driver appears.

- **Diff-level table / chain create + delete.** v1.5.0 ships rule-level
  diff only; full schema reconciliation (add/delete tables, chains,
  sets, maps to converge) needs a downstream that actually reshapes
  schemas at runtime. Sutra's playbook layer is the likely first
  caller — wait for sutra's design to settle before extending.
- **Insert-position-aware rule diff.** Current diff treats rule order
  within a chain as irrelevant (all matches are at-end appends). nft
  rule precedence depends on order; if a consumer needs deterministic
  ordering, the diff algorithm must compute `insert before handle N`
  ops. Wait for a consumer to surface the requirement.
- **Live-rule fuzz harness.** `diff_parse_live` is exercised by 16
  test assertions on hand-curated inputs. A property-based fuzz
  harness against synthetic `nft list ruleset -a` output would
  harden it further. Low priority — the smoke surface is already
  well covered.

## v2.0.0 — Ecosystem integration (blocked on upstream)

- **`mcp` module — Claude MCP tool descriptors.** Blocked on
  [bote](https://github.com/MacCracken/bote) Cyrius port. Tools:
  `nein_render_firewall`, `nein_apply_firewall`, `nein_validate_rule`,
  `nein_inspect_status`, `nein_diff`.
- **Full TOML struct parsing** (sutra-driven). Blocked on richer
  `toml` stdlib parsing — the v1.0 scoped enum-dispatchers in
  `config.cyr` cover today's needs but not nested struct shapes.
- **Fleet-playbook schema** (sutra-driven). Defines a serializable
  firewall plan independent of the in-memory builder API. Sequenced
  after the TOML unblock.
- **Optional rule-set signing** via sigil. Stored ruleset includes
  Ed25519 signature; aegis verifies before apply. Defense-in-depth
  for at-rest plan tampering. Wait for sigil's signing surface to
  stabilize at >= 3.0.0.
- **daimon firewall MCP tools shipped jointly** (one PR pair against
  daimon).

## Blocked on upstream

| Item | Blocked on |
|------|-----------|
| `mcp` module | bote Cyrius port |
| Full TOML struct parsing | richer `toml` stdlib |
| Sutra playbook schema | sutra design + TOML parsing |
| Sigil-signed rulesets | sigil >= 3.0.0 signing API |

## Deferred (with rationale)

- **Packed Result on hot paths.** Re-measured at v1.5.0: validators
  run ~500ns–1µs, dominated by string scanning, not the 16-byte
  Result alloc. Eliminating the alloc saves ~100-200ns at most.
  Migration cost (every `is_err_result` / `payload` caller across 18
  modules and 350+ public fns) does not pay back. **Permanently
  parked** unless a future hot path surfaces real heap-alloc pressure.
- **Doctest pass.** `cyrius doctest` returns "0 passed, 0 failed"
  on `///` Rust-style and `# Example:` cyrius-stdlib styles alike —
  the convention isn't yet documented or implemented upstream. Wait
  for cyrius docs to publish the doctest format.

## Forward principles

- Don't ship docs-only releases — fold prose currency into the next
  feature minor.
- Don't add deps speculatively — nein dropped agnostik in v1.1.1 and
  is now agnosys-core only. New deps need a function nein actually
  calls.
- Don't over-engineer the diff layer. The v1.5.0 byte-equality match
  is correct-by-construction; extend only when a consumer measures
  pain from the verbose delete+add pairs.

---

For shipped releases see [`CHANGELOG.md`](../../CHANGELOG.md).
For doc currency see [`doc-health.md`](../doc-health.md).
For per-module capability footprint see [`capability-map.md`](capability-map.md).
For threat surface see [`threat-model.md`](threat-model.md).
