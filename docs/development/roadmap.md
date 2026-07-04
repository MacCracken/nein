# Roadmap

Last refresh: 2026-07-03 (post v1.6.0 — mcp module shipped;
1.6.1 / 1.6.2 next).

Forward-looking only. The release history (v1.0.0 → v1.6.0) lives in
[`CHANGELOG.md`](../../CHANGELOG.md); the rationale for each shipped
decision is preserved there, not duplicated here. This file tracks
**what's next**.

---

## Current state — v1.6.0

Library is feature-complete for the AGNOS-ecosystem consumers
identified at port time (stiva / daimon / aegis / sutra). 19 modules
(mcp added at 1.6.0), 624 test assertions, 31 benchmarks, 5 per-target
fuzz drivers, integration test scaffold, single-file `dist/nein.cyr`
bundle (bote-free — mcp is out of `[lib]`). Type-check end-to-end
clean; aarch64 cross-build green.

The next two minors continue the ecosystem-integration surface: sigil
signing is stable (3.10.0), unblocking signed rulesets; the daimon MCP
tools build on 1.6.0's `mcp` module. Everything beyond 1.6.2 stays
consumer-driven — features a downstream asks for, not speculative
additions.

---

## v1.6.0 — `mcp` module ✅ shipped

MCP tool descriptors + handlers over
[bote](https://github.com/MacCracken/bote)'s core, so agents drive nein
directly. Shipped the **merged** agent-ergonomic surface (six flat-arg
tools) rather than the originally-sketched five library-shaped tools —
render/apply-whole-firewall would need a JSON→Firewall schema nein
doesn't have yet, whereas flat args map cleanly to how an LLM calls a
tool: `nein_status`, `nein_allow`, `nein_deny`, `nein_validate`,
`nein_list`, `nein_diff`. `nein_tools_register(dispatcher)` mounts them;
handlers are injection-safe (validate + JSON escaping).

**Dependency note:** bote is **vendored** (`src/vendor/bote-core.cyr`), not a
git dep — `cyrius deps` resolves bote's full manifest git-deps for a
core-bundle consumer instead of the bundle's `.deps` sidecar, which
fails and blocks the build (filed on bote's roadmap; see
`src/vendor/README.md`). Restore the git dep once fixed upstream. Also
renamed `ERR_PARSE` → `NEIN_ERR_PARSE` (value 6 unchanged) to dodge a
collision with bote's `BoteErrTag::ERR_PARSE`.

## v1.6.1 — sigil-signed rulesets + daimon MCP setup

- **Optional rule-set signing via sigil.** Stored ruleset carries an
  Ed25519 signature; aegis verifies before apply. Defense-in-depth
  against at-rest plan tampering. **Unblocked:** sigil signing is
  stable (sigil 3.10.0; the gate was >= 3.0.0).
- **Setup for daimon firewall MCP tools.** Land the shared surface
  daimon's tools build on — tool-descriptor wiring plus agent
  access-control hooks — so 1.6.2 is a clean joint ship, not a
  big-bang PR.

## v1.6.2 — daimon firewall MCP tools

Ship the daimon firewall MCP tools jointly: one PR pair against
[daimon](https://github.com/MacCracken/daimon), building on the 1.6.1
setup.

## v2.0.0 — breaking-API rewrite (language-gated, no date)

The 2.0 bucket is reserved for a breaking API change large enough to
warrant a major bump — most likely a full rewrite once the Cyrius
language grows the primitives nein currently works around. The
trigger is **wider / precise integer types**: today every value is an
i64 (ports, protocol numbers, priorities, handles, and raw cstring
pointers all share one width), and every compound value is hand-laid
with `alloc(N)` + `store64` / `load64` offset arithmetic.

When the language ships fixed-width ints (and, ideally, typed
structs / records), 2.0 can:

- Express the domain at its real widths — `u16` ports, `u8` protocol /
  family / verdict discriminants, `i32` chain priority, `u64` handles
  — instead of untyped i64. This is an API break: every public
  signature that takes or returns these changes shape, so consumers
  (stiva / daimon / aegis / sutra) recompile against new types.
- Replace the manual offset structs (`LiveRule`, rule / match records)
  with real typed structs. That retires the `store64(lr + 16, …)`
  pattern outright — the exact footgun behind the v1.5.5 block-stack
  OOB write — making that whole bug class unrepresentable rather than
  merely tested against.

No date and no driver: this waits on the language, not a consumer.
Until the int-type work lands upstream, everything shippable fits
under the 1.x line.

## Later — driver-gated (no version yet)

- **Live-rule fuzz harness.** `diff_parse_live` is exercised by 16
  test assertions on hand-curated inputs. A property-based fuzz
  harness against synthetic `nft list ruleset -a` output would harden
  it further. **Raised in priority** after the v1.5.5 block-stack OOB
  fix — fuzzing over nested/adversarial rulesets is exactly what would
  have caught that class of bug. Strongest near-term hardening
  candidate.
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
- **Full TOML struct parsing** (sutra-driven). Blocked on richer
  `toml` stdlib parsing — the v1.0 scoped enum-dispatchers in
  `config.cyr` cover today's needs but not nested struct shapes.
- **Fleet-playbook schema** (sutra-driven). Defines a serializable
  firewall plan independent of the in-memory builder API. Sequenced
  after the TOML unblock.

## Blocked on upstream

| Item | Blocked on |
|------|-----------|
| Full TOML struct parsing | richer `toml` stdlib |
| Sutra playbook schema | sutra design + TOML parsing |

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
  agnosys in v1.5.4; it now carries no git deps. New deps need a
  function nein actually calls (the 1.6.x line will pull bote / sigil
  / daimon precisely because the mcp + signing surfaces call them).
- Don't over-engineer the diff layer. The v1.5.0 byte-equality match
  is correct-by-construction; extend only when a consumer measures
  pain from the verbose delete+add pairs.

---

For shipped releases see [`CHANGELOG.md`](../../CHANGELOG.md).
For doc currency see [`doc-health.md`](../doc-health.md).
For per-module capability footprint see [`capability-map.md`](capability-map.md).
For threat surface see [`threat-model.md`](threat-model.md).
