# Roadmap

Last refresh: 2026-07-17 (post v1.6.4 — banked bote 3.1.4 + libro 2.8.2's
bare-error-enum repairs on top of v1.6.3's toolchain 6.4.66 + full
dependency refresh; no feature or API change. v1.6.2 shipped nein's half
of the daimon firewall-MCP joint ship: [lib.mcp] bundle + dispatch
adapter, whose paired daimon-side PR is the only 1.6.x item left).

Forward-looking only. The release history (v1.0.0 → v1.6.4) lives in
[`CHANGELOG.md`](../../CHANGELOG.md); the rationale for each shipped
decision is preserved there, not duplicated here. This file tracks
**what's next**.

---

## Current state — v1.6.4

Library is feature-complete for the AGNOS-ecosystem consumers
identified at port time (stiva / daimon / aegis / sutra). 20 modules
(mcp at 1.6.0, sign at 1.6.1), 664 test assertions + a bundle-consume
integration guard, 31 benchmarks, 5 per-target fuzz drivers, single-file
`dist/nein.cyr` bundle (still bote/sigil-free) plus the opt-in
`dist/nein-mcp.cyr` (`[lib.mcp]`) for MCP hosts. Type-check end-to-end
clean; aarch64 cross-build green. libro / majra / bote / sigil / patra
consumed as git deps (daimon recipe) via `cyrius lib sync` + `cyrius deps`;
no vendored bundles. As of 1.6.3 sigil + patra carry explicit `[deps.*]`
pins (full `dist/sigil.cyr`, mirroring bote 3.1.2) so libro 2.8.x's thin
sigil sub-bundles don't collide with the full crypto bundle.

nein's side of the 1.6.x ecosystem work is done. The only open 1.6.x
item is the **paired daimon-side PR** (below). Everything beyond stays
consumer-driven — features a downstream asks for, not speculative additions.

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

## v1.6.1 — sigil-signed rulesets + daimon MCP setup ✅ shipped

- **Rule-set signing via sigil** — `src/lib/sign.cyr`, Ed25519 over the
  rendered nft body, fail-closed `apply_signed_ruleset`. aegis holds the
  trusted pubkey and verifies before apply (at-rest tamper defense).
- **daimon MCP setup** — bote `ToolAnnotations` (read-only vs
  destructive) + `firewall` / `firewall_admin` profiles on all 6 tools,
  a `nein_tools_register_gated(dispatcher, gate_fp)` access-control seam,
  and public `nein_mcp_ok` / `nein_mcp_err` helpers for daimon to reuse.
  The gate is claims-ready but decides on host policy (bote `claims` is a
  reserved 0 today).
- **Dep migration** — retired the 1.6.0 vendoring; bote-core + sigil are
  now git deps (daimon recipe). The 1.6.0 "resolver bug" was an
  incomplete `[deps] stdlib`: Cyrius doesn't auto-resolve (supply-chain
  safety), so `cyrius lib sync` materializes the declared stdlib before
  `cyrius deps` pulls the bundles.

## v1.6.2 — daimon firewall MCP tools

**nein side ✅ shipped.** The `[lib.mcp]` bundle (`dist/nein-mcp.cyr` —
core + sign + mcp, bote/sigil-free for the consumer to supply) plus a
daimon-friendly dispatch adapter: `nein_mcp_dispatch(name, args, claims)`
+ `nein_mcp_set_gate` + the single-source tool table
(`nein_tool_name/desc/read_only/admin`). Integration guide at
[`docs/guides/mcp-host-integration.md`](../guides/mcp-host-integration.md);
a bundle-consumability guard runs in CI.

**daimon side — the paired PR (open, in daimon's repo).** daimon adds
`[deps.nein] modules = ["dist/nein-mcp.cyr"]`, registers nein's six tools
in its MCP host from the tool table, routes `nein_*` calls to
`nein_mcp_dispatch`, and wires the gate to its agent identity
(`agent.cyr` / `agent_id`) — exposing read-only firewall tools broadly and
the `firewall_admin` (mutating) set only to privileged agents. Because
daimon dispatches builtins by name (not via a bote `Dispatcher`), it uses
the adapter path, not `nein_tools_register`. This is the only open 1.6.x
item and belongs to daimon's release cadence.

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
