# Roadmap

Last refresh: 2026-08-21 (post v1.6.10 — every open P(-1) audit finding closed except two deliberately-deferred MEDIUM. v1.6.8 deleted `rust-old/`. v1.6.7 closed
every functional gap the Rust→Cyrius port-completeness audit turned up,
including one shipped bug where `dry_run` was write-only; v1.6.8 lifted the
Rust tree's supply-chain policy into a first-party gate and removed the tree.
The audit that cleared it is [`port-completeness.md`](port-completeness.md).
v1.6.2 shipped nein's half of the daimon firewall-MCP joint ship: [lib.mcp]
bundle + dispatch adapter, whose paired daimon-side PR is the only other item
still open).

Forward-looking only. The release history (v1.0.0 → v1.6.8) lives in
[`CHANGELOG.md`](../../CHANGELOG.md); the rationale for each shipped
decision is preserved there, not duplicated here. This file tracks
**what's next**.

---

## Quality gates — complete as of 1.6.9

All four Cyrius-side successors to the Rust `Makefile`'s `cargo deny` /
`cargo vet` / coverage gates are now wired:

| Gate | Command | Wired |
|------|---------|-------|
| Supply-chain policy | `scripts/supply-chain.sh` | 1.6.8 |
| Include-path policy | `cyrius deny src/main.cyr` | 1.6.8 |
| API test coverage | `scripts/test-coverage.sh` (floor 63%) | 1.6.9 |
| Doc coverage | `scripts/doc-coverage.sh` (floor 17%) | 1.6.9 |

Two of the four are first-party scripts rather than toolchain subcommands,
for the same reason in both cases — the subcommand exists but cannot gate:

- **`cyrius deny`** is an include-path checker (absolute paths, `../`
  traversal) with no allow-list; it cannot express a licence or source policy.
- **`cyrius coverage --min`** measures *reference* coverage from an entry
  point — a dead-code metric, as its own output says. On this tree its default
  mode walks only `src/main.cyr` and reports 1/1 = **100%**, so
  `cyrius coverage --min 80` would pass vacuously while measuring nothing.
  `--full` reports 2%, dominated by unreferenced vendored stdlib. Neither
  number is about nein's tests.
- **`cyrius doc --check`** does the right analysis but exits 0 regardless, and
  only examines the one file it is handed. `scripts/doc-coverage.sh` sums it
  across all modules and supplies the exit code.

Both new floors are **ratchets at the measured figure**, not targets. The
direction of travel for API test coverage is 80%; the 141 currently-uncalled
public fns are listed by `scripts/test-coverage.sh --list`, and the
crypto surface (`verify_ruleset_hex`, `apply_signed_ruleset_hex`,
`signed_body`) is the most worth closing first.

---

## P(-1) audit — closed as of v1.6.10

The [2026-08-21 audit](../audit/2026-08-21-audit.md) found 1 CRITICAL, 6 HIGH,
10 MEDIUM and 17 LOW. v1.6.9 fixed 5 of the 7 CRITICAL/HIGH; **v1.6.10 closed
the remaining 3 HIGH, 8 of the 10 MEDIUM, and all 6 documentation errors.**

Two MEDIUM remain, both deliberately deferred:

- **Pipe-ordering deadlock** (`apply.cyr`). The whole ruleset is written before
  stderr is drained, so both pipes can fill. Verified *not* reachable with real
  nft — it needs the child to emit >64 KiB to stderr. Fixing it properly means
  a poll loop over both descriptors, or redirecting the child's stderr to a
  temp file; neither is worth the churn for an unreachable path until something
  makes it reachable.
- **No replay binding on signed rulesets.** Nothing ties a signature to a time,
  nonce, or ruleset version, so a previously-valid signed ruleset can be
  re-applied. Closing it is a format change to the `nein-sig` envelope and
  wants a consumer (aegis holds the trusted pubkey) to design against.

---

## P1 — stop comparing benchmarks across machines

`scripts/bench-track.sh` records a baseline on whatever machine cuts the
release; `scripts/bench-regression.sh` then compares it against a shared
GitHub runner. Those are different machines, so every run carries a uniform
offset that has nothing to do with the code.

Measured on the 1.6.8 baseline: **all 16 ns-bracket benchmarks read 21.5% to
57.8% slower on CI (median ~34%)**. The 1.6.8 stopgap raised the ns threshold
to 90% and gave `validate_iface` a 120% band, which stops the false failures
but also blunts the gate — a genuine 60% regression in a validator now passes.

Two ways out, either of which is better than a wider band:

1. **Record baselines on CI hardware.** A workflow on the release tag runs the
   suite and commits the result. Removes the offset entirely; costs a CI job
   and a bot commit.
2. **Normalize against the run's own median delta.** Compute the median delta
   across all checked benchmarks, treat that as the machine factor, and flag a
   bench only when it exceeds the median by the threshold. A uniform shift
   cancels out; a single bench that doubled still fires. No new
   infrastructure, and it keeps a tight threshold — likely the better option.

Whichever lands, drop the ns threshold back toward 50% and shrink or remove
`BENCH_NS_THRESHOLD` in the same change.

---

## Deferred — full TOML struct parsing

`config.cyr` ships the string→enum dispatch layer; `from_toml` / `to_toml`
were not ported. Scheduled for sutra's port start, when there is a consumer
to shape the schema around. Until then a consumer layers its own TOML on top
of `cfg_parse_*`.

---

## Current state — v1.6.9

Library is feature-complete for the AGNOS-ecosystem consumers
identified at port time (stiva / daimon / aegis / sutra). 21 modules
(mcp at 1.6.0, sign at 1.6.1), 729 test assertions + a bundle-consume
integration guard, 48 benchmarks, 5 per-target fuzz drivers, single-file
`dist/nein.cyr` bundle (still bote/sigil-free) plus the opt-in
`dist/nein-mcp.cyr` (`[lib.mcp]`) for MCP hosts. Type-check end-to-end
clean; aarch64 cross-build green; `capacity --check` is a real gate again
as of 1.6.5. libro / majra / bote / sigil / patra consumed as git deps
(daimon recipe) via `cyrius lib sync` + `cyrius deps`; no vendored bundles.
sigil + patra carry explicit `[deps.*]` pins (full `dist/sigil.cyr`) so
libro 2.8.x's thin sigil sub-bundles don't collide with the full crypto
bundle. Full `[deps]` rationale lives in
[`dependencies.md`](dependencies.md) as of 1.6.6 — the `.cyml` parser
mis-resolves deps when comments sit inside the `stdlib` array, so the
manifest carries none.

nein's side of the 1.6.x ecosystem work is done. Open items are the **P1
quality gates** above and the **paired daimon-side PR** (below). Everything
beyond stays consumer-driven — features a downstream asks for, not speculative
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
  agnosys in v1.5.4, then re-added git deps in the 1.6.x line (bote /
  sigil / libro / majra / patra / sakshi) precisely because the mcp +
  signing surfaces call them. New deps still need a function nein
  actually calls, not a "might need it later".
- Don't over-engineer the diff layer. The v1.5.0 byte-equality match
  is correct-by-construction; extend only when a consumer measures
  pain from the verbose delete+add pairs.

---

For shipped releases see [`CHANGELOG.md`](../../CHANGELOG.md).
For doc currency see [`doc-health.md`](../doc-health.md).
For per-module capability footprint see [`capability-map.md`](capability-map.md).
For threat surface see [`threat-model.md`](threat-model.md).
