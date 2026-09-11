# Roadmap

Last refresh: 2026-09-10 (post v1.6.11 — the cyrius 6.6.2 value-form migration: 104 validator error paths were failing OPEN, see the CHANGELOG and the trap below. Previously 2026-08-21, post v1.6.10 — every open P(-1) audit finding closed except two deliberately-deferred MEDIUM. v1.6.8 deleted `rust-old/`. v1.6.7 closed
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

## Recently closed

Detail lives in [`CHANGELOG.md`](../../CHANGELOG.md) and the
[2026-08-21 audit](../audit/2026-08-21-audit.md); kept here only where it
changes what the next person should do.

- **All four quality gates are wired** (1.6.8–1.6.9): `scripts/supply-chain.sh`,
  `cyrius deny`, `scripts/test-coverage.sh` (floor 64%),
  `scripts/doc-coverage.sh` (floor 17%). Both coverage floors are **ratchets at
  the measured figure** — raise them as coverage improves, never lower one to
  make a build pass.
- **The P(-1) audit is closed** except the two items below. 1 CRITICAL,
  6 HIGH, 10 MEDIUM, 17 LOW confirmed; v1.6.9 fixed 5 of the 7 CRITICAL/HIGH
  and v1.6.10 the rest, plus 8 of 10 MEDIUM and all 6 documentation errors.

### Traps worth not re-stepping in

**The value form fails OPEN when migrated naively (1.6.11).** Since cyrius
6.6.0 a `Result` is a two-register `(tag, payload)` value. `var vr = f();` binds
the **tag only**, so the once-idiomatic `if (is_err_result(vr) == 1) { return vr; }`
returns the payload alone and the caller reads an `Err` as **success**. 104 nein
sites were on that path. Bind both halves and propagate with `return Err(v);`.
The compiler now warns, and the type-check gate enforces it — see the next item
for why that gate cannot filter on the warning's text.

**A gate must not share a defect with the thing it checks (1.6.11).** cyrius
6.6.x warns on `return None();` even though `lib/tagged.cyr` documents the
nullary constructor as correctly tag-only — and the false positive's message is
**byte-identical** to a real propagation trap's. Filtering the text would have
made the gate green while blinding it to the class above. The gate instead reads
the reported source line, deriving the exemption a different way than the
message. Injection-verified. If you ever relax this gate, re-run that injection.

**Removing `[deps.sigil]` / `[deps.patra]` to silence `refusing to overwrite
stdlib leaf` makes things worse (1.6.11).** The pins look inert — cyrius treats
both as stdlib leaves and skips the dep artifact, so `lib/sigil.cyr` is
byte-identical to the toolchain snapshot. But the sections are load-bearing for
their *exclusion* effect: without them libro's sidecar resolves its thin sigil
sub-bundles (`sigil-mldsa`, `sigil-x509`, …) into `lib/`, colliding with the
full bundle across dozens of `duplicate fn` warnings. Measured, not guessed.

Three toolchain subcommands do **not** do what their names suggest, and each
cost a round of investigation:

- `cyrius deny` is an **include-path checker** (absolute paths, `../`
  traversal). It takes no allow-list and cannot carry a licence or source
  policy — that is `scripts/supply-chain.sh`.
- `cyrius coverage --min` measures **reference** coverage from an entry point.
  On this tree its default mode walks only `src/main.cyr` and reports
  1/1 = **100%**, so `--min 80` would pass vacuously while measuring nothing.
  Do not wire it.
- `cyrius doc --check` does the right analysis but **exits 0 regardless**, and
  only examines the one file handed to it. `scripts/doc-coverage.sh` sums it
  and supplies the exit code.

---

## Open — audit findings deliberately deferred

- **Pipe-ordering deadlock** (`apply.cyr`). The whole ruleset is written before
  stderr is drained, so both pipes can in principle fill. The audit verified
  this is **not reachable with real nft** — it needs the child to emit >64 KiB
  to stderr. Fixing it properly means a poll loop over both descriptors, or
  redirecting the child's stderr to a temp file; not worth the churn until
  something makes it reachable.
- **No replay binding on signed rulesets.** Nothing ties a signature to a time,
  nonce, or ruleset version, so a previously-valid signed ruleset can be
  re-applied. Closing it is a format change to the `nein-sig` envelope and
  wants a consumer — aegis holds the trusted pubkey — to design against.

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

Two ways out, either better than a wider band:

1. **Record baselines on CI hardware.** A workflow on the release tag runs the
   suite and commits the result. Removes the offset entirely; costs a CI job
   and a bot commit.
2. **Normalize against the run's own median delta.** Treat the median delta
   across all checked benchmarks as the machine factor, and flag a bench only
   when it exceeds the median by the threshold. A uniform shift cancels out; a
   single bench that doubled still fires. No new infrastructure, keeps a tight
   threshold — likely the better option.

Whichever lands, drop the ns threshold back toward 50% and shrink or remove
`BENCH_NS_THRESHOLD` in the same change.

---

## Current state — v1.6.11

Library is feature-complete for the AGNOS-ecosystem consumers
identified at port time (stiva / daimon / aegis / sutra). 21 modules
(mcp at 1.6.0, sign at 1.6.1), 754 test assertions + a bundle-consume
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

## Open — daimon-side MCP PR (v1.6.2's other half)

nein's side shipped at v1.6.2: the `[lib.mcp]` bundle (`dist/nein-mcp.cyr`)
plus the dispatch adapter `nein_mcp_dispatch(name, args, claims)`,
`nein_mcp_set_gate`, and the single-source tool table
(`nein_tool_name/desc/read_only/admin`). Integration guide:
[`../guides/mcp-host-integration.md`](../guides/mcp-host-integration.md); a
bundle-consumability guard runs in CI.

**What remains is in daimon's repo, on daimon's cadence.** daimon adds
`[deps.nein] modules = ["dist/nein-mcp.cyr"]`, registers nein's six tools from
the tool table, routes `nein_*` calls to `nein_mcp_dispatch`, and wires the
gate to its agent identity — read-only firewall tools broadly, the
`firewall_admin` mutating set only to privileged agents. daimon dispatches
builtins by name rather than through a bote `Dispatcher`, so it uses the
adapter path, not `nein_tools_register`.

*(The v1.6.0 / v1.6.1 design notes that used to sit here have been removed:
they were shipped history, which belongs in `CHANGELOG.md` per this file's own
policy, and one of them still described the bote vendoring that was retired at
v1.6.1.)*

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
  have caught that class of bug. **Raised again at v1.6.9**: the P(-1)
  audit found a live SIGSEGV in this exact parser (an ordinary
  table-level `counter` block desynced the brace stack), reached by
  reading the code rather than by any test. That is twice now that
  hand-curated inputs missed a memory-safety bug a fuzzer would have
  found. Strongest near-term hardening candidate by some distance.
- **Diff-level table / chain create + delete.** v1.5.0 ships rule-level
  diff only; full schema reconciliation (add/delete tables, chains,
  sets, maps to converge) needs a downstream that actually reshapes
  schemas at runtime. Sutra's playbook layer is the likely first
  caller — wait for sutra's design to settle before extending.
- ~~**Insert-position-aware rule diff.**~~ **Done at v1.6.10** — though not
  the way this entry anticipated. It assumed order-sensitivity was a nicety to
  wait on "until a consumer surfaces the requirement"; the 2026-08-21 audit
  surfaced it as a **HIGH security finding** instead. Treating a chain as an
  unordered set meant a re-added deny rule was appended *after* the accept it
  was meant to precede, leaving a host permitted. Fixed by rebuilding any
  chain that differs, in order, rather than by computing
  `insert before handle N` — safe because the ops go out as one atomic
  `nft -f -` batch. See audit H-5.
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
  modules and 394 public fns) does not pay back. **Permanently
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
  sigil / libro / majra / patra) precisely because the mcp +
  signing surfaces call them. New deps still need a function nein
  actually calls, not a "might need it later".
- Be careful what you call correct-by-construction. This list used to say
  "the v1.5.0 byte-equality match is correct-by-construction; extend only when
  a consumer measures pain" — and `diff.cyr`'s header said the same. Both were
  wrong: byte-equality over an unordered set silently reordered rules, which
  for a firewall is a security failure, and no consumer would have "measured
  pain" before a packet got through. Waiting for a downstream complaint is a
  reasonable prioritisation rule for ergonomics and a bad one for correctness.
  Prefer an argument from the semantics — here, that rule order *is* nftables'
  evaluation model — over an argument from the absence of complaints.

---

For shipped releases see [`CHANGELOG.md`](../../CHANGELOG.md).
For doc currency see [`doc-health.md`](../doc-health.md).
For per-module capability footprint see [`capability-map.md`](capability-map.md).
For threat surface see [`threat-model.md`](threat-model.md).
