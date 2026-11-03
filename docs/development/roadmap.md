# Roadmap

Last refresh: 2026-11-03 (post v1.8.2 — the P(-1) audit after three toolchain moves; every HIGH and 16 of 18 MEDIUM fixed, the rest planned below. Rewritten as forward-looking only: completed items removed, open work organised into 1.9.x → 2.0.0 and post-2.x.)

This file tracks **what is next**. Shipped history lives in
[`CHANGELOG.md`](../../CHANGELOG.md); audit findings and their status in
[`../audit/`](../audit/) (latest: [2026-11-03](../audit/2026-11-03-audit.md));
lessons that cost a round of investigation in [`traps.md`](traps.md).

---

## Where things stand — v1.8.2

nein is feature-complete for the consumers identified at port time (stiva,
daimon, aegis, sutra): 21 modules, 397 public fns, 870 unit + 18 integration
assertions, 48 benchmarks, 6 fuzz drivers, and a load test that has real nft
parse every builder's output. Pinned at cyrius 6.7.18 with every dependency at
its latest release. Consumers still on cyrius 6.6.x stay on nein 1.7.1, the
last release built on 6.6.20.

Everything below is driven by a consumer, by the language, or by a finding
deferred with a reason — not by speculation.

---

## 1.9.x → 2.0.0

### 1.9.0 — consumer-contract changes, made with the consumers

Each of these changes what a consumer writes or what it receives, so each is
designed against the consumer that holds the other side, and they ship
together in one minor.

- **Replay binding for signed rulesets** — with **aegis**, which holds the
  trusted key. Today any envelope ever signed with the trusted key verifies
  and applies forever; an older "accept 22" outlives a newer "drop 22"
  (2026-08-21 MEDIUM, re-confirmed 2026-11-03). Sketch from the audit: a
  `nein-sig: v2` envelope whose signature covers a domain-separated message —
  version, monotonic `seq`, `not_after`, a `scope` (host or role), `keyid`,
  body — carried in clear headers the verifier rebuilds the message from.
  nein stays stateless: `verify_ruleset_v2(signed, pk, scope, min_seq)` returns
  the seq; aegis keeps the last applied seq per (key, scope), persists it only
  after a successful apply, and refuses v1 once a floor is set (otherwise the
  downgrade is the replay).
- **MCP host-gate contract** — with **daimon** (audit M-2). The gate is called
  through a run-time pointer, so a gate returning a `Result` is truncated to
  its tag and `Err` reads as *permit*; and one process-wide `_nein_gate` is
  replaced by any later registration. Plan: a permit value that is neither `0`
  nor `1`, and a gate held per registration. 1.8.2 documents the hazard in the
  host guide.
- **A "reads the live firewall" tool class** — with **daimon** (audit M-3).
  `nein_status` / `nein_list` / `nein_diff` run `nft -a list ruleset` as root
  and return the ruleset, yet are classed read-only in the plain `firewall`
  profile, which hosts treat as safe to expose. Plan: a separate class and
  profile (e.g. `firewall_read`), denied by default without claims; only
  `nein_validate` stays in the harmless set.
- **An "outcome unknown" apply result** (audit S-8). With SIGCHLD set to
  SIG_IGN, or a reaper that wins the race, apply returns `Err` after nft has
  committed, and a caller that retries an additive apply duplicates rules. A
  distinct error code tells the caller to re-diff rather than re-apply.
- **GeoIP on prerouting by default** (audit B-9, part). The default `input`
  hook does not see forwarded or DNAT'd container traffic. A behaviour change
  for every GeoIP consumer, so it rides the minor.

### 1.9.x — hardening and follow-ups

- **Parse `nft -j` instead of the text listing.** The structural fix behind
  two audit findings: text quoting is not reversible (P-4 — 1.8.2 refuses an
  unbalanced listing rather than guess), and rule bodies are compared
  byte-for-byte against nft's canonical text, so a chain whose target nft
  re-spells (`10.0.0.5/32` lists as `10.0.0.5`) is rebuilt on every diff (P-8 —
  churn, counters reset, handles move). JSON gives exact strings and a
  canonical form. The fuzz harness (`fuzz/diff_parse_live.fcyr`) carries over.
- **Engine dispatch by process, not by source address** (audit B-2, related).
  Outbound dispatch keys on `ip saddr`, which any local process can choose with
  `bind()`. `meta skuid` / `socket cgroupv2` binds a policy to the process.
- **Identifiers that are nft keywords** (audit I-10). `validate_identifier`
  accepts `fwd`, which nft refuses as a chain name; the batch fails closed.
  Needs nft's keyword list, or quoting of names nft allows quoted.
- **Named stateful objects** (audit I-7, part). `counter name "x"` references
  a counter object nein's table model cannot declare, so it always fails at
  apply. Model counter / quota / limit objects in tables, or retire the verdict.
- **Builder name lengths** (audit B-8). Builders accept ids that, once composed
  into `<id>_in`, `<prefix>_filter`, `iso_<name>`, exceed `firewall_validate`'s
  64-byte limit; the firewall then fails validation (closed). Validate the
  composed names in the builders.
- **Tighten the bench thresholds.** Since 1.8.2 the bench gate normalizes every
  delta by the run's median shift, so the cross-machine offset no longer has
  to fit inside the thresholds. The 90% (ns) / 80% (µs) thresholds and
  `BENCH_NS_THRESHOLD` were sized for that offset; after a few CI runs show the
  normalized spread (±27% on the first), drop them toward 50% and retire the
  per-bench override.
- **Raise the coverage ratchets.** API test coverage is gated at 65% (direction
  of travel 80%), doc coverage at 17% (the deficit is one-line accessors). Raise
  each floor to the measured figure as it moves; never lower one.
- **Consumer adoption** (work in the consumers' repos, tracked here):
  daimon's half of the 1.6.2 MCP integration (`[deps.nein]` →
  `dist/nein-mcp.cyr`, route `nein_*` to `nein_mcp_dispatch`, wire the gate to
  agent identity) — and daimon, stiva and aegis moving to cyrius ≥ 6.7.2 to
  take 1.8.x and its audit fixes. stiva writes its ruleset to a fixed
  `/tmp/stiva-nft-ruleset.nft` before `nft -f` (predictable path for a root
  process; reported, unverified) — stiva's to fix.
- **Full TOML struct parsing** — blocked on a richer `toml` in the stdlib;
  `config.cyr`'s enum dispatchers cover today's needs.
- **Doctests** — blocked: `cyrius doctest` still reports `0 passed, 0 failed`
  on every comment style (re-checked on 6.7.18); wait for the format.

### 2.0.0 — breaking-API rewrite (language-gated, no date)

Reserved for a breaking change large enough to warrant a major — most likely a
rewrite once Cyrius grows the primitives nein works around. The trigger is
**fixed-width integers and typed structs**: today every value is an i64
(ports, protocol numbers, priorities, handles, cstring pointers share one
width), and every compound value is hand-laid with `alloc(N)` +
`store64` / `load64` offsets.

- Express the domain at its real widths — `u16` ports, `u8` protocol / family /
  verdict, `i32` priority, `u64` handles — so a port of 70000 or a priority
  outside int32 cannot be constructed rather than being caught by a validator
  (the 1.8.2 audit added a dozen such range checks). Every public signature
  changes shape; consumers recompile.
- Replace the offset structs (`LiveRule`, rules, matches, NAT rules) with typed
  structs. That retires the `store64(lr + 16, …)` pattern — the root of the
  v1.5.5 block-stack OOB write — making the class unrepresentable.
- Fold in any 1.9.x contract that proved awkward to express without types.

No driver but the language: until it ships, everything fits under 1.x.

---

## Post-2.x

Driver-gated work that is best done once, on 2.0's typed model:

- **Fleet-playbook schema** (sutra). A serializable firewall plan independent
  of the in-memory builder API — defined once, on the final types. Sequenced
  after the TOML unblock.
- **Diff-level table / chain create and delete** (sutra). `nein_diff`
  reconciles rules inside the chains the target declares (target-scoped since
  1.8.2); converging tables, chains, sets and maps themselves needs a consumer
  that reshapes schemas at runtime. Sutra's playbook layer is the likely first;
  it can move earlier if sutra's design lands first.
- **An agnos backend.** agnos has its own network stack and no nftables, so
  the apply layer refuses on `--agnos` (since 1.6.12). A backend is a different
  piece of work from a syscall shim, and has no consumer yet.

---

## Blocked on upstream

| Item | Blocked on |
|------|-----------|
| Full TOML struct parsing | richer `toml` stdlib |
| Doctests | a published `cyrius doctest` format |
| 2.0.0 rewrite | fixed-width ints and typed structs in Cyrius |
| Fleet-playbook schema | sutra design + TOML parsing |

## Forward principles

- Don't ship docs-only releases — fold prose currency into the next release.
- Don't add deps speculatively. New deps need a function nein actually calls.
- A consumer-facing contract changes in a minor, designed with that consumer
  (1.9.0 above) — not in a patch, and not by surprise.
- Be careful what you call correct-by-construction. The v1.5.0 diff's
  byte-equality match was called that, and silently reordered rules (1.6.10,
  H-5); its live-rule parser was trusted, and deleted other tenants' rules and
  lost counter-led ones (1.8.2, P-1 / P-2). Prefer an argument from nftables'
  semantics over an argument from the absence of complaints — no consumer
  "measures pain" before a packet gets through.
- Load what you render. Every builder's output is parsed by real nft in CI's
  integration step (`tests/integration/nft_load.tcyr`); a substring test of
  rendered text proves nothing about whether nft accepts it — the mesh
  ruleset never loaded, and nothing noticed, until 1.8.2.

---

For doc currency see [`doc-health.md`](../doc-health.md).
For per-module capability footprint see [`capability-map.md`](capability-map.md).
For threat surface see [`threat-model.md`](threat-model.md).
