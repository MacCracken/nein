# Roadmap

Last refresh: 2026-11-04 (post v1.9.1 — hardening: nft names checked against nft's own grammar (I-10), builder-composed names and comments (B-8), an IPv6 spelling nft cannot parse, `pe_validate` no longer quadratic in parses; bote 3.8.9. Forward-looking only: completed items removed.)

This file tracks **what is next**. Shipped history lives in
[`CHANGELOG.md`](../../CHANGELOG.md); audit findings and their status in
[`../audit/`](../audit/) (latest: [2026-11-03](../audit/2026-11-03-audit.md));
lessons that cost a round of investigation in [`traps.md`](traps.md).

---

## Where things stand — v1.9.1

nein is feature-complete for the consumers identified at port time (stiva,
daimon, aegis, sutra): 21 modules, 411 public fns, 1,145 unit + 41 integration
assertions, 59 benchmarks, 7 fuzz drivers, a load test that has real nft parse
every builder's output, and a grammar test that has the installed nft judge
every name rule and a few hundred IPv6 spellings nein's validators take.
Pinned at cyrius 6.7.18 with every dependency at its latest release (bote
3.8.9). Every MEDIUM-or-higher finding of the 2026-11-03 audit is fixed, and
of its deferred LOWs I-10 and B-8 (1.9.1); the open ones are below. Consumers still on cyrius
6.6.x stay on nein 1.7.1, the last release built on 6.6.20.

Everything below is driven by a consumer, by the language, or by a finding
deferred with a reason — not by speculation.

---

## 1.9.x → 2.0.0

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
- **Named stateful objects** (audit I-7, part). `counter name "x"` references
  a counter object nein's table model cannot declare, so it fails at apply
  unless something outside nein declared that object in the same table (nft
  merges the table blocks, and then the reference resolves — checked on 1.1.7,
  1.9.1). Model counter / quota / limit objects in tables; retiring the verdict
  would break a consumer that declares its objects out of band.
- **Tighten the bench thresholds.** Since 1.8.2 the bench gate normalizes every
  delta by the run's median shift, so the cross-machine offset no longer has
  to fit inside the thresholds. The 90% (ns) / 80% (µs) thresholds and
  `BENCH_NS_THRESHOLD` were sized for that offset; after a few CI runs show the
  normalized spread (±27% on the first), drop them toward 50% and retire the
  per-bench override.
- **Raise the coverage ratchets.** API test coverage is gated at 71% (1.9.1;
  direction of travel 80%), doc coverage at 19% (the deficit is one-line
  accessors). Raise each floor to the measured figure as it moves; never lower
  one.
- **The netns builder composes comments it never validates.** `nsf_build`
  writes `<agent> outbound <proto>:<port> -> <host>`, which a 64-byte agent
  name and a long IPv6 host push past 128 bytes; the firewall then fails
  `firewall_validate` (closed). The other builders check what they compose since
  1.9.1 (B-8); netns has no validator to put the check in, so it needs a new
  public `nsf_validate` — a minor's addition.
- **The keyword lists are nft 1.1.7's** (1.9.1). Re-probe on each nft release
  the CI or the consumers move to; `tests/integration/nft_grammar.tcyr` names
  any word the installed nft lists in its errors and refuses as a name.
- **Consumer adoption** (work in the consumers' repos, tracked here):
  - **daimon → 1.9.x** (on 1.8.1 today). Its gate returns `1`, which 1.9.0
    reads as a denial, so the bump fails closed until the gate returns
    `NEIN_GATE_PERMIT` — and it permits every `nein_tool_read_only` tool, so
    its unauthenticated `POST /v1/mcp/call` hands the live root ruleset to any
    caller. Migrate per the host guide's "Migrating a 1.8 gate": classify with
    `nein_tool_class`, deny `READS_LIVE` until daimon has caller identity
    (its roadmap 2.5.x), check `nein_mcp_set_gate`'s result.
  - **aegis → v2 signing**, once it signs rulesets at all (it consumes
    `dist/nein.cyr`, which carries no signing, and is on cyrius 6.6.20 /
    nein 1.7.1): keep the last applied seq per (key, scope), persist it only
    after `apply_signed_ruleset_v2` returns `Ok`, raise it on
    `NEIN_ERR_OUTCOME_UNKNOWN`, and never accept v1.
  - stiva and aegis moving to cyrius ≥ 6.7.2 to take 1.8.x / 1.9.x and the
    audit fixes. stiva writes its ruleset to a fixed
    `/tmp/stiva-nft-ruleset.nft` before `nft -f` (predictable path for a root
    process; reported, unverified) — stiva's to fix. GeoIP consumers: the
    default hook is prerouting since 1.9.0 (`geoip_set_hook(bl, HOOK_INPUT)`
    for the old scope).
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
- Retire the v1 signed envelope (`sign_ruleset`, `verify_ruleset`,
  `apply_signed_ruleset` and the `_hex` forms): it is unbound, and a verifier
  that still accepts it can be replayed through it. v2 has been the answer
  since 1.9.0; 2.0 is the first release allowed to remove a function.
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
  (as 1.9.0's were) — not in a patch, and not by surprise.
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
