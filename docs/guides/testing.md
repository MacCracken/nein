# Testing Guide

Last refresh: **2026-11-07** (v1.9.2). Replaces the Rust-era guide that
shipped with the v1.0.0 port.

## Unit Tests

The full unit-test suite lives in `tests/nein.tcyr` — 1,327 assertions
across 61 test groups (validators, rule rendering, NAT, sets/maps,
chains, tables, firewall validation, builders, policy, geoip, mesh,
bridge, engine, config, netns, inspect, diff, sign, sign_v2, mcp,
since 1.9.1 nft names at every position and the names builders compose,
and since 1.9.2 the diff's canonical form — what nft lists for each rule
shape — and a round trip through every struct accessor).

```sh
cyrius test tests/nein.tcyr
```

There is no per-module test target — `cyrius test` compiles and runs
the whole `.tcyr` file. To exercise a subset, comment out unwanted
test groups in the file or copy the relevant blocks into a scratch
`.tcyr`.

CI runs every `tests/*.tcyr` file via the workflow's auto-discover
loop, so adding new test files is just dropping them into `tests/`.

## Integration Tests

Apply-layer integration tests need:

- Root privileges (or `CAP_NET_ADMIN`)
- A kernel with `nf_tables` + `nf_conntrack` modules loaded
- `nft` binary installed at the pinned `/usr/sbin/nft` (override at
  runtime via `nein_set_nft_path`; PATH is **not** consulted — see
  threat model T-3)

The integration harness ships in `tests/integration/*.tcyr` — 41 assertions
(14 `apply_outcome` + 8 `apply_smoke` + 19 `mcp_consume_smoke`) plus
`nft_load` (1.8.2), `nft_grammar` (1.9.1) and `diff_converge` (1.9.2), run
via `cyrius test tests/integration`.

**`apply_outcome` (1.9.0) needs nothing** — no root, no nft. It stands nft in
with small `/bin/sh` scripts (through `nein_set_nft_path`, in a fresh
`/tmp/nein-outcome-<pid>` it removes after) and checks what an apply reports
when nft dies on a signal, is killed at a shortened deadline, or is reaped
with SIGCHLD ignored: `NEIN_ERR_OUTCOME_UNKNOWN` for an apply, a plain
failure for a read, and the definite outcomes unchanged.

**`nft_load` has real nft parse every builder's output** (`nft -c -f`, as root
inside a throwaway user + network namespace via `unshare -rn`, so it needs no
privilege and touches no host ruleset). Where that cannot run — no nft, or
unprivileged user namespaces disabled, as on GitHub's Ubuntu runners — it
prints SKIP and passes, so **run it locally before every release.** It exists
because every builder test checked substrings of rendered text, and the mesh
ruleset nft has always refused shipped green (2026-11-03 audit B-4); on its
first run it found two more renders nft refuses.

**`nft_grammar` (1.9.1) has the installed nft judge nein's validators**, the
same way (`unshare -rn`, SKIP where it cannot run — so locally before every
release). It declares every listed keyword as a chain name, the ct-scope words
both as ct timeout names and as chain names, fixed near-misses (`FWD`,
`_3f2a`, a 64-byte name) and the references nft reads differently
(`@ll`, `flow offload @last`); checks **every** name of 1–3 characters from
`[a-z0-9_-]` that `validate_nft_name` takes as a chain, 4,000 to a batch, a
refused batch bisected to the word; harvests every word nft names in its own
"expected any of" errors and, for each `validate_nft_name` takes, checks nft
takes it too; creates and lists real tables named by the words nft expects
after `list` / `reset` / `monitor` (and their plurals) against
`list_table_with_handles`; generates 400 IPv6 spellings the same way every run
and checks each one `validate_addr` takes parses in nft; and loads each
builder's output at the B-8 length limits, and quoted interface names. About
11 s. It FAILs when nein takes what nft refuses (the batch
would fail at apply) and NOTEs the reverse (an older nft with fewer keywords).
A keyword a later nft adds shows up as a failure that names the word.

**`diff_converge` (1.9.2) has real nft judge the live diff**, the same way
(`unshare -rn`, SKIP where it cannot run — locally before every release). Each
ruleset — every builder, a corpus of one chain per match and verdict shape
nein renders (87 single-rule chains across inet, ip, ip6 and bridge tables), and 400
generated addresses biased toward the spellings inet_ntop rewrites — is loaded
into a fresh namespace, listed back with handles (what `nein_diff` reads) and
diffed against itself: any op is a FAIL that prints nein's predicted spelling
beside the body nft listed. Then each is perturbed (a stray counter rule at the
head and tail of a chain), diffed toward the target, the ops applied in a
second fresh namespace (handles are allocated in load order, so they match),
and the result must diff clean. It exists because through 1.9.1 every chain
holding a rule nft re-spells — a `/32`, a mark, a `counter` — was rebuilt on
every diff (audit P-8). About 2 s.

On non-permissive hosts the
apply assertions fall through the permission-denied class; the
pure-function assertions still run. You can also run a smoke test
manually:

```sh
sudo ./build/nein   # exits 0 with "nein ready" — confirms apply
                    # path doesn't crash before nft contact
```

**Warning:** the live-apply integration tests flush the live nftables
ruleset. They are designed to run in a network namespace; do not
disable the namespace guard on production systems.

## Coverage

Two coverage gates run in CI as of v1.6.9, both **ratchets at the
currently-measured figure** rather than aspirational targets:

- `scripts/test-coverage.sh` — what fraction of the public API surface is
  called by a test. Floor **89%** (368/411, 1.9.2; it was 64% at 1.6.9 and
  71% at 1.9.1). Reference coverage: a fn called once counts, so it catches
  "shipped an API, never tested it" and nothing finer. `--list` names every
  uncovered fn by module; at 1.9.2 the 43 left are accessors of bridge,
  policy, netns, geoip and mesh, `nein_diff` / `diff_apply` (they run nft) and
  `status_raw_ruleset`.
- `scripts/doc-coverage.sh` — doc-comment coverage. Floor **19%** (80/411),
  low by the shape of the surface rather than neglect: the logic-carrying
  modules are at or near 100% and the deficit is one-line accessors.

**`cyrius coverage --min` is deliberately NOT wired.** It measures *reference*
coverage from an entry point — a dead-code metric — and on this tree its
default mode walks only `src/main.cyr` and reports 1/1 = 100%, so it would
pass vacuously while measuring nothing.

## Benchmarks

The benchmark suite lives in `tests/nein.bcyr` — 63 benchmarks
covering validators, rule rendering, full firewall generation,
multi-agent engine, namespace firewall, (since 1.9.0) signing — v1
against v2 on the same body — and the MCP gate, (since 1.9.1)
`validate_nft_name` and `pe_validate` at 100 agents, and (since 1.9.2) the
live diff of a 100-rule chain already in place, in nein's spelling and in
nft's, the address canonicalizer and the counter-state strip.

⚠ **Code layout moves single benchmarks.** Adding includes to the bench
binary (1.9.0: the sign and MCP modules) moved `firewall_1000_rules_validate`
from 249 to ~310 µs with not one byte of its code changed; the same sources
with the 1.8.2 bench file measure 258 µs, and adding a different subset of
the includes moves it back to 263. A move confined to one benchmark after a
change that did not touch its code is layout until shown otherwise — check
by running the old bench file against the new sources.

```sh
cyrius bench tests/nein.bcyr
```

Output shape: `<name>: <avg>(ns|us|ms) avg (min=… max=…) [N iters]`.

### Regression gate

`scripts/bench-regression.sh` compares the current run against the
most recent committed baseline in `docs/benchmarks/history.csv`.

**Every delta is normalized by the run's machine factor** (1.8.2): the median
current/baseline ratio across all benchmarks. Baselines are recorded on the
release machine; CI runs on a slower shared runner (1.8.2: every benchmark
1.23×–1.82× slower, median 1.43×), so raw deltas carry the machine difference.
Each benchmark is judged against `baseline × factor` — a uniform shift cancels,
a single regressed benchmark still stands out. The factor is printed on every
run, and a factor above 2.0× fails the gate on its own (a very different
machine, or a regression in most benchmarks at once — the case a median cannot
see; locally the factor sits near 1.0, so a global regression shows up there
directly). Override the limit with `BENCH_MAX_MACHINE_FACTOR`. It
fires on > 90% (ns-bracket, abs > 50ns; `validate_iface` 120%) or
> 80% (µs-bracket, abs ≥ 2µs) slowdown per benchmark, and on any
benchmark in the baseline that the current run does not produce
(`**MISSING**`). Its summary states its own coverage:
`48 checked of 48 in the baseline, 0 new, 0 missing, 0 regressions`.
If "checked" is ever below the baseline count, something was not
compared. Through 1.8.0 every result printed in fractional µs / ms
went uncompared without a word: 27 of 48 benchmarks.

```sh
./scripts/bench-regression.sh           # default thresholds
./scripts/bench-regression.sh 30 50     # tighter percent thresholds
```

To ack a deliberate slowdown (e.g. correctness fix that costs perf),
or a benchmark retired before a new baseline is recorded, include
`[bench-regression-ack]` in the HEAD commit message and the gate skips
with a notice.

### Baseline refresh

Baselines update on each release tag. Append a new row per benchmark
to `docs/benchmarks/history.csv` with the new version/commit:

```
timestamp,version,commit,benchmark,time_ns
2026-05-10T21:29:32Z,1.1.4,abcd1234,rule_render/simple,1000
…
```

The bench-regression script reads **every row carrying the newest
timestamp** as the comparison baseline, so older rows stay for
historical reference without affecting the gate. (Through 1.8.0 it read
the most recent row per benchmark *name* across all history. With the
missing-benchmark check that would fail forever on a benchmark retired
long ago.) `scripts/bench-track.sh` records a baseline; it normalizes
every result to whole nanoseconds.

## Fuzzing

The fuzz harness is 7 per-target drivers in `fuzz/*.fcyr` (`validate`,
`config_parse`, `rule`, `nat`, `firewall`, since 1.8.2 `diff_parse_live`, and
since 1.9.0 `sign_v2_parse`), auto-discovered and run via:

```sh
cyrius fuzz
```

`cyrius fuzz` builds each driver, runs it, and exits 0 only if every
driver exits 0; crash attribution is by driver name.

CI runs a bare `cyrius fuzz` — no iteration count and no timeout. The first
five drivers are fixed deterministic corpora (`validate` also asserts two
relations since 1.9.1: `validate_nft_name` takes a subset of what
`validate_identifier` takes and never a leading digit or `-`, and
`validate_addr` never takes a dotted quad without `::`); `diff_parse_live` is a seeded
mutation fuzzer (real nft 1.1.7 listings, 20,000 deterministic mutations,
under a second) with strict semantic oracles — golden parses of every seed,
header-backed attribution, valid live names, no op on a table the target
does not contain. Run it under `cyrius fuzz --bounds` and `--poison` too; it
is clean in both. `sign_v2_parse` (20,000 mutations of envelopes signed with a
fixed key, about 3 s) carries a **uniqueness** oracle — an input that verifies
under v2 must be the envelope that was signed — and a cross-version one — no
mutation verifies under v1. Its mutations favour line boundaries, where header
ambiguities live, and include NUL insertion and uppercase hex; parsers made
to strip a trailing `\r` from header values, to allow a NUL in one, or to
allow uppercase hex each fail it. It prints how many inputs parsed and verified, so a run that never
reaches the verifier shows. Also clean under `--bounds` and `--poison=ab`. (Through v1.6.9 this section claimed "500
iterations under a 10-second wall clock timeout per file"; neither the
iteration count nor the timeout ever existed.)

A property-based harness over synthetic `nft list ruleset -a` output is the
strongest open hardening item on the roadmap — hand-curated inputs have now
missed two memory-safety bugs in the live-rule parser that a fuzzer would
have found.

## What CI Runs

The current CI workflow (`.github/workflows/ci.yml`) gates:

- `cyrius deps --verify` — sha256 of every resolved dep against `cyrius.lock`
- `cyrius fmt --check` drift check on src/ + tests/ + fuzz/
- `cyrius lint` on src/ + fuzz/ (no `warn ` lines allowed)
- `cyrius vet` — include-graph audit
- `cyrius deny` — include-path policy: no absolute paths, no `../` traversal
- `cyrius capacity --check` — a real gate since 1.6.5 (the `|| true` was
  dropped when the arch-peer false positive was fixed upstream)
- `CYRIUS_TYPE_CHECK=1` build (zero nein-side warnings)
- `CYRIUS_DCE=1` build on x86_64 + aarch64 cross-build
- Unit + config + **integration** suites, and the benchmark run
- `cyrius fuzz` — all 7 drivers
- API-surface snapshot diff (`scripts/api-surface.sh check`)
- Doc-coverage floor (`scripts/doc-coverage.sh`)
- Test-coverage floor (`scripts/test-coverage.sh`)
- Supply-chain policy (`scripts/supply-chain.sh`)
- Bench-regression gate (`scripts/bench-regression.sh`)
- Security scan (sys_system / hardcoded paths / large fn-scope buffers)
- dist-bundle staleness (`cyrius distlib` + `distlib mcp` must be committed)
- Doc completeness + currency check

Running all of these locally reproduces CI:

```sh
# Resolve + verify
cyrius lib sync && cyrius deps && cyrius deps --verify
# Static gates
cyrius vet src/main.cyr && cyrius deny src/main.cyr
cyrius capacity --check src/main.cyr
# Build both arches
CYRIUS_DCE=1 cyrius build src/main.cyr build/nein
CYRIUS_DCE=1 cyrius build --aarch64 src/main.cyr build/nein-aarch64
# Test + bench + fuzz
cyrius test tests && cyrius bench tests/nein.bcyr && cyrius fuzz
# Surface, coverage, policy, regression
./scripts/api-surface.sh check
./scripts/doc-coverage.sh
./scripts/test-coverage.sh
./scripts/supply-chain.sh
./scripts/bench-regression.sh
# dist bundles must be regenerated and committed
cyrius distlib && cyrius distlib mcp && git diff --exit-code dist/
```
