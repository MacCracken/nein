# Testing Guide

Last refresh: **2026-08-21** (v1.6.10). Replaces the Rust-era guide that
shipped with the v1.0.0 port.

## Unit Tests

The full unit-test suite lives in `tests/nein.tcyr` — 754 assertions
across 42 test groups (validators, rule rendering, NAT, sets/maps,
chains, tables, firewall validation, builders, policy, geoip, mesh,
bridge, engine, config, netns, inspect, diff, sign, mcp).

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

The integration harness ships in `tests/integration/*.tcyr` — 18 tests
(6 `apply_smoke` + 10 `mcp_consume_smoke`), run via
`cyrius test tests/integration/*.tcyr`. On non-permissive hosts the
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
  called by a test. Floor **64%** (255/394). Reference coverage: a fn called
  once counts, so it catches "shipped an API, never tested it" and nothing
  finer.
- `scripts/doc-coverage.sh` — doc-comment coverage. Floor **17%** (69/394),
  low by the shape of the surface rather than neglect: the logic-carrying
  modules are at or near 100% and the deficit is one-line accessors.

**`cyrius coverage --min` is deliberately NOT wired.** It measures *reference*
coverage from an entry point — a dead-code metric — and on this tree its
default mode walks only `src/main.cyr` and reports 1/1 = 100%, so it would
pass vacuously while measuring nothing.

## Benchmarks

The benchmark suite lives in `tests/nein.bcyr` — 48 benchmarks
covering validators, rule rendering, full firewall generation,
multi-agent engine, and namespace firewall.

```sh
cyrius bench tests/nein.bcyr
```

Output shape: `<name>: <avg>(ns|us|ms) avg (min=… max=…) [N iters]`.

### Regression gate

`scripts/bench-regression.sh` compares the current run against the
most recent committed baseline in `docs/benchmarks/history.csv`. It
fires on > 50% (ns-bracket, abs ≥ 50ns) or > 80% (µs-bracket,
abs ≥ 2µs) slowdown per benchmark.

```sh
./scripts/bench-regression.sh           # default thresholds
./scripts/bench-regression.sh 30 50     # tighter percent thresholds
```

To ack a deliberate slowdown (e.g. correctness fix that costs perf),
include `[bench-regression-ack]` in the HEAD commit message and the
gate skips with a notice.

### Baseline refresh

Baselines update on each release tag. Append a new row per benchmark
to `docs/benchmarks/history.csv` with the new version/commit:

```
timestamp,version,commit,benchmark,time_ns
2026-05-10T21:29:32Z,1.1.4,abcd1234,rule_render/simple,1000
…
```

The bench-regression script reads the **most recent row per benchmark
name** as the comparison baseline, so older rows stay for historical
reference without affecting the gate.

## Fuzzing

The fuzz harness is 5 per-target drivers in `fuzz/*.fcyr` (`validate`,
`config_parse`, `rule`, `nat`, `firewall`), auto-discovered and run via:

```sh
cyrius fuzz
```

`cyrius fuzz` builds each driver, runs it, and exits 0 only if every
driver exits 0; crash attribution is by driver name.

CI runs a bare `cyrius fuzz` — no iteration count and no timeout. The
drivers are fixed deterministic corpora, not iterating fuzzers, so a run is
the same length every time. (Through v1.6.9 this section claimed "500
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
- `cyrius fuzz` — all 5 drivers
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
cyrius tests && cyrius bench tests/nein.bcyr && cyrius fuzz
# Surface, coverage, policy, regression
./scripts/api-surface.sh check
./scripts/doc-coverage.sh
./scripts/test-coverage.sh
./scripts/supply-chain.sh
./scripts/bench-regression.sh
# dist bundles must be regenerated and committed
cyrius distlib && cyrius distlib mcp && git diff --exit-code dist/
```
