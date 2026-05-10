# Testing Guide

Last refresh: **2026-05-10** (v1.1.4). Replaces the Rust-era guide that
shipped with the v1.0.0 port.

## Unit Tests

The full unit-test suite lives in `tests/nein.tcyr` — 580 assertions
across 42 test groups (validators, rule rendering, NAT, sets/maps,
chains, tables, firewall validation, builders, policy, geoip, mesh,
bridge, engine, config, netns, inspect).

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
- `nft` binary installed at one of `/usr/sbin/nft` / `/sbin/nft` /
  `/usr/bin/nft` (apply.cyr tries each in order; PATH is **not**
  consulted — see threat model T-3)

The integration harness is not yet shipped (roadmap v1.4.0 — "real
nftables integration test harness"). Until then, run smoke tests
manually:

```sh
sudo ./build/nein   # exits 0 with "nein ready" — confirms apply
                    # path doesn't crash before nft contact
```

**Warning:** future integration tests will flush the live nftables
ruleset. They are designed to run in a network namespace; do not
disable the namespace guard on production systems.

## Coverage

Cyrius does not yet ship a coverage tool. `cyrius coverage` is listed
in `cyrius --help` but is a no-op in 5.10.x. Roadmap-watched —
empirical coverage from the 580 assertions is the gate today.

## Benchmarks

The benchmark suite lives in `tests/nein.bcyr` — 31 benchmarks
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

The fuzz harness lives in `tests/nein.fcyr` and is built like a
regular `.cyr` program:

```sh
cyrius build tests/nein.fcyr build/fuzz_nein
./build/fuzz_nein 500    # 500 iterations
```

Today the harness is one monolithic file. Splitting it per-validator
(`fuzz/validate_addr.fcyr`, `fuzz/rule_render.fcyr`, …) is on the
v1.3.0 roadmap to allow per-target iteration tuning and crash
attribution.

CI runs the harness for 500 iterations under a 10-second wall clock
timeout per file (best-effort — slow runners may exit cleanly with
fewer iterations).

## What CI Runs

The current CI workflow (`.github/workflows/ci.yml`) gates:

- `cyrius fmt` drift check on src/ + tests/
- `cyrius lint` on src/ (no `warn ` lines allowed)
- `cyrius vet` — include-graph audit
- `cyrius capacity --check` (informational — see capacity job for caveat)
- `CYRIUS_TYPE_CHECK=1` build (zero nein-side warnings)
- `CYRIUS_DCE=1` build on x86_64 + aarch64 cross-build
- Test suite + benchmark run
- API-surface snapshot diff (`scripts/api-surface.sh check`)
- Bench-regression gate (`scripts/bench-regression.sh`)
- Security scan (sys_system / hardcoded paths / large fn-scope buffers)
- Doc completeness + currency check

Running all of these locally reproduces CI:

```sh
# Toolchain check
cyrius deps && cyrius build src/main.cyr build/nein
# Test + bench
cyrius test tests/nein.tcyr && cyrius bench tests/nein.bcyr
# Surface + regression
./scripts/api-surface.sh check
./scripts/bench-regression.sh
```
