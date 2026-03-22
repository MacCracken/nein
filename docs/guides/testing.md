# Testing Guide

## Unit Tests

Run all unit tests:

```sh
cargo test --all-features
```

Run tests for a specific module:

```sh
cargo test --all-features rule::tests
cargo test --all-features bridge::tests
```

## Integration Tests

Integration tests require:
- Root privileges (or `CAP_NET_ADMIN`)
- A kernel with nftables modules loaded (`nf_tables`, `nf_conntrack`)
- The `nft` binary installed

```sh
NEIN_INTEGRATION=1 cargo test --test integration
```

**Warning:** Integration tests flush the live nftables ruleset. Do not run on
production systems.

## Coverage

Using cargo-tarpaulin:

```sh
cargo tarpaulin --all-features
```

Using cargo-llvm-cov:

```sh
cargo llvm-cov --all-features --html --output-dir coverage/
```

Or via the Makefile:

```sh
make coverage
```

## Benchmarks

Run benchmarks:

```sh
cargo bench --all-features
# or
make bench
```

Results are written to `target/criterion/`.

### Historical Tracking

The `bench-track` script runs benchmarks and appends results to a local TSV log
(`benchmarks/history.tsv`) for tracking performance across versions:

```sh
make bench-track                          # run and record
./scripts/bench-track.sh --compare        # show historical results
```

Each run records: timestamp, version, git commit, benchmark name, and median
time. Raw criterion output is also saved per version in `benchmarks/`.

The `benchmarks/` directory is gitignored — it is a local development tool.

## Fuzzing

Requires nightly Rust and cargo-fuzz:

```sh
cargo +nightly fuzz run fuzz_rule_render -- -max_total_time=30
cargo +nightly fuzz run fuzz_toml_config -- -max_total_time=30
cargo +nightly fuzz run fuzz_validation -- -max_total_time=30
```

Or via the Makefile:

```sh
make fuzz
```
