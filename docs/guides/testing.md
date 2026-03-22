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

```sh
cargo bench --all-features
```

Results are written to `target/criterion/`.

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
