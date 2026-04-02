.PHONY: check fmt clippy test bench bench-track audit deny fuzz coverage build doc clean

# Run all CI checks locally
check: fmt clippy test audit deny

# Format check
fmt:
	cargo fmt --all -- --check

# Lint (zero warnings)
clippy:
	cargo clippy --all-targets -- -D warnings
	cargo clippy --features full --all-targets -- -D warnings
	cargo clippy --no-default-features --all-targets -- -D warnings

# Run test suite
test:
	cargo test --features full
	cargo test --features full --doc

# Run benchmarks (criterion)
bench:
	cargo bench --features full --no-fail-fast

# Run benchmarks and record to historical log
bench-track:
	./scripts/bench-track.sh

# Security audit
audit:
	cargo audit

# Supply-chain checks (license + advisory + source)
deny:
	cargo deny check

# Run fuzz targets (30 seconds each)
fuzz:
	cargo +nightly fuzz run fuzz_rule_render -- -max_total_time=30
	cargo +nightly fuzz run fuzz_toml_config -- -max_total_time=30
	cargo +nightly fuzz run fuzz_validation -- -max_total_time=30

# Generate coverage report
coverage:
	cargo llvm-cov --features full --lcov --output-path lcov.info

# Build release
build:
	cargo build --release --features full

# Generate documentation
doc:
	RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --features full

# Clean build artifacts
clean:
	cargo clean
	rm -rf coverage/ lcov.info
