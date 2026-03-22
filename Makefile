.PHONY: check fmt clippy test bench bench-track audit deny fuzz coverage build doc clean

# Run all CI checks locally
check: fmt clippy test audit

# Format check
fmt:
	cargo fmt --all -- --check

# Lint (zero warnings)
clippy:
	cargo clippy --all-features --all-targets -- -D warnings

# Run test suite
test:
	cargo test --all-features

# Run benchmarks (criterion)
bench:
	cargo bench --all-features --no-fail-fast

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
	cargo tarpaulin --all-features --skip-clean
	@echo "Coverage report generated"

# Build release
build:
	cargo build --release --all-features

# Generate documentation
doc:
	RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --all-features

# Clean build artifacts
clean:
	cargo clean
	rm -rf coverage/
