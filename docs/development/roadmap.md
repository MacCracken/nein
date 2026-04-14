# Roadmap

## Completed (v1.0.0)

Complete rewrite from Rust to Cyrius. 18 modules ported, 580 tests, 31 benchmarks.

- [x] Full Rust → Cyrius port (~8,857 LOC Rust → ~4,100 LOC Cyrius, ~54% reduction)
- [x] Core: error, validate, rule, set, nat, chain, table, firewall, builder
- [x] Feature: policy, geoip, mesh, bridge, engine, config, netns, apply, inspect
- [x] Test suite (580 assertions / 42 groups), benchmarks (31), fuzz harness
- [x] Injection-safe validators preserved across 8 input types
- [x] Modern Cyrius 4.3.0 toolchain
- [x] `nft -f -` subprocess execution via fork+pipe+execve (synchronous, blocking)

## Blocked on Upstream Ports

- [ ] `mcp` — blocked on [bote](https://github.com/MacCracken/bote) Cyrius port
- [ ] Full TOML struct parsing — only needed by sutra; scoped config dispatchers already shipped

## Future (v1.x)

- [ ] Apply-layer integration tests (require root + real nftables)
- [ ] Downstream consumer integration: daimon firewall MCP tools
- [ ] Fleet playbook TOML schema (sutra-driven)
- [ ] MCP tool descriptors (when bote lands)

## v1.0 Criteria

- [x] All ported modules pass test + benchmark suites
- [x] Firewall rendering matches Rust output byte-for-byte on tested paths
- [x] Validators reject all known injection patterns
- [x] Documentation: architecture, CHANGELOG, roadmap, README, threat model
- [x] Deferred work documented with explicit upstream blockers
