# Roadmap

Completed phases (0-8) are documented in the [CHANGELOG](../../CHANGELOG.md).

All planned phases are complete. Nein is at v0.90.0, approaching v1.0.

## v1.0 Criteria

- [ ] Stabilize public API — remove or finalize any experimental types
- [ ] Comprehensive documentation — all public types/functions documented with examples
- [ ] Doc-tests for key workflows (host firewall, container bridge, policy engine)
- [ ] Config module coverage — TOML parsing for all Phase 4-5 types (defines, flowtables, ct timeouts, quotas, etc.)
- [ ] Serde roundtrip tests for all new types
- [ ] Fuzz target coverage for new match/verdict variants
- [ ] Integration test coverage for new apply.rs functions (insert, replace, flush_chain, delete_chain)
- [ ] Performance audit at scale — 1000+ rules, 100+ agents
- [ ] `#[non_exhaustive]` on all public structs (not just enums)
- [ ] MSRV CI validation against 1.89
