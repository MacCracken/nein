# Nein — Claude Code Instructions

## Project Identity

**Nein** (German: no) — Programmatic nftables firewall — rules, NAT, port mapping, service access control

- **Type**: Shared library
- **License**: GPL-3.0-only
- **Language**: Cyrius (sovereign systems language, compiled by cycc; pinned `cyrius = "6.4.66"` in `cyrius.cyml`)
- **Version**: SemVer, version file at `VERSION`
- **Status**: 1.6.4 — Cyrius port complete + MCP/Ed25519-signing surface (mcp 1.6.0, sign 1.6.1, daimon dispatch adapter 1.6.2; toolchain 6.4.66 + dependency refresh 1.6.3–1.6.4). 664 unit + 16 integration assertions, 31 benchmarks, 5 fuzz drivers, 383 public fns. CI gates: fmt/lint/vet/capacity/type-check/aarch64-cross/security-scan/api-surface/bench-regression/fuzz/integration/dist-staleness
- **Genesis repo**: [agnosticos](https://github.com/MacCracken/agnosticos)
- **Standards**: [First-Party Standards](https://github.com/MacCracken/agnosticos/blob/main/docs/development/applications/first-party-standards.md)
- **Shared crates**: [shared-crates.md](https://github.com/MacCracken/agnosticos/blob/main/docs/development/applications/shared-crates.md)

## Scaffolding

**This project was scaffolded using:**
- Ported from Rust: `cyrius port /path/to/rust-project`

**Do not manually create project structure.** Use the tools. They ensure consistency with first-party standards across all AGNOS repos. If the tools are missing something, fix the tools.

## Consumers

| Project | Usage |
|---------|-------|
| stiva | Container bridge/NAT, port mapping, network isolation |
| daimon | Service mesh network policy, agent access control |
| aegis | Host firewall rules |
| sutra | Fleet-wide firewall playbooks |

## Architecture

```
src/
  main.cyr         — public API (includes all modules)
  lib/
    error.cyr      — NeinError type
    validate.cyr   — input validation, injection prevention
    rule.cyr       — core rule building (Match, Verdict, Protocol)
    table.cyr      — tables, families, metadata
    chain.cyr      — chains, hooks, policies
    set.cyr        — named sets and maps
    nat.cyr        — NAT rules (DNAT, SNAT, masquerade, redirect)
    bridge.cyr     — container bridge networking
    engine.cyr     — multi-agent policy engine
    mesh.cyr       — service mesh (sidecar/envoy)
    config.cyr     — TOML serialization
    geoip.cyr      — country-based blocking
    apply.cyr      — nft execution layer
    inspect.cyr    — live firewall status
    diff.cyr       — live-rule diff + idempotent apply (v1.5.0)
    builder.cyr    — pre-built configurations
    policy.cyr     — Kubernetes-style network policy
    netns.cyr      — network namespace firewall
    firewall.cyr   — top-level manager (add_table, validate, render)
    sign.cyr       — Ed25519-signed rulesets (v1.6.1)
    mcp.cyr        — MCP tool surface over bote (v1.6.0)

rust-old/          — preserved Rust source (9,338 lines, reference only)
```

## Development Process

### P(-1): Scaffold Hardening (before any new features)

0. Read roadmap, CHANGELOG, and open issues — know what was intended
1. Cleanliness check: `cyrius build`, `cyrlint`, all tests pass
2. Benchmark baseline: `cyrius bench`
3. Internal deep review — gaps, optimizations, correctness, docs
4. External research — domain completeness, best practices
5. **Security audit** — review all input handling, syscall usage, buffer sizes, pointer validation. Run against known CVE patterns for the domain. File findings in `docs/audit/YYYY-MM-DD-audit.md`
6. Additional tests/benchmarks from findings
7. Post-review benchmarks — prove the wins
8. Documentation audit
9. Repeat if heavy

### Work Loop (continuous)

1. Work phase — new features, roadmap items, bug fixes
2. Build check: `cyrius build`
3. Test + benchmark additions for new code
4. Internal review — performance, memory, correctness
5. **Security check** — any new syscall usage, user input handling, buffer allocation reviewed for safety
6. Documentation — update CHANGELOG, roadmap, docs
7. Version check — VERSION, cyrius.cyml in sync
8. Return to step 1

### Security Hardening (before release)

Run a dedicated security audit pass before any version release:

1. **Input validation** — every function that accepts external data (user input, file content, network data) validates bounds, types, and ranges before use
2. **Buffer safety** — every `var buf[N]` and `alloc(N)` verified: N is in BYTES, max access offset < N, no adjacent-variable overflow
3. **Syscall review** — every `syscall()` and `sys_*()` call reviewed: arguments validated, return values checked, error paths handled
4. **Pointer validation** — no raw pointer dereference of untrusted input without bounds checking
5. **No command injection** — no `sys_system()` or `exec_cmd()` with unsanitized user input. Use `exec_vec()` with explicit argv instead
6. **No path traversal** — file paths from external input validated against allowed directories. No `../` escape
7. **Known CVE check** — review dependencies and patterns against current CVE databases
8. **File findings** — all issues documented in `docs/audit/YYYY-MM-DD-audit.md` with severity, file, line, and fix

Severity levels:
- **CRITICAL** — exploitable immediately, remote or privilege escalation
- **HIGH** — exploitable with moderate effort
- **MEDIUM** — exploitable under specific conditions
- **LOW** — defense-in-depth improvement

### Closeout Pass (before every minor/major bump)

Run a closeout pass before tagging x.Y.0 or x.0.0. Ship as the last patch of the current minor (e.g. 2.2.5 before 2.3.0):

1. **Full test suite** — all .tcyr pass, zero failures
2. **Benchmark baseline** — `cyrius bench`, save CSV for comparison
3. **Dead code audit** — check for unused functions, remove dead source code
4. **Stale comment sweep** — grep for old version refs, outdated TODOs
5. **Security re-scan** — quick grep for new `sys_system`, unchecked writes, unsanitized input, buffer size mismatches
6. **Downstream check** — all consumers that depend on this crate still build and pass tests with the new version
7. **CHANGELOG/roadmap sync** — all docs reflect current state, version numbers consistent
8. **Version verify** — VERSION, cyrius.cyml, CHANGELOG header all match
9. **Full build from clean** — `rm -rf build && cyrius lib sync && cyrius deps && cyrius build` passes clean

### Task Sizing

- **Low/Medium effort**: Batch freely — multiple items per work loop cycle
- **Large effort**: Small bites only — break into sub-tasks, verify each before moving to the next
- **If unsure**: Treat it as large

## Key Principles

- **Correctness is the optimum sovereignty** — if it's wrong, you don't own it, the bugs own you
- **Never skip benchmarks.** Numbers don't lie. The CSV history is the proof.
- **Tests + benchmarks are the way.** Minimum 80%+ coverage target.
- Test after EVERY change, not after the feature is done
- ONE change at a time — never bundle unrelated changes
- Research before implementation — check vidya for existing patterns
- Study working programs (`cyrius/programs/*.cyr`) before writing new code
- Programs must call main() at top level: `var exit_code = main(); syscall(60, exit_code);`
- `cyrius build` handles everything — NEVER use raw `cat file | cycc`
- Source files only need project includes — deps resolve explicitly: `cyrius lib sync` then `cyrius deps` (from cyrius.cyml)
- Every buffer declaration is a contract: `var buf[N]` = N BYTES, not N entries
- **Own the stack.** If an AGNOS crate wraps an external lib, depend on the AGNOS crate.
- **No magic.** Every operation is measurable, auditable, traceable.
- `str_builder` over manual buffer writes — avoid offset miscalculation
- Vec of pointers over hashmap — when indices are known, direct access beats hashing
- `#ifdef` for optional modules — consumers pull only what they need
- sakshi tracing on all operations — structured logging for audit trail
- Packed Result for all fallible operations — zero-alloc success path
- Validate all external input before use — nftables injection prevention is critical for this crate

## Documentation Structure

```
Root files (required):
  README.md, CHANGELOG.md, CLAUDE.md, CONTRIBUTING.md,
  SECURITY.md, CODE_OF_CONDUCT.md, VERSION, LICENSE

docs/ (required):
  development/roadmap.md — completed, backlog, future

docs/ (when earned):
  adr/ — architectural decision records
  audit/ — security audit reports (YYYY-MM-DD-audit.md)
  guides/ — usage patterns, integration
  sources/ — academic/domain citations (required for science/math crates)
```

## .gitignore (Required)

```gitignore
# Build
/build/

# Cyrius — /lib/ is the resolved-deps dir, never committed (dist/ + cyrius.lock ARE tracked)
/lib/

# Rust (preserved in rust-old/)
rust-old/target/
rust-old/Cargo.lock

# IDE
.idea/
.vscode/
*.swp
*~

# OS
.DS_Store
Thumbs.db
```

## CHANGELOG Format

Follow [Keep a Changelog](https://keepachangelog.com/). Performance claims MUST include benchmark numbers. Breaking changes get a **Breaking** section with migration guide. Security fixes get a **Security** section with CVE references where applicable.

## DO NOT

- **Do not commit or push** — the user handles all git operations (commit, push, tag)
- **NEVER use `gh` CLI** — use `curl` to GitHub API only
- Do not add unnecessary dependencies — keep it lean
- Do not skip tests before claiming changes work
- Do not use `sys_system()` with unsanitized input — command injection risk
- Do not trust external data (file content, network input, user args) without validation
- Do not skip benchmarks before claiming performance improvements
