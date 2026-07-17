# Security Policy

Last refresh: **2026-07-17** (v1.6.4).

## Scope

nein is a programmatic nftables firewall library that renders rulesets
from typed Cyrius values and applies them via `fork + pipe + execve` to
the `nft` binary. It is intended to run under root or `CAP_NET_ADMIN`
in the caller's process.

The detailed threat model lives in
[`docs/development/threat-model.md`](docs/development/threat-model.md) —
8 numbered threats (T-1 through T-8). This file is the **policy**
shorthand; consult the threat model for the mitigations.

## Reporting a Vulnerability

If you discover a security vulnerability in nein, please report it
responsibly:

1. **Email** [security@agnos.dev](mailto:security@agnos.dev) with a
   description of the issue, steps to reproduce, and any relevant
   context (kernel version, `nft --version`, nein version).
2. **Do not** open a public issue for security vulnerabilities.
3. You will receive an acknowledgment within **48 hours**.
4. We follow a **90-day disclosure timeline**, with extensions
   negotiated case-by-case for kernel-side defects that require a
   distro patch chain.

Issues mapped to a numbered threat in the threat model expedite triage
— include the T-N reference if you can identify one.

## Supported Versions

| Version | Supported |
| ------- | --------- |
| 1.6.x   | Yes       |
| 1.0.x   | Best-effort (security-only fixes) |
| 0.9x.x  | No (Rust-era) |
| < 0.9x  | No (Rust-era) |

The Rust-era line (≤ 0.90.0) is preserved in `rust-old/` as a reference
checkout — it is not maintained. The Cyrius port baseline is v1.0.0.

## Security Properties (current, v1.6.x)

The properties below are enforced today. Each ties back to a numbered
threat in the threat model.

- **Injection-safe rendering** (T-1, T-2). Every string flowing into
  rendered nftables grammar passes through `validate_*` in
  `src/lib/validate.cyr`. Dangerous chars `; { } | \n \r \0 \` $ "`
  rejected. Address-shape, identifier-shape, interface-name-shape, and
  closed-set validators backstop the character allowlist with semantic
  checks. As of v1.1.2, all validators carry `(s: cstring): i64` type
  annotations and the type-check CI gate confirms callers pass the
  right shape.
- **No PATH-based execve** (T-3). The `nft` subprocess is invoked via a
  single pinned absolute path (`/usr/sbin/nft`); PATH is never consulted.
  A caller can override the path at runtime via `nein_set_nft_path`
  (validated: absolute, ≤ 256 bytes, non-null). The CI security-scan gate
  allowlists the pinned path in `src/lib/apply.cyr` and fails the build on
  any new hardcoded `/etc/`, `/bin/`, or un-allowlisted `/sbin/` literal.
- **Child-process hygiene** (T-4). `_run_nft_stdin` and
  `_run_nft_capture` always close unused pipe ends, drain stderr, and
  `sys_waitpid` regardless of stdin-write outcome. Execve failure
  routes to `sys_exit(127)` in the child; the parent observes that
  exit and returns `Err(ERR_PERMISSION_DENIED)`.
- **No `sys_system`** (T-1 / T-3). CI security scan hard-fails on any
  `\bsys_system\s*\(` match in `src/`. The shell-quoting attack
  surface is precisely what fork+pipe+execve avoids.
- **Lockfile-pinned deps** (T-8). `cyrius.lock` records the sha256 of
  each resolved dep. `cyrius deps --verify` in CI fails on hash
  mismatch. Cyrius itself is pinned in `cyrius.cyml`
  (`cyrius = "6.4.66"`). nein's git dep set (`cyrius.cyml` `[deps.*]`):
  libro 2.8.2, majra 2.5.1, bote 3.1.4, sigil 3.12.1, patra 1.12.12,
  sakshi 2.4.6 — sigil + patra carry explicit pins. Deps do not
  auto-resolve: `cyrius lib sync` pulls the declared stdlib subset, then
  `cyrius deps` fetches the git bundles.
- **Symbol-collision audit** (T-7). v1.1.1 renamed nein-side fns that
  collided with agnostik/stdlib (`network_policy_new` →
  `nein_network_policy_new`, `err_code` → `nein_err_code`). Future
  collisions surface as `duplicate fn ... (last definition wins)`
  build warnings — none in the current build.
- **Buffer review** (T-4). CI security scan flags any fn-scope
  `var buf[N]` ≥ 4 KB (warn) or ≥ 64 KB (fail). Current 4 KB
  warnings on `apply.cyr` (stderr/stdout capture) are review-acked.

## Security-Adjacent Tooling

- **`scripts/api-surface.sh`** — diffs the public-fn surface against a
  committed snapshot; an unexplained add (e.g. a new validator
  bypass) shows up in PR review.
- **`scripts/bench-regression.sh`** — guards against perf regressions
  that could mask latent issues (e.g. a sudden 100× slowdown in
  `_has_dangerous_char` would surface here before a release).
- **Type-check gate** (`CYRIUS_TYPE_CHECK=1`) — catches a wrong-type
  arg passed to a validator, e.g. a `Str` where `cstring` was
  expected.
- **No `unsafe` keyword in Cyrius**. The language has no escape hatch
  — all syscall surface is mediated by stdlib wrappers, surfaced via
  the security-scan gate.

## Standards Compliance

- **nftables** — [nftables wiki](https://wiki.nftables.org/);
  rulesets compatible with Linux netfilter (kernel ≥ 4.18 recommended;
  flowtables / interval sets need ≥ 4.18).
- **OWASP injection prevention** — allowlist-based validation,
  parameterised input via typed enums (closed-set validators for
  `family`, `ct_state`, `protocol`, etc.).
- **License** — GPL-3.0-only, compatible with Linux kernel ecosystem.

## Out of Scope

- The `nft` userspace tool's own attack surface.
- The Linux netfilter subsystem's kernel-side defects.
- Downstream callers' threat models (stiva, daimon, aegis, sutra —
  each owns its own SECURITY.md).
- Privilege-management policy. nein assumes the caller is running with
  appropriate capabilities; it does not drop, gain, or check privileges.
