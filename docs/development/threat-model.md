# Threat Model

Last refresh: **2026-05-10** (v1.4.0 — T-3 hardened to single pinned
absolute path; integration test scaffold + inspect-parser hardening
added).

## Scope

nein renders nftables rulesets from typed Cyrius values and applies them
by piping the rendered text to `nft -f -` via fork + pipe + execve. The
threat model covers:

1. Inputs flowing from a caller into the rendered ruleset (injection)
2. The handoff to the `nft` subprocess (subprocess hygiene, PATH attacks)
3. The kernel-side surface nein touches (privilege model)
4. Supply chain — Cyrius toolchain, agnosys dependency, lockfile

Out of scope: the `nft` userspace tool's own attack surface, the kernel
netfilter subsystem, and downstream callers (stiva, daimon, aegis,
sutra) which carry their own threat models.

## Threats

### T-1 — nftables syntax injection

**Threat.** A caller passes attacker-influenced strings (IP, interface
name, comment, log prefix, set element) that get interpolated into the
rendered ruleset, injecting arbitrary nft commands when piped to
`nft -f -`.

**Mitigation.** Every string interpolated into nftables grammar passes
through a `validate_*` function in `src/lib/validate.cyr` before the
render call. Validators reject the dangerous-char set `; { } | \n \r \0
\` $ "` plus per-type allowlists:

| Validator | Allowlist |
|-----------|-----------|
| `validate_identifier` | alnum + `_` + `-`, 1–64 chars (table/chain names) |
| `validate_addr` | hex + `.` + `:` + `/`, must contain a digit and at least one of `.`/`:` (IPv4/IPv6/CIDR) |
| `validate_iface` | alnum + `_` + `-` + `.`, 1–15 chars (Linux `IFNAMSIZ`) |
| `validate_family` | closed set: `inet`/`ip`/`ip6`/`arp`/`bridge`/`netdev` |
| `validate_ct_state` | closed set: `new`/`established`/`related`/`invalid`/`untracked` |
| `validate_comment` | rejects `"` and dangerous chars; ≤ 128 chars |
| `validate_log_prefix` | same as comment but ≤ 64 chars (nftables limit) |
| `validate_nft_element` | rejects `"` and dangerous chars; non-empty |

`firewall_validate` walks the full tree before render; downstream
`apply_*` functions validate any new strings passed at apply time. As
of v1.1.2, all validators carry `(s: cstring): i64` annotations so the
type-check gate catches a wrong-type input at compile time.

**Residual risk.** The `Raw` Match variant (per ADR-0004) bypasses
validation — documented for trusted-input use only. The convenience
builders `matching_addrs` / `matching_addrs6` use Raw internally but
pre-validate each address. Callers who construct `Raw` matches
themselves own the validation contract.

### T-2 — incremental-apply injection

**Threat.** `add_rule_live` / `insert_rule_live` / `replace_rule_live` /
`delete_rule_live` take `family`/`table`/`chain` strings plus a rule
struct and shell out to `nft add rule …`. Attacker-controlled string
parameters could inject nft commands.

**Mitigation.** Every incremental-apply function validates its string
parameters before interpolation:

- `family` — `validate_family` (closed set)
- `table` / `chain` — `validate_identifier`
- Rule bodies — rendered via `rule_render`, which already passed
  validate-during-construction
- Handles — `i64`, no injection surface

### T-3 — `nft` PATH injection

**Threat.** `apply.cyr` invokes the nft binary via `execve`. If an
attacker controls `PATH` and can place a malicious `nft` earlier in the
search path, they get arbitrary execution under nein's caller (typically
root with `CAP_NET_ADMIN`).

**Current mitigation (v1.4.0).** The execve call uses **a single pinned
absolute path** — no PATH consultation, no fallback chain. The default
is `/usr/sbin/nft`; callers running on systems with nft elsewhere
override at runtime via `nein_set_nft_path("/sbin/nft")`. The setter
rejects:

- `0` / null pointers
- Non-absolute paths (anything not starting with `/`)
- Paths longer than 256 bytes

The v1.1.1 security-scan CI gate continues to allowlist `src/lib/apply.cyr`
for path literals; that exception is now narrower (one literal default
plus the doc-comment block) but the gate still fails the build on any
new `"/etc/"` / `"/bin/"` / un-allowlisted `"/sbin/"` literal added
elsewhere.

**Pre-v1.4.0 behavior** tried `/usr/sbin/nft` → `/sbin/nft` →
`/usr/bin/nft` in order. That was a soft form of PATH consultation: an
attacker who controlled `/usr/sbin/` could plant a malicious binary
before the real one, since execve would try it first. The v1.4.0 single-
path model forces the operator to either trust `/usr/sbin/nft` exactly
or set the path explicitly — closing the multi-path race.

**Residual risk.** A compromised system that has rewritten the
configured `nft` binary at its absolute path is already root-equivalent
— nein cannot defend against that. The mitigation is upstream
(integrity-protected filesystems via dm-verity / IMA / etc., out of
nein's scope).

### T-4 — child-process hygiene

**Threat.** The forked `nft` child could become a zombie, leak file
descriptors, or hang the parent if stdin writes fail.

**Mitigation.** `_run_nft_stdin` and `_run_nft_capture` always close
the unused pipe ends, drain stderr, and call `sys_waitpid` regardless
of the stdin-write outcome. On execve failure the child falls through
to `sys_exit(127)`; the parent observes that exit status and returns
`Err(ERR_PERMISSION_DENIED)`.

**Residual risk.** A pathological `nft` that never terminates would
block the parent's `sys_waitpid`. Timeouts are not currently set on
that call. Tracked as a future hardening item — low priority because
nft itself is not adversarial.

### T-5 — denial of service via rule explosion

**Threat.** A configuration with many agents, isolation groups, or
geoip country lists produces a ruleset so large that nft rejects it
or the kernel netfilter table runs out of memory.

**Mitigation.**
- Bridge port isolation (ADR-0007) and the `PolicyEngine` outbound-host
  set use **named nftables sets** instead of per-pair rules — O(1)
  lookup, O(N) memory in the element count, no rule-count blowup.
- GeoIP rules use **interval sets** so a country with thousands of
  CIDRs compresses to one set with `flags interval`.
- `firewall_render` is observable before any apply — callers can size
  the output and refuse to apply if implausible.

### T-6 — TOML config inputs

**Threat.** A malformed or adversarial TOML config produces unexpected
rules.

**Mitigation.** Today nein consumes only **scoped enum dispatchers**
from `config.cyr` — they accept individual strings and return enum
variants or `Err(ERR_PARSE)`. Full TOML struct parsing is not yet
shipped (blocked on richer `toml` stdlib parsing, roadmap v2.0.0).
Once it lands, the same `validate_*` pass applies — the TOML parser
is a typed-input source like any other.

### T-7 — symbol-collision shadow

**Threat (historical, fixed in v1.1.1).** When a dependency adds a
function with the same name as one of nein's, "last definition wins"
silently shadows nein's implementation. If the shadow has different
semantics (e.g. agnostik 1.2.x's no-arg `network_policy_new` vs nein's
3-arg version), nein's callers get wrong behavior.

**Mitigation.** v1.1.1 audited and renamed colliding symbols:
- `network_policy_new` → `nein_network_policy_new`
- `err_code` → `nein_err_code`

CI's build step prints any `duplicate fn` warnings (the toolchain
emits them on stdout); a green build implies zero collisions. Future
deps that introduce new collisions surface on the first build after
the bump.

### T-8 — supply chain

**Threat.** A compromised Cyrius toolchain release or a poisoned
agnosys release could inject malicious code into the nein binary.

**Mitigation.**
- Cyrius version is pinned in `cyrius.cyml` (`cyrius = "5.10.34"`);
  CI installs from the version-pinned GitHub release URL — no `latest`,
  no floating tags.
- `cyrius.lock` records sha256 of each resolved dep. CI's
  `cyrius deps --verify` step fails on hash mismatch.
- nein's dep set is **deliberately minimal**: agnosys 1.2.4
  (`dist/agnosys-core.cyr` profile only) is the sole `[deps.*]`
  entry as of v1.1.1. The agnostik dep was dropped in v1.1.1 after
  audit found zero call sites.
- No external `unsafe` paths — Cyrius doesn't have an `unsafe` block
  concept; all syscall surface is stdlib-mediated and surfaced through
  the security-scan CI gate.

## What is NOT a mitigation

- **No stack canaries.** Cyrius does not emit stack-protector epilogues.
  Buffer-overflow exploit primitives are bounded by source-level
  validation, not runtime checks. See `_run_nft_stdin`'s `var errbuf[4096]`
  and `_run_nft_capture`'s `var buf[4096]` — both are written by
  `sys_read` with explicit length caps; the v1.1.1 security-scan gate
  flags any new fn-scope buffer ≥ 4 KB for review (≥ 64 KB fails the
  build).
- **No ASLR-aware hardening at compile time.** Inherits whatever the
  Cyrius runtime + Linux loader provide.

## Discovery process

Found a defect that affects this surface? Follow `SECURITY.md`'s private
disclosure process. The next minor cuts may fold the fix in; CVE-class
findings get a SECURITY-tagged patch and a `## Security` section in
`CHANGELOG.md`.
