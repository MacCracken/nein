# Threat Model

Last refresh: **2026-11-07** (v1.9.2 — T-2: the live diff compares in nft's spelling, and why a wrong prediction can only cost a rebuild. Previously v1.9.1 — T-1: names rendered bare must be names nft reads (`validate_nft_name`), IPv6 addresses ones nft parses, and the residual of a probed keyword list; T-5: `pe_validate` parses each address once. Previously v1.9.0 — T-9 gains the replay-bound v2 envelope and its residual risk; T-10 rewritten for the 1.9.0 gate contract: tool classes, offline-only default, one permit value, install-once. Previously v1.8.2 — T-4 rewritten for the memfd apply path after the 2026-11-03 P(-1) audit; T-3's override is copied, not borrowed. Previously 2026-08-21, v1.6.10 — T-4 rewritten and T-7 corrected after that audit. Earlier passes added T-9 signed-ruleset trust (v1.6.1), T-10 MCP
destructive-tool access control (v1.6.0) and T-11 MCP argument injection and
output escaping; the v1.4.0 refresh hardened T-3 to a single pinned absolute
path.)

## Scope

nein renders nftables rulesets from typed Cyrius values and applies them
by handing the rendered text to `nft -f -` via fork + execve, the
ruleset staged in a memfd on nft's stdin (pipes until 1.8.2). The
threat model covers:

1. Inputs flowing from a caller into the rendered ruleset (injection)
2. The handoff to the `nft` subprocess (subprocess hygiene, PATH attacks)
3. The kernel-side surface nein touches (privilege model)
4. Supply chain — Cyrius toolchain, git dependencies, lockfile
5. Signed-ruleset trust — the Ed25519 verify-before-apply path (`sign.cyr`)
6. MCP tool dispatch — agent access-control + tool-arg injection (`mcp.cyr`)

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
| `validate_identifier` | alnum + `_` + `-`, 1–64 chars (quoted object names, labels, key ids) |
| `validate_nft_name` | `validate_identifier`, plus a leading letter or `_` and no nft keyword (names rendered bare: table, chain, set, map, flowtable, ct timeout, define; jump / goto targets; `@` references) — 1.9.1 |
| `validate_addr` | parses as IPv4 or IPv6 with an in-range prefix (1.8.2); an IPv6 dotted-quad tail needs `::` (1.9.1) |
| `validate_iface` | alnum + `_` + `-` + `.`, 1–15 chars (Linux `IFNAMSIZ`); since 1.9.1 rendered quoted as flowtable devices and ifname set / map values, where bare nft reads `vxlan` or `3eth` as a keyword or a number |
| `validate_family` | closed set: `inet`/`ip`/`ip6`/`arp`/`bridge`/`netdev` |
| `validate_ct_state_list` | comma-separated list, each token from the closed set `new`/`established`/`related`/`invalid`/`untracked` |
| `validate_comment` | rejects `"` and dangerous chars; ≤ 128 chars |
| `validate_log_prefix` | same as comment but ≤ 64 chars (nftables limit) |
| `validate_nft_element` | rejects `"` and dangerous chars; non-empty |

`firewall_validate` walks the full tree before render; downstream
`apply_*` functions validate any new strings passed at apply time. As
of v1.1.2, all validators carry `(s: cstring): i64` annotations so the
type-check gate catches a wrong-type input at compile time.

**Validated must mean parseable (1.9.1).** Injection-safe is not enough:
a value nft cannot parse fails the whole batch at apply, which for a
caller is a firewall that did not change. Probing nft 1.1.7 found shapes
nein accepted and nft refuses:
- a name starting with a digit or `-` (`3f2a_in`, from a container-id
  agent);
- an nft keyword as a name (`fwd`, `log`, … 160 of them, and 16 more as
  a table name to `nft list`);
- an IPv6 address written as six groups and a dotted quad with no `::`;
- an interface name nft reads as a keyword or a number where it renders
  as a value (`devices = { vxlan }`).

Each is now refused at validation, or quoted (interface names). The
builders check the names, comments, ports and protocols they compose
(`<id>_in`, `<prefix>_filter`, `policy:<name> ingress from <peer>`), so a
builder config that validates builds a firewall that validates.

**Residual risk.** The `Raw` Match variant (per ADR-0004) bypasses
validation — documented for trusted-input use only. The convenience
builders `matching_addrs` / `matching_addrs6` use Raw internally but
pre-validate each address. Callers who construct `Raw` matches
themselves own the validation contract. The keyword lists are nft
1.1.7's, found by probing it: a keyword a later nft adds passes
validation and fails closed at apply, as every keyword did through
1.9.0. `tests/integration/nft_grammar.tcyr` tries every word the
installed nft names in its own syntax errors as a chain name, so such a
keyword shows there as a failure naming the word; an older nft with
fewer keywords costs a name, not a batch.

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

**The diff's comparison (1.9.2, audit P-8).** `nein_diff` decides which
chains to leave alone by comparing each target rule with the body nft lists
for the live one. A comparison that called two different rules equal would
leave a live rule in place that the target does not hold. That is the
dangerous direction: an allow the operator removed would stay. Since 1.9.2
the target side is rendered in the spelling nft lists, and the live side
loses counter values and quota usage. The safety argument:

- Every rewrite is one nft makes to the same rule. It masks host bits nft
  masks at load, drops prefixes and defaults nft drops, and prints a set or
  number the way nft prints it. None changes what a rule matches, so a live
  body equal to the canonical target is a rule equal to the target.
- The prediction is never trusted the other way. A spelling nein predicts
  wrongly compares unequal, and the chain is rebuilt, which is what every
  diff did through 1.9.1.
- State is dropped only outside quoted strings and only at a token boundary,
  so a comment or log prefix that spells `counter packets 1 bytes 2` cannot
  be edited into a match. A target rule cannot carry a `"` inside a string
  (`validate_comment`, `validate_log_prefix`), so a forged quote in a live
  comment cannot make a live body equal any target.
- The ops still carry the body as rendered and validated, never the
  canonical form, so what reaches `nft -f -` is unchanged.

Residual: the spellings are nft 1.1.7's and glibc's inet_ntop. A different
nft, or nft built on musl (whose inet_ntop prints `::c000:201` where glibc
prints `::192.0.2.1`), costs churn on the forms it spells differently, never
a false match. `match_raw` text is compared as written. nft's dependency
elision is not modelled: it drops a `meta l4proto tcp` before `reject with
tcp reset` in an ip table, so such a chain still churns.
`tests/integration/diff_converge.tcyr` names every form that churns against
the installed nft.

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

and, since 1.8.2, **copies** the accepted path into nein's own buffer
(2026-11-03 audit S-10). Through 1.8.1 it kept the caller's pointer, so a path
built in a stack buffer or a reused heap buffer later had execve run whatever
bytes were there by then.

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
descriptors, hang the parent, kill the parent, or let a failed apply be
reported as a success.

**Mitigation (rewritten at 1.8.2).** The apply layer uses no pipes. The
whole ruleset is written to a close-on-exec memfd **before** the fork; nft's
stdout goes to `/dev/null` and its stderr to a second memfd; the capture path
reads nft's stdout from a memfd after it exits. Then:

- **The child allocates nothing** between fork and execve — argv is built on
  the parent's frame first. An `alloc()` there could inherit the allocator's
  lock held by another thread of the host and spin forever (2026-11-03 audit
  S-1, reproduced).
- **Every descriptor nein opens is close-on-exec**, and the child closes
  every other descriptor it inherited (`close_range`), so a process the host
  forks concurrently cannot hold nft's input open, and host descriptors do
  not leak into nft (S-2).
- **A host that dies mid-write cannot hand nft a truncated batch** — nothing
  is written after the fork (S-3).
- **The child starts clean**: empty signal mask, SIGPIPE and SIGXFSZ at
  `SIG_DFL`, `PR_SET_PDEATHSIG` so it dies with the host (S-9). Its stdin,
  stdout and stderr are never the host's.
- **The parent waits with a deadline**: a pidfd, polled for 60 s; a wedged
  nft is SIGKILLed and the call fails closed (closes the old "no timeout"
  residual). `sys_waitpid`'s return value is checked, `-EINTR` retried — an
  unchecked wait decoded a failed apply as exit 0 (1.6.10).
- **A ruleset containing NUL is refused**: nft stops parsing at the first
  NUL and exits 0, so the prefix would be applied and reported as success.
- **Descriptors land on 0 / 1 / 2 through copies above fd 10**, so a source
  already sitting on 0-2 (a daemonized host closed them) is never clobbered
  by another's `dup2` — the general form of the 1.6.10 `_child_redirect` guard.
- On execve failure the child exits 127, which the parent maps to
  `Err(NEIN_ERR_PERMISSION_DENIED)`; nft's stderr is logged on any failure.
- The SIGPIPE guard (`signal_ignore(13)`, 1.6.10) is no longer load-bearing —
  nein writes to no pipe — and is kept only so a host relying on its
  process-wide effect sees no change; `nein_set_sigpipe_guard(0)` disables it.

**History.** Through v1.6.9 this section claimed the parent observes the
child's exit on execve failure; it was killed by SIGPIPE first (2026-08-21
audit H-7). Through 1.8.1 it described the pipe design and accepted two
residuals — no timeout, and a pipe-ordering deadlock — both closed by the
memfd design (2026-11-03 audit S-4).

**Residual risk.**

- When nein cannot learn nft's fate — the host sets SIGCHLD to `SIG_IGN` or
  reaps children itself, nft is killed at the deadline, or it dies on a
  signal — an apply returns `NEIN_ERR_OUTCOME_UNKNOWN` (1.9.0, audit S-8):
  the batch is committed whole or not at all, but which is unknown. Through
  1.8.2 this was `NEIN_ERR_NFT_FAILED`, and a caller that retried an
  *additive* apply duplicated rules. The residual is the caller's: on this
  code, re-diff (`nein_diff`) rather than re-apply. A read (`nft list`) in
  the same cases is a plain `NEIN_ERR_NFT_FAILED`.
- `close_range` needs Linux 5.9 and `pidfd_open` 5.3. On older kernels the
  first is skipped (nein's own descriptors are still close-on-exec) and the
  wait falls back to an unbounded `waitpid`.

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
- `pe_validate` parses each agent's address once for its duplicate check
  (1.9.1): through 1.9.0 it re-parsed every later address for every
  agent, n²/2 parses — 1.1 ms at 100 agents and 112 ms at 1,000 (measured;
  now 0.26 ms and 15 ms). The pair comparison is still O(n²), on 16-byte
  keys.

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

**Corrected at v1.6.10.** This section used to claim "CI's build step prints
any `duplicate fn` warnings (the toolchain emits them on stdout); a green
build implies zero collisions." Both halves were wrong:

- The warnings go to **stderr**, not stdout.
- `cyrius build` **exits 0** with duplicate definitions present, so a green
  build implies nothing about collisions. Reproduced: a two-`fn dupe()` file
  builds successfully and emits `warning:<source>:2:1: duplicate fn 'dupe'`.

The gate that does catch them is the **type-check step**, which greps the
combined output for nein-side `^warning:` lines and fails on any — a
`duplicate fn` naming a `src/` symbol is not filtered by the `^warning:lib/`
exclusion, so it fails the build. That step had its own defect, also fixed at
v1.6.10: `cyrius` prints its `compile … [arch] ` progress line **without a
trailing newline**, so the first warning of every build was concatenated onto
it and invisible to `^warning:` (verified — 10 occurrences of `warning:` in
the output, 9 visible to the grep). The step now normalizes embedded warnings
onto their own lines first.

One known collision is accepted and tracked: `_sub_new`, duplicated between
`lib/libro.cyr` and `lib/majra.cyr`. It is a dependency-internal symbol nein
does not call, and it is excluded by the `^warning:lib/` filter.

**Residual risk.** A collision between two *dependency* symbols is filtered
out by design and would not fail the build. Only collisions involving a
`src/` symbol are gated.

### T-8 — supply chain

**Threat.** A compromised Cyrius toolchain release or a poisoned
git-dependency release could inject malicious code into the nein binary.

**Mitigation.**
- Cyrius version is pinned in `cyrius.cyml` (`cyrius = "6.7.18"` as of 1.8.2), and CI
  passes that pin to the installer — the toolchain *payload* is
  version-pinned, never `latest`.

  **But the installer script itself is not pinned** (noted v1.6.10): CI runs
  `curl … /MacCracken/cyrius/main/scripts/install.sh | sh`, fetching from the
  **`main` branch** and piping it to a shell. Whoever can push to that branch
  can run arbitrary code in every AGNOS repo's CI. This is a first-party
  repository under the same ownership, which is why it is accepted rather
  than blocking — but the earlier claim of "no floating tags" was not true of
  the fetch path, only of the version it installs. Pinning the installer to a
  tag or vendoring it would close the gap.
- `cyrius.lock` records sha256 of each resolved dep. CI's
  `cyrius deps --verify` step fails on hash mismatch.
- nein's `[deps.*]` set is pinned to explicit tags: libro 2.8.8,
  majra 2.6.7, bote 3.3.2, sigil 3.12.9, patra 1.13.9 (sigil + patra
  carry their own explicit `[deps.*]` pins). sakshi left the git set at
  1.6.5 — libro 2.8.8 stopped pulling it transitively, so it resolves
  from the declared stdlib subset of the pinned snapshot. Deps do
  **not** auto-resolve: `cyrius lib sync` pulls the declared stdlib
  subset from the pinned snapshot, then `cyrius deps` fetches the git
  bundles. The set grew from the 1.6.x MCP + Ed25519-signing surface
  (bote/sigil); each addition is a git bundle with an audited call site.
- No external `unsafe` paths — Cyrius doesn't have an `unsafe` block
  concept; all syscall surface is stdlib-mediated and surfaced through
  the security-scan CI gate.

### T-9 — signed-ruleset trust and integrity (`sign.cyr`, v1.6.1)

**Threat.** `sign.cyr` attaches an Ed25519 signature to a rendered
ruleset so a verifier detects at-rest tampering before
`apply_signed_ruleset` touches nft. Four ways an attacker could subvert
that: (a) **key substitution** — re-sign a malicious ruleset with an
attacker key and rely on the envelope's carried pubkey being trusted;
(b) **tampering** — mutate the nft body while keeping a valid-looking
envelope; (c) **downgrade / strip** — remove the signature, or swap the
algorithm/version so a weaker or no check runs, then apply; (d)
**replay / rollback** — re-present an older, legitimately-signed
envelope to roll the firewall back to a weaker but validly-signed state.

**Mitigation.**
- **Trust root is caller-supplied, never the envelope.**
  `_sign_verify_parsed` decodes the envelope's `nein-sig-pubkey` header
  and requires it to byte-match the 32-byte key the caller passes in
  (`memeq(hdr_pk, pubkey, 32)` → else `NEIN_ERR_SIG_KEY_MISMATCH`,
  `sign.cyr:216`). The header pubkey is only a carrier/audit label; an
  attacker who re-signs with their own key produces an envelope whose
  header key ≠ the operator's trusted key and is rejected before
  `ed25519_verify` even runs. `verify_ruleset` /
  `apply_signed_ruleset` (and their `_hex` forms) take the trusted key
  as an explicit argument — there is no "trust the key in the file"
  entry point.
- **Signature covers the rendered body bytes; any mutation fails
  closed.** `ed25519_verify` runs over exactly the bytes between the
  `BEGIN/END NFT RULESET` delimiters (`_sign_verify_parsed` →
  `signed_body`, `sign.cyr:223`); a one-byte body edit yields
  `NEIN_ERR_BAD_SIGNATURE`. The `nein-sig-digest` (sha256) header is
  documented and treated as an **audit aid only** —
  `parse_signed_ruleset` never reads it back, so there is no
  digest-only fast path to downgrade to.
- **Version + algorithm are gated at parse.** `parse_signed_ruleset`
  rejects `nein-sig:` ≠ `v1` (`NEIN_ERR_SIG_VERSION`) and
  `nein-sig-alg:` ≠ `ed25519` (`NEIN_ERR_SIG_UNSUPPORTED_ALG`); a
  missing `pubkey`/`sig` header, malformed hex, or wrong hex length
  (64/128) yields `NEIN_ERR_SIG_MALFORMED`. Stripping the signature
  therefore fails *parse*, not verify — there is no unsigned path
  reachable through the signed-apply functions.
- **Fail-closed apply on the identical bytes it verified.**
  `apply_signed_ruleset` parses, calls `_sign_verify_parsed`, and only
  on `Ok` calls `apply_ruleset_str(signed_body(sr))`
  (`sign.cyr:252-258`). Verify and apply consume the same
  `(data + body_start, body_len)` span — no re-render or re-parse
  between them — so there is no verify-vs-apply TOCTOU. Any error
  short-circuits before nft is touched.
- **Keygen entropy is fail-closed.** `sign_keygen` delegates to sigil's
  `ed25519_generate_keypair`, which fills the 32-byte seed through
  sigil's single CSPRNG boundary (`_sigil_random_fill` → `random_bytes`
  → per-target getrandom / getentropy / ProcessPrng). On entropy
  failure it zeroizes both outputs and returns 0, which `sign_keygen`
  propagates; a key produced on failure is all-zero, so any later
  verify against it fails deterministically rather than silently
  accepting weak material.

- **Replay / rollback / misdirection: the v2 envelope (1.9.0).**
  `sign_ruleset_v2` signs a domain-separated message — `"nein-sig-v2\0"`,
  a `seq`, a `not_after`, a length-prefixed `scope` and `keyid`, then the
  body — and carries those fields in clear headers the verifier rebuilds
  the message from. `verify_ruleset_v2(signed, pk, scope, min_seq, now)`
  checks the signature first and only then the bounds: another scope is
  `NEIN_ERR_SIG_SCOPE`, `seq < min_seq` is `NEIN_ERR_SIG_STALE`, a passed
  expiry is `NEIN_ERR_SIG_EXPIRED`. The parser is strict (each header
  once, in order, nothing after END, no NUL in a header, hex in lowercase,
  the digest checked) and is fuzzed
  with a uniqueness oracle (`fuzz/sign_v2_parse.fcyr`): an input that
  verifies must be the envelope that was signed. Cross-version reuse is
  closed both ways — the v2 message holds a NUL, which v1 signing refuses
  and (since 1.9.0) v1 parsing refuses too.

**Residual risk.**
- **Replay defence needs the verifier's state, and v2.** nein is
  stateless: the floor (`min_seq`) is the caller's last applied seq per
  (key, scope), which the caller must persist after a successful apply
  and raise on `NEIN_ERR_OUTCOME_UNKNOWN` — to a seq `verify_ruleset_v2`
  returned, never one parsed without verification. A verifier that keeps no floor
  gets only scope and expiry checks. **v1 envelopes are unbound** and
  verify forever; a verifier that still accepts v1 can be replayed
  through it, so a host adopting v2 must stop calling the v1 functions
  (planned removal: 2.0). `now` comes from the caller's clock: a verifier
  whose clock can be set back extends every expiry. A verifier at 1.8.2 or
  older lacks the v1 NUL refusal and would accept a v1 wrapper around a v2
  message as authentic; it cannot become a ruleset (its apply refuses the
  NUL, and nft the bytes).
- **Secret-key custody is the operator's.** nein never persists `sk`
  (64 bytes, `seed32||pk32`); at-rest protection of the signing key is
  the signer's responsibility.
- **Enforcement is opt-in by entry point.** `apply_ruleset_str` and the
  incremental `*_live` functions remain direct unsigned apply paths.
  "Signed rulesets only" is a property the caller gets by choosing
  `apply_signed_ruleset*` as its sole apply entry point; nein does not
  globally forbid unsigned apply.

### T-10 — MCP access control (`mcp.cyr`, v1.6.0; contract 1.9.0)

**Threat.** `mcp.cyr` exposes nein as MCP tools an agent host can
drive. Two of the six — `nein_allow` and `nein_deny` — perform a
**live** `add_rule_live` against the running firewall; three more —
`nein_status`, `nein_list`, `nein_diff` — run `nft -a list ruleset` as
root and return live state (set elements, allowed sources, comments).
An agent that reaches the dispatcher could change the ruleset, or read
it, without operator intent — directly, or by slipping past the gate.

**Mitigation.**
- **A class for every tool, by what it reaches (1.9.0, audit M-3).**
  `nein_tool_class(i)`: `NEIN_TOOL_OFFLINE` (`nein_validate`),
  `NEIN_TOOL_READS_LIVE` (status / list / diff), `NEIN_TOOL_MUTATES`
  (allow / deny); `0` for an unknown index, and `nein_tool_index(name)`
  is `-1` for an unknown name, so a gate keyed on the class denies what it
  cannot classify. On the bote path the classes are also profile tags
  (`firewall` on all, `firewall_read`, `firewall_admin`) and annotations.
  One table feeds both integration paths and the gate.
- **No gate, offline only (1.9.0).** Until the host installs a gate,
  `_nein_gate_check` permits only `NEIN_TOOL_OFFLINE`. Through 1.8.2 the
  default was fail-open: an ungated register exposed live `allow` /
  `deny` to any caller that reached the transport.
- **Permit is one value (1.9.0, audit M-2).** The gate permits only by
  returning `NEIN_GATE_PERMIT` (`0x4E45494E2D4F4B21`), a constant above the
  x86_64 / aarch64 user-space range, so no bool, `Result` tag, error code
  or pointer equals it. Through 1.8.2 permit was `== 1`, and `fncall2`
  truncates a `Result` to its tag — a gate returning `Err` permitted.
- **One gate, installed once (1.9.0).** `_nein_gate_install` sets the gate
  by compare-and-swap from empty; re-installing the same gate is a no-op,
  and replacing or clearing it is refused, logged, and leaves the
  installed gate in place. `nein_tools_register_gated` under a refused
  gate mounts nothing. Through 1.8.2 any later register or `set_gate(0)`
  replaced or removed the gate for every dispatcher already serving.
- **Consulted first in every handler**, before argument parsing, nft,
  or apply; a denied call returns "access denied" and never touches the
  firewall.

**Residual risk.**
- **One policy per process.** The handler ABI `(args, claims)` carries
  no registration, so a host with several dispatchers cannot give them
  different gates — tools mounted by plain `nein_tools_register` run
  under whatever gate is installed, before or after — and the gate must
  decide from the tool name and `claims`.
- **The gate is only as good as the host's identity.** `claims` is `0`
  unless the host runs bote with auth (3.7.5+ hands the verified token);
  a host without caller identity cannot tell agents apart and should
  deny `READS_LIVE` and `MUTATES` outright (daimon does, for `MUTATES`).
- **`read_only` is not "safe".** `nein_tool_read_only` keeps its MCP
  meaning (does not change the firewall) and is `1` for the live
  readers; a gate keyed on it, as 1.8-era gates were, exposes the live
  ruleset. Gate on `nein_tool_class`.

### T-11 — MCP tool-argument injection (`mcp.cyr`, v1.6.0)

**Threat.** MCP tool arguments arrive as an attacker-influenced JSON
`arguments` object. Two directions of injection: (a) a crafted
`protocol`/`port`/`source`/`table`/`chain` (or a `nein_diff` rule
element) could inject nft grammar into the rule that `add_rule_live`
applies; (b) nft-derived output (live rule bodies, table/chain names)
echoed back into the MCP `{"content":[...]}` envelope could break out
of the JSON string and forge tool results.

**Mitigation.**
- **Every arg that reaches nft is validated before interpolation.**
  `_mcp_check_rule_args` gates the shared rule surface: `protocol` must
  be `tcp`/`udp` (`_mcp_valid_proto`), `port` is `atoi`'d and
  range-checked to `1..65535`, `table`/`chain` pass
  `validate_identifier`, and `source` (when present) passes
  `validate_addr` — the same T-1 validators, rejecting the
  `; { } | \n \r \0 \` $ "` set. `_mcp_build_rule` interpolates only
  those already-validated components, and `add_rule_live` independently
  re-runs `_validate_rule_args` — `validate_identifier` on family/table/
  chain plus `validate_nft_element` over the whole composed rule body
  (T-2) — so the MCP path inherits both injection gates. The
  `nein_diff` element parser applies the same protocol/port/verdict
  checks and then builds the target through **typed constructors**
  (`rule_new` / `match_protocol` / `match_dport`) — no untrusted string
  is ever concatenated into nft grammar on the diff path.
- **All nft-derived output is JSON-escaped.** Every text field emitted
  back — the result message in `_mcp_result`, and the
  `family/table/chain/rule` fields in `nein_list`/`nein_diff` — goes
  through bote's `_json_emit_escaped`, which escapes `" \ \n \r \t`.
  Live-rule bytes therefore cannot terminate the JSON string early or
  inject envelope keys such as a forged `"isError":false`.
- **Preview tools never apply.** `nein_validate` and `nein_diff` are
  read-only: they validate / compute ops and return them without
  touching nft, so a malformed arg on those tools is a rejected
  request, not a state change.

**Residual risk.**
- **`jsonx` is a minimal parser.** `jsonx_get_str` returns string
  values **without** decoding escapes (`\n`, `\"` pass through
  verbatim) and `jsonx_get_raw` returns verbatim source bytes. This is
  safe here because every consumed value is subsequently range/charset
  -validated (`validate_identifier` / `validate_addr` / `atoi`) before
  use — the validators reject the raw escape/metacharacter bytes. Any
  *future* MCP arg that is interpolated without a `validate_*` pass
  would reintroduce injection; new tool args must route through the
  same validators. The `nein_diff` brace-depth element splitter is a
  hand-rolled scanner over the `rules` array — it is bounded by `alen`
  and copies each element to a NUL-terminated buffer, but it assumes
  well-formed brace nesting; malformed nesting degrades to a
  best-effort parse (rejected downstream by the per-field checks), not
  memory unsafety.

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
