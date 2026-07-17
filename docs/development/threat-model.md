# Threat Model

Last refresh: **2026-07-17** (v1.6.4 — modeled the two 1.6.x
security-relevant surfaces: added **T-9** (Ed25519 signed-ruleset
trust / integrity, `sign.cyr` v1.6.1), **T-10** (MCP destructive-tool
access control, `mcp.cyr` v1.6.0), and **T-11** (MCP tool-argument
injection + output escaping). The prior pass brought the T-8 dep set +
toolchain pin current; the v1.4.0 refresh hardened T-3 to a single
pinned absolute path and added the integration test scaffold +
inspect-parser hardening).

## Scope

nein renders nftables rulesets from typed Cyrius values and applies them
by piping the rendered text to `nft -f -` via fork + pipe + execve. The
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
git-dependency release could inject malicious code into the nein binary.

**Mitigation.**
- Cyrius version is pinned in `cyrius.cyml` (`cyrius = "6.4.66"`);
  CI installs from the version-pinned GitHub release URL — no `latest`,
  no floating tags.
- `cyrius.lock` records sha256 of each resolved dep. CI's
  `cyrius deps --verify` step fails on hash mismatch.
- nein's `[deps.*]` set is pinned to explicit tags: libro 2.8.2,
  majra 2.5.1, bote 3.1.4, sigil 3.12.1, patra 1.12.12, sakshi 2.4.6
  (sigil + patra carry their own explicit `[deps.*]` pins). Deps do
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

**Residual risk.**
- **Replay / rollback is not defended.** The signed message is the body
  bytes alone — no nonce, timestamp, or monotonic version counter. A
  captured, still-valid envelope re-verifies and re-applies
  indefinitely; an attacker who can substitute an older signed ruleset
  can roll the firewall back to a weaker-but-signed state.
  Freshness / anti-rollback (a generation counter or wall-clock bound
  checked by the operator) is a verifier-side control, out of
  `sign.cyr`'s scope today — tracked as future hardening.
- **Secret-key custody is the operator's.** nein never persists `sk`
  (64 bytes, `seed32||pk32`); at-rest protection of the signing key is
  the signer's responsibility.
- **Enforcement is opt-in by entry point.** `apply_ruleset_str` and the
  incremental `*_live` functions remain direct unsigned apply paths.
  "Signed rulesets only" is a property the caller gets by choosing
  `apply_signed_ruleset*` as its sole apply entry point; nein does not
  globally forbid unsigned apply.

### T-10 — MCP destructive-tool access control (`mcp.cyr`, v1.6.0)

**Threat.** `mcp.cyr` exposes nein as MCP tools an agent host can
drive. Two of the six — `nein_allow` and `nein_deny` — perform a
**live** `add_rule_live` against the running firewall. An agent that
reaches the dispatcher could invoke the mutating tools directly, or
slip past a host's intended gate, and change the live ruleset (open a
port, drop traffic) without operator intent.

**Mitigation.**
- **Side-effect classification travels with every tool.**
  `nein_tool_read_only` marks `nein_allow`/`nein_deny` as mutating
  (`0`) and the other four as read-only (`1`); `nein_tool_admin`
  promotes the mutating pair to the `firewall_admin` profile. On the
  bote-dispatcher path (`_nein_reg`) the mutating tools get
  `ann_destructive()` annotations and the `{firewall, firewall_admin}`
  profile vec, while read-only tools get `ann_read_only()` and
  `{firewall}`. A host can therefore filter/gate by side-effect
  (`tools/list?profile=firewall_admin`) and expose the admin set only
  to privileged agents — without any dependency on bote's reserved
  `claims`.
- **Fail-closed gate primitive, consulted first in every handler.**
  When a gate is installed — `nein_tools_register_gated(d, gate_fp)`
  (dispatcher path) or `nein_mcp_set_gate(gate_fp)` (daimon
  dispatch-adapter path) — each handler's first act is
  `_nein_gate_check(name, claims)`, which permits only when
  `fncall2(_nein_gate, name, claims) == 1` and otherwise returns the
  `"access denied"` envelope **before** any validate/apply. A denied
  mutating call never reaches `add_rule_live`.
- **Single source of truth for both integration paths.** The
  bote-dispatcher registration and the daimon-friendly
  `nein_mcp_dispatch` adapter both read the same
  `nein_tool_name/desc/read_only/admin` table, so a tool cannot be
  classified destructive on one path and read-only on the other.

**Residual risk.**
- **The default registration is ungated (fail-open).** Plain
  `nein_tools_register`, or `nein_mcp_dispatch` with no prior
  `nein_mcp_set_gate`, leaves `_nein_gate == 0`, and `_nein_gate_check`
  then returns "permit" for every tool — including the destructive
  pair. nein ships the fail-closed *primitive* and the classification
  metadata; **enforcing** it is the host's responsibility. A host that
  mounts the tools with the plain register exposes live `allow`/`deny`
  to any agent that can reach the transport. Hosts driving nein should
  install the gate (gated register / `set_gate`) and deny
  `firewall_admin` tools by default.
- **No per-agent identity yet.** bote's `claims` is a reserved `0` in
  the 2.x ABI, so the gate decides on tool name + whatever ambient host
  policy `gate_fp` encodes — it cannot yet distinguish *which* agent is
  calling. Per-agent authorization must wait for bote to populate
  `claims`; the seam is threaded claims-ready
  (`fncall2(_nein_gate, name, claims)`) so no signature change is
  needed when it lands.
- **Process-global, last-writer-wins gate.** `_nein_gate` is a single
  module-scope slot; the final `register_gated`/`set_gate` wins and the
  setting is shared across every dispatcher in the process. A host
  standing up multiple dispatchers with different policies cannot
  express per-dispatcher gating through this seam.
- **Read-only tools still disclose live topology.**
  `nein_status`/`nein_list`/`nein_diff` return live table/chain/rule
  state to any permitted agent. They are correctly classed read-only
  (no mutation), but a host that treats "read-only" as "safe for all
  agents" leaks firewall topology; the `{firewall}` profile lets a host
  withhold even the read set from unprivileged agents.

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
