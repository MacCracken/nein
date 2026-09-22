# Rust → Cyrius Port Completeness Audit

Last refresh: **2026-08-21** (v1.6.8 — `rust-old/` deleted).

The record that justified deletion of `rust-old/`, which happened at
**v1.6.8**. The tree is recoverable from git history at any commit up to
and including the v1.6.7 tag; nothing below has been rewritten to hide
that it once existed. Every public item in the
preserved Rust tree (9,338 lines, 19 modules) was checked against the
Cyrius surface: ported, intentionally dropped with a reason, or a gap.
Gaps found by this audit were closed in **v1.6.7** except the one
tracked at the top of [`roadmap.md`](roadmap.md).

---

## Method

Three passes, all mechanical rather than by eye:

1. **Public functions.** Every `pub fn` and `pub async fn` (including
   `impl`-block methods, excluding `#[cfg(test)]` bodies) extracted from
   `rust-old/src/*.rs`, then matched against `^fn NAME(` across
   `src/main.cyr` + `src/lib/*.cyr` — the same definition of "public"
   that `scripts/api-surface.sh` gates on. Method names were mapped
   through the port's abbreviation conventions (`BridgeFirewall::` →
   `bf_`, `PolicyEngine::` → `pe_`, `NamespaceFirewall::` → `nsf_`,
   `PortMapping::` → `pm_`, `AgentPolicy::` → `ap_`, `PortSpec::` →
   `ps_`, `IsolationGroup::` → `iso_`).
2. **Enum variants.** Every `pub enum` body compared variant-for-variant
   against its Cyrius constant block. This is the pass most likely to
   catch a quietly dropped case, since a missing variant compiles fine
   on both sides.
3. **Non-source content.** Tests, benchmarks, fuzz targets, examples,
   and build tooling compared by name and by what they exercise.

---

## Result: public functions

**172 Rust public functions. 167 have a Cyrius counterpart. 5 are
intentionally absent.**

Of the 13 that did not map on the first pass, 8 were real gaps (all
closed at 1.6.7 — see below) and 5 are deliberate drops.

### Intentionally absent

| Rust item | Why |
|---|---|
| `config::from_toml` | Full TOML struct parsing deferred to sutra's port. `config.cyr` ships the string→enum dispatch layer and says so in its header; README lists it under **Deferred**. |
| `config::to_toml` | Same. |
| `netns::apply_to_namespace` | Took an `agnosys::netns::NetNamespaceHandle`. agnosys was dropped at the agnosys → agnodrm decomposition (2026-06-19); consumers vendor `netns_apply_nftables_ruleset` instead. See [`dependencies.md`](dependencies.md). |
| `netns::NamespaceFirewall::for_agent` | Took an `agnosys::netns::NetNamespaceConfig`. `namespace_firewall_new(agent_name)` is the surviving constructor. |
| `mcp::build_allow_rule` / `build_deny_rule` / `tool_descriptors` | The MCP surface was deliberately redesigned at 1.6.0 into six flat-arg tools (`nein_status`, `nein_allow`, `nein_deny`, `nein_validate`, `nein_list`, `nein_diff`) registered via `nein_tools_register`. Rationale in the v1.6.0 CHANGELOG entry. |

---

## Result: enum variants

**Exact parity on all 22 public enums.** No variant was dropped anywhere.

| Enum | Rust | Cyrius | | Enum | Rust | Cyrius |
|---|---|---|---|---|---|---|
| `Match` | 30 | 30 | | `SetType` | 5 | 5 |
| `Verdict` | 13 | 13 | | `RateUnit` | 4 | 4 |
| `LogLevel` | 8 | 8 | | `QuotaUnit` | 4 | 4 |
| `NeinError` | 7 | 7 (+6 signing) | | `Protocol` | 4 | 4 |
| `Family` | 6 | 6 | | `PktType` | 3 | 3 |
| `Hook` | 6 | 6 | | `SetFlag` | 3 | 3 |
| `RejectReason` | 6 | 6 | | `MapVerdict` | 3 | 3 |
| `Ipv6ExtHdr` | 6 | 6 | | `ChainType` | 3 | 3 |
| `CmpOp` | 6 | 6 | | `Transport` | 3 | 3 |
| `NatRule` | 5 | 5 | | `Policy` / `QuotaMode` / `PolicyAction` / `ChainRule` | 2 each | 2 each |

`NeinError`'s three colliding bare tokens were renamed
(`ERR_PERMISSION_DENIED` / `ERR_PARSE` / `ERR_IO` → `NEIN_ERR_*`) to
dodge symbol collisions with sibling AGNOS enums; numeric values are
unchanged, so `nein_err_code()`'s contract holds.

---

## Gaps found, and what was done (v1.6.7)

### P0 — `dry_run` was write-only *(shipped bug, not a port gap)*

`firewall_set_dry_run()` / `firewall_dry_run()` existed and were tested,
but **nothing read the flag**. `apply_firewall` validated, rendered, and
applied unconditionally; `nein_diff` did the same. Rust's
`Firewall::apply` and `Firewall::flush` both short-circuited on it.

A consumer setting dry-run and calling apply **wrote rules to the live
firewall**, while the API's shape promised the opposite. The port lost
the behavior silently because Rust's `dry_run_does_not_apply` integration
test had no Cyrius equivalent.

**Fixed.** Both apply paths now check the flag with `!= 0` (fail-safe:
any non-zero value skips the apply). Dry-run still validates and renders,
so a caller gets the same errors a real apply would raise. `nein_diff`
returns the ops it *would* have applied. Covered by
`test_dry_run_does_not_apply` and `test_dry_run_still_validates` in
`tests/integration/apply_smoke.tcyr` — the discriminating assertion is
that on a non-permissive host a real apply returns `Err` while a dry-run
apply returns `Ok`, which is only possible if nft was never spawned.

### P1 — `Firewall::deduplicate`

No counterpart existed. **Added** as `firewall_deduplicate(fw)`,
returning the number of rules removed. Duplicates are detected by
comparing *rendered* text rather than fields — a stronger test that also
catches rules assembled by different code paths into the same line.

Only **consecutive** duplicates collapse, matching Rust's `Vec::dedup`.
That is deliberate: a non-terminal rule (`counter`, bare `log`) appearing
twice with other rules between them is counted twice on purpose, and
collapsing across a gap would silently change packet accounting.

### P1 — `Rule::matching_ports` / `matching_addrs` / `matching_addrs6`

The anonymous-set builders (`tcp dport { 80, 443 }`,
`ip saddr { a, b }`) had no counterpart. The only remaining path was
hand-building `match_raw` — which is the *unvalidated* escape hatch
(ADR-0004), so the ergonomic path was gone and the surviving one was the
hazardous one.

**Added** as `rule_matching_ports` / `rule_matching_addrs` /
`rule_matching_addrs6`, each taking a Vec and returning a packed Result.

**Deliberate deviation from Rust:** `Rule::matching_addrs` filtered
invalid addresses out and logged a warning, keeping the rest. For a deny
rule that fails **open** — the dropped address stops being denied and
nothing in the return value says so. The Cyrius versions return
`Err(NEIN_ERR_INVALID_RULE)` on the first bad element and leave the rule
**unmodified**: all inputs are checked before any match is pushed, so a
rejected call cannot leave a half-built rule behind.

### P1 — `apply::find_rules_by_comment` / `parse_rules_with_handles`

Comment-keyed live-rule lookup — "find every rule I created for agent X"
— had no counterpart. `diff.cyr` parsed handles, but only keyed on rule
*body*, so nothing could produce the handle that `add_rule_after_live` /
`delete_rule_live` require from a comment.

**Added** `parse_rules_with_handles(raw, prefix)` (pure, testable against
captured nft output without root) and `find_rules_by_comment(family,
table, prefix)` in `diff.cyr`, plus `list_table_with_handles(family,
table)` in `apply.cyr` for the scoped `nft -a list table` call. The
needle is `comment "PREFIX` — the opening quote is part of it, so a
prefix cannot match inside another rule's operand text.

### P2 — `PolicyEngine::agent_ids`

Reconstructible from `pe_agents` + `ap_agent_id`, but **added** as
`pe_agent_ids(pe)` for parity.

### P2 — Scale benchmarks

The Cyrius suite (31 benches) was not a superset of Rust's (33). It added
validator micro-benches but dropped **every scale benchmark** — exactly
the ones that catch algorithmic regressions, which `bench-regression.sh`
then could not gate on.

**Ported at 1.6.7**, bringing the suite to 43: `firewall_1000_rules_render`
/ `_validate`, `engine_100_agents_render` / `_validate`,
`set_1000_elements_render`, `table_20_defines_render`, plus
`deep_protocol_render` / `_validate`, `flowtable_render`,
`ct_timeout_render`, `quota_rule_render`, `nat_range_render`. Fixtures are
built once before timing starts, matching the criterion originals.

> **Correction (1.6.8).** The 1.6.7 version of this section — and the
> v1.6.7 CHANGELOG entry — claimed the port had covered *every* scale
> benchmark. It had not. A name-by-name diff at 1.6.8 found six still
> unported:
>
> - **`bridge_large_render` / `bridge_large_to_firewall`** — a genuine
>   scale fixture (50 port mappings + 5 isolation groups). The Cyrius
>   `bridge_render` used the *small* fixture, so the bridge path had no
>   scale coverage at all.
> - **`engine_100_agents_to_firewall`, `geoip_10_countries_to_firewall`,
>   `mesh_to_firewall`** — the `*_to_firewall` conversion family, which
>   times the *build* step apart from the render. An O(n²) assembly bug
>   hides behind a linear render if only the render is measured.
>
> All six were ported at 1.6.8, taking the suite to **48**. Every one of
> the 33 Rust benchmarks now maps to a Cyrius counterpart, directly or
> through a documented rename, with the single exception below.

`toml_parse_small` is not ported — there is no TOML parser to measure.

### P2 — Example coverage

Rust shipped four `examples/*.rs`. `host_firewall` and `policy_engine`
already had README equivalents; `container_bridge` was only partially
covered (raw NAT helpers, not `BridgeFirewall` + isolation groups) and
`geoip_blocklist` had none. All four APIs were already well covered by
unit tests, so this was documentation loss, not capability loss.
**README gained** container-bridge, GeoIP, anonymous-set, and dry-run
sections at 1.6.7.

---

## Non-source content

| Rust artifact | Disposition |
|---|---|
| `tests/integration.rs` (7 tests) | Covered by `tests/integration/*.tcyr`, now 8 tests. `dry_run_does_not_apply` was the notable miss — restored at 1.6.7. The Cyrius side adds path-pinning and bundle-consume tests Rust never had. |
| `fuzz/fuzz_targets/` (3) | Superset: 5 `fuzz/*.fcyr` drivers. `fuzz_toml_config` is N/A. |
| `benches/benchmarks.rs` (33) | 48 Cyrius benches as of 1.6.8. Full name-for-name parity except `toml_parse_small` (see the 1.6.8 correction above). |
| `examples/` (4) | README sections (see above). |
| `Cargo.toml` | Package metadata (name, keywords, categories, `[features]`, dependency list) — superseded by `cyrius.cyml`. The `[features]` map is the one part with a live counterpart: it became the `#ifdef` module gating described in CLAUDE.md, and every feature listed (`nat` `policy` `inspect` `apply` `builder` `bridge` `engine` `mesh` `mcp` `config` `geoip` `netns`) has a module of the same name in `src/lib/`. Not covered by the v1.6.7 table — added at 1.6.8. |
| `Makefile` | Superseded by `cyrius` subcommands + CI. |
| `rust-toolchain.toml` | Superseded by the `[package].cyrius` pin. |
| `deny.toml` (cargo-deny) | **Lifted at 1.6.8** into [`scripts/supply-chain.sh`](../../scripts/supply-chain.sh) + [`supply-chain-policy.md`](supply-chain-policy.md), wired as a CI gate. Not into `cyrius deny`, which despite the name is an include-path checker with no allow-list. |
| `codecov.yml` (80% target) | Partly superseded — see **Unenforced** below. |
| `supply-chain/` (cargo-vet) | N/A. The audited crates are not dependencies any more; dep integrity is `cyrius.lock` + `cyrius deps --verify`. |
| `benchmarks/` (975 criterion files) | Rust-era archive, moved under `rust-old/` at 1.6.5. Nothing reads it. |

### Unenforced quality gates

Not a port gap — a CI gap the port surfaced. The Rust `Makefile` ran
`cargo deny`, `cargo vet`, and an 80% coverage gate. At 1.6.8 two of the
four Cyrius-side equivalents were wired (`scripts/supply-chain.sh` and
`cyrius deny`); `cyrius coverage --min` and `cyrius doc --check` remain,
and CLAUDE.md still states an 80% coverage target that nothing enforces.
Tracked at the top of [`roadmap.md`](roadmap.md).

---

## Verdict — acted on at v1.6.8

`rust-old/` held nothing that was not either in the Cyrius tree,
intentionally dropped with a documented reason, or preserved in git
history. It was deleted at **v1.6.8**, along with `.cargo/config.toml` —
a tracked, dead Cargo `[patch]` for `agnosys` (dropped at the
agnosys → agnodrm decomposition) that sat *outside* `rust-old/` and
would otherwise have survived the removal. Its own comment claimed it
was gitignored; it was not.

1,014 files left the working tree. Every one is recoverable via
`git show <rev>:rust-old/...` at any commit through the v1.6.7 tag.

Two things were lifted out of the tree first, rather than lost with it:

- **`deny.toml`'s supply-chain policy** → `scripts/supply-chain.sh` +
  [`supply-chain-policy.md`](supply-chain-policy.md), now a CI gate.
- **Six unported benchmarks** → `tests/nein.bcyr` (see the 1.6.8
  correction above), taking the suite to 48.
