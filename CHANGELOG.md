# Changelog

All notable changes to nein are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/).

## [1.6.4] — 2026-07-17

**Banks the upstream bare-error-enum repairs.** bote and libro both
namespaced the `ERR_*` enums that shared bare tokens, so nein's last two
benign duplicate-symbol warnings (`ERR_JSON` / `ERR_IO`, libro↔bote-core) are
now fixed *at the source on both sides* rather than merely avoided by include
order. No nein source or API change (383 public fns); the only warning left in
a clean build is majra's long-documented `_sub_new` last-wins dup. 664 unit +
16 integration assertions, 31 benches (no regressions), 5 fuzz drivers green;
`cyrius deps --verify` clean.

### Changed

- **bote `3.1.2` → `3.1.4`.** 3.1.3 namespaced `BoteErrTag` `ERR_* →
  BOTE_ERR_*` (13 tags); 3.1.4 bumped bote's own `[deps.libro]` to 2.8.2 and
  realigned its tag↔lock. Same cyrius 6.4.66 pin, identical wire contract —
  numeric error values and JSON-RPC code mapping unchanged, so nein's consumed
  `jsonx` / dispatcher / `ToolAnnotations` surface needs no edits.
- **libro `2.8.1` → `2.8.2`.** Namespaced `LibroErr` `ERR_* → LIBRO_ERR_*`
  (13 constants, `LIBRO_ERR_IO=3` …) and moved its internal deps to sigil
  3.12.1 / patra 1.12.12 under the 6.4.66 pin — matching nein's own top-level
  `[deps.sigil]` / `[deps.patra]` pins, so nothing else in nein's dep set
  shifts (majra 2.5.1, sigil 3.12.1, patra 1.12.12, sakshi 2.4.6 unchanged).
- **`dist/nein.cyr` + `dist/nein-mcp.cyr` regenerated at 1.6.4** (version banner
  only; `[lib]` bodies and the `.deps` sidecars are unchanged).

## [1.6.3] — 2026-07-17

**Toolchain 6.4.66 + full dependency refresh.** No nein source or API change
(383 public fns unchanged) — the release moves every pin to its current tag,
clears the manifest-pin drift, and (the one structural change) reworks how
nein resolves sigil so libro 2.8.x's thinned sigil surface stops colliding
with the full bundle. 664 unit + 16 integration assertions, 31 benches (no
regressions), and 5 fuzz drivers stay green; `cyrius deps --verify` clean
(56 files).

### Changed

- **cyrius pin `6.3.45` → `6.4.66`.** Clears the "manifest-pin: 6.3.45 (drift
  — wrapper is 6.4.66)" warning. The 6.4.x line makes `cyrius lib sync`
  default to the declared `[deps].stdlib` subset (`--full` for the whole
  snapshot), adds a lib-freshness shadow check (6.4.63) that surfaces
  registry-lag, and re-subsets per-profile distlib `.deps` sidecars. nein's
  build, type-check, and aarch64 cross-build all pass clean under the new pin.
- **Dependency refresh — every git dep to its latest tag:**
  - **libro `2.7.10` → `2.8.1`** — banks the `patrastore_append` bound-INSERT
    fix (a `'` in an audit field no longer silently drops the row). 2.8.0 also
    *thinned* libro's sigil surface into per-primitive sub-bundles, which
    forced the sigil rework below.
  - **majra `2.5.0` → `2.5.1`** — dist body byte-identical (banner restamp);
    toolchain/dep refresh only.
  - **bote `3.0.0` → `3.1.2`** — no bote logic change, a toolchain + dependency
    refresh. nein's consumed `jsonx` / dispatcher / `ToolAnnotations` surface
    is unchanged, so `src/lib/mcp.cyr` needed no edits.
  - **sigil `3.9.8` → `3.12.1`** — banks 3.9.9's crypto-bank thread-local slot
    fix (slot 0 → 8): slot 0 collided with patra's SQL scratch, corrupting
    banked crypto state in any process that links *both* — which nein does
    (patra via libro's audit store + sigil via `src/lib/sign.cyr`). Defense in
    depth for the 1.6.1 Ed25519 signing path.
  - **patra `1.12.7` → `1.12.12`** — banks the SQL-quote escaping fix; matches
    the 6.4.66 snapshot so no shadow-lib warning fires.
  - **sakshi `2.4.3` → `2.4.6`** — arrives via bote's pin; custom headers +
    W3C 128-bit trace-id.
- **sigil moved from `[deps]` stdlib to an explicit `[deps.sigil]` full-bundle
  pin** (`dist/sigil.cyr` @ 3.12.1), mirroring bote 3.1.2. libro 2.8.x's `.deps`
  sidecar now vendors thin sigil sub-bundles (`sigil-mldsa` + `sha_ni` +
  `sha256` + `hex`) transitively; layered under the full stdlib sigil bundle
  they redefined every sha/hex/ed25519 fn (**226 duplicate-fn last-wins
  warnings**). The top-level pin wins over the transitive thin bundles and
  reaches the latest self-contained bundle (the stdlib registry lags). nein's
  whole sigil surface is `sign.cyr`'s ed25519 + sha256 + hex; bote-core uses no
  sigil crypto. An explicit `[deps.patra]` pin was added for the same reason —
  keep the transitive audit dep current and snapshot-matched. The build is now
  clean but for three pre-existing, benign upstream "last-definition-wins"
  warnings (libro↔bote-core `ERR_JSON`/`ERR_IO`, majra `_sub_new`).
- **`dist/nein.cyr` + `dist/nein-mcp.cyr` regenerated at 1.6.3** (version banner
  only — the `[lib]` module bodies are unchanged).

## [1.6.2] — 2026-07-04

**nein's half of the daimon firewall-MCP joint ship:** a consumable bundle
+ a host-friendly dispatch adapter so a host (daimon) can mount nein's
firewall tools. The daimon-side PR (`[deps.nein]` + registration + gate
wiring to daimon's agent identity) lands separately in daimon's repo.

### Added

- **`[lib.mcp]` bundle profile → `dist/nein-mcp.cyr`.** `cyrius distlib mcp`
  emits nein's core + `sign` + `mcp` as one bundle for hosts that want the
  firewall + signing surface. It leaves bote (`jsonx` / dispatcher /
  annotations) and sigil (`ed25519` / `hex` / `sha256`) symbols unresolved —
  the consumer supplies them (per `dist/nein-mcp.deps`: `thread`,
  `thread_local`, `sigil`, `bote-core`), exactly as bote's `[lib.core]`
  leaves its stdlib. The default `dist/nein.cyr` stays bote/sigil-free.
- **Daimon-friendly dispatch adapter (`src/lib/mcp.cyr`).** For hosts that
  route MCP calls by name (daimon's `mcp_dispatch_builtin` model) instead of
  a bote `Dispatcher`: `nein_mcp_dispatch(name, args, claims)` routes to the
  right handler (or an "unknown tool" envelope); `nein_mcp_set_gate(gate_fp)`
  installs the access-control gate without a dispatcher. A single-source
  tool table — `nein_tool_count` / `nein_tool_name` / `nein_tool_desc` /
  `nein_tool_read_only` / `nein_tool_admin` — drives both this path and the
  bote-`Dispatcher` `nein_tools_register` path, so names/descriptions/
  classification never drift. Public fn surface 376 → 383.
- **Integration guide** ([`docs/guides/mcp-host-integration.md`](docs/guides/mcp-host-integration.md))
  and a **bundle-consumability guard** (`tests/integration/mcp_consume_smoke.tcyr`,
  10 assertions) that supplies bote+sigil, consumes `dist/nein-mcp.cyr`, and
  drives the tools + signing through it — failing CI if the `[lib.mcp]`
  bundle drifts. CI dist-staleness now checks both `dist/nein.cyr` and
  `dist/nein-mcp.cyr`. Unit suite **652 → 664**.

## [1.6.1] — 2026-07-04

**Signed rulesets + daimon MCP setup, and a real git-dep migration.**

### Added

- **`src/lib/sign.cyr` — Ed25519-signed rulesets.** A stored ruleset can
  carry an Ed25519 signature (via [sigil](https://github.com/MacCracken/sigil))
  so a verifier (aegis) detects at-rest tampering before applying. The
  signed message is the rendered nft **body bytes only** — render once, sign
  the bytes, apply the same bytes; the envelope's carried pubkey is never the
  trust root (verification uses the caller-supplied key and rejects a
  mismatch). API: `sign_ruleset(fw, sk, keyid)` / `sign_ruleset_body`,
  `verify_ruleset(signed, pubkey)` / `_hex`, `parse_signed_ruleset` +
  accessors, `apply_signed_ruleset(signed, pubkey)` / `_hex` (fail-closed —
  verify or never touch nft), `sign_keygen`. `.nftsig` envelope: `nein-sig:`
  header block (alg, keyid, pubkey, sha256 digest, sig) + verbatim body.
  6 additive `NEIN_ERR_SIG_*` codes (8–13; values 1–7 unchanged). 18 tests:
  round-trip, wrong-key mismatch, **tamper → bad-signature**, fail-closed apply.
- **daimon MCP setup (`src/lib/mcp.cyr`).** All 6 tools now carry bote
  `ToolAnnotations` (read-only vs destructive) and profile tags
  (`firewall` / `firewall_admin`) so a host filters/gates them by
  side-effect. `nein_tools_register_gated(dispatcher, gate_fp)` adds a host
  access-control seam — `fn(tool_name, claims) -> 1 permit / 0 deny`
  consulted by every handler (fail-closed, claims-ready but not
  claims-dependent, since bote's `claims` is a reserved 0 today). Public
  `nein_mcp_ok` / `nein_mcp_err` envelope helpers for daimon to reuse.
  10 tests. Public fn surface 361 → 376.

### Changed

- **Dep model: retired vendoring, adopted git deps** (matches daimon). bote
  MCP core + sigil are now `[deps.*]` git bundles, not vendored files —
  `src/vendor/` removed. The 1.6.0 "resolver bug" was a wrong diagnosis:
  Cyrius does **not** auto-resolve deps (supply-chain safety — you declare
  every module). The build sequence is explicit: `cyrius lib sync` copies the
  declared `[deps] stdlib` subset from the pinned snapshot into `./lib/`,
  **then** `cyrius deps` clones the git bundles. Added `[deps.libro]` /
  `[deps.majra]` / `[deps.bote]` (dist/bote-core.cyr) and the transitive
  stdlib the graph needs (`ct, keccak, random, slice, thread, thread_local,
  sync, atomic, result`, + `sigil`) — the minimal transport-free set, no
  `ws_server` / `tls` / `sandhi`. CI gained a `cyrius lib sync`
  step before `cyrius deps`; new `cyrius.lock` pins the git-dep hashes. `vet`
  is clean (0 untrusted — git-dep bundles are trusted). `sign.cyr` and
  `mcp.cyr` stay out of `[lib]`, so `dist/nein.cyr` remains self-contained.
  Suite **624 → 652**.

## [1.6.0] — 2026-07-03

**MCP surface — nein tools over bote's core.** A new `mcp` module exposes
nein's firewall operations as Model Context Protocol tools so an agent host
can drive nein through [bote](https://github.com/MacCracken/bote)'s
Dispatcher / ToolRegistry. nein owns no transport: the consuming binary
builds the dispatcher + a transport, then calls `nein_tools_register(d)`.

### Added

- **`src/lib/mcp.cyr` — 6 MCP tools.** `nein_status` (table/rule summary),
  `nein_allow` / `nein_deny` (add an accept/drop rule to the live ruleset),
  `nein_validate` (validate a port-rule request without applying),
  `nein_list` (live rules, optionally filtered by table/chain, as JSON),
  and `nein_diff` (preview the nft ops to converge the live ruleset onto a
  target rule set — no apply). Handlers follow bote's 2.0 ABI
  (`fn(args, claims) -> result_cstr`), read args with `jsonx_*`, and return
  injection-safe `{"content":[...],"isError":bool}` envelopes — every
  string field runs through `validate_identifier` / `validate_addr` and
  JSON escaping (`_json_emit_escaped`). `nein_tools_register(dispatcher)`
  mounts all six. 23 new assertions (`test_mcp`): envelope shape, every
  `nein_validate` decision path incl. injection rejection, `nein_diff`
  array parsing, and registration. Suite **601 → 624**.
- **Vendored bote-core bundle** at `src/vendor/bote-core.cyr` (bote 3.0.0,
  transport-free core profile) + `bayan` added to `[deps] stdlib`.

### Changed

- bote is **vendored**, not wired as a `[deps.bote]` git dep. `cyrius deps`
  recursively resolves bote's manifest git-deps (libro / majra / patra /
  sigil) for a self-contained core-bundle consumer instead of honoring the
  bundle's `.deps` sidecar (`hashmap` + `bayan`); that resolution fails
  (`dep libro requires 'ct' … not in the cyrius stdlib`) and blocks the
  build. Vendoring the self-contained bundle sidesteps it. See
  `src/vendor/README.md`; filed upstream on bote's roadmap. Restore the git dep
  once fixed. `src/lib/mcp.cyr` is intentionally **not** in `[lib]`, so the
  `dist/nein.cyr` consumer bundle stays self-contained (bote-free).

### Breaking

- **`NeinError::ERR_PARSE` renamed to `NEIN_ERR_PARSE`** (numeric value
  unchanged: **6**). bote's `BoteErrTag` defines a bare `ERR_PARSE` (=4);
  under Cyrius single-pass include the later definition would clobber
  nein's value ("last definition wins"). The `NEIN_ERR_` prefix — as with
  `NEIN_ERR_PERMISSION_DENIED` / `NEIN_ERR_IO` at 1.5.3 — keeps nein's value
  fixed and the `nein_err_code()` contract intact.
  **Migration:** replace `ERR_PARSE` with `NEIN_ERR_PARSE`. The code value
  (6) returned by `nein_err_code()` is unchanged, so any consumer keying on
  the number needs no change.

## [1.5.5] — 2026-07-03

Toolchain bump and a block-stack buffer fix in the ruleset parsers.
nein carries no git dependencies since the agnosys drop in 1.5.4, so
the `[deps] stdlib` snapshot rides the compiler pin — updating the
pin updates the dependency surface.

### Security

- **Out-of-bounds stack write in the live-ruleset parsers.**
  `diff_parse_live` (`src/lib/diff.cyr`) and `_parse_ruleset`
  (`src/lib/inspect.cyr`) declared their block-nesting stack as
  `var …_stack[16]` — 16 **bytes**, i.e. 2 i64 slots — but index it
  as `&stack + bs_depth * 8` with `bs_depth` guarded `< 15`, i.e. a
  16-**slot** (128-byte) stack. Any nested ruleset (`table → chain`,
  depth ≥ 2 — the shape of all real `nft list ruleset` output) wrote
  a `BLOCK_*` enum value one slot past the buffer, over an adjacent
  stack variable. In `diff_parse_live` the clobbered slot was the
  `current_chain` cstring pointer, so every parsed rule got a bogus
  chain pointer (`BLOCK_CHAIN` = 2) and a later `streq` dereferenced
  address `2` → SIGSEGV. In `_parse_ruleset` the corruption was
  silent (only an integer rule count is returned). Impact was
  stack-layout-dependent — latent since the diff module shipped
  (1.5.0). Fix: size both buffers to `[128]` (16 i64 slots).

### Changed

- `cyrius.cyml`: `cyrius = "6.2.11"` → `cyrius = "6.3.45"` (latest).
- `dist/nein.cyr`: regenerated with `cyrius distlib` against the
  6.3.45 stdlib snapshot.

## [1.5.4] — 2026-06-19

**Dropped `[deps.agnosys]` (agnosys → agnodrm decomposition).** nein's *source*
never called an agnosys symbol — `src/lib/error.cyr` defines its own `NeinError`
enum (the permission/io members deliberately prefixed `NEIN_ERR_*` to avoid the
agnosys-core `ERR_PERMISSION_DENIED` / `ERR_IO` collision), and the netns
apply-side is invoked by the integrator against the kernel-interface lib directly
(`src/lib/netns.cyr`). The only agnosys touch was the **test suite**, which
referenced agnosys-core's bare `ERR_PERMISSION_DENIED` / `ERR_IO` for its
nonzero/distinctness checks — repointed those to nein's own `NEIN_ERR_*` (enum
values + `nein_err_code()` contract unchanged). Its local `path = "../agnosys"`
also broke when the repo folder was renamed to `../agnodrm`. Removed the dep +
its stale `cyrius.lock` (nein now has no git deps). Verified: `cyrius deps` +
build clean, `tests/nein.tcyr` **601/0**, `apply_smoke` **6/0**.

## [1.5.3] — 2026-06-15

Toolchain bump. Cyrius compiler `6.1.24` → `6.2.11`; `agnosys`
dependency `1.4.1` → `1.4.3`.

### Changed

- `cyrius.cyml`: `cyrius = "6.2.11"`, `agnosys.tag = "1.4.3"`.
- `cyrius.cyml`: dropped `json` / `toml` from `[deps] stdlib` — the
  6.2.11 stdlib snapshot no longer ships those modules, and nein never
  used them (config.cyr does its own value parsing). They were dead
  deps that broke `cyrius deps` on a clean install.

### Fixed

- `error.cyr`: renamed `ERR_PERMISSION_DENIED` → `NEIN_ERR_PERMISSION_DENIED`
  and `ERR_IO` → `NEIN_ERR_IO` (numeric values unchanged: 5 and 7).
  agnosys 1.4.3's `SysError` enum now defines `ERR_PERMISSION_DENIED`
  and `ERR_IO`, colliding with `NeinError`. The duplicate symbols
  failed the type-check CI gate and were a latent "last definition
  wins" bug (include order decided the resolved value). The
  consumer-facing `nein_err_code()` contract is unchanged.

## [1.5.2] — 2026-06-10

Toolchain bump. Cyrius compiler `5.10.44` → `6.1.24`; `agnosys`
dependency `1.2.5` → `1.4.1`. No source changes.

### Changed

- `cyrius.cyml`: `cyrius = "6.1.24"`, `agnosys.tag = "1.4.1"`.
- CI/release toolchain install migrated to the upstream
  `scripts/install.sh` installer (keyed on the `cyrius.cyml` pin),
  replacing the pre-6.x hand-rolled tarball extraction that copied
  `bin/cc5` — renamed to `cycc` in the 6.x toolchain. Matches the
  patra / bote / agnosys 6.x convention.
- CI aarch64 cross-build now probes `cycc_aarch64` (was the stale
  `cc5_aarch64`, which 6.x renamed — the step had been silently
  skipping).

## [1.5.1] — 2026-05-11

Toolchain bump. Cyrius compiler `5.10.34` → `5.10.44`; `agnosys`
dependency `1.2.4` → `1.2.5`. No source changes.

### Changed

- `cyrius.cyml`: `cyrius = "5.10.44"`, `agnosys.tag = "1.2.5"`.

## [1.5.0] — 2026-05-10

Live-rule diff + idempotent apply. New `src/lib/diff.cyr` module
computes the minimal nft operations to converge a live ruleset onto a
target firewall plan, and applies them atomically via a single
`nft -f -` invocation. 601/601 tests pass (was 585 — 16 new diff
assertions); api-surface grew by 10 fns.

### Added

- **`src/lib/diff.cyr`** — new module. Public API:
  - **`diff_parse_live(raw_str: Str): i64`** — parses `nft list ruleset -a`
    output into a Vec of `LiveRule` tuples `(family, table, chain, body,
    handle)`. Reuses the v1.4.0 `_classify_block_open` + block-nesting
    tracker. Strips `# handle N` suffix from rule bodies.
  - **`diff_target_rules(fw: i64): i64`** — walks a `Firewall` and
    yields the same Vec shape (handle=0, body comes from `rule_render`
    converted to cstring).
  - **`diff_compute(target_fw: i64, live_raw: Str): i64`** — symmetric
    diff by (family, table, chain, body) byte-equality. Returns
    `Vec<cstring>` of nft commands (`add rule …\n` for target-not-in-live,
    `delete rule … handle N\n` for live-not-in-target).
  - **`diff_apply(ops: i64): i64`** — concatenates the op vec into a
    single `nft -f -` invocation (atomic per kernel semantics).
  - **`nein_diff(target_fw: i64): i64`** — convenience: list_ruleset +
    diff_compute + diff_apply; returns `Ok(applied_ops_vec)` or `Err`.
  - **`LiveRule` accessors**: `live_rule_family` / `live_rule_table` /
    `live_rule_chain` / `live_rule_body` / `live_rule_handle`.
- **16 new test assertions** in `tests/nein.tcyr` covering: handle
  extraction, family/table/chain/body fields, empty-diff on identical
  inputs, add-op generation for target-only rules, delete-op
  generation for live-only rules, all-deletes on empty target,
  `_strip_handle_suffix` edge cases.
- **`dist/nein.cyr`** now bundles diff.cyr; api-surface snapshot grew
  to 360 fns (+10 from diff module).

### Changed

- Conservative-match design: byte-equality on rule bodies. Drift in
  whitespace or operand ordering produces a delete+add pair instead
  of a no-op — verbose but always correct (nft accepts duplicates,
  rejects invalid deletes; both surface as `ERR_NFT_FAILED`).
- Threat model + capability-map + README + doc-health refreshed for
  diff module + v1.5.0 baseline.

### Deferred (with rationale)

- **Doctest pass** — `cyrius doctest` returns "0 passed, 0 failed
  (0 total doc tests)" on any input format we tried (`///` Rust-style,
  `# Example:` cyrius-stdlib style). The tool exists but the
  convention isn't documented or implemented. Tracked upstream;
  re-evaluate when cyrius docs publish the doctest format.
- **Packed Result on hot paths** — re-measured: validators run
  ~500ns–1µs, dominated by string scanning, not the 16-byte
  Result alloc. Eliminating the alloc saves ~100-200ns at most,
  not enough to justify breaking every `is_err_result` /
  `payload` caller across 18 modules and 350+ public fns.
  Permanently parked unless a future hot path emerges (sutra's
  bulk apply playbooks might surface one).
- **Block creation in diff** — v1.5.0 emits add/delete rule
  operations only; table/chain create/delete is not computed.
  Tables and chains are assumed pre-existing with the right
  shapes. Future revision can extend if a consumer needs full
  schema reconciliation.

## [1.4.0] — 2026-05-10

Apply-layer hardening minor. Closes threat-model T-3 (PATH-injection
race), hardens the inspect parser against real-shape `nft list ruleset`
output, scaffolds an integration test harness for the apply path.
585/585 tests pass (was 580 — 5 new parser tests); api-surface grew
by 2 fns (`nein_nft_path`, `nein_set_nft_path`).

### Added

- **`nein_set_nft_path(path: cstring): i64`** — runtime override for the
  `nft` binary path. Validates absolute (must start with `/`), length
  (≤ 256 bytes), non-null. Default `/usr/sbin/nft`; override on systems
  with nft elsewhere (Alpine, Void, embedded).
- **`nein_nft_path(): cstring`** — read-back accessor.
- **`tests/integration/apply_smoke.tcyr`** — apply-layer integration
  scaffold. 6 assertions covering: default path value, valid override,
  relative-path rejection, null-path rejection, apply outcome
  classification (Ok / ERR_PERMISSION_DENIED / ERR_NFT_FAILED — all
  three are valid on different host policy), `_parse_ruleset` against
  representative real-shape nft output with handle annotations.
  Designed to run anywhere; live-apply assertions fall through the
  permission-denied class on non-permissive hosts.
- **CI `Integration tests` step** — runs `cyrius test tests/integration/*.tcyr`
  unconditionally; the test classifier handles whether root + nft are
  available. To exercise the live-apply path explicitly, set
  `NEIN_INTEGRATION=1` and wrap with `sudo unshare -n` to isolate in a
  fresh netns.

### Changed

- **Threat model T-3 closed at the multi-path-race level.** The pre-v1.4.0
  `/usr/sbin/nft` → `/sbin/nft` → `/usr/bin/nft` fallback chain (a soft
  form of PATH consultation) replaced with a **single pinned absolute
  path**. An attacker who could plant a binary at `/usr/sbin/nft` no
  longer wins the race against a separately-installed nft at
  `/sbin/nft` — the operator chooses which path to trust.
- **`_parse_ruleset` block-nesting tracker.** The inspect-layer rule
  counter now tracks `{`/`}` nesting and the block kind at each level.
  Lines inside `set` / `map` / `flowtable` / `ct timeout` blocks are
  NOT counted as rules (previously `flags interval;` / `elements = …;` /
  `devices = …;` all spuriously incremented the count). New
  `_classify_block_open` helper. Comment / handle-annotation lines
  (`# handle N`) inside chains are also skipped.
- **Threat model + capability map + README + doc-health** refreshed to
  reflect the v1.4.0 changes. The capability-map's subprocess section
  rewrites from "three paths tried in order" to "single pinned path,
  configurable".

### Deferred (with rationale)

- **`nein diff <target>`** — live-rule diffing was scoped for v1.4.0
  but is a significant new module (parse target plan + parse live
  ruleset + compute minimal add/delete set + render incremental nft
  commands). Roughly 200+ LOC plus a fresh test surface. Defer to
  **v1.5.0** so v1.4.0 ships the hardening + scaffold cleanly.
- **Packed Result on hot paths** — still no measured win on the
  validator bracket. Re-evaluate after live-rule diffing lands (which
  may surface heap-alloc pressure on a hotter path).
- **Doctest pass** — still no `///` comments. Folds into v1.5.0's docs
  pass once the diffing API stabilizes (any new doctest examples want
  the diff surface to be stable first).

## [1.3.0] — 2026-05-10

Validation-depth minor. Fuzz harness expanded from one monolithic file
to five per-target drivers under `fuzz/`. Idiom adoption audited and
documented. 580/580 tests pass on both arches; all five fuzz drivers
exit clean; zero CI gate regressions.

### Added

- **Per-target fuzz drivers under `fuzz/`** (split from
  `tests/nein.fcyr`):
  - `fuzz/validate.fcyr` — 8 validators against ~30 inputs (valid, empty,
    injection-bearing, length-boundary, high-bit bytes, embedded NULs,
    256-byte fills with varied content)
  - `fuzz/config_parse.fcyr` — 16 enum dispatchers against ~50 inputs
    (valid for each closed set + invalid + adversarial + length-boundary)
  - `fuzz/rule.fcyr` — match constructors + `rule_render` +
    `rule_validate` with fuzzed strings in addr/iface/comment/raw/jump
    positions, plus stacked-match composition
  - `fuzz/nat.fcyr` — DNAT/SNAT/masquerade/redirect/DnatRange across
    addr + comment + iface positions, plus the convenience constructors
  - `fuzz/firewall.fcyr` — full firewall composition (table→chain→rule),
    plus PolicyEngine, GeoIP blocklist, BridgeFirewall, and
    NamespaceFirewall flows
- **CI `Fuzz` step** uses `cyrius fuzz` for auto-discovery — adding a
  new `fuzz/*.fcyr` file picks it up automatically; crash attribution
  is by harness name; CI summary line surfaces pass/fail counts.

### Changed

- **CI fmt/lint loops** now scan `fuzz/*.fcyr` instead of
  `tests/*.fcyr`. fmt is gated; lint is gated on `src/` + `fuzz/`,
  informational on `tests/` (test fixtures legitimately have long
  lines).
- **`docs/architecture/overview.md`** — new "Rendering Idioms" section
  documenting `str_builder`-over-manual-buffer and vec-of-pointers
  patterns. Includes the per-module `str_builder_*` call-count audit
  and the three legitimate `var buf[N]` exceptions in apply.cyr +
  rule.cyr.

### Removed

- `tests/nein.fcyr` (monolithic smoke harness) — replaced by the five
  per-target drivers under `fuzz/`.

### Deferred (with rationale)

- **Packed Result on hot paths.** The current `Result` shape is a
  16-byte heap-allocated tagged value (`Ok(v)` / `Err(e)` from stdlib
  `tagged.cyr`). Switching validators to a packed `i64` (high bit =
  err flag, low 63 bits = code) would eliminate the per-call alloc but
  breaks every caller's `is_err_result(res)` / `payload(res)` shape
  (both load through the heap pointer). Without a measured win on the
  validator bench bracket (~1µs today, dominated by string scanning
  not alloc), the migration cost isn't paid for yet. Revisit in v1.4.0
  when the apply-layer integration tests give concrete heap-alloc
  pressure to measure against.
- **Doctest pass.** `cyrius doctest tests/nein.tcyr` runs cleanly
  (`0 passed, 0 failed`) — nein currently ships zero `///` doc-comment
  examples. Adding examples module-by-module is real work and doesn't
  fit v1.3.0's "validation depth" theme. Queued for v1.3.1 if we keep
  patching, otherwise folds into v1.4.0's apply-layer documentation
  pass.

## [1.2.1] — 2026-05-10

Annotation closeout. Type-check coverage extended to every public fn
across all 18 modules. Bundle regenerated; 580/580 tests pass on both
arches; zero type-check warnings; no API surface drift.

### Added

- **Type annotations on the remaining 14 `src/lib/` modules** —
  ~250 fn signatures across chain, table, set, nat, firewall, builder,
  policy, geoip, mesh, bridge, engine, config, netns, inspect. Joins
  the v1.1.2 (validate, error), v1.1.3 (rule, apply) annotation work
  for full coverage. Pattern:
  - `cstring` — names, addresses, interface names, comments, raw
    nftables fragments, set-element strings, country codes
  - `i64` — port numbers, handles, struct/vec pointers (Cyrius
    doesn't distinguish pointer types from integers), enum
    discriminants, flags
  - `Str` — Cyrius value-typed strings (only consumer-facing apply
    fns took this; internally most renders also return `Str`, now
    annotated)
- `nat_dnat_range` signature wrapped to fit the 120-char lint limit
  (only line that needed splitting after annotation expansion)

### Verified

- All 14 modules build clean with `CYRIUS_TYPE_CHECK=1` (zero
  nein-side warnings, filtered against stdlib self-flags and the
  known-tracked `large static data` warning)
- aarch64 cross-build OK
- API-surface snapshot unchanged: 348 public fns, same names + arities
  (annotations don't change either)
- Bench-regression gate: 0 regressions vs v1.1.2 baseline
- `dist/nein.cyr` regenerated (4564 lines; +2 from the wrapped
  signature)

## [1.2.0] — 2026-05-10

First feature minor since the port. Adds the consumer-bundle shape,
the audit-trail story, and the capability map — all patterns the
broader AGNOS ecosystem stabilized on between agnosys 1.0.0 and
1.2.x. 580/580 tests pass; zero nein-side type-check warnings;
binary unchanged on x86_64 (635 KB DCE).

### Added

- **`dist/nein.cyr` bundle.** New `[lib]` section in `cyrius.cyml`
  declares the 18 modules; `cyrius distlib` writes the single-file
  4621-line / 147 KB bundle to `dist/nein.cyr`. Consumers
  (stiva, daimon, aegis, sutra) pull this one file via
  `[deps.nein] modules = ["dist/nein.cyr"]` instead of vendoring
  individual files. CI gate (`Verify dist bundle is in sync`)
  rebuilds + diffs to ensure the committed bundle matches the
  source tree on every PR.
- **Sakshi tracing on `apply.cyr`.** `_run_nft_stdin` and
  `_run_nft_capture` both wrap their fork/pipe/execve sequence
  in a `sakshi_span_enter` / `sakshi_span_exit` pair. Per-step
  failures emit `sakshi_error`; nft exit=0 emits `sakshi_info`;
  nft exit nonzero emits `sakshi_warn`. exit=127 (no executable
  found at any of the three allowlisted nft paths) gets its own
  error message so the operator can distinguish "no nft installed"
  from a real rule-application failure. Audit-trail coverage on
  apply is now end-to-end; CLAUDE.md mandate honored.
- **`docs/development/capability-map.md`** — per-module footprint
  for syscalls, `sys_*` wrappers, subprocess binaries, and
  hard-coded fs paths. Two reading lenses for sandbox-policy
  authors: "rendering-only callers" (zero syscall surface) and
  "apply-layer callers" (9 `sys_*` wrappers, 3 nft paths,
  `CAP_NET_ADMIN`). Pattern lifted from agnosys 1.2.x.
- **`cyrius.lock` and `dist/` now tracked in git.** Both were
  previously gitignored. The lockfile being in-tree turns the CI
  "Verify dep hashes" step from informational-warning to a hard
  gate. The bundle being in-tree means consumers don't run
  `cyrius distlib` themselves.

### Changed

- **`docs/doc-health.md`** — adds capability-map row (✅,
  refreshed in v1.2.0); ledger refresh date bumped.
- **`docs/development/roadmap.md`** — v1.2.0 marked done with
  honest scope notes. The original v1.2.0 plan included a
  "split deps by profile" item; investigation showed nein's
  `netns.cyr` is builder-only (consumers integrate
  `netns_apply_nftables_ruleset` themselves) so the split is
  unnecessary. That item is removed. OTLP audit-emit deferred:
  it would re-pull the agnostik dep dropped in v1.1.1, which
  doesn't pay for itself for a single function (`Span_to_otlp_proto`).
  The annotation pass on the remaining 14 modules carries to
  v1.2.1.

### Deferred

- **OTLP audit-emit hook.** Was scoped for v1.2.0; deferred —
  the only consumer is agnostik 1.2.0's `Span_to_otlp_proto`,
  and re-pulling agnostik for one function regresses the v1.1.1
  cleanup. A nein-side OTLP emitter could be written, but no
  consumer is asking for it yet. Will revisit when
  daimon / aegis actually wire OTLP intake.
- **Annotation pass on remaining 14 `src/lib/` modules.**
  Mechanical work — chain, table, set, nat, firewall, builder,
  policy, geoip, mesh, bridge, engine, config, netns, inspect.
  Now that the cstring/Str/i64 patterns are settled, this is a
  steady-state cleanup that fits v1.2.1.

## [1.1.4] — 2026-05-10

v1.1 minor closeout pass. Prose-doc currency, dead-code audit, clean
build verification. No source-level behavior change.

### Changed

- **`docs/guides/testing.md`** — full Rust→Cyrius rewrite. Was
  entirely cargo-era (cargo test, cargo bench, cargo-tarpaulin,
  cargo-fuzz, `make` targets). Now documents `cyrius test`,
  `cyrius bench`, the `scripts/bench-regression.sh` flow with
  threshold semantics and the `[bench-regression-ack]` bypass,
  `tests/nein.fcyr` fuzz invocation, and the full CI gate
  reproduction recipe.
- **`CONTRIBUTING.md`** — full Rust→Cyrius rewrite. Was Rust 1.89
  MSRV, cargo-deny, cargo-fuzz, cargo-llvm-cov, Makefile targets,
  `#[cfg(test)]` conventions. Now documents the Cyrius 5.10.34
  toolchain install, the reproduce-CI-locally recipe, the new-module
  workflow including `scripts/api-surface.sh update` and
  CHANGELOG/roadmap sync, code style (annotations + lint),
  test/bench/integration policy, and threat-model coupling.
- **`SECURITY.md`** — refreshed for v1.1.x. Removed Rust-era
  references (`cargo audit`, `#[non_exhaustive]`,
  `std::net::IpAddr::parse`, `make fuzz`). Added explicit ties to
  threat-model T-1…T-8 numbering, the v1.1.1 PATH-injection
  allowlist for `/sbin/nft` execve, the v1.1.1 symbol-collision
  audit, the lockfile-pinned dep story, and the type-check arc.
  Supported-versions table refreshed (v1.1.x maintained, v1.0.x
  best-effort, Rust-era ≤ 0.90.0 not maintained).
- **`docs/architecture/overview.md`** — refreshed for v1.1.x.
  Module map updated to the on-disk `src/lib/` layout (no phantom
  `mcp`, all 18 modules present). New data-flow diagram including
  validate → render → apply with the fork/pipe/execve detail. New
  "Type Boundary" section documenting the cstring / Str / i64
  conventions from the v1.1.2 / v1.1.3 annotation passes. ADR table
  cross-referenced to current module surface.

### Verified at closeout

- Full build from clean (`rm -rf build/ lib/` → `cyrius deps` →
  `cyrius build`) passes
- All CI gates green: fmt, lint, vet, type-check, x86_64+aarch64
  build, smoke, 580/580 tests, bench, api-surface snapshot,
  bench-regression
- Dead-code audit: all "dead: …" warnings are unused stdlib
  symbols (Err/None/Some/streq/memeq/atoi/etc), not nein-side
- Downstream consumers surveyed: stiva/sutra repos absent; daimon
  on cyrius 5.7.12 with no nein dep; aegis on cyrius 5.10.0 with
  no nein dep. No breakage downstream because no consumer yet
  imports nein. Integration tracked per consumer's roadmap.

## [1.1.3] — 2026-05-10

Surface-tracking gates + annotation pass on the construction surface +
prose-doc refresh. 580/580 tests pass on both arches; zero nein-side
type-check warnings.

### Added

- **`scripts/api-surface.sh` + `docs/api-surface.snapshot`.** New
  `<module>::<fn>/<arity>` snapshot of nein's 348 public fns across
  `src/main.cyr` + `src/lib/*.cyr`. CI `check` mode diffs current
  against committed snapshot and fails on unexplained adds/removes.
  Intentional API bumps regenerate via `scripts/api-surface.sh update`
  and ride into the same PR. Note: `cyrius_api_surface` upstream
  doesn't yet walk `src/lib/` includes, so this script greps source
  directly while emitting the same shape — drop-in once upstream
  resolves.
- **`scripts/bench-regression.sh` + `docs/benchmarks/history.csv`.**
  Initial baseline (31 benchmarks, captured at v1.1.2 commit) seeded
  the CSV. Gate fires on > 50% (ns-bracket, abs ≥ 50ns) or > 80%
  (µs-bracket, abs ≥ 2µs) slowdown vs the most recent committed row
  per benchmark. `[bench-regression-ack]` in the HEAD commit message
  bypasses the gate for intentional perf trade-offs. Pattern lifted
  from agnostik.
- **Currency check (CHANGELOG + roadmap).** New CI step asserts the
  current `VERSION`'s `## [X.Y.Z] — YYYY-MM-DD` line exists in
  `CHANGELOG.md` with a non-future date, and that the roadmap's
  `Last refresh:` marker is ≤ 90 days old. Catches the "forgot to
  bump the date" class of PR mistake.
- **`docs/doc-health.md`** added to the required-docs check (was
  added in v1.1.2 but the CI check didn't gate it).
- **Type annotations** on the construction surface — ~55 fns:
  - `src/lib/rule.cyr` — all match/verdict constructors carry
    `(arg: cstring|i64): i64` shapes. cstring args: `addr`, `proto`,
    `iface`, `states_str`, `field`/`set_name`, `helper`,
    `flags_str`, `tname`, `name`, `expr`, `chain`, `prefix`. i64
    args: `port`, `rate`/`unit`/`burst`, `val`, `reason`, `code`,
    `id`, `hdr`, `pt`, `count`, `mask`/`op`/`value`, log levels.
  - `src/lib/apply.cyr` — full public surface (15 fns) annotated.
    `apply_ruleset_str` uses `Str` (stdlib `: Str` type) rather than
    `cstring`; everything else uses `cstring` for the
    family/table/chain/rule injection boundary plus `i64` for
    handles.

### Changed

- **`README.md`** — refreshed for v1.1.x baseline. Bumped test count
  (541 → 580) and bench count (30 → 31). Rust-syntax `Match::Raw`
  replaced with prose pointing at ADR-0004. Added `cyrius deps` to
  the build commands. Linked the new `docs/development/threat-model.md`
  alongside `SECURITY.md`. Doc-health row updated: 🟠 → ✅.
- **`CLAUDE.md`** — refreshed for v1.1.x baseline. cc3 → cc5; pinned
  cyrius version + CI gate inventory in the status line. Removed
  `mcp.cyr` from the architecture tree (it doesn't exist; blocked on
  bote per roadmap v2.0.0). Doc-health row updated: 🟠 → ✅.
- **CI required-docs check** now also gates `docs/doc-health.md`,
  `docs/development/roadmap.md`, `docs/development/threat-model.md`.

## [1.1.2] — 2026-05-10

Type-check arc + doc currency. No runtime behavior change; 580/580 tests
pass on x86_64 and aarch64. Type-check gate (`CYRIUS_TYPE_CHECK=1`) now
green with zero nein-side warnings.

### Added

- **`CYRIUS_TYPE_CHECK=1` CI gate**. Routes cyrius build output through
  a tempfile (matches agnostik's $-eats-null-bytes workaround), filters
  stdlib self-flags via `^warning:lib/` and the known-tracked
  `large static data` warning (roadmap v1.3.0 — str_builder audit), and
  fails on any other `^warning:` line.
- **`: cstring` / `: i64` parameter annotations** on `src/lib/validate.cyr`'s
  full surface (8 public validators + 6 private char-class helpers). All
  validators carry `(s: cstring): i64` shapes — the security-critical
  injection surface is now type-checked end-to-end.
- **`: i64` annotations on `src/lib/error.cyr`**. `nein_ok`, `nein_err`,
  `nein_err_code` annotated to match packed-Result conventions.
- **`docs/doc-health.md`** — currency ledger for prose documentation,
  patterned on agnosys/agnostik 1.2.x. Tracks refresh age and traffic-light
  status (✅/🟠/🔴) for top-level docs, architecture, ADRs, development,
  and guides.

### Changed

- **`docs/development/threat-model.md`** — full rewrite. The v1.0.0 file
  was Rust-era prose referencing `std::net::IpAddr::parse()`,
  `cargo audit`, `Firewall::deduplicate()`, and Match::Raw — replaced
  with a Cyrius-era 8-threat model (T-1 syntax injection, T-2
  incremental-apply, T-3 nft PATH injection, T-4 child-process
  hygiene, T-5 rule explosion, T-6 TOML inputs, T-7 symbol-collision
  shadow, T-8 supply chain). Folds in v1.1.1's
  `/usr/sbin/nft`→`/sbin/nft`→`/usr/bin/nft` allowlist and the
  `nein_*`-prefix collision audit.

### Deferred

- `: cstring` / `: Str` annotations on rule.cyr (71 fns, mixed-type
  constructors) and apply.cyr (15 fns, heterogeneous shapes) — too
  sprawling for v1.1.2's patch scope. Queued for v1.1.3.

## [1.1.1] — 2026-05-10

CI gate expansion + portability fixes surfaced by the new gates. All 580
tests pass on x86_64 **and** aarch64. Binary size: 809 KB → 636 KB on
x86_64 (-21%); aarch64 cross-build emits 679 KB.

### Added

- **CI gates** (mirrored from agnosys/agnostik patterns):
  - `cyrius fmt` drift gate (diff against committed source)
  - `cyrius lint` gate on `src/` (fail on `^\s*warn ` lines)
  - `cyrius vet` (include-graph audit)
  - `cyrius capacity --check` (informational — current tool emits
    arch-peer-resolution false-positives, exits 0)
  - aarch64 cross-build step (best-effort; skip with warning if
    `cc5_aarch64` is missing from the toolchain bundle)
  - `CYRIUS_DCE=1` enabled on all builds
  - Security-scan job: `sys_system` calls, hardcoded writes to
    `/etc` / `/bin` / `/sbin` (apply.cyr allowlisted — `/sbin/nft`
    execve is nein's reason to exist), fn-scope buffers ≥ 4 KB (warn)
    / ≥ 64 KB (fail)
- `CYRIUS_NO_WARN_SHADOW_LIB=1` set workflow-wide to silence the
  ./lib/ cwd-shadow note (the resolved deps directory is intentional)

### Fixed

- **aarch64 portability** (`src/lib/apply.cyr`): three call sites
  switched from `syscall(SYS_PIPE, ...)` (x86-only — aarch64 uses
  `SYS_PIPE2`) to the portable `sys_pipe(...)` stdlib wrapper that
  exists in both arch peers. Unblocks aarch64 cross-builds.
- **Symbol-collision shadowing**:
  - `network_policy_new` (`src/lib/policy.cyr`) → `nein_network_policy_new`
    — agnostik 1.2.x introduced a no-arg `network_policy_new` that
    silently shadowed nein's 3-arg version via include order.
  - `err_code` (`src/lib/error.cyr`) → `nein_err_code` — `err_code`
    is now stdlib (lib/syscalls_*.cyr) for errno extraction; nein's
    Result-payload extractor collided.
- **`src/main.cyr`**: stale `cyrius.toml` reference in header comment
  updated to `cyrius.cyml`.
- **`src/lib/{rule,nat,bridge}.cyr`**: continuation-line indent drift
  from the pre-`cyrius fmt` era; now fmt-clean.
- **`tests/nein.tcyr`**: extracted three readability variables
  (`v_bad`, `v_good`, `expected_cm`) to fit the 120-char line limit
  on render-assertion call sites.

### Removed

- **agnostik dependency** — nein never called any agnostik symbol
  (the original 0.97.1 import was speculative). Dropping the dep
  eliminates four cross-crate `err_*` duplicate-fn warnings
  (`err_permission_denied`, `err_invalid_argument`, `err_not_supported`,
  `err_io` are defined in both agnosys-core and agnostik) and removes
  the `trait` stdlib requirement that came in with agnostik's
  OpenTelemetry traits. Cuts ~170 KB from the x86_64 binary.
- `trait` stdlib entry from `cyrius.cyml` (was added briefly for the
  agnostik traits; no longer needed).

## [1.1.0] — 2026-05-10

Toolchain + dependency modernization. No source-level API changes; all 580 tests pass under the new toolchain.

### Changed

- **Cyrius**: 4.5.0 → 5.10.34 (declared in `cyrius.cyml`)
- **agnosys**: 0.97.2 → 1.2.4 — switched to `dist/agnosys-core.cyr` bundle (modules-via-distlib pattern)
- **agnostik**: 0.97.1 → 1.2.1 — switched to `dist/agnostik.cyr` bundle
- **Manifest**: `cyrius.toml` → `cyrius.cyml` with `${file:VERSION}` interpolation, `repository` field, and `output = "build/nein"`
- **Lockfile**: `cyrius.lock` now generated and committed (sha256 per resolved dep)
- **CI workflows**: rewritten against the agnosys/agnostik 5.10.x pattern — versioned install layout (`~/.cyrius/versions/<v>/{bin,lib}` + symlinks, required by cc5 ≥ 5.10.9 for arch-peer include resolution), version extracted from `cyrius.cyml` via grep, lockfile-hash verification step, ELF magic check, version-consistency gate against CHANGELOG

### Removed

- `.cyrius-toolchain` — obsolete; the cyrius version is now declared in `cyrius.cyml`
- `sakshi_full` stdlib entry — not present in 5.10.x stdlib (`sakshi` alone is sufficient)

### Fixed

- `.gitignore` ambiguity: `lib/*.cyr` (which could match `src/lib/*.cyr` at any depth) replaced with anchored `/lib/`. Added `cyrius.lock` is tracked; `/lib/` and `/dist/` are not.

## [1.0.0] — 2026-04-13

Complete rewrite from Rust to Cyrius. Rust source preserved in `rust-old/` for reference.

### Added

**18 modules ported with full API parity:**

- **error** — `NeinError` enum (7 variants), packed Result helpers (`nein_ok`, `nein_err`, `err_code`)
- **validate** — 8 injection-safe validators (identifier, addr, iface, ct_state, comment, log_prefix, nft_element, family)
- **rule** — 30 Match variants, 13 Verdict variants, Rule struct with render + validate. `RejectReason`, `Protocol`, `RateUnit`, `QuotaMode`, `QuotaUnit`, `PktType`, `Ipv6ExtHdr`, `CmpOp`, `LogLevel` sub-enums
- **set** — Named sets (ipv4_addr, ipv6_addr, inet_service, inet_proto, ifname) with interval/timeout/constant flags; verdict maps with Accept/Drop/Jump
- **nat** — DNAT, SNAT, Masquerade, Redirect, DnatRange with IPv6 bracket wrapping; `port_forward`, `port_range_forward`, `container_masquerade` helpers
- **chain** — ChainType, Hook, Policy; base and regular chains; ChainRule wrapper dispatches rule vs NAT rendering
- **table** — Family, Define, Flowtable, CtTimeout; render order: defines → flowtables → ct_timeouts → sets → maps → chains
- **firewall** — Top-level manager with add_table, render, full-tree validate
- **builder** — `basic_host_firewall`, `container_bridge`, `service_policy` pre-built configurations
- **policy** — NetworkPolicy with ingress/egress rules, "any" peer handling, `agent_to_agent` convenience
- **geoip** — Country-based blocking with interval sets, dual-stack IPv4/IPv6, ISO 3166-1 alpha-2 validation
- **mesh** — Envoy sidecar rules with UID/CIDR/port exclusions, configurable inbound/outbound ports, transparent TCP redirect
- **bridge** — BridgeFirewall with port mappings, O(1) set-based isolation groups, duplicate port detection
- **engine** — Multi-agent PolicyEngine with dispatch chains, per-agent in/out chains, O(1) host restriction sets; `Transport` enum (TCP/UDP/QUIC); `PortSpec` helpers
- **config** — String→enum dispatchers for TOML/JSON/CLI configuration sources (16 enum types)
- **netns** — `NamespaceFirewall` builder for per-agent network namespace rulesets (established/loopback/DNS defaults + inbound/outbound port allow-lists and host restrictions); pairs with agnosys's `netns_apply_nftables_ruleset` for in-namespace apply
- **apply** — execute rulesets via `nft -f -` using fork+pipe+execve (synchronous); batch ops (`apply_ruleset_str`, `apply_firewall`, `flush_ruleset`); table/chain ops (`flush_table`, `delete_table`, `flush_chain`, `delete_chain`); incremental rule ops (`add_rule_live`, `insert_rule_live`, `add_rule_after_live`, `replace_rule_live`, `delete_rule_live`); `list_ruleset`, `list_ruleset_with_handles`
- **inspect** — `status()` returns `FirewallStatus { tables, total_rules, raw_ruleset }` parsed from live `nft list ruleset` output

### Testing

- 580 test assertions across 42 test groups (was 409 in Rust era)
- 31 benchmarks covering validators, rule rendering, full firewall generation, multi-agent engine, and namespace firewall
- Apply path smoke-tested end-to-end: non-root `list_ruleset` returns `Err` cleanly (no crash, no hang)
- Fuzz harness covering validators, rule rendering, NAT, and config dispatchers

### Performance (Cyrius)

| Benchmark | Time |
|-----------|------|
| `validate_*` (injection checks) | 450ns–1us |
| `rule_render/simple` | 1us |
| `rule_render/complex` (6 matches + comment) | 3us |
| `nat_dnat_render` | 1us |
| `basic_host_firewall` (full render) | 13us |
| `container_bridge` | 21us |
| `mesh_render` | 24us |
| `bridge_render` (port mappings + iso) | 48us |
| `geoip_render` | 11us |
| `engine_10_agents_render` | 400us |
| `netns_render` | 34us |

### Changed

- **Language**: Rust → Cyrius (sovereign systems language, compiled by cc3)
- **Code size**: ~7,913 LOC Rust → ~3,553 LOC Cyrius (55% reduction across ported modules)
- **Dependencies**: serde/thiserror/tracing/tokio → cyrius stdlib + agnosys/agnostik deps
- **Error handling**: `Result<T, NeinError>` → stdlib tagged Result (`Ok`/`Err`/`is_err_result`/`payload`)
- **Feature gates**: Cargo `#[cfg(feature = ...)]` → cyrius preprocessor `#ifdef`
- **TOML support**: Scoped to string→enum dispatchers (full struct parsing awaits sutra port)

### Deferred (blocked on upstream)

- `mcp` — blocked on [bote](https://github.com/MacCracken/bote) Cyrius port
- Full TOML struct parsing — blocked on sutra port start (only consumer)

### Security

All validators preserved from Rust: dangerous-character rejection (`; { } | \n \r \0 \` $`), quote filtering for comments/log prefixes/set elements, length limits (identifiers 64, interfaces 15, comments 128, log prefixes 64). `Match::Raw` remains the explicit, documented escape hatch.

## [0.90.0] — 2026-04-02

### Added

#### Phase 4 — Production Hardening
- **Define variables**: `Define` struct for `define $VAR = value;` inside tables
- **Flowtables**: `Flowtable` struct for hardware offload (`flowtable ft { hook ingress priority 0; devices = { eth0 }; }`)
- **Conntrack timeout policies**: `CtTimeout` struct with per-protocol timeout tuning (`ct timeout name { protocol tcp; policy = { established: 7200 }; }`)
- **Quota rules**: `QuotaMode`/`QuotaUnit` enums + `Match::Quota` for byte-based rate limiting (`quota over 25 mbytes`)
- **Mark setting verdicts**: `Verdict::SetMark(u32)`, `Verdict::SetCtMark(u32)` for packet/conntrack marking
- **NAT port range mappings**: `NatRule::DnatRange` + `port_range_forward()` for range-to-range DNAT (`80-89 -> 8080-8089`)
- **Rule insertion ordering**: `insert_rule()` (beginning of chain), `add_rule_after()` (after handle)
- **Rule replacement**: `replace_rule()` for atomic handle-based rule updates
- **Chain operations**: `flush_chain()`, `delete_chain()` in apply module
- `Table` struct extended with `defines`, `flowtables`, `ct_timeouts` fields
- Render order: defines, flowtables, ct_timeouts, sets, maps, chains

#### Phase 5 — Deep Protocol Support
- **ICMP type+code**: `Match::IcmpTypeCode(String, u8)`, `Match::Icmpv6TypeCode(String, u8)`
- **VLAN ID matching**: `Match::VlanId(u16)` — validated 0-4094
- **DSCP/ToS matching**: `Match::Dscp(u8)` — validated 0-63
- **IPv6 extension headers**: `Ipv6ExtHdr` enum + `Match::Ipv6ExtHdrExists` (hbh, rt, frag, dst, mh, auth)
- **Fragment matching**: `Match::FragOff { mask, op, value }` with typed `CmpOp` enum
- **Packet type matching**: `PktType` enum + `Match::PktType` (unicast, broadcast, multicast)
- **Enhanced logging**: `LogLevel` enum + `Verdict::LogAdvanced { prefix, level, group, snaplen }`
- **Named counters**: `Verdict::CounterNamed(String)` for `counter name "name"` references

#### Phase 6 — Ergonomics
- **Bulk match builders**: `Rule::matching_ports()`, `matching_addrs()`, `matching_addrs6()` — anonymous set syntax with input validation
- **Set-based isolation**: bridge isolation groups now use O(1) nftables set lookups instead of O(n^2) explicit rules
- **Set-based outbound hosts**: PolicyEngine outbound host restrictions use named sets instead of O(n*M) rules
- **Rule deduplication**: `Firewall::deduplicate()` removes adjacent duplicate rules

#### Phase 7 — Ecosystem Integration
- **daimon**: `firewall` feature wires `nein_status`/`nein_allow`/`nein_deny`/`nein_list` MCP tools into daimon's handler registry
- **aegis**: `firewall` feature adds `isolate_agent()`, `rate_limit_agent()`, `hardened_host()` firewall profiles
- **sutra**: `nein` module implementing `SutraModule` trait with `apply`/`check`/`flush` actions for fleet firewall configs
- **stiva**: container port mapping NAT rules now applied to nftables via `nft -f -` on container connect

#### Phase 8 — QUIC Support
- **Transport enum**: `Transport::Tcp`/`Udp`/`Quic` in PolicyEngine — QUIC maps to UDP protocol with semantic distinction in policy comments
- **QUIC rate limiting**: `rate_limit_quic()` convenience function with 2x burst for connection migration protection
- `rate_limit_udp()` convenience function
- `PortSpec::quic(port)` constructor

#### Production Firewall Completeness
- **Reject with reason**: `Verdict::RejectWith(RejectReason)` — TCP RST, ICMP host/port/net/admin-unreachable, ICMPx admin-prohibited
- **Connection count limiting**: `Match::ConnLimit(u32)` for per-source connection count (`ct count over N`)

#### v1.0 Readiness
- **Serde roundtrip tests**: 19 tests across all modules (rule, table, nat, engine types)
- **Config module**: TOML parsing for all Phase 4-8 types (defines, flowtables, ct_timeouts, quota, dscp, vlan, frag, pkttype, log_advanced, counter_named, set_mark, reject_with, conn_limit)
- **Doc-tests**: 6 doc-tests on key entry points (lib.rs, rule.rs, builder.rs, engine.rs, bridge.rs, netns.rs)
- **Scale benchmarks**: 1000-rule firewall (176µs render, 82µs validate), 100-agent engine (548µs to_firewall, 320µs render)
- **ADRs**: 3 new records — set-based isolation (007), typed enums over strings (008), non-exhaustive structs (009)
- **Tracing**: added structured logging to bridge, mesh, geoip, engine, policy, config, inspect modules

### Changed
- `bote` dependency changed from path to crates.io `v0.91`
- `agnosys` dependency changed from path to git tag `v0.50.0`
- `criterion` upgraded from `0.5` to `0.8` (`black_box` migrated to `std::hint::black_box`)
- `validate_addr()` now parses actual IP/CIDR via `std::net::IpAddr` instead of character-set-only checks
- `validate_family()` added — closed set validation for nftables address families
- All `apply.rs` incremental functions validate `family` param against closed set
- `Rule::render()` rewritten with `write!` to single buffer (was `Vec<String>` + `join`) — **60% faster rendering**
- `Chain::render()`, `Table::render()` use `write!` with pre-allocation
- `mcp::build_allow_rule`/`build_deny_rule` now validate `table` and `chain` fields
- `port_range_forward()` uses `saturating_sub`/`saturating_add` to prevent overflow
- `#[non_exhaustive]` added to all public enums and structs
- `#[must_use]` added to ~70 pure/builder functions
- `#[inline]` added to hot-path functions (`Rule::new`, `render`, `matching`)
- `Hash` derived on all public enums and value structs
- `Serialize`/`Deserialize` added to `Firewall`, `PolicyEngine`, `GeoIpBlocklist`, `BridgeFirewall`, `FirewallStatus`, `RuleHandle`
- `PartialEq`/`Eq` added to all config and MCP types
- Makefile, bench-track.sh, CI workflows switched from `--all-features` to `--features full`
- `deny.toml` updated with `allow-git` for agnosys GitHub URL
- SECURITY.md updated with v0.90.0 support, new attack surfaces, standards compliance section
- Threat model updated with incremental apply injection, MCP tool input, supply chain sections

### Fixed
- `mcp.rs` formatting (was only `cargo fmt` failure at session start)
- `config.rs` redundant `let mut chain = chain;` re-binding
- `apply.rs` incremental functions now validate all parameters before interpolation (security)
- `matching_addrs()`/`matching_addrs6()` now validate each address before embedding in `Raw` (security)
- `rate_limit_quic()` burst uses `saturating_mul` to prevent overflow
- `CtTimeout` validates protocol is TCP/UDP only, l3proto is Ip/Ip6 only
- `Flowtable` validates at least one device is present
- CI `cargo test --doc` now uses `--features full` so feature-gated doc-tests run
- Release workflow `sed` patterns fixed for `#[cfg(feature = "netns")]` stripping
- Release workflow uses `--allow-dirty` for publish after stripping private deps

### Performance
- `rule_render`: 305 ns → 123 ns (**-60%**)
- `rule_complex_render`: 497 ns → 268 ns (**-46%**)
- `bridge_large_render`: 45.4 µs → 27.0 µs (**-41%**)
- `engine_10_agents_render`: 40.8 µs → 14.9 µs (**-63%**)
- `mesh_render`: 2.96 µs → 1.22 µs (**-59%**)
- Bridge isolation: O(n^2) → O(1) per group via nftables sets
- PolicyEngine outbound hosts: O(ports * hosts) → O(ports) via named sets
- Scale: 1000-rule render 176µs, 100-agent engine 548µs

### Tests
- 396 unit tests, 7 integration tests, 6 doc-tests = **409 total** (up from 217 unit tests)

## [0.24.3] — 2026-03-24

### Added
- **`netns` feature**: agent network namespace firewall integration via agnosys
  - `NamespaceFirewall` builder — type-safe nftables rulesets for agent namespaces (established/related, loopback, DNS, inbound/outbound ports, host restrictions)
  - `apply_to_namespace()` — renders and applies firewall inside a namespace via `agnosys::netns::apply_nftables_ruleset`
  - 15 unit tests, doctest
  - Feature-gated behind `dep:agnosys` (optional path dependency, not included in `full` or `default` — agnosys is `publish = false`)

### Changed
- `full` feature no longer enables all features — excludes `netns` since agnosys is a private crate
- CI (`ci.yml`): `--all-features` replaced with `--features full` across all jobs (clippy, test, MSRV, coverage, benchmarks, docs) to avoid requiring private path dependencies
- `deny.toml`: switched from `all-features = true` to `features = ["full"]` for the same reason

## [0.22.3] — 2026-03-22

### Added
- Benchmark tracking script (`scripts/bench-track.sh`) — records criterion results to `benchmarks/history.tsv` with version, commit, and timestamp for historical performance tracking
- Expanded benchmarks: 22 criterion benchmarks covering all modules (rule render/validate, complex rules with IPv6/rate-limit/TCP-flags, NAT, host firewall, bridge small/large, engine 10 agents, policy, mesh, geoip 10 countries, set 1000 elements, TOML parse)
- 6 architecture decision records (ADRs) in `docs/decisions/`: render-not-execute, validate-before-apply, feature-gated-modules, raw-match-escape-hatch, chain-rule-enum, sets-in-tables
- Future roadmap (`docs/development/roadmap.md`): Phases 4-7 (production hardening, deep protocol support, ergonomics, ecosystem integration)
- Development section in README with quick-reference commands
- Documentation links in README (architecture, threat model, ADRs, testing guide)

### Changed
- Version bump for stiva 0.22.3 ecosystem release
- README roadmap replaced with link to `docs/development/roadmap.md` — completed phases removed (in CHANGELOG)
- `Makefile` adds `bench-track` target
- `CONTRIBUTING.md` expanded with benchmark tracking workflow
- `docs/guides/testing.md` expanded with historical benchmark tracking

## [0.21.3] — 2026-03-22

### Added

#### Publishing Infrastructure
- CI/CD pipeline (`.github/workflows/ci.yml`): 10-job pipeline — lint (3x feature combos), security audit, cargo-deny, test, test-minimal, MSRV, coverage (codecov), benchmarks (artifact upload), documentation (-D warnings), semver checks (PRs)
- Release automation (`.github/workflows/release.yml`): triadic version verification (VERSION + Cargo.toml + git tag), publish to crates.io, create GitHub release
- Community files: `CONTRIBUTING.md`, `SECURITY.md` (threat model, disclosure policy), `CODE_OF_CONDUCT.md` (Contributor Covenant v2.1), `codecov.yml` (80% project, 75% patch)
- 4 runnable examples: `host_firewall`, `container_bridge`, `policy_engine`, `geoip_blocklist` (feature-gated)
- 3 fuzz targets: `fuzz_rule_render`, `fuzz_toml_config`, `fuzz_validation` (libfuzzer)
- Supply chain: `supply-chain/config.toml`, `supply-chain/audits.toml` (cargo-vet)
- Documentation: `docs/architecture/overview.md`, `docs/development/threat-model.md`, `docs/guides/testing.md`
- Expanded `Makefile`: coverage, fuzz, clippy --all-features, doc with -D warnings
- `Cargo.toml`: publish excludes, example entries with required-features
- Expanded `lib.rs` module documentation with feature table

#### Firewall Features
- **TCP flags matching**: `Match::TcpFlags` renders as `tcp flags { syn, fin }`
- **ICMP type matching**: `Match::IcmpType`, `Match::Icmpv6Type` for fine-grained ICMP filtering
- **Packet mark matching**: `Match::MetaMark` for `meta mark` matching
- **IPv6 DNAT fix**: brackets around IPv6 addresses in DNAT rendering (`dnat to [addr]:port`)
- Improved config parse error messages — all parsers now list valid options on error

#### Phase 3 — Advanced
- **Named sets and maps** (core): `NftSet` with element types (ipv4_addr, ipv6_addr, inet_service, inet_proto, ifname), flags (constant, interval, timeout). `NftMap` verdict maps. Integrated into `Table` — sets/maps render before chains
- **IPv6 support**: `Match::SourceAddr6`/`DestAddr6` for `ip6 saddr`/`ip6 daddr`. `deny_source6()` convenience function. `validate_addr` accepts IPv6 notation
- **Rate limiting**: `Match::Limit { rate, unit, burst }` renders as `limit rate N/unit burst M packets`. `RateUnit` enum (second/minute/hour/day). `rate_limit_tcp()` convenience
- **Connection tracking helpers**: `Match::CtHelper` renders as `ct helper "name"` with identifier validation
- **Set membership matching**: `Match::SetLookup { field, set_name }` renders as `field @setname`. `match_set()` convenience
- **TOML config** (`config` feature): `from_toml()`/`to_toml()` for firewall config files. Tagged union match types, all verdict/family/hook/chain_type variants. Round-trip serialization for sutra playbooks
- **GeoIP blocking** (`geoip` feature): `GeoIpBlocklist` with `CountryBlock` entries. Generates nftables interval sets per country + drop rules. Dual-stack (IPv4 + IPv6 in separate tables). Country code validation (ISO 3166-1 alpha-2)
- `validate_nft_element()` for set/map element validation
- `Eq` added to `ChainRule`, `Chain`, `Table`, `NetworkPolicy`
- `Clone` added to `Firewall`
- MCP `build_allow_rule`/`build_deny_rule` now validate source CIDRs
- 255 unit tests, 7 integration tests

#### Phase 2 — Daimon Integration
- **Agent policy engine** (`engine` feature): `PolicyEngine` manages per-agent network policies with `AgentPolicy`, `PortSpec`. Generates unified firewall with dispatch chains that jump to per-agent `{id}_in`/`{id}_out` chains. Supports inbound/outbound port control, outbound host restrictions, established/loopback toggles
- **Dynamic rule operations** in `apply` module: `add_rule()`, `delete_rule()` for incremental rule management; `list_ruleset_with_handles()`, `find_rules_by_comment()`, `parse_rules_with_handles()` for rule discovery by comment prefix; `flush_table()`, `delete_table()` for table-level operations
- **Service mesh sidecar proxy** (`mesh` feature): `SidecarConfig` with Envoy defaults (ports 15006/15001, UID 1337). Generates transparent TCP redirect rules with UID-based proxy bypass, CIDR exclusions, port exclusions for both inbound and outbound interception
- **MCP tool building blocks** (`mcp` feature): `ToolDescriptor`, `ToolResult`, request/response types for `nein_status`, `nein_allow`, `nein_deny`, `nein_list`. Includes `build_allow_rule()` and `build_deny_rule()` helpers, `tool_descriptors()` for MCP registration

#### Phase 1 — Stiva Integration
- **Bridge module** (`bridge` feature): `BridgeConfig`, `BridgeFirewall`, `PortMapping`, `IsolationGroup` — full container bridge firewall management
- Port mapping lifecycle: `add_port_mapping` (with duplicate detection), `remove_port_mapping`
- Network isolation groups with cross-CIDR intra-group traffic rules
- Integration tests (`tests/integration.rs`) — 7 tests gated behind `NEIN_INTEGRATION=1` env var, require root + nft
- Criterion benchmarks (`benches/benchmarks.rs`) — rule render, validate, NAT render, host firewall, bridge firewall (small/large), policy, 100-rule validation

#### Phase 0 — Foundation
- Input validation module (`validate`) — rejects dangerous characters in addresses, interface names, identifiers, comments, and log prefixes to prevent nftables injection
- `Firewall::validate()` — walks all tables/chains/rules, called automatically before `apply()`
- `Rule::validate()` and `NatRule::validate()` for per-rule validation
- `NetworkPolicy::validate()` — checks policy name and peer addresses
- `ChainRule` enum — chains now natively hold both filter rules (`Rule`) and NAT rules (`NatRule`)
- `Chain::add_nat_rule()` for direct NAT rule insertion without `Match::Raw` workaround
- `Verdict` implements `Display`
- `Firewall::tables()` accessor
- `DPortRange(lo, hi)` validation rejects inverted ranges
- `PartialEq`/`Eq` derives on `Rule`, `Match`, `Table`, `Chain`, `NatRule`, `ChainRule`, `NetworkPolicy`, `PolicyRule`, `PolicyPort`
- **Bridge module** (`bridge` feature): `BridgeConfig`, `BridgeFirewall`, `PortMapping`, `IsolationGroup` — full container bridge firewall management
- Port mapping lifecycle: `add_port_mapping` (with duplicate detection), `remove_port_mapping`
- Network isolation groups with cross-CIDR intra-group traffic rules
- Integration tests (`tests/integration.rs`) — 7 tests gated behind `NEIN_INTEGRATION=1` env var, require root + nft
- Criterion benchmarks (`benches/benchmarks.rs`) — rule render, validate, NAT render, host firewall, bridge firewall (small/large), policy, 100-rule validation
- 70 unit tests, 6 integration tests (up from 24)

### Fixed
- Zombie process in `apply_ruleset` — child is now always waited on, even if stdin write fails
- `inspect::status()` no longer swallows errors — propagates `list_ruleset` failures via `?`
- `container_bridge` builder no longer wraps NAT rules through `Match::Raw`, eliminating a validation bypass

### Changed
- Feature flags now gate modules: `nat`, `policy`, `inspect`, `apply`, `builder`, `bridge` (previously decorative)
- `tokio` is optional, gated behind the `apply` feature
- Default features: `nat`, `policy`, `apply`, `builder`, `bridge`
- Removed unused `rules` feature (core types always compiled)

### Removed
- Unused dependencies: `anyhow`, `serde_json`, `toml`, `chrono`, `uuid`, `nix`
- Unused `validate_nft_value` function
- Unused `_agent_dest` parameter from `builder::service_policy()`

### Security
- `Match::Raw` documented as unvalidated escape hatch — must not receive user-controlled input
- `Firewall::flush()` documented as flushing the entire host ruleset, not just owned tables
