# Integrating nein's firewall MCP tools into a host

nein exposes its firewall operations as six MCP tools (`nein_status`,
`nein_allow`, `nein_deny`, `nein_validate`, `nein_list`, `nein_diff`) plus a
signing surface. This guide is for an MCP **host** (e.g. daimon) that wants
to expose those tools to agents. nein owns no transport — the host supplies
the dispatcher/transport and the agent-identity policy.

## Consume the bundle

nein ships an opt-in bundle, `dist/nein-mcp.cyr` (built by `cyrius distlib
mcp`), that carries nein's core + `mcp` + `sign` modules. It deliberately
leaves **bote** (`jsonx` / dispatcher / annotations) and **sigil**
(`ed25519` / `hex` / `sha256`) symbols unresolved — the host supplies them,
exactly as it already does for the full bote bundle.

```toml
# host cyrius.cyml
[deps.nein]
git = "https://github.com/MacCracken/nein.git"
tag = "1.9.1"
modules = ["dist/nein-mcp.cyr"]
```

⚠ **Pin 1.6.6 or later.** `dist/nein-mcp.deps` listed `bote-core` through
1.6.5, which asserted that bote's bundle ships in the cyrius stdlib. On cyrius
≥ 6.5.24 that fails the host's `cyrius deps` outright with `dep nein requires
'bote-core' but it is not in the cyrius stdlib`; on earlier toolchains it
resolved only by accident, out of the host's own `./lib`. 1.6.6 renames the
manifest section to `[deps.bote-core]` so `cyrius distlib` treats the fold as a
named dep, and the line is gone from both sidecars. See
[`dependencies.md`](../development/dependencies.md). The bundle body is
identical across the fix.

Since 1.6.3 `sigil` is nein's own explicit `[deps.sigil]` git pin (full
`dist/sigil.cyr`, mirroring bote 3.1.x) rather than a stdlib leaf, so it is not
emitted in the sidecar either. The bundle body still leaves **bote** and
**sigil** (`ed25519` / `hex` / `sha256`) symbols unresolved, so include it
**after** bote and sigil in the host's single-pass include chain (a bote+sigil
host — e.g. daimon — already has both).

## Wire the tools — two paths

### Path B — dispatch by name (recommended for daimon)

daimon routes MCP calls by name (`mcp_dispatch_builtin`) rather than
standing up a bote `Dispatcher`. nein provides a matching adapter. Register
descriptors from nein's tool table, then forward every `nein_*` call:

```
# registration — read the tool table
var i = 0;
while (i < nein_tool_count()) {
    mcp_register_builtin(reg, mcp_tool_new(
        str_from(nein_tool_name(i)), nein_tool_desc(i)));   # + your metadata
    i = i + 1;
}

# install the access-control gate BEFORE serving calls; it installs once
if (nein_mcp_set_gate(&host_firewall_gate) != 0) { /* refused: fail startup */ }

# dispatch — in mcp_dispatch_builtin, route nein_* names to nein
fn mcp_dispatch_builtin(name, args) {
    if (nein_tool_index(name) >= 0) {           # a table lookup, not a prefix test
        return nein_mcp_dispatch(name, args, claims);   # -> MCP result envelope cstr
    }
    ...
}
```

`nein_mcp_dispatch(name, args, claims)` returns the tool's
`{"content":[...],"isError":bool}` envelope cstr (or an "unknown nein tool"
error). Every handler consults the installed gate first.

### Path A — bote Dispatcher

If the host runs a bote `Dispatcher`, skip the adapter and register directly:

```
nein_tools_register_gated(dispatcher, &host_firewall_gate);
```

This registers all six descriptors (with annotations + profiles) and binds
handlers on the dispatcher. `nein_tools_register(dispatcher)` is the
ungated variant: until a gate is installed, only `nein_validate` runs (1.9.0).

Since 1.8.2 each tool goes through bote's `dispatcher_register_tool`: the
definition and its handler land under one registries write lock, and bote
publishes `bote/tool/registered`, so its listen streams hear of the tools.
Both functions return the number of tools bote **refused** (0 when all six
registered; a refusal is logged with bote's reason). Check it:

```
if (nein_tools_register_gated(dispatcher, &host_firewall_gate) != 0) { /* fail startup */ }
```

Through 1.8.1 they returned 0 unconditionally, registered the definition and
bound the handler in two separate writes (a call landing between them on a
threaded server found the tool and no handler), and ignored a refusal while
still binding the handler.

## The access-control gate (1.9.0 contract)

`gate_fp` is `fn(tool_name: cstring, claims: i64) -> i64`. nein calls it before
each tool acts and runs the tool **only when it returns `NEIN_GATE_PERMIT`**;
any other value — `0`, `1`, `-1`, a `Result`, a pointer — is a denial, answered
with an "access denied" envelope **before the firewall is touched**. The host
owns agent identity (daimon's `agent.cyr`). `claims` is whatever bote hands the
handler, passed through unchanged: `0` when the host configures no auth, and
(bote 3.7.5+) a NUL-terminated heap copy of the verified token when HTTP or
WebSocket auth is configured. nein never reads `claims` itself.

Classify with the tool table, by what each tool can reach:

| class | tools | what it does |
|---|---|---|
| `NEIN_TOOL_OFFLINE` | `nein_validate` | checks arguments; touches nothing outside the process |
| `NEIN_TOOL_READS_LIVE` | `nein_status`, `nein_list`, `nein_diff` | runs `nft -a list ruleset` **as root** and returns live state — `list` and `diff` verbatim: set elements, allowed sources, comments |
| `NEIN_TOOL_MUTATES` | `nein_allow`, `nein_deny` | changes the live firewall |

```
fn host_firewall_gate(name, claims) {
    var c = nein_tool_class(nein_tool_index(name));   # 0 for a name nein does not know
    if (c == NEIN_TOOL_OFFLINE) { return NEIN_GATE_PERMIT; }
    if (c == NEIN_TOOL_READS_LIVE && host_may_read_firewall(claims) == 1) { return NEIN_GATE_PERMIT; }
    if (c == NEIN_TOOL_MUTATES && host_is_firewall_admin(claims) == 1) { return NEIN_GATE_PERMIT; }
    return 0;
}
```

The rules, and what each closes:

- **Permit is one value.** nein calls the gate through a run-time pointer
  (`fncall2`), and cyrius truncates a `Result` returned that way to its tag with
  no diagnostic. Through 1.8.2 permit was `1`, so a gate returning `Err` (tag 1)
  **permitted** (audit M-2). `NEIN_GATE_PERMIT` is a 64-bit constant above the
  user-space address range, so no bool, tag, error code or pointer equals it.
- **One gate per process, installed once.** `nein_mcp_set_gate` and
  `nein_tools_register_gated` share one gate. Installing the gate already
  installed is a no-op (`0`); a different gate, or `0` to clear it, is
  **refused** (`1`) and the installed gate stays. `nein_tools_register_gated`
  under a refused gate mounts nothing and returns `nein_tool_count()`. Through
  1.8.2 a later call silently replaced or removed the gate for every
  dispatcher already serving. (A gate per registration is not possible: the
  handler ABI `(args, claims)` carries no registration.) Tools mounted with
  plain `nein_tools_register` run under whatever gate the process installs,
  before or after; a host serving two dispatchers of different trust gets one
  policy for both and must tell callers apart through `claims`.
- **No gate, offline only.** Until a gate is installed, `nein_validate` runs and
  the other five answer "access denied: no host gate installed". Through 1.8.2
  an ungated host ran all six, `nein_allow` and `nein_deny` included.

`nein_tool_read_only(i)` and `nein_tool_admin(i)` keep their 1.6.1 meaning
(`read_only` = does not change the firewall, the MCP `readOnlyHint`), but
**`read_only` is not "safe to expose"**: three of the four read the live
ruleset as root. Gate on `nein_tool_class`.

On the bote-Dispatcher path the classes are also carried as profile tags —
`firewall` on all six, `firewall_read` on the live readers, `firewall_admin` on
the mutating pair — filterable with `tools/list?profile=`, and as bote
`ToolAnnotations` (read-only vs destructive). A profile is a listing filter
the client chooses, not access control; the gate is the access control.

### Migrating a 1.8 gate

A 1.8 gate returns `1` to permit, which 1.9.0 reads as a denial — an
unmigrated host fails closed (every nein tool denied, `nein_validate`
included), never open. To migrate:

1. Return `NEIN_GATE_PERMIT` where the gate returned `1`.
2. Decide the live readers separately. A gate that permitted every
   `nein_tool_read_only(i) == 1` tool exposed the live ruleset to every caller;
   permit `NEIN_TOOL_READS_LIVE` only to callers allowed to see it.
3. Install once at startup, and check the result.
4. A host that called `nein_tools_register` without a gate and relied on the
   live tools must now install one.

## Arguments (1.8.2)

Every tool now refuses arguments that are not one JSON object whose top-level
keys are spelled plainly and appear once: a duplicate key, or a key written
with an escape (`"\u0070ort"`), is an error. bote read a key as what it
decodes to and let the first duplicate win, while most JSON parsers let the
last win, so a host-side filter or an approval UI could be shown a different
argument than nein acts on. `port` must be a plain integer 1–65535 (no sign,
leading zero, fraction or exponent). Tool results are unchanged in shape.

Since bote 3.8.6 (nein 1.9.1 pins 3.8.9) a request that names any key twice,
at any depth, is refused by bote's codec as `-32600` before nein sees it; nein's
own check stays for hosts that call `nein_mcp_dispatch` with arguments they
built. Since 1.9.1 `table` and `chain` must be names nft reads
(`validate_nft_name`: no leading digit or `-`, no nft keyword such as `fwd`
or `log`); through 1.9.0 such a name passed and the apply failed in nft.

## Signing (optional)

The bundle also exports the signed-ruleset surface (Ed25519 over the rendered
nft body). Use **v2** (1.9.0) for anything a verifier applies:

```
# signer: seq increases per scope; not_after is a unix second, or 0 for none
var s_t, env = sign_ruleset_v2(fw, sk, "fleet-key", "web-01", seq, now + 86400);

# verifier: keeps last_seq per (key, scope), records it only after Ok
var a_t, a_v = apply_signed_ruleset_v2(env, trusted_pk, "web-01", last_seq + 1, now);
if (is_err_result(a_t) == 0) { last_seq = a_v; persist(last_seq); }
```

`verify_ruleset_v2` / `apply_signed_ruleset_v2` refuse an envelope signed for
another scope (`NEIN_ERR_SIG_SCOPE`), below the floor (`NEIN_ERR_SIG_STALE` — a
replay or rollback), or past its expiry (`NEIN_ERR_SIG_EXPIRED`), and a v1
envelope (`NEIN_ERR_SIG_VERSION`). On `NEIN_ERR_OUTCOME_UNKNOWN` from the apply,
the ruleset may be live: raise the floor to the seq `verify_ruleset_v2` returns
for the same bytes, then diff. Never take a floor from `parse_signed_ruleset_v2`,
which does not verify — a rewritten `nein-sig-seq` would freeze every later
envelope out as stale.

The v1 functions (`sign_ruleset`, `verify_ruleset`, `apply_signed_ruleset`)
remain for existing stores, but a v1 envelope verifies forever, anywhere —
accepting one is the replay v2 exists to stop. A host that adopts v2 should
stop calling them. Build envelope helpers `nein_mcp_ok` / `nein_mcp_err`
are public so host-side firewall tools emit the identical MCP envelope.
