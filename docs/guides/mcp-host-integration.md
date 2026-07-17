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
tag = "1.6.4"
modules = ["dist/nein-mcp.cyr"]
```

`dist/nein-mcp.deps` lists `bote-core`. Under cyrius 6.4.x `thread` /
`thread_local` fold into the always-resolved `std` group, and since 1.6.3
`sigil` is nein's own explicit `[deps.sigil]` git pin (full `dist/sigil.cyr`,
mirroring bote 3.1.2) rather than a stdlib leave — so neither is emitted in
the sidecar. The bundle body is unchanged: it still leaves **bote** and
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

# install the access-control gate BEFORE serving calls
nein_mcp_set_gate(&host_firewall_gate);

# dispatch — in mcp_dispatch_builtin, route nein_* names to nein
fn mcp_dispatch_builtin(name, args) {
    if (_starts_with(name, "nein_") == 1) {
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
ungated variant.

## The access-control gate

`gate_fp` is `fn(tool_name: cstring, claims: i64) -> 1 permit / 0 deny`. The
host owns agent identity (daimon's `agent.cyr`); nein just calls the gate
before each tool acts and returns an "access denied" envelope on `0`,
**never touching the firewall**. Today bote's `claims` is a reserved `0`
(2.x ABI), so gate on the host's own agent context; the seam lights up for
free when claims populate.

Classify by side-effect using the tool table:

- `nein_tool_read_only(i)` — `1` for `status` / `validate` / `list` / `diff`
  (safe to expose broadly), `0` for `allow` / `deny` (live apply).
- `nein_tool_admin(i)` — `1` for the mutating tools (the `firewall_admin`
  profile). Expose read-only firewall tools to low-trust agents; gate the
  mutating set to privileged agents.

On the bote-Dispatcher path the same split is carried by bote
`ToolAnnotations` (read-only vs destructive) and the `firewall` /
`firewall_admin` profile tags, filterable via `tools/list?profile=`.

## Signing (optional)

The bundle also exports the signed-ruleset surface: `sign_ruleset(fw, sk,
keyid)`, `verify_ruleset(signed, pubkey)`, and fail-closed
`apply_signed_ruleset(signed, pubkey)` (Ed25519 over the rendered nft body).
Use it if the host stores/serves rulesets and wants at-rest tamper
detection before apply. Build envelope helpers `nein_mcp_ok` / `nein_mcp_err`
are public so host-side firewall tools emit the identical MCP envelope.
