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
tag = "1.6.10"
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

## The access-control gate

`gate_fp` is `fn(tool_name: cstring, claims: i64) -> 1 permit / 0 deny`. The
host owns agent identity (daimon's `agent.cyr`); nein just calls the gate
before each tool acts and returns an "access denied" envelope on `0`,
**never touching the firewall**. `claims` is whatever bote hands the
handler, passed through unchanged: `0` when the host configures no auth, and
(as of bote 3.7.5) a NUL-terminated heap copy of the verified token when HTTP
or WebSocket auth is configured. A host running bote with auth can gate on
it; one without auth, or one using the dispatch adapter below, gates on its
own agent context. nein never reads `claims` itself.

### ⚠ Two gate hazards (1.8.2 audit, contract changes planned for 1.9.0)

- **Return exactly `1` or `0` — never a `Result`.** nein calls the gate through
  a run-time function pointer (`fncall2`), and cyrius truncates a `Result`
  returned that way to its tag with no diagnostic. A `Result` gate's `Err` has
  tag `1` — which nein reads as **permit** — and its `Ok` reads as deny. A gate
  written the way nein's own "Packed Result for fallible operations" guideline
  suggests is therefore inverted. (daimon's gate returns `1` / `0`, so it is
  unaffected.)
- **There is one gate per process.** `_nein_gate` is a single variable shared
  by both paths: a second `nein_tools_register_gated`, or
  `nein_mcp_set_gate(0)`, replaces or removes the gate for every dispatcher
  already registered. Install it once, at startup.

1.9.0 replaces this contract (a permit value that is neither `0` nor `1`, and a
gate per registration), together with daimon.

Classify by side-effect using the tool table:

- `nein_tool_read_only(i)` — `1` for `status` / `validate` / `list` / `diff`,
  `0` for `allow` / `deny` (live apply). ⚠ "Read-only" means *does not change
  the firewall*, not *harmless to expose*: `status`, `list` and `diff` run
  `nft -a list ruleset` **as root** and return the live ruleset (`list` and
  `diff` verbatim — set elements, allowed sources, comments), and each call
  spawns a root nft. Only `validate` touches nothing. Do not expose the three
  readers to unauthenticated or low-trust callers; a separate "reads the live
  firewall" class is planned for 1.9.0.
- `nein_tool_admin(i)` — `1` for the mutating tools (the `firewall_admin`
  profile). Expose read-only firewall tools to low-trust agents; gate the
  mutating set to privileged agents.

On the bote-Dispatcher path the same split is carried by bote
`ToolAnnotations` (read-only vs destructive) and the `firewall` /
`firewall_admin` profile tags, filterable via `tools/list?profile=`.

## Arguments (1.8.2)

Every tool now refuses arguments that are not one JSON object whose top-level
keys are spelled plainly and appear once: a duplicate key, or a key written
with an escape (`"\u0070ort"`), is an error. bote reads a key as what it
decodes to and lets the first duplicate win, while most JSON parsers let the
last win, so a host-side filter or an approval UI could be shown a different
argument than nein acts on. `port` must be a plain integer 1–65535 (no sign,
leading zero, fraction or exponent). Tool results are unchanged in shape.

## Signing (optional)

The bundle also exports the signed-ruleset surface: `sign_ruleset(fw, sk,
keyid)`, `verify_ruleset(signed, pubkey)`, and fail-closed
`apply_signed_ruleset(signed, pubkey)` (Ed25519 over the rendered nft body).
Use it if the host stores/serves rulesets and wants at-rest tamper
detection before apply. Build envelope helpers `nein_mcp_ok` / `nein_mcp_err`
are public so host-side firewall tools emit the identical MCP envelope.
