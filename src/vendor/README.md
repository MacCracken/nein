# vendor/

Vendored third-party Cyrius bundles. **Do not hand-edit the `.cyr` files
here — they are generated artifacts.** Update them only by re-copying from
the upstream source at the pinned version (see below).

## `bote-core.cyr`

The transport-free **core profile** of [bote](https://github.com/MacCracken/bote)
(MCP core service) — `dist/bote-core.cyr`. Provides the Dispatcher /
ToolRegistry / schema / jsonx / content-envelope surface that
`src/lib/mcp.cyr` registers nein's MCP tools against. nein owns no
transport, so it takes the core (opt-in) profile, not the full bundle.

| | |
|---|---|
| Source | `bote` `dist/bote-core.cyr` |
| Version | **3.0.0** (git commit `8bd9db4`) |
| sha256 | `b31b4a3097095cbaf2aa5dcb6171de5e905a327015a1b6d0915f0ec9b7f6e66f` |
| Folds in | `hashmap`, `bayan` only (per its `.deps` sidecar — both opt-in in `cyrius.cyml [deps] stdlib`) |

### Why vendored instead of a `[deps.bote]` git dep

The normal path is a git dep (`git` + `tag` + `modules = ["dist/bote-core.cyr"]`,
per bote's `DEPS-PATTERN.md`). It does **not work** for a core-bundle
consumer today: `cyrius deps` recursively resolves bote's *manifest*
git-deps (libro / majra / patra / sigil) rather than the bundle's own
`.deps` sidecar (`hashmap` + `bayan`). Those transitive deps fail —
`dep libro requires 'ct' but it is not in the cyrius stdlib` (even though
`ct.cyr` exists in the 6.3.45 snapshot, and even after adding the demanded
modules to `[deps] stdlib`) — and because `cyrius build` runs deps first,
the whole build is blocked. This contradicts bote's DEPS-PATTERN.md
("core consumers … without `slice` / `sigil`").

Vendoring the self-contained bundle sidesteps the broken transitive
resolution: it needs only `hashmap` + `bayan`, which nein already declares.

This is a **documented temporary bridge**. Filed upstream on bote's
roadmap. Restore the `[deps.bote]` git dep and delete this file once
bundle-dep resolution is fixed upstream (bote-core declaring no git-deps,
or `cyrius deps` honoring the `.deps` sidecar).

### How to update

```sh
cp ../bote/dist/bote-core.cyr src/vendor/bote-core.cyr   # from bote at the pinned tag
sha256sum src/vendor/bote-core.cyr                        # update the table above
cyrius build src/main.cyr build/nein                  # rebuild + test
```

Confirm the bundle still folds in only `hashmap` + `bayan`
(`grep '^include' src/vendor/bote-core.cyr`); if bote's core profile grows a
new stdlib fold, add it to `[deps] stdlib`.
