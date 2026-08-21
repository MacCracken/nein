# Dependencies

Last refresh: **2026-08-21** (v1.6.5).

Why each entry in `cyrius.cyml`'s `[deps]` block exists, and why the
resolution order is what it is. This file is the prose home for that
rationale — the manifest itself carries no comments inside the `stdlib`
array, because the `.cyml` parser scans `#` comment text for quoted
tokens and `[section.name]` headers and mis-resolves deps when it finds
them there.

---

## Build sequence

Cyrius does **not** auto-resolve dependencies. Two explicit steps, in
order:

```bash
cyrius lib sync   # copy the declared [deps].stdlib subset from the pinned
                  # toolchain snapshot into ./lib/
cyrius deps       # clone each [deps.NAME] at its tag, copy dist/*.cyr into ./lib/
```

`lib sync` must run first: the git-dep bundles' own requirements resolve
against what is already in `./lib/`. `./lib/` is gitignored; `dist/` and
`cyrius.lock` are tracked.

---

## `[deps].stdlib` — declared subset

The list is a **declaration**, not a convenience: nothing is pulled that
isn't named. Order matters — Cyrius is single-pass, so a module must
precede anything that forward-references it.

### Core surface (nein's own code)

`string`, `fmt`, `alloc`, `vec`, `str`, `syscalls`, `io`, `args`,
`assert`, `tagged`, `result`, `hashmap`, `process`, `bench`, `fnptr`,
`callback`, `freelist`, `fs`, `net`, `regex`, `chrono`, `sakshi`.

`sakshi` backs the structured tracing on every operation (the audit
trail). `tagged` + `result` back the packed `Result` used by every
fallible function.

### `bayan` — JSON

Added at **1.6.0**. The 6.1.x consolidated data module (`json_parse` /
`json_get`). Required by the bote-core bundle (its `.deps` sidecar folds
in only `hashmap` + `bayan`) and by `src/lib/mcp.cyr`'s handlers, which
read tool-call arguments as JSON.

### Transitive stdlib for the bote-core / sigil stack

Added at **1.6.1**: `ct`, `keccak`, `random`, `slice`, `thread`,
`thread_local`, `sync`, `atomic`.

- The Ed25519 sign path (`src/lib/sign.cyr`) needs `ct` / `keccak` /
  `random` / `slice` / `thread` / `thread_local`.
- libro / majra / patra add `sync` / `atomic`.
- `ct` / `keccak` / `random` precede `sigil` so the single-pass forward
  references resolve; `thread` precedes `thread_local` for sigil's TLS
  `crypto_scratch` path.

This is the **minimal** set for the transport-free bote-core. bote's
full-transport deps — `ws_server`, `tls`, `sandhi` — are deliberately
**not** declared. nein renders and applies rules; it terminates no
sockets.

### `sigil` is not a stdlib entry

It is an explicit `[deps.sigil]` git pin instead — see below.

---

## `[deps.*]` — git pins

| Dep | Tag (v1.6.5) | Bundle | Why |
|-----|--------------|--------|-----|
| `libro` | 2.8.8 | `dist/libro.cyr` | bote's manifest graph references it |
| `majra` | 2.6.7 | `dist/majra.cyr` | bote's manifest graph references it |
| `bote` | 3.3.2 | `dist/bote-core.cyr` | MCP core, transport-free bundle |
| `sigil` | 3.12.9 | `dist/sigil.cyr` | Ed25519 + sha256 + hex for `sign.cyr` |
| `patra` | 1.13.9 | `dist/patra.cyr` | libro's audit store links it |

`libro` + `majra` are declared **before** `bote` because bote's graph
references them and Cyrius resolves single-pass.

### Why `sigil` gets a top-level pin

Two jobs, both dating to **1.6.3**:

1. **Reach the latest self-contained bundle.** The stdlib registry in a
   toolchain snapshot lags the upstream sigil release; a top-level git
   pin tracks the real thing.
2. **Win over libro's thin sub-bundles.** libro 2.8.x pulls transitive
   thin sigil pieces (`sigil-mldsa`, `sha_ni`, `sha256`, `hex`). Without
   the explicit pin those co-exist with the full bundle and collide —
   226 duplicate-fn last-definition-wins warnings, since the full bundle
   re-defines every sha / hex / ed25519 function the thin set carries.

nein's whole sigil surface is `src/lib/sign.cyr`'s ed25519 + sha256 +
hex. bote-core uses no sigil crypto.

### `patra`

libro 2.8.x's audit store links it, and libro's `.deps` sidecar pulls it
transitively. It is pinned explicitly as well so the pin stays current
independent of libro's own choice and no shadow-lib warning fires. nein
calls no patra symbol directly.

### `sakshi`

Through 1.6.4 sakshi resolved as a **git** dep (tag 2.4.6), pulled
transitively by libro. As of the 1.6.5 refresh libro 2.8.8 no longer
requires it that way, so sakshi resolves purely from the declared
`[deps].stdlib` list against the 6.5.33 toolchain snapshot. Dep count
dropped 6 → 5 commit-pinned.

---

## Dropped

**`[deps.agnosys]`** — dropped at the agnosys → agnodrm decomposition
(2026-06-19). nein never called an agnosys symbol: the netns apply-side
is invoked by the integrator against the kernel-interface library
directly (see `src/lib/netns.cyr`), so nein carried no real agnosys
surface. The local `path = "../agnosys"` also broke when the repo folder
was renamed.

**`src/vendor/bote-core.cyr`** — the vendored bundle used through 1.6.0,
retired at 1.6.1 once bote's core-bundle `.deps` sidecar resolved
correctly and the git dep could be restored.

---

## `dist/*.deps` sidecars

`cyrius distlib` writes a `.deps` sidecar next to each bundle naming
what a consumer must have in scope. Toolchain 6.5.x widened
`dist/nein.deps` from a computed leaf set to the full declared stdlib
list. Consumers of `dist/nein.cyr` that declared a narrower `[deps]
stdlib` will need to widen theirs to match — the names are all stdlib
modules, so `cyrius lib sync` covers them.
