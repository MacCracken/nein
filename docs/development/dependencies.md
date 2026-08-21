# Dependencies

Last refresh: **2026-08-21** (v1.6.8).

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

> **Correction (1.6.8).** Through 1.6.7 this section stopped at the
> sentence above, which was true about the *declaration* and misleading
> about the *tree*. Declaring nothing does not keep a module out of
> `./lib/`: `cyrius deps` also honours each git dep's own `.deps`
> sidecar, and **`dist/majra.deps` requires `tls`, `dynlib`, `fdlopen`,
> `async` and `sandhi`** — so a full TLS stack (`tls` plus seven
> `tls_native_*` modules) resolves into the tree via majra, not bote.
> nein declares none of them and calls none of them, but they are there
> and are hash-pinned in `cyrius.lock` like everything else. See
> **Undeclared transitives** below.

### `sigil` is not a stdlib entry

It is an explicit `[deps.sigil]` git pin instead — see below.

---

## `[deps.*]` — git pins

| Dep | Tag (v1.6.8) | Bundle | Why |
|-----|--------------|--------|-----|
| `libro` | 2.8.8 | `dist/libro.cyr` | bote's manifest graph references it |
| `majra` | 2.6.7 | `dist/majra.cyr` | bote's manifest graph references it |
| `bote-core` | 3.3.2 | `dist/bote-core.cyr` | MCP core, transport-free bundle |
| `sigil` | 3.12.9 | `dist/sigil.cyr` | Ed25519 + sha256 + hex for `sign.cyr` |
| `patra` | 1.13.9 | `dist/patra.cyr` | libro's audit store links it |

`libro` + `majra` are declared **before** `bote-core` because bote's graph
references them and Cyrius resolves single-pass.

### Why the bote section is named `bote-core`, not `bote`

The section is named for the **module** it pulls, not the repo it pulls from —
the repo is still `bote.git` and the tag is still bote's. This is load-bearing
packaging, fixed in **1.6.6**.

`cyrius distlib` omits a fold from the generated `.deps` sidecar only when the
fold's **basename equals the dep's section name** (`_distlib_named_deps` in the
toolchain's `cbt/commands.cyr`). Under the section name `bote`, the basename
`bote-core` matched nothing, so `src/main.cyr`'s `include "lib/bote-core.cyr"`
was written into **both** `dist/nein.deps` and `dist/nein-mcp.deps` as a
**stdlib leaf** — claiming bote-core ships in the cyrius stdlib, which it does
not.

Every consumer's `cyrius deps` then failed:

```
error: dep nein requires 'bote-core' but it is not in the cyrius stdlib
```

The defect shipped in 1.6.4 and 1.6.5 but stayed **invisible until cyrius
6.5.24**. Through 6.5.23, `_dep_find_stdlib_dir()` returned the consumer's own
half-populated `./lib` as the stdlib for any project with a `src/main.cyr` — and
a consumer that declares bote drops `lib/bote-core.cyr` there itself, so the bad
leaf resolved by accident. 6.5.24/6.5.25 fixed that lookup to consult the pinned
snapshot, and the latent bug surfaced as a hard error in every downstream repo
(filed from stiva 3.0.17).

Renaming the section makes the basename match, so distlib treats the fold as a
named dep and resolves it transitively instead of listing it as a leaf. Nothing
else changes: `cyrius.lock` records the same commit, url and tag (only the dep
label moves), and both `dist/*.cyr` bundles differ only by their version banner
— the two removed sidecar lines are the entire functional change.

⚠ Same rule, same trap, elsewhere in the ecosystem: libro's CLAUDE.md quirk #9
documents the identical failure for its thin `sigil-mldsa` folds. **Any dep
whose section name differs from its module basename will do this.** Of nein's
five pins, only bote had that mismatch.

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

## Undeclared transitives

`cyrius lib sync` copies the declared `[deps].stdlib` subset into
`./lib/`. `cyrius deps` then adds whatever each git dep's `.deps`
sidecar requires on top. That second set appears nowhere in
`cyrius.cyml`, so at v1.6.8 there were **74 files in `lib/` against 31
declared stdlib modules**.

Collapsing arch/platform variants, 14 base modules arrive undeclared:

| Module(s) | Pulled by | Notes |
|---|---|---|
| `tls`, `tls_native`, `tls_native_{conn,ctx,hs12,hs13,keysched,lowlevel}` | majra | Full TLS stack. nein calls none of it. |
| `dynlib`, `fdlopen` | majra | Dynamic loading. |
| `async`, `sandhi` | majra | Async runtime + transport. |
| `mmap` | toolchain snapshot | |
| `test` | libro | |

nein cannot control a dependency's own sidecar, so these are recorded
rather than removed. They are enumerated in
[`scripts/supply-chain.sh`](../../scripts/supply-chain.sh)'s
`ACCEPTED_TRANSITIVES`, and its check 8 **fails the build if a module
appears in `lib/` that is neither declared nor on that list** — so the
next arrival is noticed instead of slipping in the way this one did.
See [`supply-chain-policy.md`](supply-chain-policy.md).

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

⚠ A sidecar may name **stdlib leaves only**. A consumer resolves every
line in it against the pinned toolchain snapshot, so a git-dep bundle
listed there is an assertion the consumer cannot satisfy. Named deps are
excluded by `distlib` automatically — but only when the section name
matches the module basename, which is why the bote section is named
`bote-core` (see above). When adding or renaming a `[deps.*]` entry,
regenerate both bundles and check that nothing new appears in
`dist/nein.deps` / `dist/nein-mcp.deps` that isn't a stdlib module.
