# Dependencies

Last refresh: **2026-11-02** (v1.8.1, cyrius 6.7.18).

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

| Dep | Tag (v1.8.1) | Bundle | Why |
|-----|--------------|--------|-----|
| `libro` | 2.11.3 | `dist/libro.cyr` | bote's manifest graph references it |
| `majra` | 2.13.0 | `dist/majra.cyr` | bote's manifest graph references it |
| `bote-core` | 3.7.5 | `dist/bote-core.cyr` | MCP core, transport-free bundle |
| `sigil` | 3.13.15 | `dist/sigil.cyr` | Ed25519 + sha256 + hex for `sign.cyr` |
| `patra` | 1.16.6 | `dist/patra.cyr` | libro's audit store links it |

`libro` + `majra` are declared **before** `bote-core` because bote's graph
references them and Cyrius resolves single-pass.

**How the tags are chosen.** Two rules, because two kinds of pin:

- **libro, majra, bote-core** — the newest tag whose own `[package].cyrius` pin
  is **at or below** nein's. A dep pinned higher may use language or stdlib that
  nein's toolchain does not have.
- **sigil, patra** — **the version the pinned toolchain snapshot folds**, read
  from the `# Version:` line of `~/.cyrius/versions/<pin>/lib/sigil.cyr` and
  `…/patra.cyr`. The snapshot ships both as stdlib leaves, and for sigil cyrius
  keeps the snapshot copy over the dep artifact (`refusing to overwrite stdlib
  leaf 'sigil'`), so the snapshot's version is what compiles whatever the pin
  says. Pinning that version keeps the pin, `cyrius.lock` and the compiled code
  in agreement. Every release through 1.7.1 did this, which is why the first rule
  looked sufficient: at 6.6.20 the newest eligible sigil happened to be the
  snapshot's. At 6.7.9 it is not — 3.13.12–3.13.15 also pin 6.7.9 but were tagged
  after the 6.7.9 snapshot folded **3.13.11** — and pinning 3.13.15 recorded a
  commit in the lock for code that never reached the binary. Confirm with
  `cmp lib/sigil.cyr ~/.cyrius/deps/sigil/<tag>/dist/sigil.cyr`.

| Release | cyrius | libro | majra | bote-core | sigil | patra |
|---|---|---|---|---|---|---|
| 1.7.1 | 6.6.20 | 2.10.8 | 2.9.3 | 3.3.17 | 3.13.10 | 1.15.2 |
| 1.8.0 | 6.7.9 | 2.11.0 | 2.12.0 | 3.4.10 | 3.13.11 | 1.16.0 |
| 1.8.1 | 6.7.18 | 2.11.3 | 2.13.0 | 3.7.5 | 3.13.15 | 1.16.6 |

At 1.8.1 every pin is its repo's newest release and all the rules agree: bote
3.7.5 pins libro 2.11.3 + majra 2.13.0, and libro 2.11.3 pins exactly the sigil
3.13.15 / patra 1.16.6 the 6.7.18 snapshot folds. (bote 3.7.6 was in progress,
untagged, at the time.) At 1.8.0 the rules disagreed: libro 2.11.0 asked for
sigil 3.13.12, and nein's root pin won (`cyrius deps` printed `sigil 3.13.12
(wanted by libro) not used`), which is the pin's second job, below. To list the
candidates:

```bash
for t in $(git -C ../libro tag --sort=-v:refname | head -20); do
  echo "$t $(git -C ../libro show "${t}:cyrius.cyml" | grep -m1 '^cyrius')"
done
```

(Under zsh write `"${t}:cyrius.cyml"`, braces included: a bare `$t:c…` is a
zsh history modifier and silently yields an empty path.)

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
`./lib/`, plus whatever those modules `include`. `cyrius deps` then adds
whatever each git dep's `.deps` sidecar requires on top. Neither set
appears in `cyrius.cyml`. At v1.8.1 there are **71 files in `lib/`
against 31 declared stdlib modules** (63 at v1.7.1 and v1.8.0, 74 at v1.6.8, 77 at v1.7.0).

Collapsing arch/platform variants and counting a family directory as one module, 8 arrive undeclared:

| Module | Pulled by | Notes |
|---|---|---|
| `alloc_cx` | `lib/alloc.cyr` | cx bytecode allocator peer (cyrius 6.6.5+). No cx target in nein. |
| `poison` | `lib/alloc.cyr`, `lib/freelist.cyr` | Allocator poisoning behind `cyrius fuzz --poison` (6.6.18). Inert unless enabled. |
| `boxed` | `lib/tagged.cyr` | Boxed Result/Option surface (6.6.0). |
| `hashseed` | `lib/hashmap.cyr` | Per-process hash seed (hash-flooding DoS). |
| `mmap` | `lib/freelist.cyr`, `lib/thread.cyr` | |
| `sys` | `lib/sigil.cyr`, sigil's sidecar | sigil's `agnosys_uname` calls `sys_uname`. |
| `math` | `lib/bayan.cyr` | Arrived at 1.8.1 (cyrius 6.7.18 snapshot). |
| `unicode` (`lib/unicode/`, 7 files) | `lib/bayan.cyr` | casefold / categories / normalize tables. Arrived at 1.8.1. A family directory counts as one module, as in a `.deps` sidecar; check 8 walks subdirectories since 1.8.1 (it globbed the top level only and could not see this one). |

`hashmap_fast` is also vendored beside `hashmap` and nothing includes it;
the gate folds `_fast` onto its base module.

**Gone at v1.7.1:** the TLS stack (`tls` + seven `tls_native_*`),
`dynlib`, `fdlopen`, `async`, `sandhi` and `test`. They arrived only
through majra's and libro's sidecars, which over-reported until cyrius
6.6.18 began deriving every sidecar by compiling the bundle (see below);
majra 2.9.3 and libro 2.10.8 name none of them. They were pruned from the
gate's list in the same release, so a return fails the build.

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
what a consumer must have in scope.

**Since cyrius 6.6.18 (nein 1.7.1) a sidecar lists only what the bundle
needs to compile on its own**, derived by compiling it across six
targets; `[deps] stdlib` no longer leaks into it. Both of nein's sidecars
are now the single leaf `syscalls`, and each bundle opens with a matching
compile-verified `include "lib/syscalls.cyr"` requires block. Through
6.6.6 `dist/nein.deps` carried the full declared stdlib list (31 leaves).

A consumer therefore declares every stdlib leaf **it** needs in its own
`[deps] stdlib`, including what nein's bundle calls, rather than relying
on nein's sidecar to bring them. A missing one fails the consumer's build
with `hint: '<fn>' is defined by stdlib leaf '<leaf>' — add it to [deps]
stdlib`. nein's own declared list (above) is a complete, working set to
copy from.

⚠ A sidecar may name **stdlib leaves only**. A consumer resolves every
line in it against the pinned toolchain snapshot, so a git-dep bundle
listed there is an assertion the consumer cannot satisfy. Named deps are
excluded by `distlib` automatically — but only when the section name
matches the module basename, which is why the bote section is named
`bote-core` (see above). When adding or renaming a `[deps.*]` entry,
regenerate both bundles and check that nothing new appears in
`dist/nein.deps` / `dist/nein-mcp.deps` that isn't a stdlib module.

## Accepted undeclared transitives — `boxed` and `hashseed` (1.6.11)

Two stdlib modules arrive in `lib/` at cyrius 6.6.x without nein declaring
them, and are recorded in `scripts/supply-chain.sh`'s `ACCEPTED_TRANSITIVES`:

- **`boxed`** — cyrius 6.6.0 moved the *boxed* Result/Option surface
  (`tagged_new`, `boxed_tag`, `boxed_payload`) out of `tagged.cyr` when
  `Result`/`Option`/`Either` became a two-register `(tag, payload)` value.
  Reached through `tagged`, which nein declares.
- **`hashseed`** — cyrius 6.6.x per-process randomized hash seeding, pulled
  in by `hashmap` (declared). Closes a hash-flooding DoS. Note that map
  iteration order now differs between processes.

nein calls no symbol from either directly.
