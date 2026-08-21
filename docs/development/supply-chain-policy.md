# Dependency Supply-Chain Policy

Last refresh: **2026-08-21** (v1.6.8).

What nein is allowed to depend on, and how that is enforced. Successor to
the Rust tree's `deny.toml` (cargo-deny), which was retired together with
`rust-old/` at v1.6.8.

Enforced by [`scripts/supply-chain.sh`](../../scripts/supply-chain.sh),
which runs as a CI gate. `scripts/supply-chain.sh --print` prints the
effective policy without checking anything.

---

## Why this file exists instead of a `cyrius deny` config

The obvious move when retiring `deny.toml` was to port its allow-list
into `cyrius deny`. That is not possible, and the name is the trap:

- **`cyrius deny <src>` is not a supply-chain tool.** It is an
  include-path checker — it rejects `include` directives using absolute
  paths or `../` parent traversal. It takes no configuration.
- **`cyrius vet <src>`** checks each include resolves and sits under a
  trusted prefix (`lib/`, `src/`, `programs/`, `cbt/`, `kernel/`). That
  prefix set is compiled into the toolchain; there is no allow-list.

Both are worth running and both do run in CI, but neither can express
"only these sources, only these licences". So the licence and source
policy lives in a first-party script that reads `cyrius.cyml` and
`cyrius.lock` directly.

---

## The policy

### Sources

Every `[deps.*]` git URL must sit under:

```
https://github.com/MacCracken/
```

First-party AGNOS only. This is the manifest-level expression of
CLAUDE.md's **own the stack** principle: if an AGNOS crate wraps an
external library, nein depends on the AGNOS crate, never on the external
one. There is no package registry in the Cyrius world, so cargo-deny's
separate `unknown-registry` rule collapses into this one check.

### Pinning

Every dependency must pin an **exact, immutable tag**:

- `git = "…"` + `tag = "…"` — required
- `branch = "…"` — rejected (floating)
- `rev = "…"` — rejected (pin by tag; `cyrius.lock` resolves it to a sha)
- `path = "…"` — rejected (not reproducible off one machine)

Every declared dep must also carry a 40-character commit sha in
`cyrius.lock`, and the tag recorded there must match the manifest. A
mismatch means someone edited the manifest without re-running
`cyrius deps`, and the build is resolving something other than what the
manifest says.

### Duplicates

A dep name declared twice is an **error**, not a warning. cargo-deny
treated `multiple-versions` as a size annoyance; here it is a
correctness bug — Cyrius resolves single-pass with last-definition-wins,
so two versions of one bundle silently picks one and mis-links the
other's callers.

### Licences

Every dependency's own declared licence must be on this list, carried
forward verbatim from `deny.toml`'s `[licenses].allow`:

`MIT` · `Apache-2.0` · `Apache-2.0 WITH LLVM-exception` · `BSD-2-Clause`
· `BSD-3-Clause` · `ISC` · `Unicode-3.0` · `GPL-3.0-only` ·
`LGPL-3.0-only` · `AGPL-3.0-only` · `MPL-2.0` · `Zlib`

All are GPL-3.0 compatible, which nein (`GPL-3.0-only`) requires of
anything it links. nein's own licence is checked against the same list.

The list is **not** narrowed to what is used today. Every current dep is
`GPL-3.0-only`, but narrowing would fail the first time a legitimately
permissive bundle is added, and the original list was already a
deliberate decision rather than an accident of the dependency graph.

The check reads each dep's licence out of its **resolved clone**
(`~/.cyrius/deps/<name>/<tag>/cyrius.cyml`) rather than a value restated
in nein's own tree — an attestation nobody verifies is worth nothing.
This is why `cyrius deps` must run before the gate.

### Advisories

Not applicable, and deliberately so. cargo-deny's `[advisories]` section
consumed the RustSec database; there is no advisory feed for AGNOS
bundles. The nearest equivalents already run in CI:

- `cyrius deps --verify` — sha256 of every resolved dep against
  `cyrius.lock`, failing on any drift
- the CI security scan — `sys_system`, path writes, oversized buffers
- the per-release security audit pass described in CLAUDE.md

---

## Current attestation (v1.6.8)

| Dep | Tag | Source | Licence |
|-----|-----|--------|---------|
| `libro` | 2.8.8 | github.com/MacCracken/libro | GPL-3.0-only |
| `majra` | 2.6.7 | github.com/MacCracken/majra | GPL-3.0-only |
| `bote-core` | 3.3.2 | github.com/MacCracken/bote | GPL-3.0-only |
| `sigil` | 3.12.9 | github.com/MacCracken/sigil | GPL-3.0-only |
| `patra` | 1.13.9 | github.com/MacCracken/patra | GPL-3.0-only |

The `bote-core` section is named for the **module** it pulls, not the
repo it pulls from — see [`dependencies.md`](dependencies.md) for why
that rename was load-bearing.

This table is documentation, not the source of truth. The script derives
all of it live; if the two disagree, the script is right and this table
is stale.

---

## What cargo-vet's `supply-chain/` became

Nothing, on purpose. Those `audits.toml` records attested to crates.io
packages (`serde`, `cfg-if`, `criterion`, …) that are not in nein's
dependency graph any more — none of them survived the port. Re-creating
them would mean attesting to packages nein does not use.

Dependency integrity is now `cyrius.lock` plus `cyrius deps --verify`:
every resolved file is sha256-pinned and CI fails on drift.

---

## Running it

```bash
cyrius lib sync && cyrius deps    # must run first — the licence check
                                  # reads the resolved clones
./scripts/supply-chain.sh         # enforce
./scripts/supply-chain.sh --print # show the policy, check nothing
```
