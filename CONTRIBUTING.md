# Contributing to nein

Thank you for your interest in contributing to nein. This document covers
the development workflow, code standards, and project conventions for the
Cyrius-era codebase.

Last refresh: **2026-08-21** (v1.6.5).

## Development Workflow

1. **Fork** the repository on GitHub.
2. **Create a branch** from `main` for your work.
3. **Make your changes**, ensuring all CI gates pass locally.
4. **Open a pull request** against `main`.

## Prerequisites

- Cyrius toolchain ≥ **6.5.33** (pinned in `cyrius.cyml`). Install
  via the canonical release:
  ```sh
  curl -sLO https://github.com/MacCracken/cyrius/releases/download/6.5.33/cyrius-6.5.33-x86_64-linux.tar.gz
  tar xzf cyrius-6.5.33-x86_64-linux.tar.gz
  # then copy bin/* and lib/* into ~/.cyrius/versions/6.5.33/
  # and symlink ~/.cyrius/bin -> ~/.cyrius/versions/6.5.33/bin
  ```
- `nft` binary at the pinned default `/usr/sbin/nft` (override elsewhere
  at runtime via `nein_set_nft_path`) for any local apply-layer smoke
  testing. The library itself doesn't need it at compile time.

CI installs the same version from the GitHub release URL — see
`.github/workflows/ci.yml`'s "Install Cyrius toolchain" step.

## Reproducing CI Locally

There is no Makefile — `cyrius` is the build tool. The full CI gate
set reproduces with:

```sh
cyrius lib sync                                   # sync declared stdlib subset from pinned snapshot
cyrius deps                                       # resolve git bundles into ./lib/
cyrius deps --verify                              # confirm cyrius.lock hashes

# Format / lint / vet
# NOTE (cyrius 6.5.x): `cyrius fmt <file>` formats IN PLACE and prints
# nothing — `--check` is the drift check. Do not diff fmt's stdout; that
# was the 6.4.x recipe and it now rewrites your tree as a side effect.
for f in src/main.cyr src/lib/*.cyr tests/*.tcyr tests/*.bcyr \
         tests/integration/*.tcyr fuzz/*.fcyr; do
  cyrius fmt --check "$f" >/dev/null 2>&1 || echo "drift: $f"
done
for f in src/main.cyr src/lib/*.cyr fuzz/*.fcyr; do cyrius lint "$f"; done
cyrius vet src/main.cyr
cyrius capacity --check src/main.cyr              # real gate since 1.6.5

# Build (DCE) on both arches
CYRIUS_DCE=1 cyrius build src/main.cyr build/nein
CYRIUS_DCE=1 cyrius build --aarch64 src/main.cyr build/nein-aarch64

# Type-check (cyrius 6.x default-on)
CYRIUS_TYPE_CHECK=1 cyrius build src/main.cyr build/nein-tc

# Test + bench + fuzz
cyrius tests                                      # all .tcyr, incl. integration
cyrius bench tests/nein.bcyr
cyrius fuzz

# Surface + regression gates
./scripts/api-surface.sh check
./scripts/bench-regression.sh

# Dist bundles must be regenerated and committed when src/lib/ or [lib] moves
cyrius distlib && cyrius distlib mcp
git diff --exit-code dist/                        # must be clean
```

Before opening a PR, confirm every step exits 0. The `Currency check`
CI step also verifies `CHANGELOG.md` has a dated entry for the current
`VERSION` and that the roadmap's `Last refresh:` marker is ≤ 90 days
old — bump both in the same PR if shipping a release.

## Adding a New Module

1. Create `src/lib/<module>.cyr` with the implementation.
2. Add a top-level `include "src/lib/<module>.cyr"` in `src/main.cyr`,
   placed in dependency order (see the existing layout — `error` →
   `validate` → core types → feature modules → integrators).
3. Add tests in `tests/nein.tcyr` under a new `=== <module> ===`
   block. Each public fn needs at least one assertion.
4. Add benchmarks in `tests/nein.bcyr` for any hot-path fn.
5. Run `./scripts/api-surface.sh update` and commit the regenerated
   `docs/api-surface.snapshot` in the same PR.
6. Update `README.md`'s module table.
7. Update `CHANGELOG.md`'s Unreleased / next-version section.

## Code Style

- **Format**: `cyrius fmt <file>` produces the canonical layout; the
  CI gate fails on any drift. Run before committing.
- **Lint**: `cyrius lint <file>` should emit zero `warn ` lines on
  src/ files. The 120-char limit applies to source; long lines in
  test fixtures (verbatim nftables grammar) are tolerated
  informationally.
- **Type annotations**: public-API fns carry `(arg: cstring|i64|Str): i64`
  shapes. The cstring boundary is the security surface — annotate any
  fn that flows user-controlled strings into nftables grammar.
  Internal polymorphic constructors (e.g. `match_new(mtype, v1, v2, v3)`)
  may stay un-annotated where the args are intentionally heterogeneous.
- **No comments that restate identifiers**. Comment WHY, not WHAT.
- **No magic**: every syscall site is sakshi-traceable; no `sys_system`;
  no PATH reliance in execve (use absolute paths only).

## Testing

- Every new fn under `src/lib/` needs an assertion in `tests/nein.tcyr`.
- Validators (the injection-safety surface) require fuzz coverage in
  `fuzz/*.fcyr` for both positive and negative cases.
- Benchmark any fn likely to be called per-rule or per-packet-evaluation.
- Integration tests against a real `nft` binary live behind the
  `NEIN_INTEGRATION=1` env gate (`tests/integration/*.tcyr` — 16 tests:
  6 apply_smoke + 10 mcp_consume_smoke).

## Performance

If your change touches a hot path (rule rendering, validation,
firewall_render), capture before/after numbers and include them in the
PR description. The CI `bench-regression` gate fires automatically on
> 50% (ns-bracket) or > 80% (µs-bracket) slowdown vs the most recent
committed baseline in `docs/benchmarks/history.csv`. To deliberately
ack a regression (correctness fix that costs perf), include
`[bench-regression-ack]` in the HEAD commit message.

Baselines are recorded with `./scripts/bench-track.sh`, which runs
`cyrius bench` and appends a row set to `docs/benchmarks/history.csv`.
Record deliberately — a new baseline moves the floor the gate compares
against, so it belongs on a release commit, not mid-cycle. Use
`--dry-run` to see the numbers without writing, and `--compare` to diff
the last two baselines.

## Cutting a Release

`./scripts/version-bump.sh <x.y.z>` moves `VERSION` (which `cyrius.cyml`
pulls through `${file:VERSION}`), regenerates both dist bundles — they
bake a version banner, and CI's staleness gate fails on a stale one —
and then reports what the bump still owes: the dated `CHANGELOG.md`
entry, the roadmap's `Last refresh:` recency, and any doc still naming
the outgoing version. `--check` reports without writing anything.

Tagging `x.y.z` runs the full CI gate set, then `release.yml`
regenerates and staleness-checks **both** `dist/nein.cyr` and
`dist/nein-mcp.cyr` along with their `.deps` sidecars, and attaches all
four as release assets alongside the source tarball and the x86_64
binary. Commit the regenerated bundles before tagging or the release
fails.

## Threat Model

When changing the validation surface (`src/lib/validate.cyr`), the
apply layer (`src/lib/apply.cyr`), or the inspect parser
(`src/lib/inspect.cyr`), update `docs/development/threat-model.md` in
the same PR with which numbered threat (T-1 … T-8) the change touches
and how. The model file is the single source of truth for the
injection surface — keep it current.

## License

nein is licensed under **GPL-3.0-only**. All contributions must be
compatible with this license. By submitting a pull request, you agree
that your contribution is licensed under the same terms.
