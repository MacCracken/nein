# Traps

Last refresh: **2026-11-03** (v1.9.0).

Things that looked right, were wrong, and cost a round of investigation each.
Kept so the next person does not re-step in them. This is reference, not a plan:
open work lives in [`roadmap.md`](roadmap.md), shipped history in
[`CHANGELOG.md`](../../CHANGELOG.md). Through 1.8.1 these sat in the roadmap
under "Traps worth not re-stepping in"; they moved here at 1.8.2 when the roadmap
was cut back to future work only.

Add to this file when a fix teaches something the code cannot say for itself —
especially a gate or tool that reports green over input it did not examine.

---

**The value form fails OPEN when migrated naively (1.6.11).** Since cyrius
6.6.0 a `Result` is a two-register `(tag, payload)` value. `var vr = f();` binds
the **tag only**, so the once-idiomatic `if (is_err_result(vr) == 1) { return vr; }`
returns the payload alone and the caller reads an `Err` as **success**. 104 nein
sites were on that path. Bind both halves and propagate with `return Err(v);`.
The compiler now warns, and the type-check gate enforces it — see the next item
for why that gate cannot filter on the warning's text.

**A gate must not share a defect with the thing it checks (1.6.11).** cyrius
6.6.x warns on `return None();` even though `lib/tagged.cyr` documents the
nullary constructor as correctly tag-only — and the false positive's message is
**byte-identical** to a real propagation trap's. Filtering the text would have
made the gate green while blinding it to the class above. The gate instead reads
the reported source line, deriving the exemption a different way than the
message. Injection-verified. If you ever relax this gate, re-run that injection.

**A gate's count is part of its claim — make it fail when the count is short (1.8.1).**
"0 regressions" from a gate that compared 21 of 48 benchmarks, and "all declared or
accepted" from one that never looked in `lib/unicode/`, are both false greens, and
neither printed anything wrong. Each skipped its input silently: a parser regex that
did not match, a glob that did not recurse. The fix in both is the same shape: derive
the set the gate SHOULD cover independently of the set it managed to read (the
baseline's benchmark list; a recursive `find`), and fail on the difference. When you
add a gate, ask what it does with input it cannot parse.

**A gate that passes here can fail where it actually runs (1.8.2).** The 1.8.2 benchmark baseline
was recorded on the release machine and the bench gate checked here — 48 of 48, 0 regressions — and
CI failed on the first push: GitHub's runner was 1.23×–1.82× slower on every benchmark, and one
crossed the 80% threshold. The offset had been documented since 1.6.8; the thresholds only absorbed
it while it happened to fit. A gate that compares against a recorded value is only verified where it
runs, against what it will see there. When CI cannot be run locally, replay its recorded output
through the gate (the 1.8.2 fix was proven on the failing run's exact numbers), and design the gate
so the machine cancels out instead of hoping it fits.

**A test that asserts the output can enshrine the bug it should catch (1.8.2).** The 2026-11-03
audit found five: tests asserted `define $LAN = …`, `icmp accept`, `tcp log prefix …` and
`oif "br0" jump …` — all four rejected by nft — and the signing test filled a "secret key" with
bytes 0–63 whose public half does not match the seed; sigil refused to sign, nein ignored the
refusal, and "a clean body still signs" passed on an envelope that could never verify. Every
builder test checked substrings of rendered text, so the mesh ruleset that nft has always refused
shipped green. An assertion over generated output needs an oracle outside the generator: load the
text into real nft (`tests/integration/nft_load.tcyr`), verify the signature with the key, round-trip
the parse. "It renders what I expected" only proves the expectation was transcribed.

**On a cyrius pin move, regenerate `cyrius.lock` — don't patch it (1.7.1).** The 6.6.17 release
notes predicted CI would refuse a stale lock at `lib sync`. What actually happens: a plain
`cyrius lib sync` restamps the lock to the new pin but re-hashes only the *declared* stdlib leaves,
so the include-closure leaves (`boxed`, `hashseed`, `mmap`, `sigil`, `sys`) keep the old pin's
hashes, and the next `cyrius deps` refuses them as "changed under an unchanged pin". `deps --relock`
gets past it but leaves the old tags' commit rows beside the new ones. What worked:
`rm -rf lib cyrius.lock && cyrius lib sync && cyrius deps`, then prove it by running CI's
`lib sync` → `deps` → `deps --verify` once more and checking the lock is byte-identical. Expect one
commit row per dep and as many hash rows as files in `lib/`.

**Removing `[deps.sigil]` / `[deps.patra]` to silence `refusing to overwrite
stdlib leaf` makes things worse (1.6.11).** The pins look inert — cyrius treats
both as stdlib leaves and skips the dep artifact, so `lib/sigil.cyr` is
byte-identical to the toolchain snapshot. But the sections are load-bearing for
their *exclusion* effect: without them libro's sidecar resolves its thin sigil
sub-bundles (`sigil-mldsa`, `sigil-x509`, …) into `lib/`, colliding with the
full bundle across dozens of `duplicate fn` warnings. Measured, not guessed.

**sigil and patra pin the toolchain snapshot's fold, not their newest tag (1.8.0).** cyrius
keeps the snapshot's `lib/sigil.cyr` over the dep artifact, so whatever the pin says, the
snapshot's sigil is what compiles. At 1.8.0 the newest sigil tag eligible for 6.7.9 was 3.13.15
but the 6.7.9 snapshot folds 3.13.11; pinning 3.13.15 put a commit in `cyrius.lock` for code
that never reached the binary. Read the version from `~/.cyrius/versions/<pin>/lib/sigil.cyr`
and confirm with `cmp lib/sigil.cyr ~/.cyrius/deps/sigil/<tag>/dist/sigil.cyr`. The full rule
is in [`dependencies.md`](dependencies.md).

**A function-pointer call reads a `Result` as its tag (1.9.0).** `fncall2(fp, a,
b)` returns one register. A callee that returns a `Result` hands back its tag —
`Ok` is `0`, `Err` is `1` — and nothing warns. The 1.6.1 MCP gate permitted on
`== 1`, so a gate written the way "Packed Result for fallible operations"
suggests had `Err` **permit** (audit M-2). Any contract crossing a run-time
pointer needs a sentinel that no `bool`, tag, error code or pointer can equal —
1.9.0's `NEIN_GATE_PERMIT` is a 64-bit value above the user-space address range.

**A fuzzer only finds what its alphabet can spell (1.9.0).** The first
`sign_v2_parse` run passed against a parser deliberately broken to strip a
trailing `\r` from header values — a textbook ambiguity — because no mutation
could insert a lone `\r` before a newline: the dictionary had `"\r\n"` (which
also adds a line) and the byte-replace hit the newline itself. Before trusting
a green fuzz run, break the code under test in the way the oracle is meant to
catch and watch it fail; then keep the dictionary entry that made it fail. The
same driver then missed a real defect a reviewer found — a NUL inside a header
line — because every dictionary entry is a C string and cannot carry a NUL: the
alphabet has to be checked against the bytes the input format can hold, not
the ones a string literal can.

**A benchmark can move 20% on layout alone (1.9.0).** Adding includes to
`tests/nein.bcyr` moved `firewall_1000_rules_validate` 249 → ~310 µs with its
code untouched. Bisecting the includes moved it back and forth (one subset
305 µs, a larger one 263 µs) — placement, not cost. When one benchmark moves
after a change that did not touch it, run the previous bench file against the
new sources before calling it a regression or a win.

Three toolchain subcommands do **not** do what their names suggest, and each
cost a round of investigation:

- `cyrius deny` is an **include-path checker** (absolute paths, `../`
  traversal). It takes no allow-list and cannot carry a licence or source
  policy — that is `scripts/supply-chain.sh`.
- `cyrius coverage --min` measures **reference** coverage from an entry point.
  On this tree its default mode walks only `src/main.cyr` and reports
  1/1 = **100%**, so `--min 80` would pass vacuously while measuring nothing.
  Do not wire it.
- `cyrius doc --check` does the right analysis but **exits 0 regardless**, and
  only examines the one file handed to it. `scripts/doc-coverage.sh` sums it
  and supplies the exit code.
