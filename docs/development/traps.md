# Traps

Last refresh: **2026-11-07** (v1.9.2).

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

Data moves it too (1.9.1). `validate_ct_state` read 85 → 124 ns with its code
unchanged: 1.9.1's keyword rows moved where its `"new"` / `"established"`
literals land. A dummy 1- or 3-byte string literal placed before it brought it
back to 88–91 ns; 7 bytes or more, 124–128; padding *code* before it did
nothing. Try both kinds of padding before calling a move a cost.

**Injection-safe is not the same as parseable (1.9.1).** Every validator
since 1.0 asked "can this value inject a command?" and none asked "can nft
read it?" — so `validate_identifier` took `fwd`, `log` and `3f2a` (a hex
container id), `validate_addr` took `1:2:3:4:5:6:1.2.3.4`, and each failed
the whole batch at apply. A list of nft keywords transcribed from the man page
would have been wrong both ways: keywords are scoped (`state` is a name, except
as a ct timeout's), and the man page does not say which. Probe the parser
instead — declare each candidate at each position under `nft -c` in an
`unshare -rn` namespace and keep what it refuses — then keep a test that asks
the installed nft again (`tests/integration/nft_grammar.tcyr`), harvesting the
words nft itself lists in its "expected any of" errors so a new keyword names
itself. Word lists still miss what nobody writes as a word: `eq`, `xor`,
`lshift` and `rshift` are keywords nft prints in its errors as `==`, `^`, `<<`
and `>>`, and an independent review, not the probe, found them. Where the space
is small enough, enumerate it: every lowercase name of 1–5 letters (12.4
million) checks in batches in under 100 s, and the test checks every name up to
3 characters on each run.

**A validator can be quadratic in the work it repeats (1.9.1).** `pe_validate`'s
duplicate-address check compared every pair of agents and re-parsed the later
address of each pair: n²/2 address parses, 112 ms at 1,000 agents. No
benchmark measured `pe_validate` until a bench was added for 1.9.1's composed
names, and it showed 1.1 ms at 100 agents. Parsing each address once into a
buffer made it 15 ms; benchmark the validators at the sizes consumers run.

**nft lists its own spelling, not yours (1.9.2).** `nein_diff` compared each
target rule with the body nft lists, byte for byte, on the reasoning that nft
prints what it was given. It does not. It masks host bits under a prefix and
drops a `/32`, compresses IPv6 through inet_ntop, prints a mark as `0x%08x`
and a DSCP value by name, drops defaults (`until`, `level warn`, an ip table's
`port-unreachable`, `dnat ip` in an ip table), sorts set elements by value and
unwraps a one-element set, and prints every `counter` with its values. So every
chain holding any of those was rebuilt on every diff, and its counters zeroed.
No test noticed, because nothing had nft list what nein applied. The
load test had nft parse each ruleset and never asked for it back. Probe the
listing the same way the parser was probed (`unshare -rn`, load, `nft -a list
ruleset`, diff against itself: `tests/integration/diff_converge.tcyr`), and
predict nft's spelling only for the comparison. Emitting it would trade churn
for a ruleset that an older nft may not parse. Loading a corpus of one chain
per rule shape, which no test had done, also turned up two shapes nft never
loaded (`gbytes`, `exthdr auth`).

**A test can pass a rule it never exercises (1.9.2).** The diff's state strip
keeps quoted text intact, and both tests of that passed when quote tracking
was deleted. Each quoted string began `"counter…`, so the separate
token-start rule (no space before it) protected it on its own. A hand-made
mutant found it, and so did the next one: the quota-usage token-end check had
no test at all. Mutate each condition you wrote, and keep a test per mutant
that dies, not per feature.

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
