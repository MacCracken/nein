# Nein Capability Map

Per-module kernel-surface capability — the syscalls, `sys_*` wrappers,
subprocess binaries, and hard-coded filesystem paths each module can
touch. Hand-curated from `src/main.cyr` + `src/lib/*.cyr` (nein is
small enough that a generator script isn't needed yet — agnosys's
`scripts/gen-capability-map.sh` pattern would be the template if it
gets one).

**Last refresh:** 2026-11-07 (v1.9.3 — no capability change: the family and hook checks are computation-only, and `tests/integration/nft_family.tcyr` runs `unshare -rn nft` from the test. Previously v1.9.2 — no capability change: the diff's canonical comparison is computation-only, and `tests/integration/diff_converge.tcyr` runs `unshare -rn nft` from the test, not the library. Previously v1.9.1 — no capability change: the new validators are computation-only, and `tests/integration/nft_grammar.tcyr` runs `unshare -rn nft -c` from the test, not the library. Previously v1.9.0 — `mcp`: the live readers are their own class; `sign`: v2 is computation-only, no clock read; no syscall added. Previously v1.8.2 — the apply path moved from pipes to memfds and a pidfd; the syscall set and filesystem paths changed)
**nein version:** 1.6.10
**cyrius version:** 6.5.33

## How to read this

For each module, four capability columns:

- **Syscalls**: direct `syscall(SYS_*)` references — kernel syscalls
  the module invokes directly. Most modules use zero direct syscalls;
  the stdlib `sys_*` wrappers are preferred.
- **`sys_*` wrappers**: cyrius stdlib helpers — each maps to one
  kernel syscall (e.g. `sys_memfd_create` → `memfd_create(2)`,
  `sys_execve` → `execve(2)`).
- **Subprocess binaries**: hard-coded absolute paths the module
  invokes via `sys_execve`. No PATH consultation — see threat model T-3.
- **Filesystem paths**: hard-coded `/sys`, `/proc`, `/dev`, `/etc`,
  `/var`, `/run` paths (read or written).

This is a static scan, not a call-graph. Module accessors (e.g.
`firewall_render`) that don't directly invoke syscalls but call into
modules that do, inherit the callee's footprint.

## Capability roll-up — for seccomp / sandbox authors

If a caller imports the full `dist/nein.cyr` bundle (v1.2.0 onward),
the worst-case syscall surface is the union below. Two reading lenses:

### Lens 1: rendering-only callers

Most consumers (stiva for rule construction, daimon for policy
descriptors, sutra for playbook expansion) only call the **builder +
render + validate** surface. Those callers see:

- **Direct syscalls:** `SYS_EXIT` (top-level `main()` exit; not
  invoked by library functions)
- **`sys_*` wrappers:** none — pure value construction and string
  rendering
- **Subprocess binaries:** none
- **Filesystem paths:** none

This is the **safe surface** — a seccomp allowlist for a rendering-
only consumer doesn't need any nein-attributable syscalls.

### Lens 2: apply-layer callers

Callers that invoke `apply_*` / `list_ruleset*` (aegis at host, daimon
when wiring agent firewalls, integration tests) additionally see:

- **Direct syscalls:** none
- **`sys_*` wrappers (1.8.2):** `sys_memfd_create`, `sys_write`,
  `sys_lseek`, `sys_open` (`/dev/null`), `sys_getpid`, `sys_fork`,
  `sys_pidfd_open`, `sys_kill`, `sys_waitpid`, `sys_read`, `sys_close`,
  `sys_exit`; in the child `sys_sigprocmask`, `sys_prctl`, `sys_getppid`,
  `sys_fcntl`, `sys_dup2`, `sys_execve`. Plus `poll` via the stdlib's
  `fd_wait_ready`, `rt_sigaction` via `signal_ignore` / `signal_default`, and
  `close_range` (raw syscall 436).
  ⚠ **The 1.8.2 apply path changed this set** (memfds and a pidfd replaced
  the pipes; `pipe2` is gone): **a seccomp allowlist built from an earlier
  version of this map will kill the first apply.**
- **`rt_sigaction`** (via the stdlib's `signal_ignore(13)`), called once
  before the first apply to set SIGPIPE to `SIG_IGN`. Added at v1.6.10; since
  1.8.2 nein writes to no pipe, so the guard is kept only so a host relying on
  its process-wide effect sees no change. Disable with
  `nein_set_sigpipe_guard(0)` if the host manages SIGPIPE itself.
- **Subprocess binaries:** `/usr/sbin/nft` (single pinned absolute path;
  override at runtime via `nein_set_nft_path`)
- **Filesystem paths:** `/dev/null` only (nft's stdout on apply, its stdin on
  capture — opened close-on-exec; apply.cyr reads / writes no other
  hard-coded fs paths; the nft binary itself reads kernel state via
  netlink — out of nein's surface)

The required capability for apply-layer callers is **`CAP_NET_ADMIN`**
(or root). nein does not check or enforce this — the caller is
responsible for capability management (threat model §3.4 / SECURITY.md).

## Per-module detail

The bulk of nein's modules are pure value construction and string
rendering — they invoke zero syscalls. Only `apply.cyr` touches the
kernel surface directly. The table below is exhaustive — if a module
isn't listed, it has zero direct syscall / subprocess / fs-path
exposure.

### `main` (`src/main.cyr`)

| | Count |
|---|---|
| Direct syscalls | 1 |
| `sys_*` wrappers | 0 |
| Subprocess binaries | 0 |
| Filesystem paths | 0 |

**Direct syscalls:**

- `SYS_EXIT` — top-level program exit (`syscall(SYS_EXIT, r);`)

Note: nein is a library; `main()` exists only as a build target so the
test harness has something to link. Production consumers import the
library and invoke their own `main()`.

### `diff` (`src/lib/diff.cyr`)

| | Count |
|---|---|
| Direct syscalls | 0 |
| `sys_*` wrappers | 0 (transitively via apply when `nein_diff` runs) |
| Subprocess binaries | 0 (transitively `nft` via apply) |
| Filesystem paths | 0 |

Pure rule-rendering + string-parsing module. `diff_compute` is a pure
function (target firewall + raw live ruleset → Vec of nft command
strings); since 1.9.2 it also renders each target rule in nft's spelling
for the comparison, still computation only. The syscall surface only opens when a caller chains the
result through `diff_apply` or `nein_diff`, which transitively use
the apply-layer wrappers below.

### `apply` (`src/lib/apply.cyr`)

| | Count |
|---|---|
| Direct syscalls | 1 raw (`close_range`); `rt_sigaction` and `poll` via stdlib helpers |
| `sys_*` wrappers | 18 |
| Subprocess binaries | 1 |
| Filesystem paths | 1 (`/dev/null`) |

**`sys_*` wrappers (1.8.2 — memfds and a pidfd replaced the pipes):**

Parent:
- `sys_memfd_create` — stage the ruleset (stdin), and hold nft's stderr / stdout
- `sys_write`, `sys_lseek` — write the ruleset into its memfd, rewind it
- `sys_open` — `/dev/null` (O_CLOEXEC) for nft's stdout (apply) or stdin (capture)
- `sys_getpid` — the parent-death check's reference pid
- `sys_fork` — spawn the `nft` child
- `sys_pidfd_open` — wait for the child with a deadline (`poll` via `fd_wait_ready`)
- `sys_kill` — SIGKILL a child that outlives the 60 s deadline
- `sys_waitpid` — reap the child and check its status
- `sys_read` — read nft's stderr (logged on failure) / captured stdout, after exit
- `sys_close` — release descriptors

Child (between fork and execve; allocates nothing):
- `sys_sigprocmask` — empty the inherited signal mask
- `rt_sigaction` via `signal_default` — SIGPIPE and SIGXFSZ back to `SIG_DFL`
- `sys_prctl` — `PR_SET_PDEATHSIG` (SIGKILL): die with the host
- `sys_getppid` — exit if the host died before the prctl
- `sys_fcntl` — `F_DUPFD_CLOEXEC` copies above fd 10
- `sys_dup2` — place them on 0 / 1 / 2
- `close_range` (raw 436) — close every other inherited descriptor (Linux 5.9+; best effort)
- `sys_execve` — replace the child image with `nft`
- `sys_exit` — fallback after a setup or exec failure

**Syscalls via stdlib helpers:**

- `rt_sigaction(SIGPIPE, SIG_IGN)` — the parent's guard, `signal_ignore(13)`,
  once per process (v1.6.10; no longer load-bearing since 1.8.2).
- `poll` — `fd_wait_ready` on the pidfd (`ppoll` on aarch64).

**Subprocess binaries:**

- Single pinned absolute path. Default: `/usr/sbin/nft`. Override at
  runtime via `nein_set_nft_path(path: cstring)` (validates: absolute
  path, ≤ 256 bytes, non-null).

PATH is not consulted; the v1.4.0 model removed the prior
`/usr/sbin → /sbin → /usr/bin` fallback chain to close the multi-path
race documented in threat model T-3.

### `sign` (`src/lib/sign.cyr`)

| | Count |
|---|---|
| Direct syscalls | 0 |
| `sys_*` wrappers | 0 (Ed25519 keygen draws randomness inside sigil; `apply_signed_ruleset` transitively via apply) |
| Subprocess binaries | 0 (transitively `nft` via apply) |
| Filesystem paths | 0 |

Signing + verification over the rendered nft body (Ed25519 via
[sigil](https://github.com/MacCracken/sigil), v1.6.1). `sign_keygen` /
`sign_ruleset` / `verify_ruleset` and their v2 forms (1.9.0) are
computation-only — v2 takes `now` from the caller rather than reading a clock —
and the syscall surface opens only when `apply_signed_ruleset` /
`apply_signed_ruleset_v2` chains a verified body through the apply layer
(fail-closed — verify or never touch nft).

### `mcp` (`src/lib/mcp.cyr`)

| | Count |
|---|---|
| Direct syscalls | 0 |
| `sys_*` wrappers | 0 directly; apply's full set transitively — from the three `READS_LIVE` tools as well as the two `MUTATES` |
| Subprocess binaries | 0 directly; `nft` transitively |
| Filesystem paths | 0 |

MCP tool dispatch surface over [bote](https://github.com/MacCracken/bote)
(v1.6.0). Handlers validate args and route to the inspect / builder / apply /
diff functions.

**"Read-only" is about the firewall, not about syscalls** (corrected v1.6.10).
`nein_status`, `nein_list` and `nein_diff` are annotated read-only because they
do not *modify* the ruleset — but all three fork and execve `nft` to read it
(`list_ruleset` / `list_ruleset_with_handles`), so they carry apply's entire
syscall footprint, and return the live ROOT ruleset. Since 1.9.0 the tool
table says so: they are class `NEIN_TOOL_READS_LIVE` (profile `firewall_read`),
denied until a host gate permits them. Only `nein_validate`
(`NEIN_TOOL_OFFLINE`) is genuinely syscall-free.

## Capabilities (Linux)

| Capability | Required by | Why |
|------------|-------------|-----|
| `CAP_NET_ADMIN` | `apply_*`, `list_ruleset*` | The `nft` child needs this to add/delete kernel netfilter rules. |
| `CAP_SYS_PTRACE` | none | nein does not trace processes. |
| `CAP_SYS_ADMIN` | none | nein does not manipulate kernel parameters or namespaces directly. |

The render path requires no capabilities. The apply path inherits its
caller's capability set — nein does not drop, gain, or check them.

## How this map ages

When a module gains a new syscall or subprocess path:

1. Update the relevant per-module table here.
2. If the syscall is in a new attack-surface category (e.g. network
   I/O, fs writes), update the threat-model document and link the
   new entry from the corresponding T-N section.
3. The CI security-scan gate (`scripts/security-scan.sh` equivalent
   in `.github/workflows/ci.yml`) hardfails on hardcoded
   `/etc`/`/bin`/`/sbin` writes outside the allowlist — that gate
   surfaces capability drift at PR time, but it doesn't update this
   map automatically. Refresh by hand at minor bumps.

The closeout pass for every minor release re-reads this file against
the current source — flagged 🟠 in `docs/doc-health.md` if a sweep is
overdue.
