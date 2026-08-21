# Nein Capability Map

Per-module kernel-surface capability — the syscalls, `sys_*` wrappers,
subprocess binaries, and hard-coded filesystem paths each module can
touch. Hand-curated from `src/main.cyr` + `src/lib/*.cyr` (nein is
small enough that a generator script isn't needed yet — agnosys's
`scripts/gen-capability-map.sh` pattern would be the template if it
gets one).

**Last refresh:** 2026-08-21 (v1.6.10)
**nein version:** 1.6.10
**cyrius version:** 6.5.33

## How to read this

For each module, four capability columns:

- **Syscalls**: direct `syscall(SYS_*)` references — kernel syscalls
  the module invokes directly. Most modules use zero direct syscalls;
  the stdlib `sys_*` wrappers are preferred.
- **`sys_*` wrappers**: cyrius stdlib helpers — each maps to one
  kernel syscall (e.g. `sys_pipe` → `pipe2(2)`, `sys_execve` →
  `execve(2)`).
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
- **`sys_*` wrappers:** `sys_pipe`, `sys_fork`, `sys_execve`,
  `sys_dup2`, `sys_close`, `sys_read`, `sys_write`, `sys_waitpid`,
  `sys_exit`
- **`rt_sigaction`** (via the stdlib's `signal_ignore(13)`), called once
  before the first write to set SIGPIPE to `SIG_IGN`. Added at v1.6.10 —
  **a seccomp allowlist built from an earlier version of this map will kill
  the first apply.** Disable with `nein_set_sigpipe_guard(0)` if the host
  manages SIGPIPE itself and you want it out of the profile.
- **Subprocess binaries:** `/usr/sbin/nft` (single pinned absolute path;
  override at runtime via `nein_set_nft_path`)
- **Filesystem paths:** none (apply.cyr does not read/write any
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
strings). The syscall surface only opens when a caller chains the
result through `diff_apply` or `nein_diff`, which transitively use
the apply-layer wrappers below.

### `apply` (`src/lib/apply.cyr`)

| | Count |
|---|---|
| Direct syscalls | 1 (`rt_sigaction`, via `signal_ignore`) |
| `sys_*` wrappers | 9 |
| Subprocess binaries | 1 |
| Filesystem paths | 0 |

**`sys_*` wrappers:**

- `sys_pipe` — create stdin / stderr pipes to the child
- `sys_fork` — spawn the `nft` child
- `sys_execve` — replace child image with `nft`
- `sys_dup2` — wire child's stdin / stderr to the pipes
- `sys_close` — release unused pipe ends
- `sys_read` — drain stderr / capture stdout
- `sys_write` — pipe rendered ruleset to child's stdin
- `sys_waitpid` — observe child exit
- `sys_exit` — child fallback after exec-chain failure

**Direct syscall:**

- `rt_sigaction(SIGPIPE, SIG_IGN)` — via the stdlib's `signal_ignore(13)`,
  once before the first write (v1.6.10). Without it, writing to an `nft` that
  has already exited terminates the whole calling process.

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
`sign_ruleset` / `verify_ruleset` are computation-only; the syscall surface
opens only when `apply_signed_ruleset` chains a verified body through the
apply layer (fail-closed — verify or never touch nft).

### `mcp` (`src/lib/mcp.cyr`)

| | Count |
|---|---|
| Direct syscalls | 0 |
| `sys_*` wrappers | 0 directly; apply's full set transitively — including from two READ-ONLY tools |
| Subprocess binaries | 0 directly; `nft` transitively |
| Filesystem paths | 0 |

MCP tool dispatch surface over [bote](https://github.com/MacCracken/bote)
(v1.6.0). Handlers validate args and route to the inspect / builder / apply /
diff functions.

**"Read-only" is about the firewall, not about syscalls** (corrected v1.6.10).
`nein_status` and `nein_list` are annotated read-only because they do not
*modify* the ruleset — but both fork and execve `nft` to read it
(`list_ruleset` / `list_ruleset_with_handles`), so they carry apply's entire
syscall footprint. Only `nein_validate` is genuinely syscall-free. A sandbox
profile that grants the read-only tool set still needs fork + execve + the
pipe syscalls.

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
