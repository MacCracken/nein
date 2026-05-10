# Nein Capability Map

Per-module kernel-surface capability — the syscalls, `sys_*` wrappers,
subprocess binaries, and hard-coded filesystem paths each module can
touch. Hand-curated from `src/main.cyr` + `src/lib/*.cyr` (nein is
small enough that a generator script isn't needed yet — agnosys's
`scripts/gen-capability-map.sh` pattern would be the template if it
gets one).

**Last refresh:** 2026-05-10 (v1.2.0)
**nein version:** 1.2.0
**cyrius version:** 5.10.34

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
- **Subprocess binaries:** `/usr/sbin/nft`, `/sbin/nft`, `/usr/bin/nft`
  (tried in order; first hit wins)
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

### `apply` (`src/lib/apply.cyr`)

| | Count |
|---|---|
| Direct syscalls | 0 |
| `sys_*` wrappers | 9 |
| Subprocess binaries | 3 |
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

**Subprocess binaries:**

- `/usr/sbin/nft` (tried first)
- `/sbin/nft` (tried second)
- `/usr/bin/nft` (tried third)

PATH is not consulted. Mismatched / replaced binaries at any of these
paths is **not** mitigated by nein — see threat model T-3 and roadmap
v1.4.0 ("nft binary discovery + pinning") for the planned hardening.

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
