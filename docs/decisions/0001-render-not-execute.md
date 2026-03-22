# ADR 0001: Render rules as strings, execute via nft stdin

## Status

Accepted

## Context

nein needs to apply nftables rules to the kernel. There are two approaches:

1. **Render to string** — generate nftables syntax and pipe it to `nft -f -`.
2. **Use libnftables** — link against the C library and call its API directly.

## Decision

Render rules as nftables syntax strings and apply via `nft -f -` stdin pipe.

## Consequences

**Positive:**
- No C FFI or unsafe code required.
- The rendered output is human-readable and debuggable (`render()` + dry-run).
- Works with any nft binary version; no library version coupling.
- Pure rendering logic is easily testable without root or nftables kernel modules.

**Negative:**
- Spawning a child process per apply is slower than direct library calls.
- String rendering introduces injection risk (mitigated by the validate module).
- Cannot query nftables state without parsing `nft list` text output.
