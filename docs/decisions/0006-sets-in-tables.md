# ADR 0006: Named sets and maps rendered inside table blocks

## Status

Accepted

## Context

nftables named sets and verdict maps must be defined inside a `table` block
before they can be referenced by rules in that table's chains. They need to
render before chains in the output.

## Decision

Add `sets: Vec<NftSet>` and `maps: Vec<NftMap>` fields to `Table`. The
`render()` method outputs sets first, then maps, then chains. Rules reference
sets via `Match::SetLookup { field, set_name }` which renders as
`{field} @{set_name}`.

Sets and maps are always available (not feature-gated) since they are core
nftables primitives used by multiple modules (geoip, bridge isolation, policy
engine).

## Consequences

**Positive:**
- Sets render in the correct position (before chains that reference them).
- `Table.add_set()` and `Table.add_map()` provide a clean API.
- GeoIP blocking uses interval sets naturally.
- `Firewall::validate()` validates set/map names and elements.

**Negative:**
- Sets are always compiled even if unused (minimal cost — small module).
- No support for anonymous sets (inline `{ elem1, elem2 }` in rules) — users
  must use named sets or `Match::Raw` for inline syntax.
