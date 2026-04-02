# ADR-008: Typed Enums Over Strings for Closed Sets

## Status: Accepted

## Context

Several match and verdict fields originally used `String` where the valid values form a closed set. Examples: fragment comparison operators (`==`, `!=`, etc.), packet types, IPv6 extension headers, log levels. String-based fields require runtime validation and risk injection.

## Decision

Replace string fields with typed enums wherever the set of valid values is closed:
- `CmpOp` for comparison operators (was `String` in `FragOff`)
- `PktType` for packet types (unicast/broadcast/multicast)
- `Ipv6ExtHdr` for extension header types
- `LogLevel` for log levels
- `Transport` for TCP/UDP/QUIC distinction in PolicyEngine
- `QuotaMode` and `QuotaUnit` for quota parameters
- `validate_family()` uses a closed set check instead of `validate_identifier()`

All new enums are `#[non_exhaustive]` with `Display` implementations.

## Consequences

- Compile-time safety: invalid values are unrepresentable
- No runtime validation needed for typed fields
- Zero-cost: enums are the same size as the discriminant
- Breaking change for `FragOff.op` (was `String`, now `CmpOp`) — acceptable pre-1.0
