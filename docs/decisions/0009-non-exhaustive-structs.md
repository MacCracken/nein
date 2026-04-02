# ADR-009: Non-Exhaustive Public Structs

## Status: Accepted

## Context

Adding fields to public structs is a semver-breaking change when consumers use struct literal construction (`MyStruct { field1, field2 }`). As nein approaches v1.0, every public struct field addition would require a major version bump.

## Decision

Add `#[non_exhaustive]` to all public domain structs (not just enums). This forces consumers to use constructors and builder methods, allowing new fields to be added in minor versions.

Config parsing structs in `config.rs` are excluded — they use `#[serde(default)]` on all fields and are primarily constructed by serde, not by hand.

## Consequences

- Consumers cannot use struct literal syntax for nein types
- All types already have constructors (`new()`, builder methods)
- New fields can be added in minor/patch versions without breaking consumers
- Combined with `#[non_exhaustive]` on enums (ADR from Phase 0), the full public API is forward-compatible
