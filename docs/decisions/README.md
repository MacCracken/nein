# Architecture Decision Records

We use ADRs to document significant architectural decisions. Each record
captures the context, decision, and consequences so future contributors
understand why the codebase is the way it is.

## Format

Each ADR follows the template:

- **Status**: proposed | accepted | deprecated | superseded
- **Context**: what problem or situation prompted the decision
- **Decision**: what was decided
- **Consequences**: what follows from the decision (positive and negative)

## Index

| ADR | Title | Status |
|-----|-------|--------|
| [0001](0001-render-not-execute.md) | Render rules as strings, execute via nft stdin | Accepted |
| [0002](0002-validate-before-apply.md) | Validate all inputs before rendering | Accepted |
| [0003](0003-feature-gated-modules.md) | Feature-gate optional modules | Accepted |
| [0004](0004-raw-match-escape-hatch.md) | Provide Raw match variant as escape hatch | Accepted |
| [0005](0005-chain-rule-enum.md) | Unify filter and NAT rules via ChainRule enum | Accepted |
| [0006](0006-sets-in-tables.md) | Named sets and maps rendered inside table blocks | Accepted |
