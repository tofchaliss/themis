# SUPERSEDED — themis-ai-1

**Archived:** 2026-07-14 · **Reason:** superseded, never implemented on `main`.

## Why archived

The Phase-3 **greenfield rebuild** (architecture book Books I–III + the 69 ADRs; sprint plan
`docs/current-changes/themis-phase-3-sprint-plan.md`) is the **sole go-forward**. The current
architecture is frozen at **v0.3.x**. This change (v0.4.0 AI enrichment on the current architecture) was
**planning-complete but never built** — no migration `000002`, no `themis-ai/` / `themis-backend/` split,
2 open questions still outstanding — so it is retired rather than implemented.

## Folded into (reference value preserved)

Its AI-enrichment design feeds the Phase-3 **Intelligence context** (INT ADRs 0056–0070, sprint **M4**) —
future `EDR-INTELLIGENCE-01`. Near one-to-one mapping:

- advisory-only (AI never owns truth) → **ADR-INT-0056**
- structured proposals → **ADR-INT-0057**
- exclusive intelligence gateway → **ADR-INT-0059**
- validate every response → **ADR-INT-0063**

## Reversible

`git mv`'d with history intact. To bring it back:
`git mv openspec/changes/archive/2026-07-14-themis-ai-1 openspec/changes/themis-ai-1`.
