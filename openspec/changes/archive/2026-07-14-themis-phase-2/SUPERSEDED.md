# SUPERSEDED — themis-phase-2

**Archived:** 2026-07-14 · **Reason:** superseded architecture reference (never an implementation source).

## Why archived

themis-phase-2 was an **architecture reference document** for the current architecture's Phase 2 (AI +
threat intelligence). As an *architectural* reference it is now **superseded** by the authoritative
Phase-3 architecture: the book under `docs/architecture/` (Books I–III) and the 69 ADRs under
`docs/adr/`. The Phase-3 **greenfield rebuild** is the sole go-forward; the current architecture is frozen
at **v0.3.x**.

Sub-phase lineage: 2a implemented + archived separately (`2026-06-17-themis-phase-2a`); 2b folded into
`themis-ai-1` (also archived 2026-07-14); 2c was planned and is now covered by the greenfield roadmap.

## Reference value preserved

Its content — the 5-layer intelligence model, AI workers, RAG/pgvector, VEX auto-apply semantics,
threat-intel feeds — is **reference input** for grilling the Phase-3 **Knowledge / Governance /
Communication / Intelligence** contexts.

## Reversible

`git mv`'d with history intact. To bring it back:
`git mv openspec/changes/archive/2026-07-14-themis-phase-2 openspec/changes/themis-phase-2`.
