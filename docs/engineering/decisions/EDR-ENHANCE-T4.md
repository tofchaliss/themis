# EDR-ENHANCE-T4 — Enhancement Tier 4: AI groundwork (deterministic prerequisites)

**Status: PROPOSED (2026-08-21) — no implementation until the user confirms.**
Everything here is deterministic work that makes the T5 capabilities honest, measurable, or
sharper — the "rule-first, then AI" standing lens. None of it invokes a model; all of it is what a
model-facing harness will stand on. These items live inside the R1 cluster on the board but are
separated here because they can (and should) land before any new capability does.

## Scope (existing backlog IDs)

| Item | What | Why it gates T5 |
| --- | --- | --- |
| **AI-204-2** | When a decline's cause is already known deterministically (range verdict impossible, no components matched, budget window), say so on the 204 (`X-Themis-AI-Reason` sub-cause) instead of the generic `insufficient` | G-AI-2's eval loop needs exactly this taxonomy: you cannot improve what you cannot classify |
| **AI-TEL-1** | `Outcome.TokensUsed` reports only the LAST attempt; a multi-attempt invocation (escalation retry) under-reports spend | G-AI-4's budget *enforcement* is unsound while the meter under-counts |
| **PLAN-5** | One Finding claimable by several upgrade steps in a remediation plan — define whether steps partition Findings or may overlap, and what the plan asserts when they do | `plan_remediation`'s grouping is the deterministic core; its semantics must be fixed before any autonomy replays it |
| **Δ3a per-CVE embedding** | Component-level embeddings conflate distinct CVEs on one component; move the Operational Semantic Index to per-(CVE, component) granularity | G-AI-3's delta-aware ranking weights neighbours — sharper neighbours first, weighting second |

## Decisions to confirm before code

1. **AI-204-2 taxonomy**: extend the existing reason header vocabulary (AI-204-1) with
   deterministic sub-causes (`insufficient:no-carrier-components`, `insufficient:range-undecidable`,
   `insufficient:contradictory-precedent`, …). Additive, header-only — old callers unaffected.
2. **AI-TEL-1**: sum across attempts and (recommended) also record per-attempt breakdown in the
   invocation log — the budget meter consumes the sum; the eval loop wants the breakdown.
3. **PLAN-5 semantics**: recommended position — **steps may overlap; the plan carries each
   Finding's full claiming-step set and marks one primary** (dropping overlaps silently would
   reintroduce the "attribution gap hides work" defect class EDR-CORRELATION-01 exists to prevent).
4. **Δ3a**: index key change ⇒ a rebuild, which is safe by design (the index is derived, owns no
   truth) — but it is an Intelligence-context schema change and needs its EDR-INTELLIGENCE-01
   realization note when confirmed.

## Delivery order

AI-204-2 → AI-TEL-1 (small, independent) → PLAN-5 (decision, then code) → Δ3a (schema + rebuild).

## Impact

`internal/intelligence/{app,adapters}` (reason taxonomy, telemetry, index schema),
`internal/governance` (204 header passthrough already exists), TESTING.md. No Governance domain
changes; no event-contract changes.
