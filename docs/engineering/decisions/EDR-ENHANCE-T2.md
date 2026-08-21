# EDR-ENHANCE-T2 — Enhancement Tier 2: correctness & robustness

**Status: PROPOSED (2026-08-21) — no implementation until the user confirms.**
This tier IS the board's top of the queue: it contains the two highest-ranked clusters (R7, R6 —
both P2, both **measured** on the live VM) plus the correctness follow-ups this week's live testing
filed. The roadmap rule the backlog already states applies: this tier outranks every capability
tier (T3–T5).

## Scope (existing backlog IDs)

| Item | Cluster | What is wrong |
| --- | --- | --- |
| **GOV-15** | **R7** | `EffectivePriority = base × blast` **clamps at 100**; at a 12-customer estate every Finding with base ≥ 50 pins to 100 — inside a release the multiplier destroys the triage order it exists to create |
| **F5** | **R6** | A crash-looping node restarted 81 times unnoticed; nothing surfaces "never became ready" (`/healthz` + `/readyz` + a startup-failure signal) |
| **DB-password rotation** | **R6** | `pgx` keeps serving pre-rotation connections; every node reports healthy until they all fail together at the next restart |
| **GUI-11** | — | The per-scan join is alias-blind: a GHSA/DSA/RHSA-keyed claim can never match posture CVEs; expose the card's alias set (Knowledge read) and join through it |
| **EV-DEDUP-2** | — | One observation ↔ many releases: an association/filing model would let identical bytes honestly attach to a second release (today: loud 409). A real EDR-EVIDENCE-01 D3 revision |
| TRUST-1 · TRUST-3 | R4 | **Guarded deferrals — to be found, not done**: each has a test that fails the build the moment its premise stops holding; they enter scope only when that fires |
| store fault-injection · feed-health residual | R5 | **Consciously deferred, trade stated** — listed for completeness; not proposed for this pass |

## Decisions to confirm before code

1. **GOV-15 (the substantive one)**: replace the clamped multiplier with an order-preserving
   scheme. Candidate directions — (a) apply blast as a **tie-breaker** after base ordering, never a
   multiplier; (b) clamp the *input* (cap customers) but never the output; (c) log-scale blast so
   saturation is asymptotic, not a wall. Recommended: **(a) ordering = (base, blast) lexicographic
   for triage, keep the multiplied number only as display** — it is the only option that provably
   cannot reorder-destroy. Needs its own decision entry in EDR-GOVERNANCE-01 when confirmed.
2. **F5 surface**: `/healthz` (process up) + `/readyz` (migrations applied, DB reachable) on every
   node + a systemd `Restart=` burst alarm, vs a platform-package health endpoint. Recommended:
   **shared platform health handler mounted by every cmd** (observability package is the precedent
   for a shared platform seam).
3. **DB rotation**: periodic pool re-verification (fail fast on stale credentials) vs documented
   rotation runbook only. Recommended: **pool ping-with-reconnect on a timer + a runbook note** —
   detection first, orchestration later.
4. **GUI-11 read surface**: expose aliases on the posture row (Governance projection carries them)
   vs a Knowledge alias-resolve endpoint. Recommended: **aliases on the Knowledge card read the GUI
   already calls** — no new endpoint, no Governance schema change.
5. **EV-DEDUP-2** is design-first by its own filing: the association model needs its own EDR
   (document stored once; filings per release; events per filing; correlation implications) before
   any code. This tier only confirms whether to *start* that EDR.

## Delivery order

GOV-15 → F5 + DB-rotation (one R6 arc) → GUI-11 → EV-DEDUP-2 EDR (design only). R4/R5 items remain
deferred unless their guards fire.

## Impact

`internal/governance/{domain,app}` (priority ordering + EDR-GOVERNANCE-01 entry), a new shared
platform health seam + every `cmd/<node>` (F5 — "new architectural pattern", explicitly flagged),
`internal/knowledge` card read + `cmd/dashboard/static/app.js` (GUI-11), a new EDR (EV-DEDUP-2).
