# Proposal — phase3-intelligence-d4b (Intelligence · Δ4b: autonomy walking skeleton)

## Why

Δ1–Δ4a shipped the REACTIVE Intelligence plane and its LLMOps replay harness — capabilities invoked
on demand, grounded, advisory. Δ4b adds the AUTONOMOUS plane (D3): Intelligence's OWN scheduled analyst
that reads enterprise knowledge and proactively raises advisory Proposals no single request would ask
for. It is the last body of R1 work and the highest-risk (generation with no caller), so it ships as a
**walking skeleton** (the proven Δ1 rhythm): ONE analyst, a scheduler, a capped pool with pause-not-fail,
ONE push seam — the analyst portfolio, cloud-tier autonomy, and event-reactive triggering deferred.

Grounded in **`docs/engineering/decisions/EDR-INTELLIGENCE-01.md` — Δ4b section** (D-Δ4b-1…6). The
immovable guardrail (D3): **autonomy of generation is allowed; autonomy of authority is never** — every
autonomous output is an advisory Proposal under Governance, and D-Δ4b-6 makes that structural + tested.

## What changes

- **The push seam (D-Δ4b-1)** — the autonomous analyst raises an advisory Proposal on an EXISTING Finding
  via the EXISTING Governance `POST /findings/{id}/proposals` (`proposer_kind: ai`), over Intelligence's
  read-API client. No new intake. Autonomous and reactive proposals arrive indistinguishable through one
  door. Needs a WRITE-scoped key on the node (new: the node only read cross-context before).
- **The skeleton analyst (D-Δ4b-2)** — cross-release decision-consistency: self-initiated
  `recommend_position`-style grounding over UNDECIDED Findings that have a DECIDED precedent on a SIMILAR
  release. Composes existing reads (Registry + PrecedentService); complements the disposition-watcher.
- **The scheduler (D-Δ4b-3)** — a configurable, DEFAULT-OFF time cadence (feed-sweep pattern) + a manual
  "sweep now" affordance.
- **The autonomous pool (D-Δ4b-4)** — a SEPARATE `Budget` (`THEMIS_INTELLIGENCE_AUTO_BUDGET_TOKENS`/
  `_WINDOW`; unset = OFF, so the pool's existence is the enable switch); pause = drain-then-stop mid-sweep;
  worst-first via existing residual priority; a HARD isolation wall (never shares slack with reactive).
- **Idempotence (D-Δ4b-5)** — the analyst records its pushes (a small `autonomous_proposals` record in the
  Δ4a store) and skips already-proposed (Finding, precedent) pairs, re-proposing only on precedent change.
- **The authority bar, structural (D-Δ4b-6, IMMOVABLE)** — Governance's auto-accept explicitly excludes
  `ai` proposers, enforced by an INVARIANT TEST that fails the build if an AI proposal could ever
  auto-accept.

## Out of scope (deferred)

The analyst portfolio (emerging-threat cluster — needs a new cross-release-by-CVE Governance read;
portfolio narrative — needs a new intake), event-reactive triggering, cloud-tier autonomy, and a
shared-with-priorities pool. No new third-party dependency.

## Immovable guardrails

Autonomy of generation, NEVER of authority (D3): every autonomous output is a rejectable advisory Proposal
under Governance, and D-Δ4b-6 guarantees it can never auto-accept. The autonomous pool can never outspend
its envelope (pause-not-fail) and never starves reactive (isolation wall). Default OFF.
