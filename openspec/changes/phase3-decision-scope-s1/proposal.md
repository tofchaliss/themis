# Proposal — phase3-decision-scope-s1 (EDR-SYNC-01, step S1)

## Why

A product ships the same build to several projects, so the same CVE on the same component sits
under each of them as its own Finding. A person assessing CVE-X on project A's release today
decides it once and copies the decision to projects B and C by hand — or never does, and the
other projects keep showing an open Finding that is already answered. Roll-forward
(EDR-ROLLFORWARD-01) only ever *proposes*, and only inside one project. The owner chose
"scope at decision time" over auto-copy and proposals-only (2026-11-03).

## What changes

- **A decision carries a scope**: `release` (default, today's behaviour) · `project` · `product`.
  `POST /findings/{id}/proposals/{pid}/accept` takes `scope`; the Position records it.
- **Propagation**: Themis establishes the same Position, recorded against the same person, on
  every undecided same-Faultline Finding whose component is alike at artifact or component
  level (`RollForwardEligibility`) and whose release lies in scope. A `scoped:` proposal is
  raised in the person's name (Asserted) and accepted at once with `propagated_from`.
- **When**: on a sweep every `THEMIS_SCOPE_SWEEP_INTERVAL` (1m; 0 off) draining the pending
  scoped Positions, and on the release-evaluation worker for Findings born later (before
  roll-forward, which then sees them as decided).
- **Preview**: `GET /findings/{id}/scope-targets?scope=` lists what a scope would reach.
- Migration governance **000023** (`scope`, `propagated_from_*`, `scope_applied_at` on
  `finding_positions`; partial index on the pending rows).

## What does NOT change

- No new decider: a propagated Position is the person's own decision, widened. No policy, no AI.
- A local decision is never overwritten. Two standing scoped decisions that disagree apply
  nothing. A propagated Position is never itself a source (no chains).
- Roll-forward's proposal road, the AI road, the precedent index.
- Syncing across products, or of proposals and recommendations (EDR-SYNC-01 "not decided").

## Decision record

EDR-SYNC-01 D1–D8. No `specs/` deltas; archive with `--skip-specs`.
