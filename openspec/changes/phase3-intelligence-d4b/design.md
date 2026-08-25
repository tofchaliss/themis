# Design — phase3-intelligence-d4b

Source of truth: `EDR-INTELLIGENCE-01.md` § Δ4b (D-Δ4b-1…6). Build-shape, not new decisions.

## The analyst (app-level) — D-Δ4b-2

`app.ConsistencyAnalyst`: given a set of release ids (from Registry), for each release's posture it finds
UNDECIDED Findings (no current Position), asks the PrecedentService for a decided precedent on a SIMILAR
release (the delta-weighted seam already exists), and — when one exists — grounds a `recommend_position`
invocation the same way the reactive path does, producing an advisory Proposal. Pure orchestration over
existing seams (posture read, PrecedentService, Gateway); no new grounding logic.

## The scheduler + sweep — D-Δ4b-3

`app.AutonomousSweep.Run(ctx)`: one pass over the analyst, driven by a cadence goroutine in
`cmd/intelligence` (mirrors the disposition-watcher / feed-sweep loops), gated on the autonomous pool being
configured. A manual trigger (`POST /autonomous/sweep` behind write-scope, or a cmd flag) runs one pass on
demand for testing/ops.

## The autonomous pool — D-Δ4b-4

A second `app.Budget` instance (the reactive one is unchanged), sized by
`THEMIS_INTELLIGENCE_AUTO_BUDGET_TOKENS`/`_WINDOW`. Unset/0 ⇒ the sweep is DISABLED (the pool's existence is
the enable switch). Each analyst invocation debits it; `Allow`→false stops the sweep mid-pass
(drain-then-stop). Findings processed worst-first by residual priority (already on the posture row).

## Idempotence record — D-Δ4b-5

A new store table `autonomous_proposals (finding_id, precedent_key, proposed_at)` in the Δ4a store
(migration `000004`). Before pushing, the analyst checks it; after a successful push it records the
(finding, precedent_key) pair. `precedent_key` encodes the precedent's identity+version so a CHANGED
precedent re-proposes. Disposable operational state (a wipe risks re-proposing, never mis-proposing).

## The push — D-Δ4b-1

A `governance` read-API client method `RaiseAIProposal(ctx, findingID, stance, rationale)` →
`POST /findings/{id}/proposals` with `proposer_kind: ai`. Needs a write-scoped key: the node gains
`THEMIS_API_KEY` (as the dashboard proxy already injects one) for its outbound write. Read-only inter-service
clients are unchanged.

## The authority bar — D-Δ4b-6 (in the GOVERNANCE context)

Governance's auto-accept policy path gains an explicit precondition: a proposal whose proposer kind is `ai`
is NEVER eligible for auto-accept (regardless of stance/evidence). An invariant test
(`TestAIProposalNeverAutoAccepts`) drives every shipped auto-accept rule against an `ai`-proposed proposal
and asserts none accepts — failing the build if a future rule could. Reason of record: EDR-GOVERNANCE-01 (a
short realization note) + EDR-INTELLIGENCE-01 D-Δ4b-6.

## Gates

New app packages (analyst/sweep) to 100%; the store migration reversible + store method ≥ 80%; the
governance invariant test in `internal/governance`. `make check-ci` green; `vet-tags`. No new dependency,
no cross-context import (the analyst pushes via the read-API client seam, never Governance's tables).
