# Proposal: phase3-intelligence-router — the tiered model router (G-AI-2b + G-AI-4)

## Why

The dependency map (GUI-UPGRADE-PLAN §3) reduces the AI harness backlog to five blockers, and
the **model router + a second chat model** is the one small blocker that advances three items:
G-AI-2b escalation, G-AI-4 degrade-not-fail, and G-AI-5's clearance routing rail. The decisions
are already accepted — ADR-INT-0062 (model selection is runtime Gateway infrastructure; callers
never name a model) and EDR-INTELLIGENCE-01 D6 (routing in the Gateway) + D4 (degrade-not-fail
deferred solely because "a deployment has a single model — downgrade needs somewhere to go").
This change gives the downgrade somewhere to go.

## What

- **Model tiers** (app-ring vocabulary, runtime-only — capabilities still declare requirements,
  never models): `primary` (today's model), `escalation` (larger, optional), `economy`
  (smaller, optional). Configured per deployment:
  `THEMIS_INTELLIGENCE_MODEL` / `_MODEL_ESCALATION` / `_MODEL_ECONOMY`.
- **G-AI-2b — escalate once on the honest decline:** when the primary model answers a Decision
  capability with `insufficient`, the Gateway retries ONCE on the escalation tier (if configured
  and budget allows). The bigger model may extract more from the same grounding; if it also
  declines, the outcome is a better-informed `insufficient` whose telemetry says both tiers
  tried. Escalation never fires for `business_invalid` (a contract problem — escalating would
  mask prompt bugs, the "which lever" distinction the backlog records) nor on timeouts (a
  slower model would time out worse).
- **G-AI-4 — degrade-not-fail:** when the budget window is nearly spent (below a configurable
  fraction, default 20%), the Gateway routes to the economy tier instead of refusing — spend
  shrinks before it stops. Full exhaustion still answers `budget_exhausted`.
- **The G-AI-5 rail:** the tier-aware `Select` is the single point where clearance routing will
  later attach; nothing else in that item is built now (local-only estates need none of it).

## Source of truth

ADR-INT-0062 + EDR-INTELLIGENCE-01 D4/D6 are the decisions; this change is their
implementation. No `specs/` deltas (phase3 convention).

## Impact

- `internal/intelligence/app`: Router port gains the tier parameter + `Available`; ExecInput
  and Outcome carry the tier; Gateway gains the escalation loop and the degrade check.
- `internal/intelligence/adapters/provider`: `TieredRouter` (StaticRouter retired); the Ollama
  provider is constructed per configured tier (same client, different model).
- Wiring/env + docs (node.env.example, systemd installer, CLAUDE.md, TESTING.md); BACKLOG
  closes G-AI-2b and G-AI-4's degrade half.
- No API change, no event change, no other context touched. Proposal metadata already carries
  the answering model — provenance is intact without a wire change.
