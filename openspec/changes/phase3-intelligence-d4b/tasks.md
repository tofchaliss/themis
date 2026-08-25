# Tasks — phase3-intelligence-d4b · Δ4b (autonomy walking skeleton)

> **Scope: Δ4b skeleton only** — one analyst + scheduler + capped pool + one push seam, grounded in
> `EDR-INTELLIGENCE-01.md` § Δ4b (D-Δ4b-1…6). Out of scope: the analyst portfolio, portfolio narrative +
> its new intake, event-reactive triggering, cloud-tier autonomy, shared-with-priorities pool. No new
> third-party dependency. Each group ends by making the gates (`make check-ci` + `vet-tags`) green.

## 1. The authority bar FIRST (D-Δ4b-6, IMMOVABLE) — in Governance

- [ ] 1.1 Governance auto-accept: an `ai`-proposer proposal is never eligible for auto-accept (explicit
  precondition in the policy path).
- [ ] 1.2 `TestAIProposalNeverAutoAccepts` — drive every shipped auto-accept rule against an ai-proposed
  proposal (all stances/evidence); assert none accepts. This is the tripwire; it lands before any
  autonomous code can push.
- [ ] 1.3 EDR-GOVERNANCE-01 realization note pointing at D-Δ4b-6. Gate.

## 2. Idempotence store (D-Δ4b-5)

- [ ] 2.1 Migration `000004`: `autonomous_proposals (finding_id, precedent_key, proposed_at)`, reversible.
- [ ] 2.2 Store methods: has-proposed?(finding, precedent_key), record-proposed. Coverage-registered.
- [ ] 2.3 Integration test: record + skip; a changed precedent_key re-proposes. Gate.

## 3. The push client (D-Δ4b-1)

- [ ] 3.1 `adapters/readapi` (or a governance write-client seam): `RaiseAIProposal` → the existing
  `POST /findings/{id}/proposals` with `proposer_kind: ai`. Uses the node's write key.
- [ ] 3.2 Test against an httptest Governance stub (the shape + proposer_kind); a non-201 is an error the
  sweep skips (best-effort per Finding). Gate.

## 4. The analyst + sweep + pool (D-Δ4b-2/3/4)

- [ ] 4.1 `app.ConsistencyAnalyst`: undecided Findings with a decided precedent on a similar release →
  ground a recommend_position invocation → advisory Proposal. Pure orchestration; app 100%.
- [ ] 4.2 `app.AutonomousSweep`: worst-first, debit the SEPARATE autonomous Budget per invocation,
  drain-then-stop when the pool can't admit; skip already-proposed pairs (group 2); record after push.
- [ ] 4.3 The pool: a second Budget (`THEMIS_INTELLIGENCE_AUTO_BUDGET_TOKENS`/`_WINDOW`); unset = the sweep
  is disabled. Hard isolation wall (reactive Budget untouched).
- [ ] 4.4 Tests: skip-already-proposed, re-propose-on-precedent-change, drain-then-stop mid-sweep,
  disabled-when-no-pool, worst-first ordering, push failure is per-Finding not fatal. Gate.

## 5. Wiring + trigger + docs (D-Δ4b-3)

- [ ] 5.1 `cmd/intelligence`: a cadence goroutine running the sweep when the pool is configured (mirrors the
  sweep loops); a manual `POST /autonomous/sweep` (write-scope) or cmd flag for on-demand runs.
- [ ] 5.2 node.env.example: the pool knobs + cadence + the node's write key; DEFAULT-OFF documented.
- [ ] 5.3 TESTING.md: enable the pool, run a manual sweep, see advisory ai proposals appear in a release
  posture; the honest note that autonomy is quiet-by-default and never auto-accepts.
- [ ] 5.4 BACKLOG: G-AI-1 half (b) note (the push seam now exists — the AI-emits-need-more-data path can
  reuse it as a follow-on); PHASE3-STATUS resume block → Δ4 COMPLETE. Gate: full `make check-ci`.

## Notes

- **NO `specs/` deltas** (phase3 change; archive with `--skip-specs -y`).
- Group 1 (the authority bar) lands FIRST and independently — the constitution before the machinery.
