# Tasks: phase3-intelligence-router

One PR off `main`, `make check-ci` green, ending with `make vet-tags` green.

## 1. Ports + Gateway (app ring, 100% tier)

- [x] 1.1 `app.ModelTier` (`primary`/`escalation`/`economy`); Router port gains the tier
      parameter + `Available`; `ExecInput.Tier`; `Outcome.Tier`
- [x] 1.2 `Budget.Limit()` (the degrade check needs the ceiling, not only the remainder)
- [x] 1.3 Gateway: LLM step runs in the tier loop — escalate ONCE on `llm:insufficient`
      (Decision output, distinct escalation model, budget still admits); every attempt debits
- [x] 1.4 Gateway: degrade-not-fail — remaining < limit × `DegradeFraction` (config, default
      0.20) with a distinct economy model → tier `economy`; escalation skipped while degraded;
      exhaustion still `budget_exhausted`
- [x] 1.5 Tests: escalation produces/declines/absent-router/budget-stops-escalation; degrade
      routes economy / skips escalation / exhaustion unchanged; tier rides Outcome

## 2. Adapters (90% tier)

- [x] 2.1 `provider.TieredRouter` (primary + optional escalation/economy; fallback to primary;
      `Available` = distinct model configured); StaticRouter retired
- [x] 2.2 LLM engine passes `ExecInput.Tier` to `Select`
- [x] 2.3 Tests: tier selection, fallback, Available semantics

## 3. Wiring + env + docs

- [x] 3.1 `THEMIS_INTELLIGENCE_MODEL_ESCALATION` / `_MODEL_ECONOMY` (+`THEMIS_INTELLIGENCE_BUDGET_DEGRADE_PCT`)
      through cmd/intelligence + wiring; a tier model equal to the primary is treated as unset
      (logged)
- [x] 3.2 Docs: node.env.example, systemd installer comment, CLAUDE.md env notes, TESTING.md
- [x] 3.3 EDR-INTELLIGENCE-01: implementation notes on D4 (degrade landed) + D6 (tiered router
      landed); BACKLOG: G-AI-2b closed, G-AI-4 degrade half closed
- [ ] 3.4 `make check-ci` + `make vet-tags` green; archive this change
