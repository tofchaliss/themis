# Design: phase3-intelligence-router

ADR-INT-0062 + EDR-INTELLIGENCE-01 D4/D6 are the design of record; this maps them to code.

## The tier vocabulary lives in the app ring, not the domain

A capability declares *requirements* (`domain.RoutingRequirements`) and never a model — that is
INT-0062's whole point, and it stays. The tier (`primary` / `escalation` / `economy`) is a
**runtime routing decision** the Gateway makes per invocation, so it is app-ring vocabulary
(`app.ModelTier`) threaded through `ExecInput`, never a capability field.

## Port change

```go
type Router interface {
    Select(req domain.RoutingRequirements, tier ModelTier) (Provider, error)
    Available(tier ModelTier) bool  // a DISTINCT model exists for this tier
}
```

`Available` exists so the Gateway can decide *whether* to escalate/degrade before spending
anything; `Select` falls back to primary for an unconfigured tier so a mis-threaded tier can
never fail an invocation. Wiring treats an escalation/economy model equal to the primary as
unconfigured (escalating to the same model is a wasted call) and logs it.

## The two hooks in Gateway.Invoke

1. **Escalation (G-AI-2b):** the LLM step runs in a tier loop — `primary`, then `escalation`
   exactly once, only when the primary's outcome was the honest `llm:insufficient` on a
   **Decision** capability, the router has a distinct escalation model, and the budget still
   admits. Every attempt debits (both tiers' costs are real). The Outcome's `Tier` says which
   tier answered; an escalated decline is telemetry gold — "the bigger model couldn't tell
   either" ends the G-AI-2 guessing.
2. **Degrade-not-fail (G-AI-4):** before the provider call, if the budget is enforced and
   remaining < `limit × degrade-fraction` (default 0.20) and a distinct economy model exists,
   the tier becomes `economy` — spend shrinks before it stops. `Allow` unchanged: exhaustion
   still refuses with `budget_exhausted`. Escalation is skipped while degraded (escalating out
   of a low-budget window would defeat the reason we degraded).

## What deliberately does NOT change

- No proposal-metadata/wire change: `Model` already rides the provenance and names the
  answering model exactly.
- No new outcome reasons: an escalated success is `ok`, an escalated decline is `insufficient`
  — the tier is telemetry (`Outcome.Tier`), not semantics.
- Information capabilities never escalate: their decline paths are guards/grounding, not the
  model saying "can't tell", and their worst case is a human disagreeing with a paragraph —
  not worth a second model call by default.
- G-AI-5 classification/clearance: not built; the tier-aware `Select` is where it will attach.
