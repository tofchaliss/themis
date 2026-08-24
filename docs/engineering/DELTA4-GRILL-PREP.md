# Δ4 (Autonomy + LLMOps) — Grilling Prep & Resume Point

**Status: PRE-GRILL. No code. Resume the grilling here next session.**
Created 2026-08-24 after the AI chain completed through the pre-Δ4 boundary (main `25c5335`)
and its live VM round passed. Δ4 is the last body of R1 work and is **design-first**: grill →
EDR realization decisions → OpenSpec change(s) → code, per the phase-3 workflow.

## Where Δ4 comes from (authoritative scope)

`EDR-INTELLIGENCE-01.md` Revision 2 (2026-07-18), the Δ-delivery table:

> **Δ4 | Autonomy + LLMOps | Autonomous engine + scheduler + push seam · LLMOps plane
> (prompt registry, golden datasets, A/B, model registry, capability promotion) +
> operational store | separate**

Plus **D3** (dual-mode; autonomy of *generation* allowed, autonomy of *authority* never —
every output is an advisory Proposal under Governance) and **D4** (budget scopes: the
per-run ceiling shipped 2026-08-23; the **autonomous pool** + **global ceiling** are Δ4).

Everything in Δ1–Δ3 was deliberately STATELESS (in-code registry, no eval loop, no cache, no
datastore/migrations). The operational DB arrives with Δ4 — it is the shared prerequisite.

## The Δ4 item tree (the branches to grill)

**A. Operational store** — prerequisite for both planes
- **A1** Intelligence datastore + migrations. NB: a DSN is ALREADY wired on the Intelligence
  node (`THEMIS_DATABASE_DSN=…/intelligence`) for the KS2 vector index (Δ3a Operational
  Semantic Index). Open question: does eval/registry/analyst state CO-LOCATE in that DB or get
  its own? (Grill A1 first — both planes depend on it.)

**B. LLMOps plane** — turns the telemetry shipped this cycle into tuning
- **B1** Prompt registry — versioned prompts (today `go:embed` in-code; EDR calls DB-backed
  versioning "deferred to Δ4").
- **B2** Golden datasets — recorded real invocations to replay.
- **B3** Evaluation loop / scoring — consumes `decline_class` (G-AI-2c, live), proposal
  acceptance rate, grounding-pass rate. This is G-AI-2(c)'s TUNING half (the classification
  half shipped 2026-08-23).
- **B4** Model registry + capability promotion — which model/prompt version is live per
  capability; A/B; promotion gate.

**C. Autonomous plane** — generation without a caller; authority unchanged
- **C1** Autonomous engine + analysts — scheduled cross-cutting analysis (shared root cause,
  emerging-threat clusters, portfolio risk narrative) that no single request would ask for.
- **C2** Scheduler + cadence.
- **C3** Outbound **push seam** (the "D-seam" in D3) into Knowledge-Proposal / Governance-Proposal
  intake. **This also unblocks G-AI-1 half (b)** — the AI emitting "need more data on CVE-X"
  and pushing it (half (a), the on-demand gather endpoint, shipped 2026-08-23).
- **C4** Autonomous budget pool — D4's separate capped pool + pause-not-fail cadence + the
  global enterprise ceiling.

## Open grilling question (Q1) — answer this first next session

**Scope: grill Δ4 as ONE change, or split it?**

Recommendation (mine, pending user confirmation): **SPLIT into two OpenSpec changes.**
- **Δ4a = operational store + LLMOps plane (A + B)** — first.
- **Δ4b = autonomous plane (C)** — second, builds on Δ4a's store.

Why: (1) autonomy (C) and LLMOps (B) share only the store (A) and are otherwise weakly
coupled; bundling blocks both until both are designed. (2) The eval loop pays off immediately —
it consumes telemetry that is ALREADY LIVE (`decline_class`, `themis_ai_declines_total`,
invocation-total tokens) and needs no new generation path. (3) It de-risks autonomy: we get the
scoring machinery to MEASURE an analyst before letting one run unattended. (4) Each change stays
~Δ2-sized (Δ2 was 9 groups) instead of one oversized change. (5) The store is the natural
Δ4a foundation Δ4b extends.

The grilling has not yet resolved Q1. It stops here.

## Downstream items Δ4 unblocks (tracked in BACKLOG, currently Δ4-gated)

- **G-AI-1 half (b)** — AI-push of "need more data on CVE-X" → the C3 push seam.
- **G-AI-2(c) tuning half** — the eval loop → B3.
- **G-AI-4 remaining scopes** — autonomous pool + global ceiling → C4 (per-run shipped).
- **G-AI-5** — cloud/provider clearance only becomes real with a non-local provider; guarded by
  `TestEveryShippedCapabilityIsLocalOnly` until then; NOT strictly Δ4, but revisited alongside it.

## Guardrails that DO NOT move in Δ4 (carry into every decision)

- **AI is advisory.** Autonomy of generation, never of authority. Every autonomous output is an
  advisory Proposal under Governance (D3, INT-0056/0066, CON-0015). Intelligence owns no truth.
- **Gathering Is Not Knowing.** A pushed Proposal is rejectable Information; only Governance /
  Knowledge reconciliation turns it into enterprise truth.
- **Disable-able / degrade-not-fail.** The autonomous pool pauses when exhausted; it never
  refuses the reactive path or blocks the pipeline.
- **The eval loop tunes routing/versioning, NEVER truth** (INT-0065).

## Resume instructions

1. Re-read this file + EDR-INTELLIGENCE-01 Revision 2 + D3/D4.
2. Re-invoke the `grilling` skill.
3. Start at **Q1** (scope: one change vs the Δ4a/Δ4b split) — recommendation above.
4. Then walk the tree: A1 (store co-location) → B branch → C branch, resolving dependencies
   first, one question at a time.
