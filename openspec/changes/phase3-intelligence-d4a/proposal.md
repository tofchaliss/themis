# Proposal — phase3-intelligence-d4a (Intelligence · Δ4a: operational store + LLMOps replay harness)

## Why

Δ1–Δ3a shipped the Intelligence Gateway as a **stateless** reactive plane (in-code registry, no eval
loop, no operational datastore beyond the KS2 vector index). The whole **pre-Δ4 R1 surface** then shipped
and was live-verified (AI-CMP-1, G-AI-3, AI-TEL-1/204-2, G-AI-2c classification, G-AI-4 per-run, G-AI-1a
gather). What is now LIVE but UNTUNED is a stream of quality telemetry — `decline_class`,
`themis_ai_declines_total`, invocation-total tokens, grounding pass/fail — with nothing that turns it into
a regression signal. Δ4a is the **LLMOps replay harness** that does, plus the small **operational store**
it needs.

Δ4 (Autonomy + LLMOps) is **split** (grill 2026-08-24): **Δ4a = store + LLMOps** (this change),
**Δ4b = autonomous plane** (a later change and grill). Δ4a first because it consumes already-live telemetry,
needs no new generation path, and gives us the machinery to MEASURE capability quality before Δ4b lets an
analyst run unattended.

Grounded in **`docs/engineering/decisions/EDR-INTELLIGENCE-01.md` — Δ4a section** (decisions D-Δ4a-1…6),
which is the source of truth for every decision, rejected alternative, and honest limit below.

## What changes

- **Operational store (D-Δ4a-1)** — new migrations (`000003…`) in the EXISTING `intelligence` DB / store
  package: a retention-capped **invocation log**, a durable **golden set**, **eval reports**, and
  **version history**. Golden set + reports are the node's first NON-DISPOSABLE state → a backup obligation.
- **Version stamp (D-Δ4a-3)** — a content-hash prompt version + the model id stamped on every invocation and
  eval row. Prompts stay `go:embed` (reviewed/CI-gated); the registry is ATTRIBUTION, not serving. No
  DB-served prompts, no live traffic-split A/B (A/B = sequential cross-deploy comparison).
- **Redacted capture (D-Δ4a-5)** — each invocation captured into the capped log, REDACTED ON WRITE (same
  boundary as the prompt); a human PROMOTES curated entries into the durable golden set.
- **Golden dataset semantics (D-Δ4a-2)** — grounding-replay scoring (grounded? schema-valid? honest
  decline?) + acceptance-outcome for the Decision capability only. Human-labeled quality DEFERRED. For
  Information capabilities the loop measures groundedness/well-formedness, NOT answer quality.
- **Eval command (D-Δ4a-6)** — an OFFLINE, ON-DEMAND, LIVE-MODEL `cmd` (`e2e-llm`-shaped) that replays the
  golden set through the current prompt/model, scores against the frozen expectations, and stores a report
  grouped by `(capability, prompt_version, model)`. Live-only (no static mode); run-it-yourself discipline
  (no CI net).
- **No model registry, no automated promotion (D-Δ4a-4)** — model identity stays config + the stamp;
  "promotion" is a human reading the report and changing config. The report ADVISES; nothing but human
  attention blocks a worse model.

## Out of scope

Δ4b (autonomous engine + scheduler + push seam + autonomous budget pool) — separate change/grill. A DB
prompt registry, live traffic-split A/B, a model registry, an automated promotion gate, a scheduled eval,
a CI eval net, and human-labeled quality datasets are all deliberately NOT built (each rejected or deferred
in the EDR with reasons). No new third-party dependency.

## Immovable guardrails

The eval tunes routing/versioning, **never truth** (INT-0065). Redaction on every write. All Δ4a state is
the node's OPERATIONAL state, never enterprise knowledge. AI stays advisory; Δ4a adds no generation path
and no authority.
