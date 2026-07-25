# Proposal — phase3-intelligence (Intelligence Gateway / AI enrichment)

## Why

**Intelligence** is a **supporting AI Gateway** beside the pipeline (sprint M4) — *not* a stage in the
Evidence → Knowledge → Governance → Communication line. It is the single exclusive entry to all
AI/ML/rule/knowledge-graph providers (INT-0059), invoked as **named capabilities** (INT-0058), producing
**validated, structured, advisory-only Proposals** (INT-0057/0063) that Knowledge and Governance record
and govern. It **never owns enterprise truth** (INT-0056); human governance stays the final authority
(INT-0066). Grounded in **`docs/engineering/decisions/EDR-INTELLIGENCE-01.md`** (D1–D13, **Revision 2**).
Ground rule: **ADR/EDR wins; the `internal/` PoC and the archived `themis-ai-1` design are reference only.**

## Destination & delivery (Revision 2)

The **destination** is the full **harness** (`docs/engineering/THEMIS-AI-HARNESS.md`): typed multi-engine
dispatch (Rule / Knowledge / LLM) behind an Engine Dispatcher, execution-plan harness, Context
Construction/RAG, an optional **Python** engine for the advanced AI stack, and a separate **LLMOps plane**.
That is too large for one change, so it migrates in **four additive deltas** — each individually shippable
and safe because the AI plane is **disable-able** (D13, the pipeline is fully correct with AI off):

| Δ | Delivers | Runtime |
| --- | --- | --- |
| **Δ1 (this change)** | Gateway walking skeleton — one reactive capability end-to-end on every real seam | Go |
| Δ2 | Typed Engine Dispatcher + Rule Engine + budget + security/privacy admission | Go |
| Δ3 | Python LLM engine (DSPy/LangGraph) + RAG / Knowledge Engine (pgvector) | +Python, +pgvector |
| Δ4 | Autonomous engine + push seam + LLMOps plane + operational store | separate |

The rule that keeps Δ2–Δ4 additive (no rewrites): **Δ1 sits on the harness's real seams**, even with one
thing behind each.

## What — Δ1 (this change)

The **walking skeleton**: one reactive capability, **pure Go**, disable-able, through every seam.

- a minimal **in-code Capability Registry** with `recommend_position@v1` — a Capability = execution plan
  (ordered engine steps; Δ1 = one LLM step) declaring context needs, output schema, business rules, routing
  requirements;
- the structured **advisory Proposal envelope** (recommendation stance + finding_id / confidence / evidence /
  reasoning / capability / metadata), recorded by Governance as a Governance Proposal;
- the **Engine port** with **one LLM engine**, no dispatcher; a **provider adapter** speaking the
  **OpenAI-compatible** schema (Ollama) plus a **fake provider** for CI;
- deterministic **Context Construction** via read-API Knowledge Providers — caller passes identifiers only;
  the Gateway pulls **Finding** (Governance) + **Faultline enrichment** (Knowledge) into `AssembledContext`;
- Gateway-owned **prompt template** (embedded; no prompt strings in business code) → **mandatory 3-stage
  validation** (schema → business/anti-hallucination → proposal construction); **"no proposal" is a
  first-class safe outcome**;
- a **synchronous reactive API** (`POST /v1/capabilities/{id}/invoke`) and an **independently-deployable,
  stateless** `cmd/intelligence`;
- **Governance as the caller, off the hot path** — a non-blocking side-path invokes the capability (when AI
  enabled) and records an **ai** proposal via `RaiseProposal`, **never auto-accepted** (human decides);
- the **single-seam disable gate** (real-vs-no-op client, one config flag) and **OpenTelemetry** execution
  telemetry via the shared observability package.

Full decision list with rationale: **EDR-INTELLIGENCE-01 (D1–D13, Revision 2)**.

## Non-goals (guardrails / deferred to later deltas)

- **Owning or establishing truth / deciding** — forbidden; every output is an advisory Proposal governed by
  Governance (INT-0056/0066, CON-0015). Autonomy of *generation*, never of *authority*.
- **Direct provider access from any context** — all provider traffic funnels through this Gateway
  (INT-0059); provider-specific code lives only here (INT-0070).
- **Deferred to Δ2–Δ4:** the Engine Dispatcher + Rule/Knowledge engines · budget + security/privacy
  admission · the **Python** engine · **RAG/pgvector** · the **autonomous engine** + push seam · the
  **LLMOps plane** (prompt registry, golden datasets, A/B, model registry, capability promotion) · the
  operational store · confidence-threshold auto-accept (a later Governance-side policy delta).
- **The existing `internal/` PoC + archived `themis-ai-1`** stay as reference and are **not modified**.

## Realizes (ADRs / EDR)

INT-0056 through INT-0070, CON-0002, CON-0003, CON-0008, CON-0015, CON-0016, DOM-0033, BCK-0037, BCK-0041,
BCK-0047, BCK-0051, BCK-0052 — via **EDR-INTELLIGENCE-01 (D1–D13, Revision 2)**. Δ1 realizes the D1/D2/D5/
D6/D7/D8/D9/D12/D13 seams; D3(autonomous)/D4/D10/D11(versioning) land in Δ2–Δ4.
