# Design — phase3-intelligence (Intelligence Gateway / AI enrichment) · Δ1

## Source of truth

All engineering decisions (rationale + rejected alternatives) live in
**`docs/engineering/decisions/EDR-INTELLIGENCE-01.md` (D1–D13, Revision 2)** — which adopts the **harness**
(`docs/engineering/THEMIS-AI-HARNESS.md`) as the destination and defines the **4-delta roadmap**. This
document states the **Δ1** layout, import rules, state, seams, and gates only.

## Δ1 scope (this change)

The **walking skeleton**: one reactive capability (`recommend_position`) end-to-end, **pure Go**,
**disable-able**, sitting on every real harness seam so Δ2–Δ4 are additive. Out of scope: the Engine
Dispatcher, Rule/Knowledge engines, budget + security/privacy admission, the Python engine, RAG/pgvector,
the autonomous engine + push seam, and the LLMOps plane (all Δ2–Δ4).

## Layout (D12 · ADR-BCK-0037; Book III §3.2)

A supporting Gateway (owns no truth), same Go module, **independently deployable**, **stateless in Δ1**.
Uses the house context-first layout `{domain,app,adapters}` (like all five other contexts, so the shared
`go-cleanarch` loop + arch test apply unchanged); the EDR's "gateway core + ports + adapters" is realized as
**domain + app + adapters**:

```text
internal/intelligence/
├── domain/     gateway-core types (Capability, ExecutionPlan, Proposal envelope, AssembledContext,
│               recommendable Stance) + in-code Capability Registry + pure 3-stage validators
├── app/        the invoke pipeline (context -> prompt -> route -> execute -> validate -> propose) + ports
│               (Engine, Provider, Router, FindingReader, FaultlineReader, PromptRenderer)
└── adapters/   LLM engine + provider adapters (Ollama OpenAI-compatible, fake) · Knowledge/Governance
                read-API clients · reactive HTTP API (oapi-codegen) · telemetry · wiring
cmd/intelligence/   independently-deployable, stateless service (reactive API; no workers in Δ1)
internal/governance/adapters/intelligence/   ACL client (the caller side) — mirrors communication/adapters/governance
```

## Vocabulary (Revision 2)

- **Engine** = a *kind of reasoning* (Rule/Knowledge/LLM), the typed unit; Δ1 ships **one LLM engine, no
  dispatcher**. Seam: `Engine.Execute(step, ctx) → RawResult`.
- **Provider / adapter** = the *concrete backend* behind an engine (Δ1: Ollama via OpenAI-compatible schema,
  plus a fake). INT-0070 confines and swaps it.

## Import + boundary rules (INT-0059/0068/0070; Book III §3.5)

- All **engine/provider-specific code is confined to `adapters/`** behind the Engine/Provider ports
  (INT-0070); a provider swap never touches any other context.
- Intelligence **reads enterprise knowledge only via read APIs** (Knowledge Providers), never a DB
  (INT-0068); it **writes nothing** to truth stores. Δ1 is **reactive-only** — the validated Proposal is
  returned in the HTTP response and **Governance records it**; there is **no proposal-intake push adapter**
  (that is Δ4/autonomous).
- No cross-context imports; enforced by `go-cleanarch` + depguard + `TestIntelligenceSupportingContext`.

## State (Δ1: none — stateless)

Owns **no enterprise truth**. Δ1 persists **nothing**: the Capability Registry is an **in-code catalog**,
there is no response cache and no evaluation loop → **no datastore, no migrations**. The operational store
(registry versions, cache, eval results) arrives with **Δ4** (LLMOps). Telemetry flows to OpenTelemetry.

## Disable gate (D13 · CON-0015)

Intelligence is an **optional plane**; the pipeline is correct with AI off. Enablement is **one wiring
choice** in Governance's composition root — the **real vs a no-op** Intelligence client (the no-op returns
"no proposal" with no network call). No call-site flags. **Disabled ≡ unavailable**: unreachable /
over-budget / declined all collapse to the same never-block "no proposal" path.

## Cross-context seams

- **Reads (grounding):** `FindingReader` (Governance read API) + `FaultlineReader` (Knowledge read API) —
  caller passes identifiers only; the Gateway assembles `AssembledContext` deterministically.
- **Reactive invoke:** Governance's ACL client → `POST /v1/capabilities/{id}/invoke` → validated Proposal
  back; Governance records it via `RaiseProposal` as an **ai** proposal, **never auto-accepted** in Δ1
  (confidence travels for a later Governance policy delta). Off the hot path (non-blocking side-path).

## Stack

Canonical stack + rationale: **`docs/engineering/STACK.md`** (read before implementing). Δ1-specific: an
**independently-deployable, stateless Go service**; **provider adapters** — Ollama (OpenAI-compatible HTTP)
plus a deterministic fake — behind the **Provider port**; **`jsonschema/v6`** for stage-1 validation; **chi +
oapi-codegen** for the reactive API; Knowledge/Governance **read-API clients**; **OpenTelemetry** (+ console
debug) via `internal/platform/observability`; **no truth-store driver, no DB in Δ1**. Local model runtime is
a **containerized service** in-cluster / **native Ollama on Mac dev** / **fake in CI** — selected by config.

## Quality gates

The six Themis gates (`make check`) — build, unit tests, coverage, dead-code, integration tests,
clean-architecture — extended to `internal/intelligence/` and `cmd/intelligence/`. Markdown passes
`markdownlint-cli2`.
