# Design — phase3-intelligence-d2 (Intelligence Gateway / AI enrichment) · Δ2

## Source of truth

All engineering decisions (rationale + rejected alternatives + the **grounded component choices C1–C7**) live
in **`docs/engineering/decisions/EDR-INTELLIGENCE-01.md` — Revision 3 (Δ2 concrete cut)**. This document
states the Δ2 **layout, seams, and gates only**. The five deferred items (**G-AI-1..5**) live in
`docs/engineering/PHASE3-BACKLOG.md` §C.

## Δ2 scope (this change)

Additive over Δ1 **on the same seams**: `recommend_position` grows from a one-step `[LLM]` plan to a two-step
`[Rule → LLM]` plan; Δ2 adds the **Engine Dispatcher**, the **Rule Engine** (all-Go, version-range), the
**`insufficient`** outcome, **precedent-Positions** grounding, the **provenance stamp**, and the one
**pre-invocation admission gate** (budget meter + minimal local-only security). Out of scope: the Python
engine + RAG (Δ3), the autonomous engine + LLMOps (Δ4), and the G-AI-1..5 deferrals.

## Layout (additive; house context-first `{domain,app,adapters}`; still stateless — no DB)

The Δ1 tree is unchanged; Δ2 adds (no new context, no datastore, no migrations):

```text
internal/kernel/value/           (+) version-range value object — ported by design from the PoC version engine
                                     (internal/domain/version_engine.go), NOT imported (C2)
internal/intelligence/
├── domain/     (+) Rule predicates (version-range applicability, one-direction certainty) ·
│               (+) ExecutionPlan grows to 2 steps · (+) Decision provenance (which step decided) ·
│               (+) `insufficient` in the recommendable set
├── app/        (+) Engine Dispatcher (typed step -> engine routing) · (+) one pre-invocation admission gate
│               (budget meter + runaway guard + authorize + redact + hard local-only) · (+) PrecedentReader port
└── adapters/   (+) Rule engine (behind the existing Engine port) · (+) Governance precedent read-API client ·
                (+) OTel budget meter · (+) Redactor (mirrors Communication)
internal/governance/adapters/http   (+) read-API: "Positions for this CVE across releases" query (C6)
```

## What is additive vs Δ1 (no rewrites)

- The **Engine port** (`Engine.Execute(step, ctx) -> RawResult`) is unchanged; Δ2 adds a **Rule engine**
  behind it and a **Dispatcher** in front (Δ1's trivial one-engine routing becomes a real two-step route)
  (C3/C4).
- The **Provider port** (OpenAI-compatible) is unchanged; **no new backend** in Δ2 — Ollama stays the default
  and a swap remains config, not code (C1).
- The **3-stage validation** is unchanged; the recommendable set gains `insufficient` (business stage +
  schema).
- **Context Construction** gains **one** read (precedent Positions), pulled **only when the plan reaches the
  LLM step** (C6) — the rule step short-circuits before any grounding cost.

## The two-step plan + dispatcher (EDR Rev 3, behavioral cut)

- **Rule step first** — version-range applicability. **Provably out of range -> certain `not_affected`,
  short-circuit** (no dispatcher hand-off to the LLM, no grounding, no provider). Certain in **one direction
  only** — never auto-`affected` ("in range" is the LLM's judgment, and auto-`affected` would duplicate
  Governance's KEV/severity `proposalFor`). Unknown ecosystem / no range -> **fall through**; no facts at all
  -> `insufficient`.
- **LLM step** — the Δ1 pipeline, now the fallback (grounding -> prompt -> provider -> 3-stage validation).
- **Deterministic-first invariant:** the LLM is invoked **iff** the rule produced no clear answer.
- **Provenance:** every result carries **which step decided** (`rule:not_affected` / `llm:<stance>` /
  `insufficient`) — the assertion hook for tests and the metric source for G-AI-2.

## Admission gate (one pre-invocation step)

- **Budget — measure now, enforce lightly:** an OTel **meter** (per-call duration / input-size / token count)
  plus one **runaway guard** (per-request timeout + prompt input-size cap). Real multi-scope enforcement +
  degrade-not-fail routing is deferred (local = free) — **G-AI-4** (C5).
- **Security/privacy — minimal, local-only:** (1) authorize the caller, (2) **Redactor** scrubs secrets/PII
  from prompt + telemetry (mirrors Communication), (3) **hard-mark the path local-only** so nothing can reach
  a cloud provider. Full data-classification -> provider-clearance is deferred — **G-AI-5** (C7).
- The gate runs **before any provider call**; the rule step (no provider) is not gated on budget/privacy.

## Boundary: Information vs Enterprise Knowledge (Domain Invariant 3)

Intelligence produces **Information** only (an advisory suggestion) and **writes no truth**; precedent
Positions are **read-only** context, handed as context-not-instruction. This reaffirms D1/D2 and Book II Ch 2's
new Domain Invariant 3, "Gathering Is Not Knowing."

## State (Δ2: still none — stateless)

No datastore, no migrations. The meter is **OTel metrics** (C5), not a store. The operational store (registry
versions, cache, eval) is Δ4.

## Disable gate (D13 — unchanged)

Intelligence stays an optional plane; the real-vs-no-op wiring choice in Governance's composition root is
unchanged. Δ2 additions never introduce a call-site AI flag. Disabled == unavailable still collapses to the
never-block "no proposal" path; `insufficient` is a distinct, first-class **enabled** outcome (not the same as
"AI off").

## Component & Technology Decisions

Summarized here; the **authoritative, alternatives-weighed table (C1–C7) is in EDR Rev 3**. Δ2 introduces **no
new third-party dependency**.

- **C1 — Model runtime:** the commitment is the **vendor-neutral Provider port (OpenAI-compatible)**, not the
  vendor; Ollama stays the Δ2 default (native Mac-dev Metal GPU / containerized in-cluster / fake in CI).
  vLLM / TGI / Cerebras / hosted APIs all slot behind the same port by config (INT-0070) — chosen because
  interfacing ~100 backends is the real problem, and the port makes each a config swap, not code.
- **C2 — Version-range comparison:** **port the PoC's proven, property-tested version engine** into a
  shared-kernel value object (frozen PoC = reference, ported not imported); it already handles Themis's real
  ecosystems (Alpine `-r0`, PyPI, GIT-vs-ECOSYSTEM) that a SemVer-only lib gets wrong; no new dependency.
- **C3 — Rule representation:** **hand-written Go predicates** (all-Go per the EDR) over a DSL/engine (CEL,
  grule) — one deterministic rule needs no runtime rule language.
- **C4 — Engine Dispatcher:** **a small in-Go typed dispatcher** over a workflow engine (Temporal) or plugins
  — the plan is a 2-step list; durable orchestration / process isolation are later-delta concerns.
- **C5 — Budget meter:** **OpenTelemetry metrics** (the mandated telemetry SoR) over Prometheus-direct or a
  DB table — vendor-neutral, needs no store (stateless Δ2).
- **C6 — Precedent grounding:** **extend Governance's read API + reuse the read-API-client seam** over a
  direct DB read (violates D5) or an Intelligence cache (violates statelessness).
- **C7 — Redaction:** **a Redactor port mirroring Communication** over a heavyweight PII scanner — premature
  for local-only Δ2.

## Stack

Canonical stack + rationale: **`docs/engineering/STACK.md`**. Δ2-specific: **no new third-party dependency**
(the version engine is ported in-repo; dispatcher/rule/meter are all-Go; the meter is OTel; the redactor
mirrors Communication). The provider stack is unchanged from Δ1 (OpenAI-compatible port + Ollama + fake).

## Quality gates

The six Themis gates (`make check`) — build, unit tests, coverage, dead-code, integration tests,
clean-architecture — extended to the new Intelligence packages, the Governance read-API addition, and the
kernel version-range value object. A **rapid property test** covers version-range applicability (carried from
the PoC's proven property test). Markdown passes `markdownlint-cli2`.
