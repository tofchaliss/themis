# EDR-INTELLIGENCE-01 — Intelligence Gateway (AI Enrichment) Supporting Context

Status: **Re-grilled against the harness — ready to implement Δ1** (13 decisions locked; revised 2026-07-18).
Ground rule: ADR/EDR wins; the `internal/` PoC and the archived `themis-ai-1` design are reference only.

## Purpose

Convert the Intelligence ADR cluster (INT-0056…INT-0070, plus CON-0002, CON-0003, CON-0008, CON-0009,
CON-0015, DOM-0024, DOM-0033, BCK-0037, BCK-0041, BCK-0047, BCK-0052) into concrete, testable engineering
decisions for the Phase-3 greenfield rebuild.

Intelligence is the supporting **AI Gateway** (Book IV). It is the single exclusive entry to all
AI/ML/rule/knowledge-graph providers, invoked as named capabilities, and it produces validated, structured,
**advisory-only Proposals** for the pipeline contexts (Knowledge, Governance). It **never owns enterprise
truth** (INT-0056); human governance stays the final authority (INT-0066).

## Revision 2 (2026-07-18) — Harness destination & delta delivery

This EDR is **revised** after re-grilling M4 against `docs/engineering/THEMIS-AI-HARNESS.md`. The harness is
adopted as the **target architecture (the destination)**; this EDR remains the single authority (**EDR
wins** — the harness doc is design input, folded here). The **authority spine — D1, D2, D7, D8, D10
(owns-no-truth, advisory-Proposal-only, mandatory validation, governed intake, human authority) — is
unchanged.** Only the *internal shape* below that spine evolves, delivered as **additive deltas**, not one
big change. The new **D13** (optional plane) makes every delta safe to ship.

### The harness is the destination; migrate in four deltas

Full harness = typed multi-engine dispatch + execution-plan harness + Capability Registry + Context
Construction/RAG + prompt/routing + 3-stage validation + reactive API + autonomous engine + budget +
security/privacy admission + OTel/eval + a **Python** engine + the **LLMOps plane**. Too large for one
change. It ships as four coherent, individually-shippable deltas (each safe because the plane is
disable-able, D13):

| Δ | Change | Establishes | Runtime |
| --- | --- | --- | --- |
| **Δ1** | Gateway skeleton + first capability (walking skeleton) | **all seams**: Capability (invoke-by-id) · advisory Proposal envelope · **Engine port** (one engine) · Gateway service boundary (API+events) · Context Construction via read-APIs · 3-stage validation · reactive invoke into Governance · **disable gate** · OTel | Go |
| **Δ2** | Typed dispatch + admission spine | **Engine Dispatcher** + **Rule Engine** (all-Go) · budget (4 scopes) · security/privacy admission · richer grounding · more capabilities | Go |
| **Δ3** | Polyglot + advanced reasoning | **Python LLM engine** (DSPy/LangGraph) behind the engine port · **RAG / Knowledge Engine** (pgvector) | +Python, +pgvector |
| **Δ4** | Autonomy + LLMOps | **Autonomous engine** + scheduler + push seam · **LLMOps plane** (prompt registry, golden datasets, A/B, model registry, capability promotion) + operational store | separate |

The one rule that keeps every later delta additive (no rewrites): **Δ1 must sit on the harness's real seams,
even with one thing behind each.** Get the seam shapes right once; fill in behind ports thereafter.

### Vocabulary: Engine vs Provider (resolves the provider/engine collision)

- **Engine** = a *kind of reasoning* — **Rule / Knowledge / LLM** — the typed unit selected by the (later)
  **Engine Dispatcher**. This is the seam Δ1 builds (`Engine.Execute(plan, ctx) → RawResult`).
- **Provider / adapter** = the *concrete backend* behind an engine (Ollama, a Python-DSPy service, a rule
  set, pgvector). This is what INT-0070 confines and swaps.
- A **Capability** declares engine requirements → the Dispatcher routes to an **Engine** → the Engine calls
  its **Provider adapter**. The former "uniform provider port" (D6/D11) is narrowed to **Engine port +
  provider adapter** — an additive rename, not a contradiction of INT-0070's swap-a-provider guarantee.
- **Δ1 builds the Engine port but ships one engine (LLM/Ollama) and no dispatcher** (one engine = trivial
  routing). Rule/Knowledge engines + the dispatcher are Δ2/Δ3.

### Δ1 concrete cut (the walking skeleton)

One reactive capability end-to-end, pure Go, disable-able:

- **Capability:** `recommend_position` — **AI-assisted affected / not-affected triage** (use case #4 in
  `docs/current-changes/themis-ai-use-cases.md`; chosen over the historical CVE-Summarizer first-pick because
  it exercises the full advisory-Proposal → governance-intake seam, and it is a **judgment/synthesis** task —
  a real LLM fit — not version-range logic, which is a rule-engine job). It grounds a Governance **Finding**,
  proposes a **disposition Stance constrained to `{affected, not_affected, mitigated}`** (never the
  human/process stances `accepted_risk` / `deferred` / `under_investigation`) + confidence + cited evidence +
  reasoning, feeding **Governance's `RaiseProposal`** as an **advisory** ai Proposal. **Trigger is on-demand**
  — a human requests a recommendation on a specific Finding — **never auto-fire per Finding** (avoids proposal
  flood + wasted compute). Δ1 proves the **seam**, not model accuracy (a local 7–8B model's triage quality is
  mediocre; advisory-only + human-decides + the Δ4 eval loop cover that).
- **Capability = execution plan** (ordered engine steps); Δ1 plans are **one LLM step**. Registry =
  **in-code catalog** (DB-backed versioning deferred to Δ4).
- **Context Construction:** the caller passes **identifiers only**; the Gateway deterministically pulls
  grounding via read-APIs — **Finding** (Governance) + **Faultline enrichment** (Knowledge). Precedent
  Positions deferred. Ports `FindingReader` / `FaultlineReader`, fakeable.
- **Prompt/routing:** Gateway-owned **versioned prompt template** (embedded asset; Prompt Registry
  deferred); router real but trivial (one engine → Ollama); **temp-0 + pinned model + structured-output**
  constraint + recorded params. The provider adapter speaks the **OpenAI-compatible** schema (Ollama serves
  it) so the runtime is swappable by config.
- **3-stage validation:** schema (`jsonschema/v6`, one retry) → business (finding_id = subject, every
  evidence-ref ∈ grounding context, confidence ∈ [0,1], stance ∈ the **recommendable subset**
  `{affected, not_affected, mitigated}`; no retry) → proposal construction. Stage-2 is a pure
  `(output, context)` function — hermetically testable. **"No proposal" is a first-class safe outcome.**
- **Reactive API:** spec-first `POST /v1/capabilities/{id}/invoke` (oapi-codegen), **synchronous** in Δ1
  with a bounded timeout; async designed-in.
- **Governance is the caller, off the hot path:** on an **on-demand human request** (a "recommend a position"
  action on a Finding), when AI is enabled, Governance invokes `recommend_position` on a **non-blocking path**
  and records the returned proposal as an **ai** Governance Proposal; **never auto-accepted in Δ1** (human
  decides; confidence travels for a later Governance policy delta). ACL client
  `internal/governance/adapters/intelligence/client.go` (mirrors Communication→Governance). Additive
  Governance extension: `GovernanceProposal` gains optional confidence / evidence-refs / source
  capability+version.
- **`cmd/intelligence`: independently deployable and STATELESS in Δ1** — in-code registry, no eval loop, no
  cache → no datastore/migrations. The operational DB arrives with Δ4. **No proposal-intake push adapter in
  Δ1** (reactive returns the envelope in the HTTP response; the push adapter is Δ4/autonomous).
- **Model runtime:** the local model is a **containerized service (own Deployment+Service)** in the cluster,
  reached over HTTP behind the provider port, **part of the optional plane** (deployed only when AI is on).
  **Mac dev runs native Ollama** (Metal GPU) at `localhost:11434`; **CI uses the fake provider**; all three
  are selected by config. Dev default model `llama3.1:8b` q4 (16 GB Apple Silicon).

## Decisions

### D1 — Intelligence is a supporting Gateway (owns no truth), beside the pipeline, the exclusive provider entry

Decision:

- Intelligence is a **supporting infrastructure context — the Intelligence Gateway** — **not** a
  truth-owning bounded context and **not** a stage in the Evidence → Knowledge → Governance → Communication
  line. It sits **beside** the pipeline and feeds it.
- It **owns no enterprise truth**: no Faultlines, Findings, Enterprise Positions, or Publications. It
  produces validated, structured Proposals that the pipeline contexts (Knowledge, Governance) **record and
  govern** as their own (INT-0056, CON-0009).
- Its only persistent state is **operational** — capability registry, telemetry, evaluation results, cache
  — never business knowledge (INT-0064/0065/0067).
- It is the **single exclusive entry** to all AI/ML/rule/knowledge-graph providers (INT-0059); **no other
  context touches a provider directly**. It is consumed via **named capabilities** (INT-0058), never raw
  model/provider calls.

ADR basis: INT-0056 (never owns truth; results enter as Proposals under governance), INT-0059 (single
exclusive Gateway; no context talks to a provider directly), INT-0058 (capability-based invocation),
CON-0009 (Governance owns authority), CON-0015 (human authority over automation).

Reference (not authority): the archived `themis-ai-1` design (7 AI workers, RAG, KB-first, AI-assisted VEX)
is the closest precursor; the greenfield lifts it behind the one Gateway + capability abstraction the ADRs
mandate, rather than per-worker provider access.

### D2 — Output is a structured, schema-validated advisory Proposal; the consuming context records it

Decision:

- Every Intelligence output is a **structured, schema-validated Proposal** (INT-0057) with a fixed envelope:
  **recommendation, confidence, supporting evidence, reasoning, originating capability, execution
  metadata**. Raw natural-language text **never** enters the enterprise directly.
- The Intelligence Proposal is an **advisory transport**; the consuming context records it as **its own**
  proposal under its own lifecycle:
  - **Into Knowledge** → a **Knowledge Proposal** (source = an AI capability), reconciled by Knowledge's
    precedence rule with **no special authority** (EDR-KNOWLEDGE-01 D2/D6).
  - **Into Governance** → a **Governance Proposal** (a proposed decision about a Finding), evaluated →
    accept/reject (EDR-GOVERNANCE-01 D4/D11).
- **Always advisory:** never authoritative; only Governance (human or policy) promotes it (INT-0056/0066,
  CON-0015). Confidence + reasoning + evidence travel for explainability (CON-0003) and to feed governance
  policy thresholds (INT-0066); originating capability + execution metadata give provenance + observability
  (INT-0064).
- Intelligence **returns** the validated Proposal to its caller (a pipeline context — INT-0058); it
  **never writes into Knowledge/Governance stores itself** (owns no truth, D1).

ADR basis: INT-0057 (structured, schema-validated proposals; no raw NL), INT-0056 (advisory proposal under
governance), INT-0066 (human governance final; policy thresholds weigh confidence), CON-0002 (proposal
before truth), CON-0003 (explainability), CON-0015 (human authority), INT-0064 (execution metadata).

Reference: `themis-ai-1`'s AI workers wrote enrichment directly; the greenfield returns a validated Proposal
the caller records — no direct writes.

### D3 — Dual-mode Intelligence: reactive capabilities + autonomous engine, one advisory-proposal exit; independent service; reactive-first

Decision:

- Intelligence is an **independently-running service beside themis-core** (its own runtime / "engine room,"
  not an in-process library — INT-0059 shared infrastructure, INT-0070 provider-confined). The seam to
  themis-core is **API + events**, not in-process calls.
- **Two operating modes**, both funnelling to the same advisory-Proposal exit (D2), both through the
  capability abstraction + Gateway (INT-0058/0059) and reading knowledge via Knowledge Providers (INT-0068):
  - **Reactive (use-centric):** a pipeline context invokes a named capability on demand (INT-0058); the
    validated Proposal **returns to the caller** (D2).
  - **Autonomous (bigger-picture):** Intelligence's **own** scheduled/continuous analysts read enterprise
    knowledge and **proactively emit cross-cutting advisory Proposals** (emergent insights — shared root
    cause, emerging-threat clusters, portfolio risk narrative) that no single request would ask for. Having
    no caller, they are **pushed to the target context's proposal-intake** (Knowledge-Proposal or
    Governance-Proposal intake) — the outbound push seam (D-seam, later).
- **Guardrail (immovable):** autonomy of **generation** is allowed; autonomy of **authority** is not. Every
  output — reactive or autonomous — is an advisory Proposal governed by Governance (INT-0056/0066,
  CON-0015). Intelligence never owns truth or decides (D1).
- **Both modes are designed in; reactive ships first**, the autonomous engine follows (the push seam +
  analyst scheduling + budget are designed now, enabled later).

ADR basis: INT-0058 (capability invocation/abstraction), INT-0059 (exclusive Gateway, shared infra),
INT-0068 (knowledge via retrieval services), INT-0056/0066 (advisory only; governance final), INT-0070
(provider independence), CON-0015 (human authority).

Honesty flag: INT-0058 describes the **reactive** (App-Service-invoked) path explicitly. The **autonomous
engine** is ADR-compatible because (a) it still uses the capability abstraction + Gateway, (b) its output is
an advisory Proposal under governance (authority unchanged), and (c) the ADR guardrails constrain
**authority, not initiative**. The autonomous mode is a deliberate architecture choice beyond the literal
INT-0058 text, kept strictly within its guardrails.

Reference: `themis-ai-1`'s 7 autonomous workers ≈ the autonomous engine's analysts; the greenfield unifies
them behind the capability abstraction + advisory-proposal exit.

### D4 — Budget / resource-consumption model: metered per run, nested scopes, Gateway-enforced, degrade-not-fail

Decision:

- **Unit of account:** every capability execution has a measured cost (tokens × provider price, or
  local-model compute), captured by INT-0064 telemetry and tagged with capability + correlation id.
- **Budget scopes (nested envelopes):** a **per-run ceiling** (runaway-prompt guard); **per-capability /
  per-context** (reactive spend over a window); a **separate, capped autonomous-engine pool** (+ cadence);
  and a **global enterprise ceiling** per period.
- **Enforcement at the Gateway (pre + post), split by mode:**
  - **Reactive** — naturally bounded (one call under the per-run + context ceiling); pre-check
    admits/downgrades/rejects, post-run debits.
  - **Autonomous** — spends from its **own capped pool on a schedule**; when exhausted it **pauses until the
    next window** (can never outspend its envelope), and works **highest-value knowledge first**
    (recently-changed Faultlines, high-severity clusters).
- **Degradation, not silent failure:** low budget → **downgrade the model** (INT-0062), reduce autonomous
  cadence, **defer** low-priority work (recorded, not dropped). Rate limits (INT-0059) and privacy class
  (INT-0069) are enforced in the same pre-invocation admission step.
- **Model default: local-model-first** — routine enrichment uses local/cheap models; cloud/paid models are
  reserved for asks that clear a value/privacy bar (INT-0062 cost-aware routing, INT-0069 privacy,
  provider-independent per INT-0070).
- **Autonomous pool sizing:** a **flat periodic budget** to start (predictable); proportional-to-activity
  (scale with SBOM/Faultline volume) is deferred as a tuning option.
- **Governance owns the budgets/policies** (INT-0066); the **Gateway enforces**; budgets are config, not
  code.

ADR basis: INT-0064 (cost/token telemetry per run), INT-0062 (cost-aware model routing), INT-0066
(governance policy sets thresholds and what may run; provider never sets policy), INT-0069
(privacy/security admission), INT-0059 (Gateway rate limiting), INT-0065 (cost feeds evaluation), INT-0070
(provider independence).

Reference: `themis-ai-1` ran Ollama locally on the same box — the local-first default carries that forward
as the routine path.

### D5 — Deterministic Context Construction Pipeline via Knowledge Providers (read APIs, never direct DB)

Decision:

- A **deterministic Context Construction Pipeline** runs **before any prompt is built** (INT-0061):
  assembles, validates, and normalizes exactly the context a capability declares it needs.
- Sourced via **Knowledge Providers** — dedicated retrieval services (INT-0068), **never direct database
  access**. **Enterprise Knowledge is primary** (Faultlines, Enterprise Positions, Findings — read through
  the pipeline contexts' **read APIs**, Book III §3.5 / no shared DB); supplemented by policies, customer
  config, external intel.
- **Deterministic:** same inputs → same assembled context (reproducible, testable, provider-independent) —
  which enables explainability (CON-0003) and keeps the AI **grounded in enterprise knowledge** (the
  RAG / KB-first idea, done via retrieval services rather than DB reads). Intelligence **reads, never
  writes** (D1).
- Context construction **completes before** prompt generation and is independent of prompt + provider
  (INT-0061).

ADR basis: INT-0061 (deterministic context pipeline before prompt generation; assemble/validate/normalize;
provider-independent), INT-0068 (Enterprise Knowledge primary; Knowledge Providers; never direct
persistence), CON-0003 (explainability/reproducibility), Book III §3.5 (read APIs, no shared DB).

Reference: `themis-ai-1`'s RAG / KB-first design ≈ the Knowledge Providers + context pipeline, boundary-
corrected to read APIs.

### D6 — Prompt construction + runtime model routing are Gateway infrastructure; provider specifics confined

Decision:

- **Prompt construction** (INT-0060): callers pass a **capability name + structured domain objects + the
  assembled context** (D5); the **Gateway** builds provider-specific prompts. **No prompt strings** in
  domain or app code.
- **Model routing** (INT-0062): the capability **declares requirements** (reasoning depth, latency, cost,
  privacy/regulatory class, availability); the **Gateway** picks the provider/model at runtime against
  those + enterprise policy + budget (D4). Callers **never name a provider or model**.
- **Provider-specific everything** — prompts, SDKs, auth, response quirks — is **confined to the Gateway**
  (INT-0070); swapping a provider changes **nothing** in the Backend or Domain, and future tech (knowledge
  graphs, agents, planners) plugs in through the same capability abstraction.
- Chain: context (D5) → prompt (INT-0060) → model routing (INT-0062) → execute → validate (D7).

ADR basis: INT-0060 (prompt construction is infrastructure; no provider prompts in business code), INT-0062
(runtime model selection by capability requirements, in the Gateway), INT-0070 (provider-specific impl
confined to the Gateway; Backend/Domain unaffected by a provider swap), CON-0005 (business language before
implementation language).

Reference: `themis-ai-1` embedded prompts and model choices inside workers; the greenfield moves both into
the Gateway.

### D7 — Mandatory 3-stage Gateway validation; unvalidated never becomes a Proposal

Decision:

- Every provider response passes a **mandatory 3-stage validation in the Gateway** (INT-0063) before it can
  become a Proposal:
  1. **Schema Validation** (structural) — matches the capability's declared output schema (INT-0057);
     malformed → reject/retry.
  2. **Business Validation** (semantic) — enterprise-valid: references **real** Faultlines/CVEs from the
     grounding context (D5), confidence in range, any stance from the allowed set, no contradiction with the
     supplied knowledge; invalid → reject.
  3. **Proposal Construction** — build the structured advisory Proposal envelope (D2) from the validated
     response.
- **Unvalidated responses never become Proposals** (INT-0063). A failure is **recorded** (telemetry,
  INT-0064) and may trigger a **retry** (INT-0059) or a graceful **"no proposal"** outcome — a raw or
  hallucinated value never leaks into the enterprise.
- Validators are **Gateway-owned** and **per-capability** (each declares its schema + business rules,
  versioned — INT-0067).
- Business Validation + D5 grounding = the **anti-hallucination backbone**: an answer citing a CVE not in
  the grounding context, or an out-of-range confidence, is rejected **before** becoming a proposal.

ADR basis: INT-0063 (mandatory 3-stage validation; unvalidated never a proposal; validators in the
Gateway), INT-0057 (schema-validated structured proposals), INT-0064 (record validation outcome), INT-0059
(Gateway retries), INT-0067 (per-capability versioned rules).

Reference: `themis-ai-1` parsed worker outputs ad-hoc; the greenfield enforces the 3-stage gate.

### D8 — One reused proposal-intake for both modes; confidence feeds enterprise-owned governance policy

Decision:

- **One intake path, reused:** every Intelligence Proposal (reactive-returned or autonomous-pushed) enters
  through the **target context's existing proposal-intake**:
  - **Knowledge Proposal** → Knowledge's Fold-Proposal intake (EDR-KNOWLEDGE-01 D6), source = AI capability,
    reconciled with **no special authority**.
  - **Governance Proposal** → Governance's `RaiseProposal` (EDR-GOVERNANCE-01 D11), evaluated →
    accept/reject.
- **Reactive** proposals return to the caller, who records them via that intake. **Autonomous** proposals
  have no caller, so Intelligence **pushes them to the intake port** (API/event) — Intelligence still
  **never writes truth** (D1); the target context records and governs.
- **Governance policy decides what happens next** (INT-0066): the confidence + capability + evaluation score
  (D2) are **inputs the enterprise-owned governance policy weighs** — auto-accept above a threshold
  (Governance's D11 policy rule), mandatory human review below it, escalation. The **policy is
  enterprise-owned; Intelligence and the provider never set it** (INT-0066, CON-0015).
- Intelligence proposes; governance policy + humans dispose. Confidence is a **policy input**, never
  self-granted authority.

ADR basis: INT-0056 (results enter as governed proposals), INT-0066 (enterprise policy defines auto-accept /
review / escalate; provider never sets policy), CON-0015 (human authority), CON-0002 (proposal before
truth). Contracts: EDR-KNOWLEDGE-01 D6, EDR-GOVERNANCE-01 D11.

Reference: `themis-ai-1`'s AI-assisted VEX auto-applied enrichment; the greenfield routes it through the
governance policy + proposal-intake.

### D9 — Observability via OpenTelemetry (+ console log for local debug); continuous evaluation, never touching truth

Decision:

- **Observability (INT-0064, BCK-0051):** every capability execution emits structured telemetry —
  capability + correlation id, provider, model, duration, tokens, estimated cost, validation outcome,
  proposal id — enough to reconstruct any execution, **correlated by stable business identifiers**
  (BCK-0051).
- **Mechanism: OpenTelemetry** (vendor-neutral **traces + metrics + logs**) is the **architectural
  telemetry**, integrating with any enterprise observability backend (provider-independent, consistent with
  INT-0070). **Plus console/structured logs for local debugging** — an implementation artifact for dev,
  **not** the architectural telemetry (BCK-0051 explicitly distinguishes debug logs from architectural
  telemetry).
- **Privacy:** sensitive prompts / confidential enterprise data are **never exposed** in telemetry unless
  explicitly authorized (INT-0064, ties INT-0069).
- **Evaluation (INT-0065):** each capability defines measurable criteria — accuracy, consistency, latency,
  cost, **proposal acceptance rate**, human feedback, business impact. Results are **operational
  intelligence, not business knowledge**: they influence provider/model routing (INT-0062) and capability
  version selection (INT-0067), and **never modify enterprise truth**.
- **Improvement loop:** the **acceptance rate from governance** (D8) flows into evaluation → tunes routing +
  which capability version is live. A capability that proposes well is used more; one that proposes badly is
  downgraded / rolled back — better **without the AI ever deciding**.

ADR basis: INT-0064 (per-execution telemetry; privacy-safe; integrate with enterprise observability),
BCK-0051 (observability = architectural capability: structured logs/metrics/traces + correlation ids by
business identifier; debug logs are implementation artifacts), INT-0065 (continuous evaluation influences
selection, never truth), INT-0062/0067 (routing + versioning), INT-0069 (privacy).

Reference: `themis-ai-1` had ad-hoc worker logging; the greenfield standardizes on OpenTelemetry + the
evaluation loop.

### D10 — Gateway-enforced pre-invocation security/privacy; sensitive data local-only

Decision:

- Security/privacy is **first-class and Gateway-enforced *before* any provider is called** (INT-0069) — the
  same pre-invocation admission step that checks budget (D4):
  - **Authn + authz** of the caller/capability request.
  - **Data classification** of the assembled context (D5) by sensitivity before anything leaves.
  - **Prompt sanitization** — secrets, PII, customer identifiers stripped/masked (same redaction discipline
    as Communication).
  - **Provider policy compliance** — a data class may only go to providers **cleared for it**; the most
    sensitive stays **local-only** (dovetails D4 local-first + privacy bar); regulatory/residency limits
    (INT-0062 privacy/regulatory routing).
  - **Output filtering** — provider responses scrubbed before entering validation (D7) / the domain.
  - **Audit logging** — every request + decision audited (INT-0064 telemetry, CON-0016 lineage).
- All of it runs **before provider invocation**; a request that can't clear classification/policy is
  **rejected or downgraded to a local model** — never sent in the clear.

ADR basis: INT-0069 (Gateway enforces authn/authz/classification/sanitization/output-filtering/audit/
provider-policy; security precedes provider invocation; an architectural responsibility), INT-0062
(privacy/regulatory routing), CON-0016 (audit lineage), INT-0064 (audit telemetry).

Reference: `themis-ai-1`'s local Ollama = the local-only path for the most sensitive data.

### D11 — Capability Registry + independent versioning + Gateway-confined provider adapters

Decision:

- The **Capability Registry** (INT-0058) is the catalog of named capabilities. Each entry declares: **id**,
  **routing requirements** (reasoning/latency/cost/privacy — for D6), **context needs** (for D5), **output
  schema + business rules** (for D7), and **version set** (INT-0067: prompt / retrieval / provider /
  evaluation / schema versions).
- **Callers invoke by capability id only** (INT-0058/0067) — never an implementation version or a provider.
  The Registry **selects the live version**, informed by the evaluation loop (D9), enabling safe
  experimentation, staged rollout, and rollback.
- **Provider independence** (INT-0070): every provider integration is a **Gateway-confined adapter** behind
  a uniform provider port; adding/swapping/removing a provider (LLM, local model, knowledge graph, rule
  engine, future agent/planner) touches **only the Gateway**, never Backend or Domain. Capabilities are
  declared in **requirements**, satisfied by whatever provider the router (D6) picks.
- The net effect: a **stable capability abstraction over an unstable provider ecosystem** (INT-0070's
  "stable abstractions rather than stable vendors").

ADR basis: INT-0058 (capability registry; interface invocation), INT-0067 (independent versioning; invoke
by id; registry manages version selection), INT-0070 (provider adapters confined to the Gateway; a provider
swap never touches Backend/Domain; future tech via the same abstraction), INT-0062 (requirement-based
routing).

Reference: `themis-ai-1`'s per-worker provider calls are unified behind the Registry + provider port.

### D12 — Operational-only state; `internal/intelligence/` gateway-core + ports + adapters; independent deployment

Decision:

- **State (operational only):** Intelligence persists the **capability registry** (definitions + versions),
  **evaluation results**, and a **response cache** (INT-0059); telemetry flows to the OpenTelemetry backend
  (D9). It owns **no enterprise truth** — no Faultlines, Findings, Positions, Publications (D1). Its store is
  an operational store, not a domain store.
- **Layout:** a self-contained **`internal/intelligence/`** tree — a **gateway core** (pipeline stages:
  context → prompt → route → execute → validate → propose, per D5–D8), **ports** (provider port,
  knowledge-provider port, proposal-intake port), and **adapters** (provider adapters [Gateway-confined,
  D11], Knowledge-Provider read clients [D5], proposal-intake push clients [D8], http/event API).
  Inward-only, no cross-context imports; reads enterprise knowledge **only via read APIs** (D5); writes
  **nothing** to truth stores (pushes proposals via intake ports, D8). `go-cleanarch` + arch test.
- **Deployment:** **independently deployable** — its own runtime/process beside themis-core (D3),
  communicating via **API + events** (capabilities invoked by pipeline contexts; proposals pushed to
  intake). Provider-specific code lives **only here** (INT-0070), so it **scales and fails independently**
  of themis-core, and the autonomous engine's load never competes with the core request path.

ADR basis: INT-0056 (owns no truth → operational state only), BCK-0037 + Book III §3.2 (context-first
structure), INT-0059 (Gateway as shared infrastructure), INT-0070 (provider-confined; provider swap never
touches Backend/Domain), Book III §3.5 (read APIs, no shared tables).

Reference: `themis-ai-1` ran in-process on the same box; the greenfield makes Intelligence an
independently-deployable service behind API + events.

### D13 — Intelligence is an optional plane; the pipeline is correct with AI disabled; disabled ≡ unavailable

Decision:

- Intelligence is an **optional capability plane**. Because it **owns no truth** (D1) and emits **only
  advisory Proposals** (D2), turning it off removes *proposals*, never *correctness*: with AI disabled,
  humans still triage, Findings still open, Enterprise Positions still get established, and Communication
  still publishes — the platform is fully functional.
- **Single-seam disable gate (the no-op adapter).** Enablement is **one wiring choice**: the composition
  root wires either the real Intelligence client or a **no-op client** (returns "no proposal" with no
  network call). Consuming contexts **never branch on an AI flag** — there is exactly one `enabled` decision,
  in one factory. This keeps the enable/disable control from spreading across call sites.
- **Disabled ≡ unavailable (graceful degradation).** If Intelligence is enabled but unreachable /
  over-budget / fails validation, the caller degrades to the **same** "no proposal" outcome and **never
  blocks** the pipeline. "Off", "down", and "declined" collapse to one safe path.
- **Granularity, designed-in:** a global `intelligence.enabled`, a per-consuming-context gate, plus
  per-capability + reactive-vs-autonomous enablement via the Capability Registry (D11) / config (R2). The
  global gate ships in Δ1; the finer flags are designed now, enabled later.
- **Deployment consequence:** the model runtime + Gateway are deployed **only when AI is on** — an AI-off
  cluster has zero AI footprint.

ADR basis: INT-0056 (owns no truth → removable without correctness loss), CON-0015 (human authority; AI is
assistive), BCK-0051 (config-driven observability), CONVENTIONS R2 (self-documented config). Consistent with
D1/D2/D8; realized by the Δ1 disable gate (Revision 2).

## Traceability → issues

One issue per implementable decision; each cross-references its decision + ADR. Suggested delivery: an
OpenSpec change `openspec/changes/phase3-intelligence/` with these as `tasks.md` groups.

| # | Issue | Realizes |
| --- | --- | --- |
| INTEL-01 | Scaffold `internal/intelligence/` (gateway core + ports + adapters); `go-cleanarch` + arch test; independently-deployable service | D1·D12 · BCK-0037/INT-0059 |
| INTEL-02 | Capability Registry — id, routing requirements, context needs, output schema + business rules, version set; invoke-by-id + version selection | D11 · INT-0058/0067 |
| INTEL-03 | Structured advisory Proposal envelope (recommendation / confidence / evidence / reasoning / capability / metadata) + schema | D2 · INT-0057 |
| INTEL-04 | Context Construction Pipeline — deterministic assembly via Knowledge-Provider read clients (read APIs, never DB); Enterprise Knowledge primary | D5 · INT-0061/0068 |
| INTEL-05 | Gateway prompt construction + runtime model routing (capability requirements → provider/model); no prompts/model names in business code | D6 · INT-0060/0062 |
| INTEL-06 | Provider adapters behind a uniform provider port (Gateway-confined; local + cloud; provider-independent) | D11 · INT-0070 |
| INTEL-07 | 3-stage validation (schema → business → proposal construction); unvalidated never a proposal; per-capability validators (+ tests) | D7 · INT-0063 |
| INTEL-08 | Reactive capability invocation API (sync + async) returning validated Proposals to callers | D3 · INT-0058 |
| INTEL-09 | Autonomous engine — scheduled analysts + push seam to Knowledge/Governance proposal-intake (advisory only); designed now, enabled after reactive | D3·D8 · INT-0056/0066 |
| INTEL-10 | Budget / resource governance — per-run / per-context / autonomous-pool / global scopes; pre-invocation admission; degrade-not-fail; local-first routing | D4 · INT-0062/0064/0066 |
| INTEL-11 | Security/privacy admission — authn/authz, data classification, sanitization, provider-clearance, output filtering, audit; before provider invocation | D10 · INT-0069 |
| INTEL-12 | Observability (OpenTelemetry traces/metrics/logs + correlation ids; console log for local debug) + continuous evaluation loop (acceptance-rate → routing/versioning) | D9 · INT-0064/0065/BCK-0051 |

## Glossary (this context)

- **Intelligence Gateway** — the single exclusive entry to all AI/ML/rule/knowledge-graph providers; a
  supporting service that owns no truth and produces advisory Proposals.
- **Capability** — a named AI operation (Summarize Vulnerability, Recommend Enterprise Position, …) invoked
  by id; provider/model/prompt hidden behind it.
- **Capability Registry** — the catalog declaring each capability's requirements, context needs, output
  schema, and version set.
- **Intelligence Proposal** — a structured, schema-validated advisory output (recommendation, confidence,
  evidence, reasoning, capability, metadata); recorded by the consuming context as a Knowledge or Governance
  Proposal.
- **Reactive mode** — a pipeline context invokes a capability on demand; the Proposal returns to the caller.
- **Autonomous mode** — Intelligence's own scheduled analysts proactively produce cross-cutting Proposals
  pushed to the target proposal-intake.
- **Context Construction Pipeline** — deterministic assembly of enterprise context via Knowledge Providers
  before any prompt is built.
- **Knowledge Provider** — a retrieval service exposing enterprise knowledge (read APIs) to Intelligence;
  never direct DB access.
- **Validation pipeline** — schema → business → proposal construction; unvalidated output never becomes a
  Proposal.
- **Provider adapter** — a Gateway-confined integration of one AI provider behind a uniform port.
- **Budget scopes** — per-run / per-context / autonomous-pool / global spend envelopes enforced at
  pre-invocation admission.
- **Evaluation loop** — continuous scoring (including proposal acceptance rate) that tunes routing and
  versioning, never enterprise truth.
- **Engine** — a *kind of reasoning* (Rule / Knowledge / LLM), the typed unit selected by the Engine
  Dispatcher; distinct from a Provider.
- **Provider / adapter** — the *concrete backend* behind an Engine (Ollama, a Python-DSPy service, a rule
  set, pgvector); Gateway-confined and swappable (INT-0070).
- **Engine Dispatcher** — routes a capability's execution-plan steps to the right typed Engine (Δ2+).
- **Execution plan** — the ordered engine steps a Capability compiles to; Δ1 plans are a single LLM step.
- **Optional plane / disable gate** — Intelligence is switched on/off by one wiring choice (real vs no-op
  client); the pipeline is correct with AI off; disabled ≡ unavailable (D13).
- **Harness** — the target Intelligence architecture (`docs/engineering/THEMIS-AI-HARNESS.md`): typed
  multi-engine dispatch + execution harness + LLMOps plane; reached by four additive deltas (Revision 2).
