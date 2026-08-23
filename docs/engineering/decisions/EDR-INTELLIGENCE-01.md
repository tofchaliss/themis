# EDR-INTELLIGENCE-01 — Intelligence Gateway (AI Enrichment) Supporting Context

Status: **Δ1 + Δ2 implemented (v0.4.0); Δ3 concrete cut recorded (Revision 4, 2026-08-03) — ready to
implement Δ3a (RAG / Knowledge Engine), R5 embedding-model pick pending.** (13 base decisions locked;
Rev 2 Δ1 · Rev 3 Δ2 · Rev 4 Δ3.) Ground rule: ADR/EDR wins; the `internal/` PoC and the archived
`themis-ai-1` design are reference only.

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

## Revision 3 (2026-07-24) — Δ2 concrete cut (typed dispatch + Rule Engine + admission spine)

Grilled 2026-07-24 (plain-English session; decisions below are the source of truth for
`openspec/changes/phase3-intelligence-d2`). Δ2 grows the Δ1 walking skeleton into the harness's **typed
multi-engine** shape **on the same seams — additive, no rewrite**. The **authority spine (D1/D2/D7/D8/D10) is
unchanged.**

**New domain boundary ratified in this grill and written into the architecture book** (Book II, Ch 2 — new
term **Information**, sharpened **Enterprise Knowledge**, and **Domain Invariant 3 — "Gathering Is Not
Knowing"**): feeds, crawlers, and the Gateway produce **Information** (gathered/AI-produced claims &
suggestions — rejectable, not-yet-accepted) only; crossing into **Enterprise Knowledge** (the reconciled view
together with Findings and Positions the enterprise stands behind) always takes a deliberate accept/reconcile
(Knowledge) or a governed decision (Governance). The boundary runs **through** the Faultline (raw Proposals = Information;
reconciled view = Knowledge). This **reaffirms D1/D2**: Intelligence never writes truth — it returns
Information the pipeline records and governs.

### Δ2 behavioral cut

`recommend_position` becomes a **two-step execution plan `[Rule → LLM]`** — the first real multi-engine plan,
so the **Engine Dispatcher** gets a genuine routing job:

1. **Rule step — version-range applicability** (deterministic, no provider). Compares the installed component
   version against the Faultline's affected range.
   - **Provably OUT of range → `not_affected`, certain → short-circuits; the LLM never runs.**
   - Certain in **one direction only**: it may short-circuit to `not_affected`, **never** to `affected`
     ("in range" ≠ affected — that is the judgment the LLM exists for; auto-"affected" would over-report **and**
     duplicate Governance's KEV/severity `proposalFor` logic).
   - Unknown/unsupported ecosystem or no range → not certain → **fall through to the LLM** (with no facts at
     all → "insufficient data").
   - **Checks the reconciled, backport-aware range** on the Faultline (the highest-precedence source's range —
     e.g. Red Hat's `2.4.37-51.el8` fix), read from grounding (`FaultlineView.AffectedRanges` + the matched
     component's ecosystem/version from its PURL), **not** a re-run of a feed's query-time filter. This is
     where it earns its keep: OSV-by-version discovery already pre-filters, so on a **pure-OSV cold start the
     rule mostly defers (acceptable)**; the payoff is catching **backport corrections** (OSV flags the upstream
     range; the distro range excludes your build) and **coarse-source over-matches** (NVD/CPE, scanners) as
     distro/NVD data enriches the card over time.
   - **Version-range is the *only* Δ2 rule.** A **withdrawn-CVE → `not_affected`** rule was considered and
     **rejected**: it would duplicate Governance's reactive `proposalFor` (FaultlineSuperseded → not_affected),
     the same duplication we avoided by not re-deriving KEV/severity. More clear-answer rules may join later
     **only where they do not duplicate Governance**.
2. **LLM step — judgment** (fallback, only when the rule can't settle it). Reasons over facts the Gateway
   **hands it** (grounding), not model memory. **Deterministic-first: the LLM runs iff there is no clear
   deterministic answer.**

**Honest fourth outcome.** The recommendable set gains **`insufficient`** — the capability may return
**"can't determine — no recommendation"** as a **first-class, non-error** outcome (never a forced guess buried
in low confidence). Δ2 only *returns* it; acting on it as an improvement signal is **G-AI-2**.

**Richer grounding — precedent Positions.** When (and only when) the plan reaches the LLM step, the Gateway
also pulls our **own past Enterprise Positions on the same CVE** (other releases) via a Governance read-API,
handed **labeled** (release, component version, decision, rationale) as **context, not instruction** —
read-only, human still decides. Ranking precedent by release-delta is **G-AI-3**.

**Provenance / testability (build requirement).** Every result records **which step decided** —
`rule:not_affected` / `llm:<stance>` / `insufficient` — so the two-step behavior is assertable ("version 3.5 →
decided by the rule, provider never called") and the same stamp feeds the G-AI-2 metric. Because the trigger is
an **API call** (Themis is API-first — no UI), Δ2 is fully testable with pure-Go rule tests, the fake provider,
and over-the-wire seam tests: **no UI and no running model required**.

### Admission spine (the one pre-invocation gate) — Δ2 slice

One gate runs before any provider call, checking two things:

- **Budget — measure now, enforce lightly.** Build the **meter** (per-call duration / input-size / token count
  via OTel metrics) + one **runaway guard** (per-request timeout + prompt input-size cap). The model is
  **local = free** in Δ2, so real multi-scope enforcement + degrade-not-fail routing is **deferred** (G-AI-4).
- **Security/privacy — minimal, local-only.** (1) authorize the caller, (2) scrub secrets/PII from prompt +
  telemetry (Communication's redaction discipline), (3) hard-mark the path **local-only** so nothing can reach
  a cloud provider. Full data-classification → provider-clearance is **deferred** to when cloud providers exist
  (G-AI-5).

### Deferred (all tracked in `docs/BACKLOG.md` §C)

**G-AI-1** on-demand fresh-CVE gathering (AI asks, feeds gather — a crawler = a new feed producing
Information); **G-AI-2** can't-determine as an improvement signal (metric / model-escalation / eval);
**G-AI-3** rank precedent by release-delta; **G-AI-4** budget enforcement policy; **G-AI-5**
data-classification / provider-clearance. Δ3 (Python engine + RAG) and Δ4 (autonomy + LLMOps) are unchanged.

### Component & Technology Decisions (Δ2)

Every choice is grounded — **rule basis · chosen · named alternatives · why better** — per STACK.md's "Not
chosen (and why)" discipline. Reused Δ1/STACK items carry a one-line "carried forward because …".

| # | Decision | Rule basis | Chosen | Alternatives considered | Why the chosen option (over the alternatives) |
| --- | --- | --- | --- | --- | --- |
| C1 | **Model runtime / serving** — the real decision is the **stable interface, not the vendor** (there are ~100 AI backends; the challenge is interfacing them to Themis) | INT-0070 ("stable abstractions, not stable vendors"), INT-0069 (sensitive→local), D4 (local-first), STACK | A **vendor-neutral Provider port speaking the OpenAI-compatible chat-completions schema** (built in Δ1); **Ollama** as the Δ2 default backend (native on Mac dev / containerized in-cluster / **fake** in CI) | Backends: **vLLM**, **Hugging Face TGI**, **Cerebras** (hosted inference), **llama.cpp**, **LM Studio**, hosted APIs (**OpenAI / Anthropic / Bedrock**) | The **port** is the architectural commitment; every named alternative also speaks (or fronts) an OpenAI-compatible endpoint, so each is a **config swap, not code** (INT-0070 satisfied → the choice is **reversible / low-stakes**). Ollama is the best *default*: runs natively on Apple-Silicon dev with **Metal GPU** (Docker-on-Mac has no GPU passthrough → vLLM/TGI containers are CPU-only on Mac dev), single-binary/low-ops, pulls quantized models (llama3.1:8b q4 on 16 GB). vLLM/TGI are higher-throughput **production** servers but heavier + GPU-hungry — premature for Δ2's advisory, low-QPS, local-first path; they slot behind the same port when throughput matters (Δ3+). Cerebras/hosted APIs conflict with the sensitive-data-local-only default (INT-0069) for the routine path — reserved for cleared, non-sensitive asks later |
| C2 | **Version-range comparison** (the Rule Engine's core computation) | Δ2 rule = version-range applicability; must span ecosystems (PyPI/npm/Maven/apk/deb/RPM/Go) whose version schemes differ | **Port the PoC's proven, property-tested version engine** (`internal/domain/version_engine.go` + `version_match.go`; OSV ecosystem-aware ranges incl. Alpine `-r0`, introduced/fixed/last_affected, GIT-vs-ECOSYSTEM) into a **shared-kernel value object** (PoC is frozen reference → **port the design, do not import**) | `Masterminds/semver` (SemVer-2.0 only), `hashicorp/go-version`, `aquasecurity/go-version` (Trivy, ecosystem-aware), OSV's Go comparators, hand-rolled | The in-repo engine already handles Themis's **real messy ecosystems** that a SemVer-only lib (Masterminds) gets wrong (Debian/RPM epochs, Alpine `-r0`, PyPI); it's **battle-tested with a rapid property test**; and it adds **no new dependency**. The **"unsupported ecosystem → not certain → defer to the LLM"** safety valve bounds residual risk. `aquasecurity/go-version` is the closest external fallback if porting proves heavy |
| C3 | **Rule representation** | EDR: "Rule Engine is **all-Go**" | **Hand-written Go rule predicates** (version-range = a small pure function) | An expression DSL — **CEL** (`google/cel-go`), `expr-lang/expr`; an external rules engine (`hyperjumptech/grule`) | Δ2 has exactly **one** deterministic rule; a DSL/engine adds a dependency + a runtime-interpreted rule language + its own test/debug surface for **zero present benefit**; all-Go keeps rules at 100% unit coverage, no dep. CEL/grule earn their place only when rules must be **authored/changed as data by non-developers at runtime** — not a Δ2 need |
| C4 | **Engine Dispatcher** | EDR Δ2 typed dispatch; harness diagram | **A small in-Go typed dispatcher** mapping an execution-plan step's engine-kind → the registered Engine | An external **workflow engine** (Temporal, a DAG runner); a **plugin** system (Go plugins / `hashicorp/go-plugin`) | The plan is a **short ordered list (2 steps)**; a typed map/switch is trivial, fully testable, dependency-free. Temporal solves durable long-running orchestration we don't have (invoke is synchronous, bounded); go-plugin solves out-of-process isolation the in-Go Engine/Provider ports already cover for Δ2. Both become candidates only if Δ4 autonomy needs durable scheduling or Δ3's Python engine needs process isolation — already separate deltas |
| C5 | **Budget meter** | R1 / STACK (OTel is the telemetry SoR); D4 / INT-0064 (cost telemetry) | **OpenTelemetry metrics** via `internal/platform/observability` (carried forward) | `prometheus/client_golang` directly; custom in-memory counters; a DB table | OTel is the **already-wired, mandated, vendor-neutral** telemetry, correlated by business id, needing **no new store** (Δ2 is stateless). Prometheus is a complement, not the SoR; a DB table would break Δ2's stateless design |
| C6 | **Precedent-Positions grounding** | D5 / INT-0068 (context via read APIs, **never** DB) | **Extend Governance's read API** with a "Positions for this CVE across releases" query + pull via the existing **read-API-client seam** (like `FindingReader` / `FaultlineReader`) | Query Governance's DB directly; a materialized precedent cache inside Intelligence | Direct DB read violates D5 (rejected); an Intelligence cache violates Δ2 statelessness. Extending the read API **keeps the boundary**, reuses the proven client seam, and adds **no store** |
| C7 | **Redaction (admission scrub)** | D10 / INT-0069 (sanitization); STACK ("same redaction as Communication") | **A `Redactor` port mirroring Communication's** (secrets/PII scrub of prompt + telemetry) | A third-party PII/secret scanner; ad-hoc regex only | Consistency + reuse across contexts; a heavyweight scanner is premature for **local-only** Δ2 (revisit with cloud providers under G-AI-5) |

## Revision 4 (2026-08-03) — Δ3 concrete cut (RAG / Knowledge Engine)

Decided across a three-session integration evaluation (source: `docs/engineering/RAG-INTEGRATION-OPTIONS.md`,
`RAG-SESSION-2-SPIKE.md`, `RAG-SESSION-3-DECISION.md`). Δ3 grows the Δ1/Δ2 skeleton into the harness's
**Knowledge Engine (RAG)** on the same seams — additive, no rewrite. The **authority spine
(D1/D2/D7/D8/D10) is unchanged:** retrieved precedent is grounding that feeds the LLM step; it is never a
decision, and every output remains an advisory Proposal ("Gathering Is Not Knowing").

**Governance basis — Book IV Chapter 8 (Semantic Retrieval).** The retrieval mechanism is independent of
the corpus it indexes; the architecture names three **Knowledge Spaces**: KS1 System of Record (Themis-owned
truth — Positions/Findings/Faultlines), KS2 **Operational Semantic Index** (the AI-Runtime-owned, derived,
rebuildable vector index — this Δ3a store), and KS3 Supporting Documentation (external vendor/OWASP/MITRE).
This Δ3a is **RC-1 — semantic precedent over Enterprise Positions** (KS1 → KS2); external-document retrieval
is **RC-2** (KS3 → KS2), a later corpus behind the *same* `VectorIndex` port. `EngineKnowledge` = the RC-1
retrieval step; the `position_embeddings` store = KS2. Embedding a Position does not make the Gateway *own*
it — Governance still owns KS1; KS2 holds only a derived vector (D12).

### Δ3 behavioral cut

`recommend_position` gains a **retrieval step**, so its plan becomes `[Rule → Knowledge(retrieve) → LLM]`:

- **Knowledge step (new Engine, `EngineKnowledge`):** embeds the subject Finding's text, does a
  nearest-neighbour search over our **own past Enterprise Positions**, and fills
  `AssembledContext.Precedents` with the top-k **semantically similar** decisions (labeled: release,
  component, stance, rationale, source CVE, score). This **generalises the Δ2 exact-CVE precedent seam**
  (`adapters/readapi/precedent.go`) to similar-CVE precedent — realising backlog **G-AI-3**. Precedents
  remain **context, not citable evidence** (stage-2 `Grounds()` unchanged); the human still decides.
- **LLM step:** reasons over the (now precedent-enriched) grounding, exactly as Δ2. Deterministic-first is
  intact — the Rule step still short-circuits `not_affected` when provably out of range, before retrieval.

### Two shippable increments

- **Δ3a — RAG / Knowledge Engine, all-Go.** The retrieval above, using the **existing Ollama LLM**. This
  delivers the value; it is the demoable slice.
- **Δ3b — Python reasoning engine.** A DSPy service behind the provider port for a *reasoning* step that
  wants prompt optimisation — added **only if** a task needs it. Deferred; not required for Δ3a.

### Δ3 component decisions (R1–R6) — rule-basis · chosen · alternatives · why

| # | Decision | Rule basis | Chosen | Alternatives | Why the chosen option |
| --- | --- | --- | --- | --- | --- |
| R1 | **Vector index** | D12 (operational, rebuildable) · corpus ≤50k · STACK minimal-deps | **In-memory Go cosine over persisted plain-PG vectors**, behind an `app.VectorIndex` port | pgvector; Qdrant; Weaviate/Milvus; Redis-vector; Chroma; FAISS | At ≤50k, brute-force search is **~47 ms/query** (measured; ~6 ms across 8 cores) — negligible vs the LLM; no extension, no new service, no `embedded-postgres` test gap; the port makes pgvector/Qdrant a config-swap upgrade past ~10⁵–10⁶ |
| R2 | **Persistence** | D12 · store convention · `embedded-postgres` testability | **Plain Postgres table** (`float4[]` / `bytea`) in a new Intelligence DB | pgvector column; a dedicated vector DB; in-memory-only | vectors as ordinary columns run under `embedded-postgres` (no extension); load-on-boot is cheap, re-embed is minutes → persist vectors; in-memory-only would re-embed 50k every restart |
| R3 | **Retrieval orchestration** | D5/D6/D7 already Go-owned · Go-first ethos · structured (not document) corpus | **Hand-rolled Go** (embed → search → rank → fill `Precedents`) | LlamaIndex; LangChain/LangGraph; DSPy-for-retrieval | records → one embedding each (no chunking/loader problem); a framework would re-own D5/D6/D7 and add a heavy Python dep tree for value that does not apply here |
| R4 | **Advanced reasoning (Δ3b)** | INT-0070 (provider port) · reactive-first | **Python DSPy behind the provider port — deferred; only if needed** | LlamaIndex/LangChain agents; Go-only reasoning | keep retrieval in Go; add Python only for a reasoning step wanting prompt optimisation/eval; isolated as a provider (process isolation), optional plane (D13) |
| R5 | **Embedding model** | D10 (local-only) · PoC precedent | **`nomic-embed-text` (768)** on the local Ollama — **PENDING** the Ollama eval | bge-small (384); e5-small (384); cloud embeddings | reuses the deployed runtime, local/private, PoC-precedented; cloud violates D10; smaller models only if memory/latency demand (they do not at 50k). Confirm recall@10 + what-text-to-embed before locking |
| R6 | **Freshness / population** | D5 (read-APIs, never foreign DB) · M5 bus | **Event-driven incremental** (bus consumer on `PositionEstablished` / `FaultlineEnriched`) + **backfill/rebuild** command | poll-and-rebuild; lazy embed-per-request | steady-state cost = one embed per new decision; index derived + rebuildable (D12); consumes events + read-APIs, never foreign tables (D5). Intelligence becomes a bus consumer for the first time |

### Status of the cut

R1–R4 + R6 are **data-backed and locked**; **R5 is CONFIRMED (2026-08-05)** — the `make e2e-embed` eval on the
VM Ollama chose **`nomic-embed-text` + `components+severity`** (recall@1 = 1.00, MRR = 1.00, ~46 ms; `+cve`
neutral, `+description` degrades to 0.83); detail in `RAG-SESSION-2-SPIKE.md` §4. Deferred as before: Δ3b
Python engine, external-intel embedding (U3), the KB-first similarity short-circuit (designed-in, enabled
after eval), and Δ4 autonomy/LLMOps. Δ3a shipped in full (groups A1–A6, 2026-08-04).

## Revision 5 (2026-08-06) — Δ3c cut: Subject Generalization (**SUPERSEDED — historical**)

> **Status: SUPERSEDED, same day, by [`EDR-TRUST-01`](EDR-TRUST-01.md).** Grilling this cut escalated past
> the invocation surface into the enterprise **trust model**. S1–S6 are absorbed or replaced: **S1/S2/S4 →
> T9** (Selection: a type plus a set, with declared cardinality — which subsumes the fan-out guard);
> **S3 → T10** (the owning context produces authoritative Domain Projections; the runtime gathers nothing and
> may only shape what it receives, under four rules);
> **S5 → T8** (two verification boundaries — Grounding in the runtime, Business in Governance);
> **S6 → T7** (two output classes — Information Response and Decision Proposal).
>
> `EDR-TRUST-01` further **rewrites D5** (context assembly leaves the Gateway) and **amends D2** (output is
> no longer a single Proposal shape). This section is retained **only** for the reasoning trail — the
> problem statement and the five-layer analysis below remain accurate and are why the trust work started.
> **Do not implement from S1–S6.**

### Why this cut exists

A capability-surface audit (2026-08-06) against the AI use-case catalog
(`docs/current-changes/themis-ai-use-cases.md`) and **Book IV §6–7** found that **one** AI capability is
implemented (`recommend_position`) and **none** of Book IV's six user use cases or three background workflows
are. The catalog's remaining entries split into three groups: solved deterministically by design (ingestion /
normalization, prioritization, SBOM correlation, report *formats*), blocked on corpora or planes not yet built
(KS3 external documentation; the Δ4 autonomy/LLMOps plane), and — the subject of this Revision — **blocked on
the shape of the invocation surface itself**.

`Gateway.Invoke(ctx, capabilityID, subjectFindingID, correlationID)` admits exactly one subject shape: a
single Governance Finding. Five committed use cases cannot be expressed against it — Book IV **UC-001**
(release readiness), **UC-002** (engineering planning / workstream clustering), **UC-006** (risk explanation),
plus catalog #5 (root-cause grouping) and #12 (trend forecasting). Each needs a **release-** or
**product-scoped** subject grounding **many** Findings.

The constraint is not one parameter. "Finding" is welded in at five layers, and the last two are the design
problem, not the rename:

| Layer | Site | Nature |
| --- | --- | --- |
| Transport | `api/intelligence.openapi.yaml` — `InvokeRequest.required: [finding_id]` | mechanical |
| Gateway signature | `app/gateway.go` — `Invoke(…, subjectFindingID, …)` | mechanical |
| Grounding assembly | `app/context.go` — unconditional `fr.GetFinding(findingID)` root | mechanical |
| **Grounding shape** | `domain/grounding.go` — `AssembledContext{Finding, Faultline, …}` singular; `Grounds()` switches over exactly those ids | **design** |
| **Output anchor** | `domain/validate.go` — stage 2 asserts `out.FindingID == subjectFindingID` | **design** |

The output anchor is the subtle one: that equality **is** the D7 anti-hallucination guarantee — it proves the
model's answer is about the thing that was asked. A many-Finding subject cannot satisfy it, so generalization
must *redesign the anchor*, not merely widen the parameter.

**Governance basis.** INT-0058 (capabilities are invoked by **name**, against a subject — the ADR never
constrains the subject to a Finding) · Book IV §6 UC-001/002/006 · D5 (deterministic Context Construction) ·
D7 (mandatory 3-stage validation) · D11 (Capability Registry). The **authority spine is unchanged**: a
release-scoped capability still emits an advisory Proposal a human or policy decides on — widening the subject
widens what AI may *discuss*, never what it may *decide* (D1/D8, CON-0015).

### Δ3c behavioral cut

`recommend_position` is **behaviourally unchanged** — same plan, same grounding, same output, same 204
semantics. It becomes the first capability that *declares* a subject kind rather than assuming one. What
changes is the harness:

- **A typed `Subject{Kind, ID}`** replaces the bare finding-id string end to end (transport → Gateway → domain
  → telemetry → Proposal). A capability declares the `SubjectKind` it accepts; a mismatch is rejected
  **before any grounding or provider call**, as a new `ReasonSubjectMismatch` outcome — the same guard shape
  as the existing `ReasonUnauthorized`.
- **`AssembledContext` becomes uniformly plural** (`Findings []`, `Faultlines []`), with subject-aware
  accessors so the singular case stays ergonomic. `Grounds()` becomes genuine set-membership over everything
  assembled — **strictly more correct** than today's five-way switch over one Finding's ids.
- **`ContextNeed` is repaired and promoted.** Today `NeedFinding` is declared, passed, asserted in tests, and
  **never consulted** — `AssembleContext` hardcodes the Finding read. The cut separates three concerns the
  current model conflates: the **Subject** (the grounding root), the **Needs** (what data is required), and
  the **read strategy** (which read API satisfies a need most cheaply — the assembler's choice, invisible to
  the capability).
- **A read fan-out guard** joins the admission spine. Subject generalization is what first makes a single
  `Invoke` capable of issuing unbounded read-API calls; the guard degrades to an honest `insufficient`.

### Δ3c component decisions (S1–S6) — rule-basis · chosen · alternatives · why

| # | Decision | Rule basis | Chosen | Alternatives | Why the chosen option |
| --- | --- | --- | --- | --- | --- |
| S1 | **Subject model** | INT-0058 (invoke by name against a subject) · D11 · D5 determinism | **Typed `Subject{Kind, ID}` value object**; `Capability.SubjectKind` declares what it accepts; mismatch → `ReasonSubjectMismatch` pre-grounding | `subject_type`+`subject_id` as bare strings; opaque `params map[string]string`; a second `/invoke-release` endpoint | Typed catches a release id sent to a Finding-scoped capability at the door instead of as a confusing grounding failure. Bare strings leave the hard layers untouched. An opaque bag breaks D5's *"same identifiers + same upstream state → same context"* determinism, which is what makes stage-2 validation authoritative. A second endpoint forks the pipeline — duplicating admission, metering, validation, telemetry — against the whole point of one Capability abstraction |
| S2 | **Grounding cardinality** | D5 · D7 (`Grounds()` is the anti-hallucination set) · 100% domain coverage tier | **Uniformly plural** `AssembledContext{Subject, Findings[], Faultlines[], Precedents[]}` + `SubjectFinding()` / `FaultlineFor(id)` accessors | Fat struct (singular *and* plural fields, populate what fits); sum type / per-shape variants | Plural makes `Grounds()` what its name always claimed — set membership over everything assembled — and fixes a latent narrowness (today it grounds one Finding's ids only). A fat struct gives two ways to express one thing and invites nil-deref bugs. A Go sum type forces a type switch into every engine for two subject kinds — cost without payoff |
| S3 | **Grounding fidelity / read strategy** | D5 (read APIs, never foreign DB) · D12 | **`ContextNeed` declares *what data*; the assembler picks the *read*.** `NeedComponents` on a release subject = N× `GET /findings/{id}` today; a components-bearing `/posture` later satisfies the same need in one read | Hardcode N detail reads; block Δ3c on enriching Governance's `PostureEntry`; read Evidence inventory | The capability contract is **identical** in both worlds, so enriching `PostureEntry` becomes a pure performance optimization landing whenever it is worth it — **Δ3c needs no Governance change at all**. Evidence is the wrong context: it knows SBOM components, not the finding→component mapping, which Governance owns (`finding_components`). Also repairs the dead `NeedFinding` by giving needs something real to express |
| S4 | **Read fan-out guard** | D4 (metered, degrade-not-fail) · D10 admission spine · G-AI-4 | **`MaxSubjectFanout`** in the admission spine, beside `MaxPromptBytes` / `ProviderTimeout`; over-cap → `insufficient` with `DecidedBy = "guard:fanout"` | No guard; cap inside each reader; unbounded with a longer timeout | A 500-Finding release × `NeedComponents` is 500 read-API calls inside one invocation — a self-inflicted DoS on Governance that today's guards do not cover (they bound prompt bytes and wall-clock, not read count). Degrading to the existing honest `insufficient` needs no new outcome vocabulary. Per-reader caps cannot see the total |
| S5 | **Stage-2 anchor** | **D7** (3-stage validation is mandatory and unweakened) | **Split stage 2:** generic rules (confidence ∈ [0,1]; every `evidence[].ref` satisfies `Grounds()`; stance ∈ `AllowedStances`) stay universal; the *subject anchor* becomes a small per-capability rule on the `Validator` | Keep `out.FindingID == subject.ID` and force every future output to be Finding-shaped; drop the anchor for non-Finding subjects | The anchor generalizes rather than weakens: Finding-scoped keeps `out.FindingID == subject.ID`; release-scoped becomes *"every Finding cited is one of the assembled Findings"* — the same guarantee over a set. Dropping it for wide subjects would surrender D7 exactly where hallucination risk is highest. Forcing one output shape would make every future capability lie about its own semantics |
| S6 | **Subject provenance** | D2 (structured output) · D9 (telemetry) · step-2 feedback loop | **`Subject` is carried on `Outcome` and `Proposal` now**; generalizing the Proposal *payload* beyond `Recommendation{FindingID, Stance}` is **deferred to the first release-scoped capability** | Generalize the payload now; defer `Subject` on `Outcome` too | The forthcoming Outcome-persistence work (feedback loop) must record what each invocation was *about*; adding `Subject` now avoids a schema migration on a table not yet created. The payload is the opposite case — designing a second output shape before a capability needs it is guesswork; the seam is what Δ3c owes, the shape is what UC-002 will settle |

### Amendments to standing decisions

- **D5 (Context Construction)** — the pipeline is now rooted at a **`Subject`**, not a Finding id, and is
  **need-driven for the root as well as the expansion**. The determinism contract is unchanged and
  strengthened: same `Subject` + same needs + same upstream state → same `AssembledContext`. Read strategy is
  an assembler-internal choice and is **not** part of the capability contract.
- **D7 (3-stage validation)** — stage 2 splits into **universal** rules and a **per-capability subject
  anchor**. Stages 1 and 3 are untouched. No capability may opt out of an anchor.
- **D9 (observability)** — the per-invocation `Outcome` gains `Subject`; the existing privacy rule holds
  (provenance only, never prompt content).
- **D11 (Capability Registry)** — `Capability` gains `SubjectKind`. Registry lookup is by id, unchanged
  (INT-0058).

### Compatibility

`POST /capabilities/{id}/invoke` is a **breaking request-body change** (`finding_id` → `subject{kind,id}`).
Mitigation: accept `finding_id` as a **deprecated alias** mapping to `{kind:"finding", id:…}` for one release,
so Governance's existing client seam keeps working while it is migrated. Governance's own
`advisor.RecommendPosition(ctx, findingID)` port is **unchanged** — its adapter constructs the `Subject`.
**No Governance, Knowledge, Evidence, Registry or Communication change is in this cut.**

### Explicitly deferred (not in Δ3c)

- The **second output payload shape** (workstreams / narratives) — settled by the first release-scoped
  capability (S6).
- **Enriching Governance's `PostureEntry`** with components — a performance optimization, unblocked by S3.
- The **release-scoped capabilities themselves** (UC-001 / UC-002 / UC-006) — Δ3c is the surface they need,
  not the capabilities.
- **KS3 external-document retrieval** (RC-2), the **Δ4** autonomy/LLMOps plane, and **G-AI-1/2/4/5** — all
  unchanged and independently tracked.

### Status of the cut

**PROPOSED — S1–S6 are open for grilling; no code.** `recommend_position` behavioural parity is the
acceptance condition (`adapters/wiring/demo_e2e_test.go` + `adapters/http/llm_e2e_test.go` must stay green
unchanged in behaviour). Note the **100% coverage tier** on `domain/`: `Subject`, the plural accessors, and
the rewritten `Grounds()` need complete branch coverage or `make check` fails. On grill closure, scaffold
`openspec/changes/phase3-intelligence-d3c/`.

## Revision 6 (2026-08-07) — the first release-scoped capability: `plan_remediation@v1`

Δ3c's surface (absorbed into EDR-TRUST-01 T7–T10) existed but nothing used it: the catalog held one
capability, Finding-scoped and Decision-class. This revision ships the Release half.

### The capability

| | |
| --- | --- |
| **ID** | `plan_remediation@v1` |
| **Selection Type** | `release`, cardinality **1..1** (T9 — the bound doubles as the fan-out guard) |
| **Output class** | **Information** (T7) — ephemeral, never enterprise truth, nothing to accept |
| **Projection** | Governance's `ReleasePosture`, enriched with each Finding's components |
| **Plan** | LLM only — no Knowledge step |

### Why Information and not Decision

A plan proposes no stance on any Finding, so there is nothing for Governance to govern. This is what
makes a release-scoped capability **safe to add**: the worst outcome of a wrong plan is a human
disagreeing with it, never a vulnerability silently suppressed. `recommend_position` remains the only
path to enterprise truth, and it remains Finding-scoped and per-item on purpose.

### Why the grouping is NOT the model's job

`ReleasePosture.PlanActions` collapses outstanding Findings into upgrade actions **deterministically**,
before the prompt is rendered. On a measured release, 231 Findings reduce to ~12 package upgrades
because one module-stream rebuild closes nine CVEs. Asking a model to rediscover that from 231 rows
would be slow, expensive and non-reproducible — grouping is a `GROUP BY`, not reasoning (T10). The
model is asked only for what needs judgement: sequencing, trade-offs, and what to say about actions
with no clean fix.

The actions are a **shaping** of the projection, not a second source (T10 rule 2): every field is
reduced from what the projection contained, and each action carries its `FindingIDs` so every claim
is traceable back (rule 3). Grounding still anchors to the **projection**, never to the shaped view
(rule 4) — validating against its own transformation would let a buggy grouping confirm itself.

### No Knowledge (precedent) step

Semantic precedent is scoped to past **Positions on Findings**. A release plan is not a position, so
retrieval would spend embedding calls on grounding that does not apply.

### Two defects this surfaced and closed

1. **The Information path never ran Grounding Verification.** It returned as soon as the schema
   validated. T8 makes grounding the **only** gate on that class — no Governance stage follows it —
   so the one load-bearing check was unexecuted. `Validator.ValidateGrounding` now exists as a
   standalone gate and both output classes run it.
2. **A successful Information Response was returned as `204`.** The handler treated
   "no Proposal" as "no content", discarding the answer at the last hop — the same class of loss as
   AI-204-1 one layer up. It is now `200` with an `InformationResponse` body.

### Projection change (Governance)

`PostureEntry` gains `components` (carrying `source`, per AI-GROUND-1), filled by ONE extra query per
release rather than one per row. It is a reusable business view — the same join serves a dashboard,
a report and the runtime — which is what T10 requires. **Deliberately not included:** the *fix
version* per component, which would need a new event field, a migration and a stamping path. The plan
therefore names the package to upgrade and what it closes; exact versions stay one drill-down away.

### Correction, same day — what "anchor to the projection" actually forbids

The first live run refused a plan: the model cited `PyYAML (rpm)` and Grounding Verification
discarded the whole answer. The initial `Grounds` implementation — and a test asserting it — treated
a package name as **the runtime's own derivation** and therefore ungrounded.

That was wrong. `PyYAML` is `component.source`, a field the projection carries. What the runtime
derives is the **grouping**; the name is data. T10 rule 4 forbids validating against a derived
**view** — not against projection fields that the view happens to surface. Component `name` and
`source` now ground; the action heading dropped its `(ecosystem)` bracket so a citation can match
exactly; and decorated forms (`python-ply (rpm)`) still fail, because matching stays exact.

The general lesson is about where the mistake was findable: a prompt and a validator are an
interface with **no compiler between them**. The disagreement could only surface by running a real
model and reading what it produced — which is why `Outcome.Detail` (TRUST-6) was load-bearing here.
`business_invalid` alone would have sent the investigation to the gate; `ungrounded evidence
"PyYAML (rpm)"` pointed straight at the rule that was too strict.

### Sibling merge — one module update is one step

The first well-formed live plan listed `perl-Carp`, `perl-Data-Dumper`, `perl-Digest`,
`perl-Digest-MD5`, `perl-Encode`, `perl-Exporter` and `perl-File-Path` as seven separate steps,
each "closes 5 findings, worst CVE-2025-40909" — **seven of the top fifteen steps were one
`dnf module update`**. A plan reading as fifteen jobs when it is eight gets the schedule wrong.

`PlanActions` therefore merges actions whose CVE sets are **exactly** equal. The CVE set is the key
because it needs no data the projection lacks: detecting the `.module+el` marker would be more
direct but lives on the *fix version*, which the posture deliberately does not carry, and the CVE-set
rule generalises to any ecosystem where one advisory covers several artifacts. Merging is
conservative — sets must match exactly, so two packages sharing four CVEs of five stay separate
rather than hiding the fifth.

### Deferred

- **Fix versions on the posture entry** — makes the plan self-contained; see the note above.
- **The severity band on the posture entry** (DASH-2) — would let a plan speak in bands rather than
  raw priorities.
- **Multi-release plans** — a different projection and a different capability, not this one invoked
  repeatedly (T9).

---

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

**Realization note (2026-08-09) — the per-capability scope is enforced; the rest is not yet.**
`app.Budget` implements the second envelope: a fixed window anchored to first use, pre-checked
immediately before the provider call (after the free deterministic steps, so a short-circuit never
spends budget it did not use) and debited with the provider's ACTUAL token count.

Four choices worth recording, because each could reasonably have gone the other way:

- **Unset = unlimited, and enforcement is opt-in.** A budget switched on by accident refuses
  recommendations, and a refusal is indistinguishable downstream from the AI being unavailable
  (D13). Off is the safe default; on is a decision.
- **Fixed window anchored to FIRST USE**, not to a wall-clock boundary — otherwise a node restarting
  at 13:59 gets a full budget twice in two minutes and a restart loop becomes a budget bypass.
- **Admission on `remaining > 0`, never on an estimate.** A call's cost is unknowable until it
  returns, so the last admitted call may overshoot by one invocation. That is a better failure than
  refusing work on a number the system invented from prompt length.
- **Every attempt debits, including one whose output fails schema validation.** A retry consumes the
  model exactly as a success does; a ledger counting only successes lets a schema-thrashing
  capability spend without limit. (Observed: one invocation burned 8,192 tokens producing nothing.)

Exhaustion is its own outcome, `budget_exhausted`, never folded into `insufficient`: nothing is
broken, nothing declined on the merits, and it clears when the window rolls.

**Still deferred:** the per-run cost ceiling beyond the existing prompt-size guard, the autonomous
pool, and the global enterprise ceiling.

**Degrade-not-fail LANDED 2026-08-13 (phase3-intelligence-router):** the downgrade now has
somewhere to go — an optional economy tier (`THEMIS_INTELLIGENCE_MODEL_ECONOMY`). When the
window's remaining tokens fall below a configurable fraction of the ceiling (default 0.20),
invocations route to the smaller model instead of refusing: spend shrinks before it stops. Full
exhaustion still answers `budget_exhausted` — degrade never removes the ceiling, because the
economy model's tokens are real tokens too.

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
  *Implemented 2026-08-13 (phase3-intelligence-router):* a **tiered router** — primary plus optional
  escalation/economy models. The tier is a RUNTIME decision the Gateway makes (an honest
  `insufficient` on a Decision capability escalates ONCE to the larger model — G-AI-2b; a
  nearly-spent budget window degrades to the smaller one — D4), threaded to the router through the
  engine so a model is chosen in exactly one place. Escalation never fires on schema/business
  failures (contract problems — a bigger model would mask which lever to pull) nor on timeouts (a
  slower model times out worse). This tier-aware selection point is also where G-AI-5 clearance
  routing will attach when a non-local provider exists.
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

### Realization note (2026-08-10) — retrieval is a service with two consumers, not an engine step

Δ3a shipped semantic retrieval as an **engine** (`EngineKnowledge`) invoked from the capability's execution
plan. That located it correctly in the *plan* and incorrectly in the *architecture*: the answer it produced
— "the best precedent available for this Finding" — had no name and no seam. It was an emergent property of
statement order inside `Gateway.invoke`: a semantic search during the plan walk, and the Δ2 exact-CVE
fallback several branches later at the LLM step, joined by the unwritten rule *fall back only when semantic
found nothing*.

That was invisible while the model was the only consumer. It became load-bearing the moment a **second**
consumer appeared — a read API showing the same precedent to a security engineer (`GET
/findings/{id}/similar`, output class **Information**, T7). Reimplementing the rule at the second call site
would have let one claim have two answers depending on who asked.

**What changed.** `app.PrecedentService` now owns the whole composite (embed → search → filter → fallback)
and both consumers call it; `adapters/engine/knowledge.go` is deleted. `domain.SubjectText` moved from
`adapters/embed` to the domain ring — it is a **rule** ("what does a Finding look like to the index") shared
by the index writer and the index reader, and the app ring cannot import an adapter.

**Two orthogonality rules, decided with the endpoint** and worth keeping when RC-2 arrives:

- **Filters are query semantics** and live *inside* the search (`excludeReleaseID`, `include_same_release`):
  they change which neighbours are candidates.
- **Redaction is an output boundary** and lives at *each consumer's edge* — the prompt bound for a provider,
  and the HTTP response bound for an engineer, are different exits with different rules. Applying it inside
  the service would bake one consumer's policy into a shared seam. Redaction is a projection: the stored
  Position is never modified.

**Two defects the extraction surfaced**, both of the *computed-then-discarded / read-then-unused* family
this repository keeps meeting:

1. `plan_remediation` is Release-scoped, so `ac.Finding()` is the zero value — yet every invocation reached
   the LLM-step fallback and asked Governance for the precedents of an **empty Faultline id**. A read whose
   result the capability had no use for. The service skips it (`FaultlineID == ""`).
2. The Knowledge-step tests stubbed the *engine*, above the rule, so they passed against a projection
   carrying no components and no severity — a subject whose `SubjectText` composes to `""` and is correctly
   skipped before the embedder is called. A stub above a rule cannot exercise the rule.

Behaviour for `recommend_position` is unchanged, guarded by `adapters/wiring/demo_e2e_test.go` (a semantic
precedent flips a recommendation). Consistent with D1 (owns no truth), D5 (read APIs only), D12
(operational, rebuildable state) and `EDR-TRUST-01` T7.

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

---

## Realization note (2026-08-23): `compare_releases@v1` — the fourth capability (AI-CMP-1, EDR-ENHANCE-T5 entry point)

The first two-subject capability, and deliberately the cheapest possible one: an **Information**
narration (T7) over Governance's deterministic release-comparison read (EDR-GOVERNANCE-01 D16),
received VERBATIM as a new `ReleaseComparison` grounding shape (`NeedReleaseComparison`). The
Selection is **ordered** — `[baseline, candidate]`, exactly two (`Min=Max=2`; the cardinality
doubles as the fan-out guard, T9). What was decided in realization:

- **The diff is never the model's job.** Buckets, ordering, and the honesty guard are all
  server-side; the model narrates a query result it cannot get wrong, and the prompt says so.
  Each bucket is capped at 15 rows worst-first, with the omission COUNTED in the prompt — a
  silent truncation would let the model claim completeness it was never given.
- **The guard's refusal is a grounding failure, not material.** Governance's 422 (an
  evidence-less side) or 502 (Evidence unreachable) surfaces as `no_grounding` — the runtime
  never narrates around a diff that proves nothing.
- **Empty buckets answer deterministically** (`rule:empty-comparison`): "no security
  difference" costs zero tokens.
- **Grounding Verification is the only gate** on this path (T8), as for its Information
  siblings: every cited ref must name a release id, finding id, CVE, or component the
  comparison contained; `AssembledContext.Grounds` anchors to the comparison when present.
- No Knowledge (precedent) step, for explain_vulnerability's reason: a narration is not a
  position. G-AI-3 (delta-aware precedent ranking) will reuse the same comparison machinery on
  the Decision path — that is its own item.
- Consumers: the GUI's Compare tab ("Ask the advisor", read-scope allowed — the invoke is in
  the dashboard gate's statelessPosts, recording nothing), and any curl. Same read, same
  grounding as the tab renders.

## Realization note (2026-08-23): G-AI-3 — delta-aware precedent ranking (the open remainder, closed)

The Δ3a cosine half shipped 2026-08-04; the remainder waited on "release-comparison machinery
that does not exist yet". It exists now (EDR-GOVERNANCE-01 D16), and the realization:

- **The delta signal is posture overlap**: `|persisting| / (|fixed|+|new|+|persisting|)` from
  the deterministic comparison read — the Jaccard of the two releases' open-Finding sets. A
  near-identical release overlaps ~1.0; a very different one ~0. A component-level diff can
  refine the signal later without moving the seam.
- **Down-weight, never drop**: `weight = 0.5 + 0.5×overlap`; ranking key = cosine × weight
  (semantic) or the weight alone (exact-CVE fallback, whose Score is 0 by construction).
  Dropping was rejected: the Δ2 stance is "clearly labeled, the model and the human weigh
  relevance themselves" — so the overlap is EXPOSED (prompt label `release-overlap NN%`,
  additive `release_overlap` on `/findings/{id}/similar`) rather than silently acted on.
- **It lives in the PrecedentService** — the one retrieval seam — so the Gateway's grounding
  and the human endpoint re-rank identically. One comparison read per distinct precedent
  release (topK-bounded, cached per call; the subject's own release is 1.0 without a read).
- **Degrade contract**: a nil seam, a failed read (including the D16 honesty guard's 422/502),
  or an empty comparison leaves that precedent UNWEIGHTED and unlabeled — an outage must never
  penalize precedent, and 0% must never be claimed when the truth is "could not ask".
