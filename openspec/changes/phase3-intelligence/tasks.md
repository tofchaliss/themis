# Tasks — phase3-intelligence · Δ1 (Intelligence Gateway walking skeleton)

> **Scope: Δ1 only** — the walking skeleton of the Intelligence Gateway per `proposal.md` / `design.md`,
> grounded in `docs/engineering/decisions/EDR-INTELLIGENCE-01.md` (**Revision 2**: harness destination,
> 4-delta roadmap, D13 optional plane). Δ1 = **one reactive capability (`recommend_position`) end-to-end,
> pure Go, disable-able**, sitting on every real harness seam so Δ2–Δ4 are additive. Δ2 (typed dispatch +
> admission), Δ3 (Python engine + RAG), Δ4 (autonomy + LLMOps) are **out of scope** here. Each group ends
> with the six Themis gates (`make check`), extended to `internal/intelligence/`.

## 1. Gateway scaffold + architecture enforcement (D1/D12 · INTEL-01)

- [x] 1.1 Create `internal/intelligence/{domain,app,adapters}` (house layout; "gateway core" = domain+app)
  with a `doc.go` per package; **stateless in Δ1** (no datastore/migrations — in-code registry, no cache, no
  eval loop).
- [x] 1.2 Extend arch enforcement: add `intelligence` to `GREENFIELD_CONTEXTS` (Makefile go-cleanarch loop),
  to `boundedContexts` (shared `TestContextFirstArchitecture`), and depguard (an `intelligence-no-cross-context`
  block + domain/app inner rules): provider/engine code confined to `adapters/`; no cross-context imports;
  reads only via read-API clients; **writes nothing to truth**.
- [x] 1.3 Gate: build green; clean-architecture green.

## 2. Capability abstraction + advisory Proposal envelope + in-code Registry (D2/D11 · INTEL-02/03)

- [x] 2.1 `Capability` = id + version + context-needs + **execution plan** (ordered engine steps) + output
  JSON Schema + business rules + routing requirements. Δ1 plans are **one LLM step**.
- [x] 2.2 **In-code Capability Registry** (lookup-by-id → definition + single live version); DB-backed
  versioning deferred to Δ4. Register `recommend_position@v1` — **AI-assisted affected/not-affected triage**
  (use case #4), output stance constrained to `{affected, not_affected, mitigated}`.
- [x] 2.3 Structured advisory **Proposal envelope** — capability(id+version) / recommendation (stance +
  finding_id) / confidence / evidence-refs / reasoning / metadata — + its JSON Schema.
- [x] 2.4 Unit tests: registry lookup + unknown-id; envelope construction; execution-plan shape (1 step).
- [x] 2.5 Gate: build + unit tests + coverage green; clean-architecture green.

## 3. Engine port + LLM engine + provider adapters (D6/D11 · INTEL-06)

- [x] 3.1 **Engine port** (`Engine.Execute(step, ctx) → RawResult`); Δ1 ships **one LLM engine**, **no
  dispatcher** (one engine = trivial routing).
- [x] 3.2 **Provider port** + **Ollama provider adapter** (Gateway-confined) speaking the **OpenAI-compatible**
  chat-completions schema; temp-0, pinned model, structured-output (schema) request. Config-driven URL/model.
- [x] 3.3 **Fake/deterministic provider** behind the same port (canned schema-valid output) — the CI/test
  default; no running model needed.
- [x] 3.4 Trivial **router** (`Router.Select(requirements) → providerBinding`) returning the single binding;
  callers never name a provider/model.
- [x] 3.5 Unit tests: provider-port substitution (fake ↔ ollama shape); router returns the one binding;
  OpenAI-compatible request/response mapping.
- [x] 3.6 Gate: six Themis gates green.

## 4. Context Construction via read-API Knowledge Providers (D5 · INTEL-04)

- [x] 4.1 Ports `FaultlineReader` (Knowledge) + `FindingReader` (Governance) in `ports/`; HTTP read-API
  client adapters in `adapters/` (mirror the existing read-API-client seam), fakeable.
- [x] 4.2 **Deterministic Context Construction**: caller passes **identifiers only** (findingID) → assemble
  Finding (Governance) + Faultline enrichment (Knowledge) → validate-present (else no-proposal) → normalize
  into a typed `AssembledContext`. Precedent Positions deferred.
- [x] 4.3 Tests: same identifiers + upstream state → identical `AssembledContext` (pure, fake clients);
  missing grounding → no-proposal. Confirm Knowledge's Faultline read-model exposes enrichment fields.
- [x] 4.4 Gate: six Themis gates green.

## 5. Prompt construction + 3-stage validation (D6/D7 · INTEL-05/07)

- [x] 5.1 Gateway-owned **versioned prompt template** (embedded asset; no prompt strings in domain/app);
  render `template + AssembledContext` → LLM input instructing structured-JSON output.
- [x] 5.2 **3-stage validation** (Gateway-owned, per-capability): (1) schema via `jsonschema/v6` — one
  bounded retry, else no-proposal; (2) **business** — finding_id = subject, every evidence-ref ∈ grounding
  context, confidence ∈ [0,1], stance ∈ the **recommendable subset** `{affected, not_affected, mitigated}`
  (never `accepted_risk`/`deferred`/`under_investigation`) — no retry, no-proposal on fail; (3) proposal
  construction.
- [x] 5.3 Tests (hermetic, fake provider): rejects malformed JSON (retry→no-proposal); **rejects hallucinated
  evidence** (CVE not in grounding context); rejects out-of-range confidence / disallowed stance; valid →
  Proposal. Record every outcome.
- [x] 5.4 Gate: six Themis gates green.

## 6. Reactive API + `cmd/intelligence` + disable gate + observability (D3/D9/D12/D13 · INTEL-08/12)

- [x] 6.1 Spec-first reactive API (`api/intelligence.openapi.yaml` + oapi-codegen): `POST
  /v1/capabilities/{id}/invoke` — request = subject identifiers + correlation id; response = the Proposal
  envelope or empty ("no proposal"). **Synchronous**, bounded timeout; async designed-in (not built).
- [x] 6.2 `cmd/intelligence/main.go` — independently deployable, **stateless**; wires read-API clients +
  provider + validators; `observability.Setup` + `RequestLogger`; graceful shutdown. Self-documented config
  in `deploy/node.env.example` (`THEMIS_INTELLIGENCE_*`, `THEMIS_OLLAMA_URL`, model, `..._ENABLED`).
- [x] 6.3 **Per-invocation execution telemetry** via `internal/platform/observability` (capability,
  correlation id, provider, model, duration, tokens, validation outcome, proposal id); privacy-safe.
- [x] 6.4 Tests: reactive round-trip returns a Proposal (fake provider); "no proposal" path; telemetry fields
  present; no truth write.
- [x] 6.5 Gate: six Themis gates green.

## 7. Governance integration — the caller (D8/D13 · INTEL-08)

- [x] 7.1 `internal/governance/adapters/intelligence/client.go` — ACL HTTP client invoking the reactive API,
  decoding the Proposal envelope into a Governance-local type (mirrors `communication/adapters/governance`).
- [x] 7.2 **Disable gate:** Governance composition root wires the **real vs no-op** Intelligence client by
  config (`THEMIS_GOVERNANCE_AI_ENABLED` / global `THEMIS_INTELLIGENCE_ENABLED`); no call-site flags.
- [x] 7.3 Record AI provenance + confidence on the proposal **via existing fields** (walking-skeleton scope):
  actor `{kind: ai, id: "recommend_position@v1"}` carries source capability+version; confidence + reasoning
  travel in the rationale. Structured `GovernanceProposal` columns (confidence / evidence-refs / source) are a
  **deferred additive follow-up** (they ripple through domain + store schema + read API) — logged in
  `PHASE3-BACKLOG.md`.
- [x] 7.4 **On-demand, off-hot-path invocation:** add a Governance "recommend a position" action on a
  Finding; on that **explicit human request**, when AI is enabled, invoke `recommend_position` on a
  non-blocking path and record the returned proposal as an **ai** Governance Proposal via `RaiseProposal` —
  **never auto-accepted** (human decides), **never auto-fired per Finding**; AI absence/failure/latency
  invisible to the core flow.
- [x] 7.5 Tests: AI-off (no-op) → zero calls, pipeline unchanged; AI-on → ai-proposal raised `StatusProposed`;
  Intelligence unreachable → same no-proposal path (disabled ≡ unavailable); Governance re-checks finding
  exists.
- [x] 7.6 Gate: six Themis gates green.

## 8. Δ1 seam e2e + docs (staged testing · CONVENTIONS)

- [x] 8.1 Intelligence per-context e2e (own reactive API + fake provider + fake read-APIs): identifiers →
  grounded → validated → Proposal; hallucination → no-proposal; disabled → no-op.
- [x] 8.2 Governance→Intelligence seam test (httptest): the exact wire JSON of invoke request + Proposal
  response; ai-proposal recorded.
- [x] 8.3 Update `docs/engineering/PHASE3-STATUS.md` + `PHASE3-BACKLOG.md` (Δ2–Δ4 remain open); `openspec/STATUS.md`.
- [x] 8.4 Gate: six Themis gates green; `markdownlint-cli2` clean.
