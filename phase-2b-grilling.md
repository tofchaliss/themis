# Phase 2b (v0.4.0 — AI Intelligence) — Grilling Decision Log

Design-grilling decision log for Phase 2b. Materialised copy of the canonical repo-memory
record so it is reviewable in-tree. Q1–Q21 (2026-07-01) locked the harness internals; a
**2026-07-02 follow-on session pivoted the architecture to a two-system monorepo split** (below),
which SUPERSEDES the in-process assumption in Q11/D-RUNTIME-1 and ADR-0001. The harness decisions
still hold — they now live in the separate `themis-ai` framework, not the Go backend.

## Architecture pivot — two-system split (grilling 2026-07-02)

- **D-ARCH-1 — Two systems over a Postgres seam.** `themis-backend` (Go) owns L0/L1, the L2 schema,
  the trigger, and the read API. `themis-ai` (Python) owns the harness (context read → hash/preflight
  → prompt → Ollama → validate → self-correct → write). Integration is the DATABASE, three contracts:
  (1) **trigger/claim** — backend sets `risk_context.ai_status='queued'`; themis-ai claims via
  `SELECT … FOR UPDATE SKIP LOCKED`; (2) **context** — a read view `v_ai_enrich_context` exposing the
  D-HASH-1 semantic inputs; (3) **result** — themis-ai writes the `ai_analyses` row +
  `risk_context.ai_status/ai_status_reason/ai_last_attempt_at`. No synchronous HTTP — themis-ai can
  be down and the backend is unaffected, so D-CONFIG-1 graceful degradation is structural.
- **D-LANG-1 — themis-ai is a Python framework.** Inference lives in Ollama (themis-ai does no ML in
  v0.4.0), but themis-ai is a growing FRAMEWORK (v0.4.1+: pgvector RAG, eval, more workers) → Python's
  LLM ecosystem. The DB seam makes the language invisible to the backend.
- **D-REPO-1 — Monorepo, symmetric split.** One repo. Go moves to `themis-backend/` (keep the
  `go.mod` module path → all `github.com/themis-project/themis/...` imports untouched); new
  `themis-ai/`; the ROOT stays generic: `openspec/`, `PROJECT_CONTEXT.md`, `project-backlog.md`,
  `CHANGELOG.md`, `cliff.toml`, `contract/`, `.github/` (GitHub-forced), `LICENSE`, a short umbrella
  `README.md`, `ARCHITECTURE.md`, and this grilling doc. `.github/workflows/` stays at root with path
  filters + `working-directory`. Rationale: single owner needing backend/ai in par → a monorepo makes
  "in par" the atomic-commit default; a `contract/` source-of-truth + a contract test both sides run
  in CI prevents drift.
- **D-SCOPE-3 — `themis-phase-2b` (this repo) = backend half + the restructure → tagged v0.4.0.**
  Delivers: the monorepo restructure; migration `000002` (**refined by D-STORE-1:**
  `public.ai_enrich_trigger` + `v_ai_enrich_context` view + `CREATE SCHEMA ai` + role grants — the
  `ai.*` result tables are themis-ai's Alembic, NOT the Go migration); the trigger gate (config
  `ai_enrichment` default off); the transparency API; `contract/` (JSON Schema + golden fixtures +
  `SEAM.md`); root docs (`CONTEXT.md`/`ARCHITECTURE.md`, superseding ADR). The harness / Ollama /
  prompts / validation / metrics (D-CONTRACT / D-HASH / D-LOOP / D-PROMPT / D-TYPES / D-METRICS) move
  to `themis-ai` and are grilled there.
- **D-API-1 — Transparency read surface.** `ai_status` + `ai_status_reason` are fields on the
  EXISTING enrichment object (`ScanVulnerabilityEnrichment`), so they surface on every findings
  endpoint (scan + the v0.3.8 scoped product/project/version lists) for free. The full `ai_analyses`
  record (summary, primary_weakness, key_factors, reproducibility) is served by a dedicated detail
  endpoint **`GET /api/v1/vulnerabilities/{id}/ai`** — mirrors the existing `…/{id}/triage`
  sub-resource; `{id}` is the finding id already returned in every list; returns the **latest**
  `ai_analyses` record; **`404`** when none (the list object's `ai_status` already says why).
  `?history=true` (the append-only ledger) is deferred to v0.4.1.
- **D-STATUS-2 — `ai_status` lifecycle: persist the active states, derive the rest at read time.**
  The `risk_context.ai_status` COLUMN persists only the pipeline states — `queued` (written by the
  backend) and `enriching`/`enriched`/`invalid_output`/`backend_unavailable` (written by themis-ai);
  it is **NULL** for findings that never enter the pipeline. `disabled` (config `ai_enrichment` off)
  and `ineligible` (gate fails) are **DERIVED at read time** by the transparency API from
  `ai_enrichment` + the gate + the NULL column — never stored. Benefits: one persisted lifecycle with
  a clean backend→themis-ai handoff (no two-writer contention on the same value), no write
  amplification across the whole `risk_context` table, and the enrichment object still shows honest
  self-describing states. **Re-enrichment rule:** the backend may set `queued` from any state EXCEPT
  `enriching` (don't interrupt an in-flight run); themis-ai's `SKIP LOCKED` claim + the D-HASH-1
  preflight (unchanged context hash → skip) make a re-queue idempotent.
  **[Refined by D-SEAM-1/D-STORE-1: `ai_status` is NOT a `risk_context` column — `queued` is derived
  from a `public.ai_enrich_trigger` row with no current `ai.finding_status`; `enriching`/`enriched`/
  `invalid_output`/`backend_unavailable` live in `ai.finding_status` (themis-ai). The re-enrich rule
  holds, now expressed as the backend appending a trigger + themis-ai's claim.]**
- **D-NOTIFY-1 — Notification wiring deferred.** v0.4.0 surfaces the summary via the read API only;
  wiring it into a notification event waits until the summary's value is proven (avoids re-notifying
  an already-notified finding from an async job).

**Contract ownership:** the backend migration is authoritative for the `public` seam objects
(`ai_enrich_trigger`, `v_ai_enrich_context`); the `ai` schema is themis-ai's (D-STORE-1);
`contract/schema/` holds the JSON Schema for the typed output + the context payload. `themis-ai`
vendors the schema and runs a contract test in CI → any drift fails the build.

## Architecture refinement — clean seam + storage (explore 2026-07-02)

An explore session tightened the seam to a strict single-writer border and pinned where L2 lives.
These REFINE D-ARCH-1 / D-SCHEMA-1 / D-STATUS-2 / D-API-1 / D-SCOPE-3 (deltas at the end).

- **D-SEAM-1 — Single-writer-per-table border; no shared cell.** Every table has exactly ONE writer;
  the two systems READ across the border but never WRITE across it. The backend writes only
  `public.ai_enrich_trigger` (a lightweight "finding X eligible as of T" row). themis-ai writes only
  its own `ai.*` tables. So `ai_status` comes OFF `risk_context` and lives in the themis-ai section.
  The D-HASH-1 idempotency hash becomes fully themis-ai-internal — the trigger carries only identity +
  timestamp; themis-ai computes the hash, checks its own section, and skips. The backend never needs
  to know about the hash.
- **D-STORE-1 — L2 lives in the SAME Postgres, in an `ai` schema owned + migrated by themis-ai.**
  One instance; two schemas; two migration tools. `public` (backend, Go `golang-migrate`) =
  `risk_context`, `ai_enrich_trigger`, `v_ai_enrich_context`. `ai` (themis-ai, Alembic; its own
  `alembic_version`) = `ai.analyses` (results + reproducibility) + `ai.finding_status` (lifecycle).
  **DB roles enforce D-SEAM-1 as a permission:** `themis_ai` role = `WRITE ai.*` + `READ`
  `public.ai_enrich_trigger` + the context view; backend role = `WRITE public.*` + `READ ai.*`.
  Same-instance rationale: the transparency API is a cheap cross-schema JOIN (`public.risk_context ⋈
  ai.finding_status ⋈ ai.analyses`) AND the "themis-ai down ⇒ backend unaffected" property holds
  (L2 is already in the DB — no live call). The schema-skew guard (`BinarySchemaVersion`) never sees
  the `ai` schema.
- **D-MEMORY-1 — Agentic memory (L1c KB) is v0.4.1, in themis-ai's OWN store.** Three data planes:
  **P1 Findings** (backend `public`, exists today), **P2 AI results** (`ai` schema, v0.4.0),
  **P3 Agentic memory** (embeddings of past summaries / triage / FP patterns for RAG). P3 is
  JOIN-FREE (never joined to backend findings), so it does NOT belong in the shared Postgres — it
  gets themis-ai's own store (pgvector / a vector DB) when a corpus exists. Deferred to v0.4.1
  (confirms D-KB-1 with the storage rationale): day-one memory is empty → RAG adds nothing.

**Supersedes / refines:**

- **D-STATUS-2** → `ai_status`/`ai_status_reason`/`ai_last_attempt_at` are NOT `risk_context`
  columns; they live in `ai.finding_status` (themis-ai-written). `disabled`/`ineligible` are still
  derived at read time, just via a LEFT JOIN instead of a column. The two-writer situation is gone.
- **D-SCHEMA-1** → the `ai_analyses` table + status live in the `ai` schema under themis-ai's
  Alembic, NOT the Go migration; the 3 `risk_context.ai_*` columns are dropped from the plan.
- **D-ARCH-1 contract ③** → themis-ai writes ONLY `ai.*`; the backend's outbound write is the
  `ai_enrich_trigger` table (not a shared `ai_status` column).
- **D-API-1** → the transparency read is a LEFT JOIN to `ai.finding_status` / `ai.analyses`.
- **D-SCOPE-3** → backend migration `000002` (Go) = `public.ai_enrich_trigger` +
  `v_ai_enrich_context` view + `CREATE SCHEMA ai` + role grants. It does NOT create `ai.analyses`
  or add `risk_context.ai_*` columns — those are themis-ai's Alembic.

## Open questions — deep dive (explore 2026-07-02)

Two points surfaced that REOPEN earlier decisions and must be resolved before the proposal is
final. Insight captured; final answers pending a deeper session.

### OQ-GRAIN — enrichment grain / dedup identity — RESOLVED (D-GRAIN-1)

The CVE Summarizer's context (D-HASH-1: `cve_id`, description, cvss, severity, CWE candidates, epss,
kev, exploit_public) is **artifact-independent** — all CVE-level facts + global signals. So the
enrichment's natural grain is the **CVE-context**, NOT the per-artifact identity `(artifact_id,
component_purl, cve_id)`. themis-ai enriches VULNERABILITIES; it does NOT need (and should not know)
`scan_id` / product / project / version — the same component sits in many SBOMs, but the summary is
identical. The backend maps CVE → findings and fans the result out.

- **Refines D-SCHEMA-1:** key `ai.analyses` on the CVE-context (`cve_id`, `worker_type`,
  `model_version`, `prompt_version`, `input_context_hash`) — **drop `artifact_id`** (and
  `component_purl`, per D-GRAIN-1). Otherwise the same CVE-context in N SBOMs = N identical Ollama
  calls (N-fold waste).
- **D-GRAIN-1 — CVE-grain (drop `component_purl` too). LOCKS the sub-decision.** The fix-version test
  resolves to *no* once D-FOOTPRINT-1 owns version-actionability: every field of the D-CONTRACT-1
  typed output (`summary`, `primary_weakness` CWE, `key_factors`) is **CVE-level**, so a
  component-version key would store byte-identical rows under different keys — pure inference waste on
  a serialized CPU 7B model. Key `ai.analyses` on
  `(cve_id, worker_type, model_version, prompt_version, input_context_hash)`; matches D-HASH-1's
  CVE-level semantic inputs exactly. **This reverses the earlier "leaning component-version"** — the
  footprint decoupling removed the summary's need to name a fix version. Revisit per worker: a future
  component-specific worker (e.g. reachability) can add `component_purl` to its OWN key via the
  generic table's `worker_type` discriminator, without touching the Summarizer's grain.
- **Fan-out correctness — RESOLVED.** One CVE-intrinsic summary stored once and fanned to every
  finding sharing `cve_id` is safe: the summary describes the *flaw* (what it is, its CWE, its
  exploitability signals — all CVE-global), not the deployment. Component-specific concerns are a
  later-worker problem, isolated by `worker_type`.

### OQ-QUEUE — queue, write-back, storage homes — RESOLVED (D-QUEUE-1)

The work items are **unique CVE-contexts** (per D-GRAIN-1). Resolved (grilling 2026-07-03) to a
level-triggered reconcile over a read-only view — the backend writes NOTHING AI-related, not even a
status.

- **D-QUEUE-1 — Level-triggered reconcile over a read-only view; NO queue/trigger table.** Three
  locked pieces:
  1. **Reconcile, not a backend queue (Q1 = option B).** themis-ai runs a loop every N s (poll
     interval; `LISTEN/NOTIFY` deferred to v0.4.1) computing
     `work = v_ai_enrich_context(eligible) − ai.analyses(done @ current hash) − ai.finding_status(terminal)`.
     The set-difference UNIFIES dispatch + D-HASH-1 idempotency + re-enrichment in one query;
     self-healing (a missed/crashed pass is re-picked next tick). **Scales on the cheap axis:** at
     4 SBOM × 100 comp the reconcile is ~1–5 ms over ~400 rows / ~hundreds of distinct eligible CVEs;
     the only real cost is the one-time cold-drain of Ollama calls, which is identical under ANY queue
     design — **grain (D-GRAIN-1), not the queue, sets inference cost.** A watermark
     (`max(signals.updated_at)` on the view, to skip unchanged CVEs) is a v0.4.1 lever for
     tens-of-thousands-of-CVE deployments; not needed now.
  2. **Gate in the view (Q2 = option i).** `v_ai_enrich_context` = one row per **distinct `cve_id`
     present in `v_latest_findings`** (in-inventory, any `effective_state`) passing the D-TRIGGER-1
     gate (`severity High OR kev_listed OR exploit_public`). Columns = the D-HASH-1 semantic inputs at
     CVE-grain (`cve_id, description, cvss_score, cvss_vector, severity, cwe_ids[], epss_score,
     kev_listed, exploit_public`). Eligibility is defined ONCE, backend-authoritative; themis-ai never
     re-implements the gate → no drift; **the view's row-set IS the eligibility contract** (thread ③).
  3. **One `ai.finding_status` table = claim + lifecycle (Q3).** Keyed on the CVE-context; claimed by
     `INSERT … ON CONFLICT DO NOTHING` (the unique constraint IS the lock → atomic, concurrency-safe
     for free even though D-CONCURRENCY-1 sets concurrency=1 for v0.4.0). Transitions
     `enriching → enriched | invalid_output (TERMINAL, filtered next pass) | backend_unavailable
     (TRANSIENT, retried)`. Lives entirely in `ai`. One mechanism = claim + lifecycle +
     terminal-exclusion + in-flight idempotency; no separate lock/queue table.
- **Falls out — closes threads ② and ③:**
  - **Migration `000002` (Go / `public`)** = `v_ai_enrich_context` view + `CREATE SCHEMA ai` + role
    grants. **No queue table, no trigger** — resolves the D-SCOPE-3 / D-TRIGGER-2 open item. The
    `ai.analyses` + `ai.finding_status` tables are themis-ai's Alembic (D-STORE-1).
  - **Role grants (thread ②):** `themis_ai` = `SELECT` on `v_ai_enrich_context` (only) + `ALL` on
    schema `ai`; `backend` = `ALL` on `public` + `SELECT` on `ai.analyses` / `ai.finding_status` (the
    transparency JOIN). Structurally enforces D-SEAM-1 — no grant lets themis-ai write `public`, none
    lets the backend write `ai`.
  - **Contract test (thread ③):** the seam contract = (1) the `v_ai_enrich_context` column schema +
    (2) the `ai.analyses` typed-output JSON schema. Golden fixtures both sides validate in CI. No
    queue-message schema (there is no queue).
- **Refines D-STATUS-2:** `queued` is now **DERIVED** at read time (`eligible in view` minus a
  `ai.finding_status` row) — the backend writes NO status. `disabled`/`ineligible` still derived; all
  persisted states live in `ai.finding_status` (themis-ai-written). Supersedes the earlier
  `ai.cve_status` name → **`ai.finding_status`**.
- **Three storage homes (resolves the "L2 is derived" confusion):**
  1. **Findings** → backend `public` (exists today).
  2. **AI results** → `ai` schema, per **CVE-context** — STORED, authoritative. The *per-finding* L2
     is DERIVED (a `cve_id` JOIN), but the enrichment itself is stored, not derived.
  3. **Agentic memory (P3)** → themis-ai's OWN store (pgvector / vector DB), v0.4.1 — a different
     data type (embeddings/learning), NOT the shared Postgres.

**Status:** BOTH OPEN QUESTIONS **RESOLVED** (grilling 2026-07-03) — OQ-GRAIN → D-GRAIN-1 (CVE-grain);
OQ-QUEUE → D-QUEUE-1 (level-triggered reconcile over a view, no queue table); footprint → D-FOOTPRINT-1.
**Ready for `openspec-propose`** — break the backend half into tasks (migration 000002 = view +
`CREATE SCHEMA ai` + grants; transparency API; contract; restructure), tagged v0.4.0.

## Footprint decision — decouple affected-releases from AI (explore 2026-07-03)

Surfaced while grilling OQ-GRAIN: the temptation to add an "affected footprint" attribute to the CVE
(which project/release/versions are affected) and feed it into the Summarizer. Rejected — it
re-couples a CVE-stable output to deployment-volatile input. Resolved cleanly by keeping the footprint
100% backend-owned and out of the prompt.

- **D-FOOTPRINT-1 — Affected-releases footprint = backend-owned INVERSE query, never an AI input.**
  "Where is CVE-X live across my inventory?" is answered by a deterministic backend endpoint
  (leaning `GET /api/v1/vulnerabilities/{cve_id}/releases`) — the **inverse of the v0.3.8 scoped
  listings** (product/project/version → findings), over the SAME `v_latest_findings` view with a
  `WHERE cve_id = $1` swap. It is NOT materialized (no `affected_footprint` column) and NOT fed to the
  LLM. Four reasons: (1) the footprint is deployment-volatile — in the prompt it makes
  `input_context_hash` (D-HASH-1) churn on every ingest → constant re-enrichment, killing the
  enrich-once property; (2) it is exact SQL — an LLM miscounts/paraphrases a precise fact-set; (3) a
  wrong footprint (the correlation engine's known FP/FN modes — el8/el9 v0.3.2, OSV GIT v0.3.7, RH VEX
  minor-stream v0.3.6) would be amplified as confident prose the AI cannot self-detect; (4)
  product-scoped API keys make cross-product footprint a DISCLOSURE question, best answered
  deterministically, never inside a summary. The AI summary stays **CVE-intrinsic**; the transparency
  API JOINs summary (`ai` schema) ⋈ footprint (`public`, computed on read) at read time. **Backend
  owns full data; zero overlays; the query is AI-independent and MAY ship before/without v0.4.0** (it
  de-risks the slice). Open sub-decisions (small):
  - **(a) Row grain** — per-`(release, component_purl)` (truthful — a CVE can hit a release via >1
    component) with `?dedupe=release`, mirroring the v0.3.8 `?dedupe`. *Lean per-(release,component).*
  - **(b) State filter** — return ALL rows each carrying `effective_state` (recall-first — "affected"
    is the caller's filter, not a hidden one) vs only-live states. *Lean return-all-with-state.*
  - **(c) Input key** — canonical `cve_id`; resolve to `vulnerabilities.id` internally; not-found →
    empty list vs `404`.
  - **(d) Row fields** — product/project/version + `component_purl` + `effective_state` +
    `fixed_version`/`installed_version` (already available since v0.3.3) — enough to render "on 1.36,
    fix in 1.37".
  - **(e) Scoping / disclosure** — *the non-obvious one:* product-scoped API key — does a CVE query
    span ALL products or filter to the key's product? Resolve deterministically here (the reason
    footprint must stay out of the AI summary).

## Decisions locked (2026-07-01 — harness internals; now owned by `themis-ai`)

> **Framing note (per D-ARCH-1).** These predate the two-system split and describe a **Go,
> in-process** implementation. Their INTENT stands, but the Go-specific nouns are **superseded** —
> the harness relocates to the `themis-ai` (Python) framework and is re-expressed there. What moves
> to `themis-ai` (no longer in the Go backend): the `domain.AIWorkerRuntime` port / `usecase/aienrich/`
> harness / `adapter/ollama/` (Q11); the in-process `JobTypeAIEnrich` on the Go `JobQueue` + the
> "second in-process queue" (D-WORKER-1 / D-CONCURRENCY-1); `go:embed` prompt templates (D-PROMPT-1);
> the Go `AIGenerate*` types (D-TYPES-1); the Go Prometheus registration + `//go:build integration_ai`
> tests (D-METRICS-1 / D-TEST-1); the self-correction loop + reproducibility harness (D-LLMOPS-1 /
> D-LOOP-1); the `input_context_hash` computation (D-HASH-1); the output validation (D-CONTRACT-1).
> What the **Go backend keeps** from this section — only the *shape* the seam needs: **D-SCHEMA-1**
> (tables/columns/view), **D-STATUS-1** (the status enum + `CHECK` set), **D-HASH-1** (the unique
> idempotency INDEX — the hash is computed by themis-ai and stored opaque), and **D-CONTRACT-1** (the
> typed-output COLUMNS; validation itself is themis-ai's). `themis-ai` config (`ai_runtime`,
> `ai_model`, `ai_worker_concurrency`) lives in that framework, not the Go backend.

- **D-SCOPE-1 — Thin foundation slice.** v0.4.0 = L3 foundation + a small cold-start-friendly
  worker set, NOT the full 7-worker Phase 2b. A lower layer emitting wrong data poisons every
  layer above.
- **D-WRITE-1 — AI advisory-only.** ZERO write to `risk_context.effective_state`. Writes only its
  own L2 table. State changes still require a human (`triage_history`). Auto-apply = Phase 2c.
- **D-KB-1 — Defer pgvector + KB to v0.4.1+.** KB-first bypass = zero value while the corpus is
  empty; v0.4.0 ships the AI pipeline WITHOUT it; re-embed the `ai_analyses` corpus later (cheap).
- **D-WORKER-1 — Exactly ONE worker = CVE Summarizer in v0.4.0**, full e2e vertical wired
  (trigger → enqueue → consume → Ollama → typed output → validate → store → transparent API).
  Defer CWE Mapper + Exploitability Analyzer. Add `JobTypeAIEnrich` to the existing JobQueue port.
- **D-TRIGGER-1 — Gate + timing.** Gate = severity High OR `kev_listed` OR `exploit_public`. Fire
  AI only after L1 has settled (L0 → L1 → L2); TWO dispatch points: (1) end of fresh-ingest enrich,
  (2) after `ReEnrichSignals` updates a finding. Idempotency is Themis-wide.
- **D-CONFIG-1 — AI opt-in, config-gated, default OFF.** Config key `ai_enrichment` (default off).
  A degraded run writes NO row and touches NOTHING in `risk_context` (no upward contamination).
- **D-LLMOPS-1 — Harness + self-correction loop + reproducibility from day one.** The harness is a
  deterministic shell around the one stochastic call. The reproducibility record is MANDATORY on
  every row. LLM-ops = reproducibility + Prometheus metrics + a thin offline golden-set eval.
- **D-LOOP-1 (Q9) — Self-correction loop guardrails.** Cap = 2 re-prompts (≤3 calls/finding);
  retry #2 invalid → terminal. Schema/validation failures are retry-able; infra failures
  (unreachable/timeout) are NOT retried → `backend_unavailable`, finding stays eligible. Hard
  ceilings: per-call ~60 s + a per-finding ceiling.
- **D-STATUS-1 (Q10) — Canonical AI status enum, honest self-describing names.** `disabled` ·
  `ineligible` · `queued` · `enriching` · `enriched` (the only state that writes `ai_analyses`) ·
  `invalid_output` (TERMINAL, our-side; reason validation/timeout/ceiling) · `backend_unavailable`
  (TRANSIENT, retried). Names encode cause + terminal-vs-retryable. Documented in CONTEXT.md.
- **Q11 — Port / harness / adapter seam.** Port `domain.AIWorkerRuntime` in `domain/ports.go`
  (single `Generate(ctx, AIGenerateRequest) (AIGenerateResponse, error)`, returns RAW
  text + tokens + timing, no parse/validate). Harness = new `usecase/aienrich/` (deterministic;
  unit-tested against a stub). Adapter = `adapter/ollama/` (backend-named, matches nvd/osv/redhat).
- **D-RUNTIME-1 (Q11) — Config-selectable single runtime, local-first.** `ai_runtime` enum (only
  valid value = `ollama`). Port + DI factory = the seam. Router + external-hosted backends are
  DEFERRED (opt-in / off-by-default + a data-egress ack when added). A future router targets the
  OpenAI-compatible `/v1/chat/completions` contract. ADR:
  `docs/adr/0001-local-first-ai-runtime.md` (Accepted).
- **D-MODEL-1 (Q12) — Default model.** `ai_model` single config value, default `qwen2.5:7b`.
  CyberPal-2.0 is a first-class opt-in alternative (set explicitly if Qwen is unavailable OR once
  eval proves it better). NO auto fallback chain. The default must be safe / verified /
  evidence-backed; the Summarizer needs the least spec of the workers.
- **D-SCHEMA-1 (Q13) — `ai_analyses` table + lifecycle on `risk_context`.** Identity
  (`artifact_id`, `component_purl`, `cve_id`) + a `worker_type` discriminator (generic table).
  Reproducibility columns MANDATORY (model, `model_version` = Ollama digest, `prompt_version`,
  `prompt_template_hash`, params, prompt/completion tokens, `raw_response`, `input_context_hash`,
  `created_at`). SUCCESSES-ONLY immutable ledger (a row exists only in `enriched`). Failures =
  metrics + `risk_context.ai_status` / `ai_status_reason` / `ai_last_attempt_at` (3 new columns).
  Re-enrich APPENDS; "current" = latest `created_at`. Additive migration; ZERO L0/L1 ALTERs.
- **D-CONTRACT-1 (Q14) — CVE Summarizer typed output.**
  `{ summary (required, ≤500 chars), primary_weakness (string|null CWE id), key_factors ([string]
  ≤5, each ≤200) }`. Deterministic validation: exact schema / no unknown keys; summary non-empty
  ≤500; `primary_weakness`, if set, MUST ∈ the context CWE ids (ANTI-HALLUCINATION →
  reject + reprompt); `key_factors` ≤5 / ≤200. NO confidence field. The 500-char summary serves
  both the notification and the transparency API.
- **D-CONCURRENCY-1 (Q15) — Dispatch + concurrency.** (1) ONE job per finding
  (`JobTypeAIEnrich`), not batched. (2) A SECOND dedicated in-process queue instance for AI
  (isolates slow inference from the shared ingestion/correlation/notify pool). (3)
  `ai_worker_concurrency` default 1 (a 7B model on CPU serialises; MacBook test-fire). Runaway
  guard = per-call ~60 s + per-finding ceiling; no rate limiter.
- **D-HASH-1 (Q16) — `input_context_hash` in the idempotency key.** Hash = SHA-256 over a
  CANONICAL JSON (sorted keys, fixed field set) of the SEMANTIC inputs the model sees (cve_id,
  description, CVSS score/vector, severity, candidate CWE id set, EPSS score, KEV bool,
  exploit-public bool) — it does NOT include the prompt template text (that is `prompt_version`).
  New UNIQUE key = `(identity, worker_type, model_version, prompt_version, input_context_hash)`.
  Resolves the Q13 ↔ D-TRIGGER-1 collision: a signal change → new hash → row APPENDS (re-enrich
  works); no change → same hash → idempotent skip. The harness computes the hash and does a
  pre-flight existence check BEFORE spending inference. The immutable append-only ledger is
  preserved.
- **D-PROMPT-1 (Q17) — Prompts-as-code + registry pattern (content-addressed immutable + human
  label).** Grounded in production LLM-ops (LangSmith / PromptLayer / Langfuse all use an immutable
  content-addressed version + a movable human label). (a) `go:embed` `text/template` files, one per
  worker, in `usecase/aienrich/prompts/`; git = registry, PR review = promotion gate. (b) TWO
  fields, both stored in the reproducibility record: `prompt_template_hash` (SHA-256 of template
  text, computed at load — immutable auto-provenance, tamper-evident) + `prompt_version` (human
  label constant, e.g. `cve-summarizer/v1`, shown in the transparency API + notifications). (c) A
  binding unit test asserts `prompt_template_hash == expected_for(prompt_version)` — editing a
  template without re-pointing the label fails CI (forces a conscious "same version or new?"
  decision). (d) ONLY `prompt_version` (the human label) is in the idempotency key; a hash that
  changed without a label bump is a BUG that CI catches, NOT a silent mass re-inference trigger.
  Production universally stores BOTH → we store both.
- **D-TYPES-1 (Q18) — `AIGenerateRequest` / `AIGenerateResponse` fields.**
  `AIGenerateParams{ Temperature (def 0), Seed (fixed def), TopP, NumPredict (per-call token
  ceiling), Stop[] }`. `AIGenerateRequest{ Model, System, Prompt, Params, Format }`.
  `AIGenerateResponse{ Text (RAW, unparsed), ModelDigest, PromptTokens, CompletionTokens, Latency
  time.Duration }`. Picks: (1) System/user SPLIT (a stable preamble shrinks the per-finding Prompt
  and cleans the input-context hash). (2) The adapter resolves `ModelDigest` via `/api/show`
  (cached) → stored as `model_version` (digest immutable, tag movable); the harness never guesses.
  (3) `Format="json"` coercion = belt NOT suspenders — still run the full D-CONTRACT-1 validation,
  never trust `format=json` for correctness. (4) A SINGLE `Latency` (total) in the ledger now; finer
  Ollama duration splits become Prometheus histogram labels later, NOT ledger columns.
- **D-TEST-1 (Q19) — Three test tiers.**
  - **T1 — Unit** (default `go test ./...`, no tags/network; ~all logic coverage): a stub
    `AIWorkerRuntime` returns SCRIPTED sequences of responses/errors to drive the whole harness
    deterministically (trigger gating, hash + pre-flight skip, the D-LOOP-1 loop:
    `invalid → valid` asserts the reprompt cap, an infra error asserts `backend_unavailable`
    no-row, persistent invalid asserts `invalid_output` terminal, D-STATUS-1 transitions, the
    successes-only ledger write). `adapter/ollama/` has its OWN unit tests via an `httptest.Server`
    mocking Ollama JSON (`eval_count` parse, digest via `/api/show`, timing).
  - **T2 — Integration** (`//go:build integration_ai` — a SEPARATE tag from the existing DB
    `integration` tag so DB-integration CI needs no model runtime): gated on
    `THEMIS_TEST_OLLAMA_URL`, skip cleanly when unset; ONE thin e2e smoke — real finding → real
    `qwen2.5:7b` → assert parse + validate + row (NOT exact text).
  - **T3 — Golden-set eval** (`make ai-eval` target, OUTSIDE `make check`): ~10–20 curated CVEs in
    `testdata/ai-eval/` + human reference notes; a regression gate run BEFORE bumping
    `prompt_version`. The v0.4.0 metric = DETERMINISTIC STRUCTURAL checks ONLY (schema valid,
    `primary_weakness` ∈ context CWE, summary ≤500, no CVE id in the summary that was absent from
    the input) + an eyeball diff. BLEU/ROUGE correlate poorly for summaries and LLM-as-judge needs
    a 2nd model → DEFER semantic/judge scoring to v0.4.1.
- **D-SCOPE-2 (Q20) — GHSA OUT of v0.4.0.** GHSA is a correlation/vuln-data feed (NVD/OSV family),
  NOT an AI feature. Excluded to preserve the D-SCOPE-1 thin slice. No hard dependency — the
  Summarizer context already gets CWE ids from the NVD/OSV catalog. It belongs in a separate
  feed-expansion change (2a lineage), decided on `intel-source-tiers` merits. Post-2b, GHSA can
  enrich AI context cleanly (a new context field → new `input_context_hash` → natural re-enrichment).
- **D-METRICS-1 (Q21) — AI-layer Prometheus metrics.** Subsystem prefix `ai_enrich`,
  `Namespace = themis`, its own `RegisterAIEnrich()` / `registerOnce` file. FIVE metrics:
  1. `themis_ai_enrich_total` — CounterVec `{worker_type, status}`; status ∈ terminal D-STATUS-1
     (`enriched` | `invalid_output` | `backend_unavailable`).
  2. `themis_ai_inference_duration_seconds` — HistogramVec `{worker_type, model}`; single Ollama
     call latency (raw `AIGenerateResponse.Latency`).
  3. `themis_ai_reprompts_total` — CounterVec `{worker_type, reason (schema|validation)}`;
     D-LOOP-1 loop health.
  4. `themis_ai_tokens_total` — CounterVec `{worker_type, kind (prompt|completion)}`.
  5. `themis_ai_queue_depth` — Gauge; DEDICATED AI queue depth.

  Picks: (1) CUSTOM buckets `[1, 2, 5, 10, 20, 30, 60, 120]` s (DefBuckets top out ~10 s, useless
  for a CPU 7B model); (2) ONE inference-only histogram (total ≈ inference × attempts is derivable,
  so no separate harness histogram); (3) a separate `themis_ai_queue_depth` (the existing
  `themis_queue_depth` is the shared pool); (4) the tokens counter is IN for v0.4.0 (cheap, Ollama
  returns the counts, useful cost baseline).

## Config keys

- `themis-backend`: `ai_enrichment` — bool, default **off** (gates whether the backend marks
  findings `ai_status='queued'`). This is the ONLY AI config in the Go backend.
- `themis-ai` (Python framework, its own config): `ai_runtime` (enum, only `ollama`), `ai_model`
  (default `qwen2.5:7b`), `ai_worker_concurrency` (default `1`) — moved out of the backend per D-ARCH-1.

## Deferred to v0.4.1+

Full roadmap: **[`NEXT-STAGE.md`](NEXT-STAGE.md)** (v0.4.1 deepening · v0.5.0 Phase 2c AI-assisted VEX
· GHSA separate track). In brief: agentic memory / pgvector KB / RAG (P3) · 6 more workers (CWE
Mapper, Exploitability, Context, VEX Recommender, Remediation, FP) · `LISTEN/NOTIFY` latency ·
reconcile watermark · notification wiring · LLM-as-judge / semantic eval · transparency `?history` ·
CyberPal-2.0 + external runtimes / router · finer Ollama duration splits as metric labels.

## Related artifacts

- `CONTEXT.md` (root, to create) — glossary: layers, principles, AI vocabulary, "AI status states",
  the two-system seam.
- `ARCHITECTURE.md` (root, to create) — the two-system split + the 3 seam contracts.
- ~~`docs/adr/0001-local-first-ai-runtime.md`~~ — **SUPERSEDED by D-ARCH-1**; the real ADR is
  "AI enrichment via an external framework over a Postgres seam".
- `contract/` (root, to create) — the seam source-of-truth: `schema/` (JSON Schema), `SEAM.md`,
  `contract_test/` (golden fixtures both sides validate).
- [`NEXT-STAGE.md`](NEXT-STAGE.md) (root) — the v0.4.1+ roadmap (everything deferred beyond the
  v0.4.0 slice: memory/RAG, more workers, latency/scale, Phase 2c AI-assisted VEX, GHSA).
- `openspec/changes/themis-phase-2/{proposal,design}.md` — architecture reference (aspirational
  master; the thin v0.4.0 slice + two-system split supersede its in-process framing).

## Next step

Backend half only: consolidate into a PRD → `openspec-propose` to scaffold
`openspec/changes/themis-phase-2b/` (migration + trigger + transparency API + contract + restructure),
tagged v0.4.0. The `themis-ai` Python framework is planned separately in `themis-ai/`.
