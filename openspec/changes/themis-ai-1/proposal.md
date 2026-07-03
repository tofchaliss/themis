# themis-ai-1 — Basic AI Enrichment (CVE Summarizer)

> Consolidated from `phase-2b-grilling.md` (design decision log) and `themis-ai-use-cases.md`
> (AI north-star). This is the **basic use case** — the thin, advisory first slice of the AI layer
> that everything else builds on. Targets **v0.4.0**. Two OPEN questions (below) must close before
> implementation.

## Why

Findings today are undifferentiated: every DETECTED high/critical finding with a CVSS score looks
the same. Analysts want a plain-language answer to *"why is this vulnerable?"* per finding, grounded
in authoritative data — not parametric recall from a large model. This is use case **#1 / #4 / #6**
from `themis-ai-use-cases.md` (summarization → triage context → remediation context), delivered as
the smallest end-to-end vertical so the foundation is proven before the 15-use-case roadmap grows.

## What changes

Introduce an AI enrichment layer as **two systems integrated over the PostgreSQL database**, plus a
monorepo restructure to house both:

- **`themis-backend`** (this Go codebase, moved to `themis-backend/`) — owns L0/L1, the read seam
  (a context view), and the transparency API. Writes **nothing** AI-specific.
- **`themis-ai`** (new Python framework, `themis-ai/`) — owns the harness: read context → prompt →
  Ollama (`qwen2.5:7b`) → validate typed output → write results. Owns its own schema + store.

The single AI worker in v0.4.0 is the **CVE Summarizer**: for each eligible finding it produces
`{ summary (≤500 chars), primary_weakness (CWE|null), key_factors[] }`, **advisory-only** — it never
touches `risk_context.effective_state`; state changes still require a human. See `design.md` for the
architecture, the clean single-writer seam, storage, and the full decision log.

## Scope

**In (v0.4.0):**

- Monorepo restructure: Go → `themis-backend/`, new `themis-ai/`, root-generic docs + `contract/`.
- Backend seam: a read-only context view + the transparency API (`ai_status` on the enrichment
  object, derived at read time; `GET /api/v1/vulnerabilities/{id}/ai` detail endpoint).
- The `ai` Postgres schema (themis-ai-owned, its own migrations) for AI results.
- themis-ai framework: one worker (CVE Summarizer), local Ollama runtime, deterministic harness
  with a mandatory reproducibility record, self-correction loop, Prometheus metrics.
- Config `ai_enrichment` (default **off**) on the backend; runtime/model config in themis-ai.
- **Affected-releases footprint (D-FOOTPRINT-1)** — a deterministic backend endpoint (leaning
  `GET /api/v1/vulnerabilities/{cve_id}/releases`), the *inverse* of the v0.3.8 scoped listings over
  `v_latest_findings`. It answers "where is CVE-X live across my inventory?" **without any AI** — the
  footprint is never a prompt input (it stays exact SQL; the summary stays CVE-intrinsic). Backend
  owns the full data, no overlays. **AI-independent — it MAY ship before/without v0.4.0**; folded in
  here because it emerged from the OQ-GRAIN discussion.

**Out / Non-goals (deferred):**

- Agentic memory / pgvector KB / RAG → **v0.4.1** (its own store).
- Additional workers (CWE Mapper, Exploitability, Context, VEX Recommender, Remediation, FP),
  auto-apply / AI-assisted VEX → **v0.4.1 / Phase 2c**.
- GHSA feed, notification wiring, external-hosted model runtimes → deferred.
- Use cases #2, #5, #7–#15 from `themis-ai-use-cases.md` → later phases.

## Resolved decisions (no open questions remain)

- ~~OQ-GRAIN~~ → **D-GRAIN-1: CVE-grain.** Key `ai.analyses` on
  `(cve_id, worker_type, model_version, prompt_version, input_context_hash)` — drop both `artifact_id`
  and `component_purl`. Every typed-output field is CVE-level and D-FOOTPRINT-1 owns
  version-actionability, so a finer grain would only duplicate rows. Enrich once per CVE-context, fan
  out by `cve_id`.
- ~~OQ-QUEUE~~ → **D-QUEUE-1: level-triggered reconcile over a read-only view; no queue/trigger
  table.** themis-ai computes `work = eligible(view) − done(ai.analyses) − terminal(ai.finding_status)`
  each pass. The **gate lives in the view** (eligibility defined once). One **`ai.finding_status`**
  table serves the claim (`INSERT … ON CONFLICT DO NOTHING`) and the lifecycle. Migration `000002` =
  view + `CREATE SCHEMA ai` + role grants only. `queued` becomes a read-time derivation — the backend
  writes no AI status.
- ~~footprint~~ → **D-FOOTPRINT-1: backend inverse query (`cve_id → releases`), never an AI input.**

**Ready for `openspec-propose`** — break the backend half into tasks (restructure, migration `000002`,
transparency API, footprint endpoint, contract), tagged v0.4.0.

## Impact

- **New repo tree:** `themis-ai/` (Python); root becomes an umbrella (generic docs + `contract/`).
- **Migration** (Go, `000002`): the context view + `CREATE SCHEMA ai` + role grants — additive, no
  L0/L1 ALTERs, no `risk_context.ai_*` columns, **no queue/trigger table** (level-triggered reconcile,
  D-QUEUE-1). The `ai.*` tables (`analyses`, `finding_status`) are themis-ai's own Alembic migrations.
- **New API:** `GET /api/v1/vulnerabilities/{id}/ai`; `ai_status` field on the enrichment object.
- **External dependency:** a local Ollama runtime (themis-ai only; backend never calls it).
- **Non-breaking** to existing behaviour: `ai_enrichment` defaults off; graceful degradation is
  structural (themis-ai down ⇒ backend unaffected).
