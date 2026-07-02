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

**Out / Non-goals (deferred):**

- Agentic memory / pgvector KB / RAG → **v0.4.1** (its own store).
- Additional workers (CWE Mapper, Exploitability, Context, VEX Recommender, Remediation, FP),
  auto-apply / AI-assisted VEX → **v0.4.1 / Phase 2c**.
- GHSA feed, notification wiring, external-hosted model runtimes → deferred.
- Use cases #2, #5, #7–#15 from `themis-ai-use-cases.md` → later phases.

## Open questions (resolve before implementation)

- **OQ-GRAIN** — enrichment dedup grain: key AI results on the **CVE-context** (drop `artifact_id`),
  so the same component across many SBOMs is enriched once and fanned out. CVE-grain vs
  (CVE + component-version)-grain still open. (Reopens D-SCHEMA-1.)
- **OQ-QUEUE** — queue ownership (themis-ai-internal, fed by the view — leaning; vs a backend-owned
  reconciled queue) and the three storage homes (findings / AI results / agentic memory).

## Impact

- **New repo tree:** `themis-ai/` (Python); root becomes an umbrella (generic docs + `contract/`).
- **Migration** (Go, `000002`): the context view + `CREATE SCHEMA ai` + role grants — additive, no
  L0/L1 ALTERs, no `risk_context.ai_*` columns (the `ai.*` tables are themis-ai's own migrations).
- **New API:** `GET /api/v1/vulnerabilities/{id}/ai`; `ai_status` field on the enrichment object.
- **External dependency:** a local Ollama runtime (themis-ai only; backend never calls it).
- **Non-breaking** to existing behaviour: `ai_enrichment` defaults off; graceful degradation is
  structural (themis-ai down ⇒ backend unaffected).
