# Design — themis-ai-1 (Basic AI Enrichment)

> Full decision log: [`phase-2b-grilling.md`](../../../phase-2b-grilling.md) (38 decisions +
> 2 open questions). This is the consolidated architecture; the grilling doc is authoritative for
> the per-decision detail and supersede history.

## Architecture — two systems over a Postgres seam (D-ARCH-1, D-LANG-1)

The AI harness is **not** in the Go backend. Two independently-deployed systems integrate through
the database:

- **themis-backend** (Go) — owns L0/L1, the read seam, the transparency API. Writes nothing AI.
- **themis-ai** (Python framework) — owns the harness (context → Ollama `qwen2.5:7b` → validate →
  write) and its own schema/store. Python because it is a *growing framework* (v0.4.1+ RAG/eval),
  even though v0.4.0 does no ML itself (inference lives in Ollama).

No synchronous HTTP: themis-ai can be down and the backend is unaffected — graceful degradation
(D-CONFIG-1) is **structural**, not coded.

## Clean single-writer seam (D-SEAM-1)

Every table has exactly ONE writer; the two systems READ across the border but never WRITE across
it. DB roles enforce this as a permission, not a convention.

```
   themis-backend (public, backend-writes)      themis-ai (ai schema + own store, ai-writes)
   ─────────────────────────────────────        ───────────────────────────────────────────
   risk_context, vulnerabilities                 work queue  (themis-ai's own)
        │  v_ai_enrich_context (read-only view)     │  reconciled from the view
        └────────────── read ──────────────────────▶│
                                                     ▼
                                               ai.analyses    ← per CVE-context · STORED
                                               ai.cve_status  ← lifecycle
   transparency API  ◀──── read: JOIN cve_id ─────────┘

   roles:  themis_ai → WRITE ai.*  · READ public view
           backend   → WRITE public.* · READ ai.*
```

## Storage — three planes (D-STORE-1, D-MEMORY-1)

| Plane | Question | Home | Owner | Phase |
| --- | --- | --- | --- | --- |
| P1 Findings | what's vulnerable | backend Postgres `public` | backend | today |
| P2 AI results | what the AI said (per CVE-context) | **same Postgres, `ai` schema** | themis-ai | v0.4.0 |
| P3 Agentic memory | what we decided before (RAG) | themis-ai's **own** vector store | themis-ai | v0.4.1 |

L2 lives in the **same** Postgres so the transparency JOIN is cheap and the "themis-ai optional"
property holds; themis-ai owns/migrates the `ai` schema (its own Alembic, disjoint from Go
`golang-migrate`). The per-finding L2 is **derived** (a `cve_id` JOIN); the enrichment itself is
**stored** once per CVE-context.

## The CVE Summarizer harness (in themis-ai)

Typed output `{ summary ≤500, primary_weakness (CWE|null), key_factors[] ≤5 }`, deterministic
validation (schema, anti-hallucination: `primary_weakness ∈ context CWEs), a self-correction loop
(≤2 reprompts), a mandatory reproducibility record (model digest, prompt version + hash, params,
tokens, `input_context_hash`), and content-addressed prompts-as-code. Idempotency via
`input_context_hash`. See the grilling doc D-CONTRACT-1 / D-HASH-1 / D-LOOP-1 / D-PROMPT-1 /
D-TYPES-1 / D-METRICS-1 / D-TEST-1 (all owned by themis-ai).

## Transparency read surface (D-API-1, D-STATUS-2)

- `ai_status` + `ai_status_reason` are fields on the existing `ScanVulnerabilityEnrichment` object,
  surfaced on every findings endpoint. `disabled`/`ineligible` are **derived at read time** (from
  `ai_enrichment` + the gate); the pipeline states come from the `ai` schema via a LEFT JOIN.
- `GET /api/v1/vulnerabilities/{id}/ai` — the full latest `ai_analyses` record (summary +
  reproducibility); `404` when none; `?history` deferred.

## Repo layout (D-REPO-1)

Monorepo. Go → `themis-backend/` (keep `go.mod` module path → imports untouched); new `themis-ai/`;
root generic (`openspec/`, `PROJECT_CONTEXT.md`, `project-backlog.md`, `CHANGELOG.md`, `cliff.toml`,
`contract/`, `.github/`, `LICENSE`, umbrella `README.md`, `ARCHITECTURE.md`, the two thinking docs).
`.github/workflows/` stays at root with path filters + `working-directory`. A `contract/` (JSON
Schema + golden fixtures) is the seam source-of-truth; a contract test both sides run in CI prevents
drift.

## Open questions (must close before task breakdown)

- **OQ-GRAIN** — key `ai.analyses` on the CVE-context (`cve_id`, `worker_type`, `model_version`,
  `prompt_version`, `input_context_hash`), dropping `artifact_id` (themis-ai enriches vulnerabilities,
  not deployments; the backend fans results out by `cve_id`). Sub-decision: CVE-grain vs
  (CVE + component-version)-grain. Reopens D-SCHEMA-1.
- **OQ-QUEUE** — queue ownership (themis-ai-internal fed by the view — leaning; vs a backend-owned
  reconciled queue), and whether migration `000002` has any trigger/queue table at all (the
  reconcile-by-hash "no trigger" option vs a queue). Downstream: this fixes the role grants (thread
  ②) and the contract-test shape (thread ③).

## Quality gates

Backend keeps the six Go gates (build, unit, coverage thresholds, deadcode, integration, clean-arch,
verify-build), scoped to `themis-backend/`. themis-ai gets its own Python CI (pytest/ruff/mypy) with
three test tiers (unit against a stubbed runtime; `integration_ai` gated on a real Ollama; an offline
golden-set eval). A cross-border contract test runs on any seam change.
