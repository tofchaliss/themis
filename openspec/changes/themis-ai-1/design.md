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

```text
   themis-backend (public, backend-writes)      themis-ai (ai schema + own store, ai-writes)
   ─────────────────────────────────────        ───────────────────────────────────────────
   risk_context, vulnerabilities                 reconcile loop (level-triggered, D-QUEUE-1)
        │  v_ai_enrich_context (read-only view)     │  work = eligible − done − terminal
        └────────────── read ──────────────────────▶│
                                                     ▼
                                               ai.analyses        ← per CVE-context · STORED
                                               ai.finding_status  ← claim + lifecycle
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
validation (schema, anti-hallucination: `primary_weakness ∈ context CWEs`), a self-correction loop
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

## Affected-releases footprint — backend-owned, not an AI input (D-FOOTPRINT-1)

"Where is CVE-X live across my inventory?" is answered by a **deterministic backend query**
(leaning `GET /api/v1/vulnerabilities/{cve_id}/releases`) — the **inverse of the v0.3.8 scoped
listings** (product/project/version → findings), over the SAME `v_latest_findings` view with a
`WHERE cve_id = $1` swap. It is **not materialized** (no footprint column) and **never fed to the
LLM**: the footprint is deployment-volatile (in the prompt it would churn `input_context_hash` on
every ingest → constant re-enrichment), it is exact SQL an LLM would miscount, a wrong footprint from
the correlation engine's known FP/FN modes would be amplified as confident prose, and product-scoped
API keys make cross-product footprint a **disclosure** question best resolved deterministically. The
AI summary stays **CVE-intrinsic**; the transparency API JOINs summary (`ai` schema) ⋈ footprint
(`public`, on read) at read time. Backend owns full data, zero overlays, and this query is
**AI-independent — it MAY ship before/without v0.4.0**. Open sub-decisions (small): row grain
(per-`(release,component_purl)` + `?dedupe=release` — lean), state filter (return all with
`effective_state` — lean), input-key not-found (empty vs 404), fields (incl. `fixed_version`/
`installed_version`, available since v0.3.3), and **scoping/disclosure** (product-scoped key: span all
products vs filter to the key's product — the non-obvious one).

## Repo layout (D-REPO-1)

Monorepo. Go → `themis-backend/` (keep `go.mod` module path → imports untouched); new `themis-ai/`;
root generic (`openspec/`, `PROJECT_CONTEXT.md`, `project-backlog.md`, `CHANGELOG.md`, `cliff.toml`,
`contract/`, `.github/`, `LICENSE`, umbrella `README.md`, `ARCHITECTURE.md`, the two thinking docs).
`.github/workflows/` stays at root with path filters + `working-directory`. A `contract/` (JSON
Schema + golden fixtures) is the seam source-of-truth; a contract test both sides run in CI prevents
drift.

## Resolved — enrichment grain (OQ-GRAIN → D-GRAIN-1)

Key `ai.analyses` on the **CVE-context** — `(cve_id, worker_type, model_version, prompt_version,
input_context_hash)` — dropping **both** `artifact_id` **and** `component_purl`. Every field of the
typed output (`summary`, `primary_weakness` CWE, `key_factors`) is CVE-level, and D-FOOTPRINT-1 owns
the only version-varying facts, so a finer grain would store byte-identical rows under different keys.
One summary is stored once and fanned to every finding sharing `cve_id`. A future component-specific
worker can add `component_purl` to its own key via the `worker_type` discriminator.

## Resolved — work discovery & the seam mechanics (OQ-QUEUE → D-QUEUE-1)

**Level-triggered reconcile over a read-only view; no queue/trigger table.** themis-ai loops every
N s computing `work = v_ai_enrich_context(eligible) − ai.analyses(done @ hash) −
ai.finding_status(terminal)` — the set-difference unifies dispatch + idempotency + re-enrichment and
is self-healing. The **gate lives in the view** (eligibility defined once, backend-authoritative; the
row-set is the contract). A single **`ai.finding_status`** table serves both the claim
(`INSERT … ON CONFLICT DO NOTHING` — atomic, concurrency-safe) and the D-STATUS-1 lifecycle. Falls
out:

- **Migration `000002` (Go/`public`)** = the view + `CREATE SCHEMA ai` + role grants. **No queue
  table, no trigger.** `ai.analyses` / `ai.finding_status` are themis-ai's Alembic.
- **Role grants (thread ②):** `themis_ai` = `SELECT v_ai_enrich_context` + `ALL ON SCHEMA ai`;
  `backend` = `ALL ON public` + `SELECT` on `ai.analyses` / `ai.finding_status`. Structurally enforces
  the single-writer seam.
- **Contract (thread ③):** the view column schema + the `ai.analyses` typed-output JSON schema;
  golden fixtures both sides validate in CI. No queue-message schema.
- **Refines D-STATUS-2:** `queued` is now derived at read time (eligible-in-view minus a
  `ai.finding_status` row) — the backend writes no AI status at all.

No open questions remain — ready for task breakdown (`openspec-propose`).

## Quality gates

Backend keeps the six Go gates (build, unit, coverage thresholds, deadcode, integration, clean-arch,
verify-build), scoped to `themis-backend/`. themis-ai gets its own Python CI (pytest/ruff/mypy) with
three test tiers (unit against a stubbed runtime; `integration_ai` gated on a real Ollama; an offline
golden-set eval). A cross-border contract test runs on any seam change.
