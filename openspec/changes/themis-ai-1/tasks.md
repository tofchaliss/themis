# Tasks — themis-ai-1 (Basic AI Enrichment, v0.4.0)

> Scope: the v0.4.0 backend half + monorepo restructure + the `themis-ai` framework, per
> `proposal.md` / `design.md` (decision log: `phase-2b-grilling.md`). Go groups end with the six
> Themis gates; Python (`themis-ai`) groups end with the Python CI gates (ruff · mypy · pytest).
> Groups 6–8 (`themis-ai`) may be split into a companion OpenSpec change if you prefer two changes;
> default is one change for atomic in-par commits (D-REPO-1).

## 1. Monorepo restructure (D-REPO-1)

- [ ] 1.1 `git mv` the Go tree into `themis-backend/` (keep the `go.mod` module path so all
  `github.com/…/themis/…` imports are untouched); move `migrations/`, `api/`, `scripts/`,
  `tests/`, `cmd/`, `internal/`, `Makefile`, `go.mod`/`go.sum` under it.
- [ ] 1.2 Create the `themis-ai/` skeleton (Python package layout, `pyproject.toml`, `alembic/`
  stub, `README.md`) — empty framework shell, no logic yet.
- [ ] 1.3 Keep root generic: `openspec/`, `PROJECT_CONTEXT.md`, `project-backlog.md`,
  `CHANGELOG.md`, `cliff.toml`, `LICENSE`, `NEXT-STAGE.md`, the two thinking docs; add umbrella
  `README.md` + `ARCHITECTURE.md` placeholders; create `contract/` dir.
- [ ] 1.4 Rewire build/CI: `Makefile` paths, `scripts/*`, and `.github/workflows/*` with path
  filters + `working-directory: themis-backend` for the Go jobs.
- [ ] 1.5 Gate (restructure): `make verify-build` + `make check` green from `themis-backend/`;
  every existing Go test passes unchanged; CI green on the new layout.

## 2. Footprint endpoint — AI-independent early win (D-FOOTPRINT-1)

- [ ] 2.1 Resolve the footprint sub-decisions (a) row grain per-`(release,component_purl)` +
  `?dedupe=release`, (b) state filter = return all with `effective_state`, (c) not-found → empty
  list, (d) fields incl. `fixed_version`/`installed_version`, (e) **scoping/disclosure** —
  product-scoped key spans its own product(s) only. Record the picks in `design.md`.
- [ ] 2.2 Store: add the inverse query on `PostgresScanQueryRepository` (over `v_latest_findings`,
  `WHERE cve_id = $1` + scope/disclosure predicate) reusing the v0.3.8 select/joins/row-scan.
- [ ] 2.3 Handler + route: `GET /api/v1/vulnerabilities/{cve_id}/releases`; OpenAPI schema +
  `make generate-api`; cursor pagination + `severity`/`effective_state` filters.
- [ ] 2.4 Tests: store query (scope, dedupe, disclosure), handler (filters, empty, pagination).
- [ ] 2.5 Gate: six Themis gates green (`make check`).

## 3. Seam contract (thread ③)

- [ ] 3.1 `contract/schema/` — JSON Schema for (1) the `v_ai_enrich_context` row (the D-HASH-1
  CVE-grain columns) and (2) the `ai.analyses` typed output (`summary` ≤500, `primary_weakness`
  CWE|null, `key_factors[]` ≤5) + the reproducibility record.
- [ ] 3.2 `contract/SEAM.md` — the three seam facts (view read · reconcile · result write) and the
  single-writer border (D-SEAM-1).
- [ ] 3.3 `contract/contract_test/` — golden fixtures (valid + boundary + invalid) both sides
  validate against the schemas.
- [ ] 3.4 Gate: contract-test runner runs standalone (schema-validates the golden fixtures); wired
  into CI in group 9.

## 4. Backend migration 000002 — the seam objects (D-QUEUE-1, D-STORE-1)

- [ ] 4.1 `v_ai_enrich_context` view: one row per distinct `cve_id` in `v_latest_findings` passing
  the D-TRIGGER-1 gate (`severity High OR kev_listed OR exploit_public`); columns = the D-HASH-1
  semantic inputs (`cve_id, description, cvss_score, cvss_vector, severity, cwe_ids[], epss_score,
  kev_listed, exploit_public`).
- [ ] 4.2 `CREATE SCHEMA ai` + role grants: `themis_ai` = `SELECT v_ai_enrich_context` + `ALL ON
  SCHEMA ai`; `backend` = `ALL ON public` + `SELECT` on `ai.analyses`/`ai.finding_status`. **No
  queue/trigger table.**
- [ ] 4.3 Confirm the schema-skew guard (`BinarySchemaVersion`) ignores the `ai` schema; bump/verify
  the migration version; `make migrate-up`/`down` reversible.
- [ ] 4.4 Gate: six Themis gates green; migration up/down verified on an embedded-Postgres test.

## 5. Backend transparency API (D-API-1, D-STATUS-2)

- [ ] 5.1 Config `ai_enrichment` (bool, default **off**) — the only backend AI config; wire into
  `infrastructure/config`.
- [ ] 5.2 Add `ai_status` + `ai_status_reason` to `ScanVulnerabilityEnrichment`: derive
  `disabled` (config off) / `ineligible` (gate fails) / `queued` (eligible-in-view minus a
  `ai.finding_status` row) at read time; LEFT JOIN `ai.finding_status`/`ai.analyses` for the
  pipeline states. Surfaces on every findings endpoint (scan + v0.3.8 scoped lists).
- [ ] 5.3 `GET /api/v1/vulnerabilities/{id}/ai` — latest `ai.analyses` record (summary +
  reproducibility); `404` when none; OpenAPI + `make generate-api`.
- [ ] 5.4 Tests: status derivation matrix (disabled/ineligible/queued/enriching/enriched/failed),
  detail endpoint (present + 404), enrichment object on the scoped lists.
- [ ] 5.5 Gate: six Themis gates green (`make check`).

## 6. themis-ai — the `ai` schema (Alembic) (D-STORE-1, D-SCHEMA-1)

- [ ] 6.1 Alembic setup in `themis-ai/` with its own `alembic_version` (disjoint from Go
  `golang-migrate`); connection via the `themis_ai` role.
- [ ] 6.2 `ai.analyses` — CVE-context key `(cve_id, worker_type, model_version, prompt_version,
  input_context_hash)` (D-GRAIN-1); typed-output columns + mandatory reproducibility columns
  (model digest, prompt version + `prompt_template_hash`, params, prompt/completion tokens,
  `raw_response`, `input_context_hash`, `created_at`); successes-only append-only ledger.
- [ ] 6.3 `ai.finding_status` — CVE-context key; `status` enum (D-STATUS-1) + reason +
  `last_attempt_at`; unique constraint that backs the atomic claim.
- [ ] 6.4 Gate: Python gates (ruff · mypy · pytest); migration applies + rolls back against a test DB.

## 7. themis-ai — harness + reconcile loop (D-QUEUE-1, D-CONTRACT-1, D-HASH-1, D-LOOP-1, D-PROMPT-1)

- [ ] 7.1 Reconcile loop (level-triggered, poll interval): `work = view(eligible) −
  ai.analyses(done @ hash) − ai.finding_status(terminal)`; claim via `INSERT ai.finding_status …
  ON CONFLICT DO NOTHING`.
- [ ] 7.2 Context read from `v_ai_enrich_context`; compute `input_context_hash` (canonical JSON,
  fixed field set) + preflight skip on unchanged hash.
- [ ] 7.3 Prompts-as-code: one template per worker under `themis-ai/prompts/`; store both
  `prompt_version` (human label) and `prompt_template_hash`; binding test asserts hash ==
  expected-for(version).
- [ ] 7.4 Ollama adapter: `qwen2.5:7b` (D-MODEL-1); request/response types (D-TYPES-1); resolve
  model digest via `/api/show`; `format=json` as belt, not trust.
- [ ] 7.5 Validate typed output (schema + anti-hallucination `primary_weakness ∈ context CWEs`) +
  self-correction loop (≤2 reprompts; infra error → `backend_unavailable` no-row; persistent
  invalid → `invalid_output` terminal).
- [ ] 7.6 Write path: on success write `ai.analyses` + reproducibility record and set
  `ai.finding_status='enriched'`; never write `public`/`risk_context` (advisory-only, D-WRITE-1).
- [ ] 7.7 Config: `ai_runtime` (ollama), `ai_model` (qwen2.5:7b), `ai_worker_concurrency` (1),
  poll interval.
- [ ] 7.8 Gate: Python gates (ruff · mypy · pytest); contract test validates emitted `ai.analyses`
  rows against `contract/schema/`.

## 8. themis-ai — observability + eval (D-METRICS-1, D-TEST-1)

- [ ] 8.1 Five Prometheus metrics (`ai_enrich` subsystem): `enrich_total{worker,status}`,
  `inference_duration_seconds{worker,model}` (custom buckets), `reprompts_total{worker,reason}`,
  `tokens_total{worker,kind}`, `queue_depth` gauge.
- [ ] 8.2 T1 unit tier — stubbed runtime returns scripted responses/errors; drives gating, hash +
  preflight skip, the loop transitions, successes-only ledger; adapter unit tests via a mock
  Ollama server.
- [ ] 8.3 T2 integration tier (`integration_ai`, gated on `THEMIS_TEST_OLLAMA_URL`, skips when
  unset) — one thin e2e smoke: real finding → real `qwen2.5:7b` → parse + validate + row.
- [ ] 8.4 T3 golden-set eval (`make ai-eval`, outside `make check`) — ~10–20 curated CVEs +
  deterministic structural checks (schema, CWE-in-context, ≤500, no hallucinated CVE id).
- [ ] 8.5 Gate: Python gates green; T1 in default CI, T2/T3 wired but not blocking.

## 9. Integration, docs, provenance, release

- [ ] 9.1 Wire the cross-border contract test into CI (runs on any change under `contract/`,
  `themis-backend/…/ai`, or `themis-ai/`).
- [ ] 9.2 `CONTEXT.md` (glossary: layers, AI status states, the two-system seam) + `ARCHITECTURE.md`
  (the split + the three seam contracts).
- [ ] 9.3 ADR: "AI enrichment via an external framework over a Postgres seam" (supersedes the old
  `0001-local-first-ai-runtime`).
- [ ] 9.4 End-to-end smoke on a real deployment: `ai_enrichment=on` → eligible CVEs enriched →
  `ai_status` + `GET …/{id}/ai` surface the summary; `ai_enrichment=off` → backend unaffected.
- [ ] 9.5 Update `PROJECT_CONTEXT.md`, `project-backlog.md`, `openspec/STATUS.md`; sync the
  `ai-enrichment` delta spec to `openspec/specs/`.
- [ ] 9.6 `docs/release-notes-v0.4.0.md` + `CHANGELOG.md`; merge to `main`; tag `v0.4.0`.
