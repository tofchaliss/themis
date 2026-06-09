# Themis Phase 2 — AI Intelligence + Threat Intelligence

## Why

Phase 1 delivered a complete, tested ingestion and correlation pipeline, but risk scores
are deterministic (severity + VEX state only) and signal quality is low. Phase 2 makes
Themis useful for real security workflows: AI contextualisation turns raw findings into
actionable signals, EPSS/KEV data prioritises what to fix first, and upstream vendor VEX
feeds close the gap between raw CVE counts and real exploitability context.

## What Changes

- **AI enrichment** — LLM-based exploitability assessment for high/critical findings; result
  stored as an `intelligence_signal` (L3) with `source=ai_enrichment`; async via JobQueue
- **EPSS + KEV** — daily sync of CISA KEV list and FIRST.org EPSS scores; new L3 signals;
  updated composite risk score formula: `g(severity, vex_state, epss_score, kev_flag)`
- **Upstream VEX feeds** — scheduled fetch of vendor VEX feeds (Red Hat, Alpine, Ubuntu,
  Debian, SUSE, Wolfi, Rocky Linux); applied as `vex_documents` with `source=upstream_vendor`
- **VEX export** — `GET /api/v1/products/{id}/versions/{v}/vex` returns the computed
  `risk_context` as a CycloneDX or OpenVEX document

## Capabilities

### New Capabilities

- `ai-enrichment`: Async LLM assessment of high/critical vulnerability findings; pluggable
  model backend (OpenAI, Claude, Ollama); result stored as L3 intelligence signal with TTL
- `epss-kev`: Daily EPSS score + KEV status sync; updated risk score formula; new migration
  to index the `epss_score` and `kev_listed` columns on `risk_context`
- `upstream-vex-feeds`: Scheduled vendor VEX feed fetcher; PURL-based matching; precedence
  rules (user-supplied VEX > upstream vendor VEX); idempotent upsert per `(purl, cve_id)`
- `vex-export`: Read `risk_context` + `vex_assertions` for a product version; serialise as
  CycloneDX VEX or OpenVEX JSON; format negotiated via `Accept` header or `?format=` param

### Modified Capabilities

<!-- No main openspec/specs/ directory exists (Phase 1 specs are archived).
     Requirement changes to enrichment scoring are captured in the epss-kev spec above. -->

## Impact

**New packages (L3 adapter layer):**

- `internal/adapter/ai/` — LLM client adapter (OpenAI/Claude/Ollama); implements new
  `domain.AIEnricher` port
- `internal/adapter/vexfeed/` — vendor VEX feed fetcher; PURL matcher; precedence resolver

**Modified packages:**

- `internal/adapter/osv/` — extend with EPSS score fetch and KEV list sync
- `internal/adapter/api/` — add VEX export handler
- `internal/usecase/enrichment/` — update risk score formula to incorporate `epss_score`
  and `kev_flag` from L3 signals
- `internal/infrastructure/config/` — new fields: AI model endpoint/key
- `internal/domain/` — new `AIEnricher` port; updated risk score formula constants
- `cmd/themis/main.go` — registers new schedulers for EPSS/KEV sync and upstream VEX feed
  fetch; wires AI enrichment job handler

**Database:**

- Migration 000014: index `risk_context(epss_score)`, `risk_context(kev_listed)`;
  add `ai_assessment_text` column to `risk_context`

**APIs:**

- `GET /api/v1/products/{id}/versions/{v}/vex` — new (VEX export)

**External dependencies:**

- OpenAI / Anthropic SDK or compatible HTTP client — AI enrichment
- FIRST.org EPSS API and CISA KEV JSON feed — public, no auth required
