## Why

The current schema conflates two distinct concerns inside one `sbom_documents` table:
**composition** (what is in an artifact — stable, determined by the image digest) and
**vulnerability scan** (what a scanner found at a point in time — temporal, evolves as CVE
data updates). This conflation causes three compounding problems:

1. **Silent triage loss on rescan.** `risk_context` keys off `component_vulnerability_id`,
   which is tied to a specific scan-document row. Every rescan creates new
   `component_vulnerabilities` rows → new `risk_context` rows → all prior `accepted_risk` /
   `false_positive` decisions are silently orphaned.
2. **`is_latest` / `supersedes_id` anti-pattern.** A linked-list chain on `sbom_documents`
   makes "how many scans exist for this artifact?" awkward and is used inconsistently.
3. **Phase 2b lock-in.** Phase 2b AI workers will reference
   `component_vulnerability_id → sbom_document_id`. Fixing the model *after* 2b ships means
   migrating every AI enrichment table too.

This is a **breaking** schema restructure that must land **before** `themis-phase-2b` so the
AI layer is built on the settled model. It ships as `v0.3.0` together with (but as a separate
change ahead of) Phase 2b.

## What Changes

- **BREAKING — Split `sbom_documents` into `sboms` + `scan_reports`.** `sboms` = composition
  (1 per artifact; Layer 0 immutable inventory). `scan_reports` = one scanner's findings at a
  point in time (N per artifact; ordered by `scanned_at DESC`).
- **BREAKING — Merge `artifacts` + `images` into one `artifacts` table** with
  `image_digest TEXT` **globally UNIQUE** (same digest = same content = same artifact).
- **BREAKING — `version.project_id` (NOT NULL) replaces `version.product_id`.** A default
  project is auto-created on product registration so the single-project case needs no manual
  step. `product_versions` becomes `versions`.
- **BREAKING — Durable-Enrichment Identity Contract.** `risk_context` and the other durable
  Layer-2/3 judgment tables — `triage_history`, `remediation_actions`, `intelligence_signals`
  (and `runtime_exposures`, with its `environment` dimension) — are re-keyed on the stable
  identity `(artifact_id, component_purl, cve_id)` instead of the per-scan
  `component_vulnerability_id`, so triage, remediation status, and enrichment survive rescans.
  Only the raw finding (`component_vulnerabilities`) stays per-scan. This is the triage-persistence
  fix generalized to the whole judgment family, and the clean base Phase 2b's AI tables build on
  (see design D15).
- **BREAKING — Remove `is_latest` and `supersedes_id`.** "Latest scan" =
  `ORDER BY scanned_at DESC LIMIT 1`.
- **FK column renames** (same logic, new target tables): `component_versions.sbom_document_id`
  → `sboms`; `dependency_relationships.sbom_document_id` → `sboms`;
  `component_vulnerabilities.sbom_document_id` → `scan_reports`; `vex_documents.sbom_document_id`
  → `artifacts`.
- **GREENFIELD migration — no data migration / no backfill.** Base migrations `000001–000004`
  are rewritten to the new schema; FK references in `000005–000019` are adjusted. Existing dev
  databases are dropped and re-initialised. No production database is carried across `v0.3.0`.
- **Registration endpoints** (moved here from Phase 1 Group 16, because this change redefines
  both tables): `POST /api/v1/products/{id}/artifacts` (16.4) and
  `POST /api/v1/projects/{id}/versions` (16.10).
- **Unchanged (algorithms):** the entire Phase 2a intelligence *logic* — EPSS/KEV sync,
  ExploitDB, Layer 1 deterministic rules, Layer 2 blast-radius, VEX matching, VEX export — is
  unchanged. The Layer-2/3 tables it writes are re-keyed per the identity contract above, but no
  algorithm changes.
- **Phase 2b is additive on this base:** the AI tables (`ai_summaries`, `ai_cwe_mappings`,
  `ai_exploitability`, `ai_vex_recommendations`, `ai_remediation_advice`, `ai_fp_analysis`) +
  pgvector KB + JobQueue wiring add on top with **zero ALTERs to core-model tables** — the success
  test for "this layer makes everything clean".

## Capabilities

### New Capabilities

- `artifact-registration`: REST registration of artifacts and versions before SBOM upload
  (`POST /api/v1/products/{id}/artifacts`, `POST /api/v1/projects/{id}/versions`), plus
  auto-creation of a default project on product registration.

### Modified Capabilities

- `sbom-store`: the storage model is restructured — `sbom_documents` split into `sboms` +
  `scan_reports`; `artifacts`/`images` merged with a globally-unique `image_digest`;
  `versions.project_id` replaces `product_versions.product_id`; FK columns re-pointed; the
  `is_latest`/`supersedes_id` chain removed.
- `cve-triage`: triage decisions and history persist across rescans because `risk_context` and
  `triage_history` are keyed on artifact-relative identity `(artifact_id, component_purl, cve_id)`
  rather than a per-scan `component_vulnerability_id` (the Durable-Enrichment Identity Contract,
  design D15, which also re-keys `remediation_actions` / `intelligence_signals`).
- `sbom-ingestion`: a single ingest produces one `sboms` row (composition) and one
  `scan_reports` row (the scan), instead of one `sbom_documents` row.
- `sbom-management`: SBOM/scan listing and soft-delete operate over the split model; "latest"
  is derived from `scan_reports.scanned_at DESC` with no `is_latest` flag.

## Impact

- **Migrations:** rewrite `000001–000004`; adjust FK references in `000005–000019` (no data
  mutations — greenfield only).
- **Code (~23 non-test `.go` files):** domain types, store layer (`catalog`, `correlation`,
  `enrichment`, `sbom`, `sbom_management`, `status`, `triage`, `vexexport`, `vulnerability`,
  `watch`), ingestion use case (split insert), `vexgen`/`watch` use cases, API handlers,
  `vexfeed` store, asset-graph blast-radius, DI wiring — FK column/table rename propagation +
  the ingestion split + `risk_context` PK query changes.
- **Durable enrichment re-keying (D15):** `triage_history`, `remediation_actions`,
  `intelligence_signals` (and `runtime_exposures` + `environment`) move off
  `component_vulnerability_id` onto `(artifact_id, component_purl, cve_id)`; their store layers
  and indexes change accordingly. Guarantees Phase 2b's `ai_*` tables are additive (zero ALTERs).
- **Tests (~23+ files):** SQL fixtures referencing `sbom_document_id` / `image_id`;
  `risk_context` store tests for the new PK; enrichment-survives-rescan integration tests (triage
  and remediation status); an additivity assertion; new registration-endpoint tests.
- **API:** additive registration endpoints; SBOM/scan response fields that exposed `is_latest`
  are re-derived. **BREAKING** for any integration that assumed the old table/column shape.
- **Docs:** README registration walkthrough (replaces manual `INSERT INTO images`), reset SQL,
  `PROJECT_CONTEXT.md` data-model section.
- **Gates Phase 2b**; depends on `v0.2.1` already shipped.
