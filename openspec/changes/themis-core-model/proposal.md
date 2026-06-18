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
- **BREAKING — `risk_context` primary key becomes `(artifact_id, component_purl, cve_id)`**
  instead of `component_vulnerability_id`. Identity-based, so triage decisions survive
  rescans. This is the triage-persistence fix.
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
- **Unchanged:** the entire Phase 2a intelligence layer — EPSS/KEV sync, ExploitDB, Layer 1
  deterministic rules, Layer 2 blast-radius, VEX matching, VEX export. Only FK traversal
  (column names / target tables) is updated; no algorithm changes.

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
- `cve-triage`: triage decisions persist across rescans because `risk_context` is keyed on
  artifact-relative identity `(artifact_id, component_purl, cve_id)` rather than a per-scan
  `component_vulnerability_id`.
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
- **Tests (~23+ files):** SQL fixtures referencing `sbom_document_id` / `image_id`;
  `risk_context` store tests for the new PK; new registration-endpoint tests; triage-survives-
  rescan integration test.
- **API:** additive registration endpoints; SBOM/scan response fields that exposed `is_latest`
  are re-derived. **BREAKING** for any integration that assumed the old table/column shape.
- **Docs:** README registration walkthrough (replaces manual `INSERT INTO images`), reset SQL,
  `PROJECT_CONTEXT.md` data-model section.
- **Gates Phase 2b**; depends on `v0.2.1` already shipped.
