## Implementation order

Migrations (1) → domain types (2) → store layer (3) → ingestion split (4) → registration
endpoints (5) → remaining use-case/adapter FK propagation (6) → API + OpenAPI (7) → tests &
fixtures (8) → docs, gates, release (9). Greenfield: no data migration, no backfill — dev DBs
are dropped and re-initialised. Each group ends with the standard gates (unit tests → coverage
→ dead code → integration tests → clean-arch → `make verify-build`).

---

## 1. Greenfield schema baseline (squash) — D13

- [ ] 1.1 Squash `000001–000019` into a single coherent `v0.3.0` baseline (retire old bodies):
  `products`; `projects`; `versions` (`project_id NOT NULL`, replaces `product_id`); merged
  `artifacts` (`version_id`, `artifact_type`, `image_digest TEXT UNIQUE`; drop `images`)
- [ ] 1.2 `sboms` keyed `UNIQUE (artifact_id, sbom_checksum)` (D9) with `raw_document`,
  composition; `scan_reports` (`sbom_id` FK, denormalized `artifact_id`, `scanner`,
  `scanned_at`, `scan_checksum`, trust/ingestion metadata; no `is_latest`/`supersedes_id`)
- [ ] 1.3 `component_vulnerabilities`: FK `scan_report_id`; **denormalized `component_purl`
  (version-qualified) + `cve_id`** (D11); UNIQUE `(component_version_id, vulnerability_id,
  scan_report_id)`
- [ ] 1.4 `risk_context` primary key `(artifact_id, component_purl, cve_id)` (D3; replaces
  `component_vulnerability_id`); keep `effective_state` + enrichment columns
- [ ] 1.5 Carry surviving Phase 2a tables unchanged (asset graph, epss_kev_signals,
  exploit_records, vex_assertions, triage_history, audit_log, etc.); `vex_documents.artifact_id`
- [ ] 1.6 Add the **schema-skew guard** (D13): startup schema-shape assertion or migrate
  baseline version gap that fails loudly with "re-initialise your database"
- [ ] 1.7 Matching `.down.sql` (greenfield: down = drop); `make migrate-up`/`migrate-down`
  clean on a fresh DB; `make check` passes (`-tags postgres`)

## 2. Domain types

- [ ] 2.1 Rename/split domain types: introduce `Sbom` (composition) and `ScanReport`
  (temporal) where `sbom_documents` types were used; drop `is_latest`/`supersedes_id` fields
- [ ] 2.2 Merge image/artifact domain types into one `Artifact` carrying `ImageDigest`;
  remove the `Image` type and `image_id` indirection
- [ ] 2.3 Update `Version` to carry `ProjectID` (was `ProductID`)
- [ ] 2.4 Update `RiskContext` identity to `(ArtifactID, ComponentPURL, CVEID)`
- [ ] 2.5 `make clean-arch` + `make check` pass; `domain/` coverage stays 100%

## 3. Store layer — FK renames, latest-scan, risk_context PK

- [ ] 3.1 Re-point FK columns in store queries across `catalog`, `correlation`, `enrichment`,
  `sbom`, `status`, `vulnerability`, `watch`, `vexexport` (`sbom_document_id` → `sboms` /
  `scan_reports` per table; `image_id` → `artifacts.image_digest`)
- [ ] 3.2 Add a **single shared latest-scan filter** (helper or SQL view `v_latest_findings`)
  defining "current findings" = `component_vulnerabilities` of the latest `scan_reports` (D10);
  replace all `is_latest` / `supersedes_id` reads with it
- [ ] 3.3 **Audit every findings-bearing read path** (`status`, `sbom_management`, `vexexport`,
  `blast_radius`, scan detail) to route through the shared filter — no ad-hoc per-query joins;
  add a regression test asserting an N-times-rescanned artifact is not N×-counted (H2)
- [ ] 3.4 Rewrite `risk_context` upsert/read to key on the denormalized
  `(artifact_id, component_purl, cve_id)` (`triage`, `enrichment`)
- [ ] 3.5 Update `vexfeed/store.go` + `assetgraph/blast_radius.go` FK traversal
- [ ] 3.6 `adapter/store/` coverage ≥ 90%; `make check` passes

## 4. Ingestion use case — split insert + idempotency

- [ ] 4.1 Split the single `sbom_documents` insert into: upsert one `sboms` row per
  `(artifact_id, sbom_checksum)` (D9; create-or-reuse) + create one `scan_reports` row for the
  correlation run
- [ ] 4.2 Link `component_versions`/`dependency_relationships` to `sboms`;
  `component_vulnerabilities` to the new `scan_reports` row, **writing the denormalized
  version-qualified `component_purl` + `cve_id`** at correlation (D11)
- [ ] 4.3 Resolve `risk_context` writes to the `(artifact_id, component_purl, cve_id)` identity
  during enrichment
- [ ] 4.4 **Idempotency (D12):** an identical re-submission matching `(sbom_id, scan_checksum)`
  (and any honored `Idempotency-Key`) returns the existing `scan_report` — no duplicate scan, no
  re-correlation; only a genuine new correlation appends
- [ ] 4.5 Update `usecase/ingestion/{service,async}.go`; `usecase/ingestion/` coverage at
  target; `make check` passes

## 5. Registration endpoints + auto-default-project

- [ ] 5.1 Auto-create a default project on `POST /api/v1/products` (idempotent; reused, not
  duplicated)
- [ ] 5.2 `POST /api/v1/projects/{id}/versions` — create a `versions` row under a project
  (16.10); `PROJECT_NOT_FOUND` on missing project; conflict on duplicate version
- [ ] 5.3 `POST /api/v1/products/{id}/artifacts` — register an artifact by `image_digest`
  (16.4); duplicate digest maps to the existing artifact
- [ ] 5.4 Ingestion integrity check resolves a registered artifact without a manual SQL insert
- [ ] 5.5 `make check` passes

## 6. Remaining use-case / adapter FK propagation

- [ ] 6.1 `usecase/vexgen/service.go`, `usecase/watch/service.go` — FK traversal to new tables
- [ ] 6.2 `adapter/vexfeed/service.go` re-enrichment paths point at `scan_reports` / artifacts
- [ ] 6.3 `infrastructure/http/api_wiring.go` DI updates for any changed constructors
- [ ] 6.4 `make clean-arch` + `make check` pass

## 7. API handlers + OpenAPI

- [ ] 7.1 `handlers_sbom.go` — derive `is_latest` from latest `scan_reports`; expose
  scan/sbom split where responses referenced `sbom_documents`
- [ ] 7.2 Add OpenAPI paths/schemas for the artifact + version registration endpoints; mappers
- [ ] 7.3 Regenerate API stubs (`make generate-api`); mapper unit tests
- [ ] 7.4 `adapter/api/` coverage at target; `make check` passes

## 8. Tests, fixtures, integration coverage

- [ ] 8.1 Update SQL fixtures referencing `sbom_document_id` / `image_id` (~23 test files)
- [ ] 8.2 `risk_context` store tests for the new `(artifact_id, component_purl, cve_id)` PK,
  incl. the distinct-versions case (busybox 1.35 vs 1.36 are distinct identities — H3/D11)
- [ ] 8.3 Integration test: **triage survives a rescan** — triage a finding, re-correlate the
  same artifact, assert `effective_state` is retained without re-triage
- [ ] 8.4 Integration test: **latest-scan counts** — rescan an artifact N times, assert status
  counts reflect only the latest scan, not N× (H2/D10)
- [ ] 8.5 Integration test: **idempotent re-submission** — identical re-upload returns the
  existing scan, no duplicate `scan_reports` (H4/D12)
- [ ] 8.6 Integration test: **divergent SBOM** — a second SBOM with a different checksum for the
  same artifact creates a new `sboms` row, findings not orphaned (H1/D9)
- [ ] 8.7 Integration tests for the registration endpoints (artifact + version, incl.
  duplicate-digest and `PROJECT_NOT_FOUND`)
- [ ] 8.8 Integration test: **schema-skew guard** — an old-schema DB fails startup loudly (H5/D13)
- [ ] 8.9 Phase 1 acceptance + AC-16..24 Phase 2a suites pass unchanged against the new schema
- [ ] 8.10 Integration tests + full coverage gate pass with `THEMIS_DATABASE_DSN` set

## 9. Docs, gates, release

- [ ] 9.1 README: replace the manual `INSERT INTO images/artifacts` walkthrough with the
  registration endpoints; update the reset/full-wipe SQL for the new tables
- [ ] 9.2 `PROJECT_CONTEXT.md` data-model section: `sboms` + `scan_reports`, merged
  `artifacts`, `versions.project_id`, `risk_context` identity PK
- [ ] 9.3 Note in README/startup docs that upgrading a populated pre-`v0.3.0` DB requires
  re-initialisation (no in-place migration)
- [ ] 9.4 `make verify-build` (`make clean && make all`) passes on the full repo
- [ ] 9.5 Update `scripts/check-coverage.sh` if package coverage targets shift
- [ ] 9.6 Coordinate with `themis-phase-2b` (this change merges first under the `v0.3.0` line);
  do not tag `v0.3.0` until Phase 2b is ready
