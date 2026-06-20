## Implementation order

Migrations (1) → domain types (2) → store layer (3) → ingestion split (4) → registration
endpoints (5) → remaining use-case/adapter FK propagation (6) → API + OpenAPI (7) → tests &
fixtures (8) → docs, gates, release (9). Greenfield: no data migration, no backfill — dev DBs
are dropped and re-initialised. Each group ends with the standard gates (unit tests → coverage
→ dead code → integration tests → clean-arch → `make verify-build`).

---

## 1. Greenfield schema baseline (squash) — D13

- [x] 1.1 Squash `000001–000019` into a single coherent `v0.3.0` baseline (retire old bodies):
  `products`; `projects`; `versions` (`project_id NOT NULL`, replaces `product_id`); merged
  `artifacts` (`version_id`, `artifact_type`, `image_digest TEXT UNIQUE`; drop `images`)
- [x] 1.2 `sboms` keyed `UNIQUE (artifact_id, sbom_checksum)` (D9) with `raw_document`,
  composition; `scan_reports` (`sbom_id` FK, denormalized `artifact_id`, `scanner`,
  `scanned_at`, `scan_checksum`, trust/ingestion metadata; no `is_latest`/`supersedes_id`)
- [x] 1.3 `component_vulnerabilities`: FK `scan_report_id`; **denormalized `component_purl`
  (version-qualified) + `cve_id`** (D11); UNIQUE `(component_version_id, vulnerability_id,
  scan_report_id)`
- [x] 1.4 `risk_context` primary key `(artifact_id, component_purl, cve_id)` (D3; replaces
  `component_vulnerability_id`); keep `effective_state` + enrichment columns
- [x] 1.4a **Durable-Enrichment Identity Contract (D15):** re-key `triage_history`,
  `remediation_actions`, `intelligence_signals` on `(artifact_id, component_purl, cve_id)` and
  `runtime_exposures` on `(artifact_id, component_purl, cve_id, environment)`; drop their
  `component_vulnerability_id` FK/indexes. Only `component_vulnerabilities` stays per-scan.
- [x] 1.5 Carry the genuinely unchanged Phase 2a tables (asset graph, epss_kev_signals,
  exploit_records, vex_assertions, audit_log, system_state, etc.); `vex_documents.artifact_id`
- [x] 1.6 Add the **schema-skew guard** (D13): startup schema-shape assertion or migrate
  baseline version gap that fails loudly with "re-initialise your database"
- [x] 1.7 Matching `.down.sql` (greenfield: down = drop); verified on Postgres 18 — `make
  migrate-up` applies the baseline; `migrate down 1` drops to 0 tables; re-`up` restores 33
  objects (31 tables + `v_latest_findings` + `schema_migrations`). `make migrate-up`/`migrate-down`
  clean on a fresh DB; `make check` passes (`-tags postgres`)

## 2. Domain types

- [x] 2.1 Rename/split domain types: introduce `Sbom` (composition) and `ScanReport`
  (temporal) where `sbom_documents` types were used; drop `is_latest`/`supersedes_id` fields
- [x] 2.2 Merge image/artifact domain types into one `Artifact` carrying `ImageDigest`;
  remove the `Image` type and `image_id` indirection
- [x] 2.3 Update `Version` to carry `ProjectID` (was `ProductID`)
- [x] 2.4 Update `RiskContext` identity to `(ArtifactID, ComponentPURL, CVEID)`
- [x] 2.5 `make clean-arch` passes and `domain/` coverage stays 100% (full repo green after
  Group 8 — `make verify-build` + `make coverage` pass).

> **Progress note:** `go build ./...` is **green end-to-end on the new model** — all
> production store/use-case/adapter code compiles, `make clean-arch` passes, `gofmt` clean,
> `domain` tests pass at 100%. Groups 3, 3b, 4, 6 are code-complete; the `v_latest_findings`
> view (D10) centralizes the latest-scan filter; findings/`risk_context` key on the
> **version-qualified** PURL (`domain.VersionedPURL`, D11) while display paths keep the
> versionless `components.purl`. **Done since:** Group 5 (registration endpoints), Group 9
> (docs), and Group 7 (OpenAPI `image_id`→`artifact_id` / version `product_id`→`project_id`
> renames in the spec, regenerated stubs with pinned `oapi-codegen@v2.7.1`, stop-gaps removed;
> registration endpoints kept as Phase-2a manual routes documented in the README).
> **Only Group 8 remains** — all `_test.go` fixtures/fakes are broken against the new interfaces
> (the large DB-gated job); `make verify-build`/`make check`, the per-group coverage gates, the
> new identity/idempotency/latest-scan integration tests, and task 1.7 `migrate-up` all gate
> here. Production `go build ./...` + `make clean-arch` are green; no residual old-schema SQL.

## 3. Store layer — FK renames, latest-scan, risk_context PK

- [x] 3.1 Re-point FK columns in store queries across `catalog`, `correlation`, `enrichment`,
  `sbom`, `status`, `vulnerability`, `watch`, `vexexport` (`sbom_document_id` → `sboms` /
  `scan_reports` per table; `image_id` → `artifacts.image_digest`)
- [x] 3.2 Add a **single shared latest-scan filter** (SQL view `v_latest_findings`)
  defining "current findings" = `component_vulnerabilities` of the latest `scan_reports` (D10);
  replaced all `is_latest` / `supersedes_id` reads with it
- [x] 3.3 Routed `status`, `sbom_management`, `vexexport`, `blast_radius`, scan detail through
  the shared filter — no ad-hoc per-query joins. (Regression test asserting N-rescan ≠ N×-count
  is in Group 8 / 8.4.)
- [x] 3.4 Rewrite `risk_context` upsert/read to key on the denormalized
  `(artifact_id, component_purl, cve_id)` (`triage`, `enrichment`)
- [x] 3.5 Update `vexfeed/store.go` + `assetgraph/blast_radius.go` FK traversal
- [x] 3.6 `adapter/store/` coverage ≥ 90% (90.4%) and the store integration gate passes against
  embedded Postgres (Group 8).

## 3b. Durable enrichment store layer — re-key on stable identity (D15)

- [x] 3b.1 Rewrite `triage` store reads/writes for `triage_history` keyed on
  `(artifact_id, component_purl, cve_id)`; "history for a finding" resolves by identity, not by
  per-scan `component_vulnerability_id`
- [x] 3b.2/3b.3/3b.4 `remediation_actions`, `intelligence_signals`, `runtime_exposures` re-keyed
  on the stable identity **in the schema (migration 1.4a)**; they have **no Go store code yet**
  (Phase 2b populates them), so there is nothing further to rewrite at this layer — the contract
  is established by the migration.
- [x] 3b.5 **Additivity assertion** — implemented as `TestCoreModelAdditivityAttachesToLatestFinding`
  (8.3a): an identity-keyed `ai_*`-shaped table joins to `v_latest_findings` with no core-model ALTER.
- [x] 3b.6 `make coverage` / store coverage — pass (Group 8).

## 4. Ingestion use case — split insert + idempotency

- [x] 4.1 Split the single `sbom_documents` insert into: upsert one `sboms` row per
  `(artifact_id, sbom_checksum)` (D9; create-or-reuse) + create one `scan_reports` row for the
  correlation run (`store/sbom.go` `SaveSBOM` → `SaveSBOMResult`)
- [x] 4.2 Link `component_versions`/`dependency_relationships` to `sboms`;
  `component_vulnerabilities` to the new `scan_reports` row, **writing the denormalized
  version-qualified `component_purl` (`domain.VersionedPURL`) + `cve_id`** at correlation (D11)
- [x] 4.3 Resolve `risk_context` writes to the `(artifact_id, component_purl, cve_id)` identity
  during enrichment; enrichment runs on the artifact's latest scan
- [x] 4.4 **Idempotency (D12):** identical re-submission matching `(sbom_id, scan_checksum)`
  returns the existing `scan_report` (Duplicate=true) — no duplicate scan, no re-correlation
- [x] 4.5 `usecase/ingestion/{service,async}.go` updated; `usecase/ingestion` coverage back to
  100% (Group 8 added the `Duplicate`/VEX-enrichment-unavailable branch tests).

## 5. Registration endpoints + auto-default-project

- [x] 5.1 Auto-create a default project on `POST /api/v1/products` (idempotent; `ensureDefaultProject`
  uses `ON CONFLICT (product_id, name) DO NOTHING`-style reuse, never duplicated)
- [x] 5.2 `POST /api/v1/projects/{id}/versions` — create a `versions` row under a project
  (16.10); `PROJECT_NOT_FOUND` (404) on missing project; `VERSION_CONFLICT` (409) on duplicate
- [x] 5.3 `POST /api/v1/products/{id}/artifacts` — register an artifact by `image_digest`
  (16.4); duplicate digest returns the existing artifact (digest globally unique)
- [x] 5.4 Ingestion integrity check resolves a registered artifact (`trust.ImageDigestExists`
  now queries `artifacts.image_digest`) — no manual SQL insert needed
- [x] 5.5 Gates pass — registration endpoints covered by `TestCoreModelRegistrationEndpoints` +
  the http integration suites (Group 8). Routes are wired manually (like the Phase 2a endpoints);
  OpenAPI spec entries for them landed in Group 7.

## 6. Remaining use-case / adapter FK propagation

- [x] 6.1 `usecase/vexgen/service.go`, `usecase/watch/service.go` — FK traversal to new tables
  (assertions keyed by artifact; watch findings against the latest scan with version-qualified purl)
- [x] 6.2 `adapter/vexfeed/store.go` re-enrichment paths point at artifacts (`v_latest_findings`);
  `vex_documents.artifact_id`; re-enrich enqueues artifact ids → `ApplyVEX(artifactID)`
- [x] 6.3 `infrastructure/http/api_wiring.go` + `usecase/ingestion/async.go` compile against the
  new constructors/signatures (apply-vex job carries an artifact id)
- [x] 6.4 `make clean-arch` and the full test/coverage gates pass (Group 8).

## 7. API handlers + OpenAPI

- [x] 7.1 `handlers_sbom.go` — `is_latest` is derived in the store from `scan_reports.scanned_at
  DESC` and surfaced as `item.IsLatest`; scan responses read from `scan_reports`/`sboms`
- [x] 7.2 OpenAPI field renames in `api/openapi.yaml`: `image_id` → `artifact_id` (upload,
  `SBOMUploadRequest`, `WebhookScanRequest`); `ProductVersion.product_id` → `project_id` (only
  that schema — `Project`/`Microservice`/query-param `product_id` left intact). Registration
  endpoints stay **manual routes** (Phase-2a convention; documented in the README) rather than
  generated, to avoid a `gen.ServerInterface` conflict.
- [x] 7.3 Regenerated stubs with `make generate-api` (pinned `oapi-codegen@v2.7.1` — the version
  that produced the committed `api.gen.go` — to avoid drift; diff = the 4 field renames + the
  embedded-spec blob, no signature changes). Removed the stop-gaps in `handlers_ingestion.go`
  (`req.ArtifactId`) and `mappers.go` (`ProjectId`). `go build ./...` + `make clean-arch` pass.
- [x] 7.4 `adapter/api/` coverage passes its threshold (80.3% ≥ 80%); mapper + handler tests run
  green against the final gen types (Group 8).

## 8. Tests, fixtures, integration coverage

> **Progress (complete):** Group 8 done — **unit + integration suites green** (`go test ./...`
> and `go test -tags integration ./...`), and the **full coverage gate passes** (`make coverage`:
> every package at/above threshold; `usecase/ingestion` back to 100%, `infrastructure/db` 91.8%,
> `adapter/store` 90.4%). The last broken old-schema fixtures (http `api_integration`/
> `e2e_acceptance` and the trust-gate `vex_documents` insert) were moved to the v0.3.0 chain —
> http e2e now registers artifacts via `POST /products/{id}/artifacts` and uploads with
> `artifact_id`; the orphaned `sbom_filter_test.go` (its production file was deleted) was removed.
> The new invariant tests live in `internal/adapter/store/coremodel_integration_test.go` (8.2–8.7)
> and `internal/infrastructure/db/database_embedded_test.go` (8.8); `make clean-arch` and
> `make verify-build` are green. The per-group gate list for this change (unit → coverage →
> deadcode → integration → clean-arch → verify-build) all pass; `make deadcode` reports only the
> 3 pre-existing `enrichment.NoOpMetricsRecorder` methods (not introduced here).

- [x] 8.1 Update SQL fixtures referencing `sbom_document_id` / `image_id` — **done** across unit
  and integration tests. Shared integration seed helpers (`seedScan`/`addFinding`/`seedFinding`)
  added; all store integration files (ingestion, vexfeed, epsskev, exploitdb, layer1,
  blast_radius, v0_2_1, vexexport, sbom_management, triage, watch, catalog) + trust gate + the
  http `api_integration`/`e2e_acceptance` suites re-authored to `sboms`+`scan_reports`/
  identity-keyed `risk_context`. Store + http + trust integration suites green against Postgres 18.
- [x] 8.2 `risk_context` store tests for the new `(artifact_id, component_purl, cve_id)` PK,
  incl. the distinct-versions case (busybox 1.35 vs 1.36 are distinct identities — H3/D11).
  `TestCoreModelRiskContextDistinctVersions`: 2 distinct identities, PK upsert collapses a
  re-write, triaging one version leaves the other `detected`.
- [x] 8.3 Integration test: **durable enrichment survives a rescan** — triage a finding and set a
  `remediation_actions` row to `in_progress`, re-correlate the same artifact (byte-distinct SBOM →
  new `scan_report`), assert the human decision (not `detected`), triage-history continuity, and
  the `in_progress` remediation are all retained without recomputation (D15).
  `TestCoreModelDurableEnrichmentSurvivesRescan`.
- [x] 8.3a Test: **additivity assertion** — a representative `ai_*`-shaped table keyed on
  `(artifact_id, component_purl, cve_id)` attaches and joins to the latest-scan finding
  (`v_latest_findings`) with no ALTER to any core-model table (proves the Phase 2b base is clean,
  D15). `TestCoreModelAdditivityAttachesToLatestFinding`.
- [x] 8.4 Integration test: **latest-scan counts** — rescan an artifact N times, assert
  `v_latest_findings` and the status repo reflect only the latest scan, not N× (H2/D10).
  `TestCoreModelLatestScanCounts`.
- [x] 8.5 Integration test: **idempotent re-submission** — identical re-upload returns the
  existing scan, no duplicate `scan_reports` (H4/D12). `TestCoreModelIdempotentResubmission`;
  also the unit `TestPipelineSBOMSaveDuplicate` covers the store-level `Duplicate` branch.
- [x] 8.6 Integration test: **divergent SBOM** — a second SBOM with a different checksum for the
  same artifact creates a new `sboms` row, earlier scan's findings not orphaned (H1/D9).
  `TestCoreModelDivergentSBOM`.
- [x] 8.7 Integration tests for the registration endpoints (artifact + version, incl.
  duplicate-digest, `PROJECT_NOT_FOUND`, `VERSION_CONFLICT`). `TestCoreModelRegistrationEndpoints`
  (store layer) + the http `api_integration`/`e2e_acceptance` suites exercise the REST routes.
- [x] 8.8 Integration test: **schema-skew guard** — a database carrying a legacy pre-v0.3.0 table
  fails `VerifySchemaShape` loudly with the "re-initialise your database" guidance (H5/D13).
  Extended `TestConnectRunMigrationsAndVerify`.
- [x] 8.9 Phase 1 acceptance + AC-16..24 Phase 2a suites pass unchanged against the new schema
  (`tests/acceptance` + all Phase 2a store/api integration suites green under `-tags integration`).
- [x] 8.10 Integration tests + full coverage gate pass (`make coverage` — embedded Postgres, or
  `THEMIS_TEST_DATABASE_DSN`/`THEMIS_DATABASE_DSN` for external Postgres): all package thresholds
  satisfied.

## 9. Docs, gates, release

- [x] 9.1 README: replaced the manual `INSERT INTO images/artifacts` walkthrough with the
  `POST /products/{id}/artifacts` registration endpoint; updated the reset/full-wipe SQL for
  the `scan_reports`/`sboms` split + identity-keyed judgment tables; fixed troubleshooting rows
- [x] 9.2 `PROJECT_CONTEXT.md` data-model section: `sboms` + `scan_reports`, merged
  `artifacts`, `versions.project_id`, `risk_context` identity PK; migrations table → squashed
  `000001_v030_baseline` + schema-skew guard
- [x] 9.3 Note in README (Full database reset) + `PROJECT_CONTEXT.md` that upgrading a populated
  pre-`v0.3.0` DB requires re-initialisation (no in-place migration; guard refuses startup)
- [x] 9.4 `make verify-build` (`make clean && make all`) — green (clean rebuild of the whole repo);
  unit + integration suites and `make coverage` all pass.
- [x] 9.5 `scripts/check-coverage.sh` — no package targets shifted (no new packages); store/api
  coverage hold their thresholds against the v0.3.0 schema (store 90.4%, api 80.3%), no
  re-baselining needed.
- [ ] 9.6 Coordinate with `themis-phase-2b` (this change merges first under the `v0.3.0` line);
  do not tag `v0.3.0` until Phase 2b is ready
