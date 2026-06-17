## Implementation order

Groups must be completed in this sequence due to compile-time dependencies:

17 → 18 → 19.0 (config) → 19 / 20 / 21 (parallel) → 22 → 23 → 24 → 25 / 26 (parallel) → 27 / 28 (parallel) → 29 → 30

Groups 19, 20, 21 can proceed in parallel once 17 and 18 are done.
Groups 25 and 26 can proceed in parallel once 22 and 23 are done.
Groups 27 and 28 can proceed in parallel once 18 is done.

---

## 17. Domain layer — new entities and ports

- [x] 17.1 Add `Microservice`, `Deployment`, `Customer`, `ExploitRecord` domain types to `internal/domain/`
- [x] 17.2 Add `ThreatSignalFetcher`, `ExploitSource`, `GraphStore` port interfaces to `internal/domain/ports.go`
- [x] 17.3 Add `EffectiveStateNotAffected = "not_affected"` constant to `internal/domain/enrichment.go`
  alongside existing `EffectiveState*` constants (`VEXStatusNotAffected` already exists but is a
  different field; a distinct `EffectiveState` constant is needed for vendor VEX writes)
- [x] 17.4 Add new job type constants to `internal/domain/ports.go`:
  - `JobTypeReEnrichSignals = "reenrich_signals"` — triggered by EPSS/KEV and ExploitDB syncs
  - `JobTypeSyncVEXFeed     = "sync_vex_feed"` — triggered by vendor VEX scheduler
  (distinct from existing `JobTypeReenrichVEX` which re-applies user VEX documents)
- [x] 17.5 Add Phase 2a risk score formula constants and `DeterministicLevel` type to `internal/domain/`
- [x] 17.6 Add `upstream_vex_coverage` enum type (`covered`, `not_covered`, `purl_mismatch`) to domain
- [x] 17.7 Unit tests: all new domain types; coverage `domain/` = 100%
- [x] 17.8 `make clean-arch` passes; `make check` passes

## 18. Database migrations

- [x] 18.1 Migration `000014` — create `microservices`, `deployments`, `customers` tables
- [x] 18.2 Migration `000014` — create `asset_graph_nodes`, `asset_graph_edges` tables; create `exploit_records` table
- [x] 18.3 Migration `000015` — create `epss_kev_signals` table keyed by `cve_id`:
  ```sql
  CREATE TABLE epss_kev_signals (
    cve_id       TEXT PRIMARY KEY,
    epss_score   NUMERIC(6,5),
    kev_listed   BOOLEAN NOT NULL DEFAULT FALSE,
    fetched_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    stale        BOOLEAN NOT NULL DEFAULT FALSE
  );
  ```
  NOTE: The existing `intelligence_signals` table (migration 000006) uses a
  different generic schema keyed by `component_vulnerability_id`. Phase 2a uses
  `epss_kev_signals` as a separate, purpose-built table keyed by `cve_id`.
- [x] 18.4 Migration `000016` — add Phase 2a columns to `risk_context`:
  ```sql
  ALTER TABLE risk_context
    ADD COLUMN epss_score          NUMERIC(6,5),
    ADD COLUMN kev_listed          BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN exploit_public      BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN deterministic_level TEXT,
    ADD COLUMN blast_radius_score  NUMERIC(4,2) NOT NULL DEFAULT 1.0,
    ADD COLUMN upstream_vex_coverage TEXT
      CHECK (upstream_vex_coverage IN ('covered','not_covered','purl_mismatch'));
  ```
  Also add `not_affected` to `effective_state` CHECK constraint (needed for vendor VEX):
  ```sql
  ALTER TABLE risk_context DROP CONSTRAINT risk_context_effective_state_check;
  ALTER TABLE risk_context ADD CONSTRAINT risk_context_effective_state_check
    CHECK (effective_state IN (
      'detected','suppressed','confirmed','in_triage',
      'accepted_risk','false_positive','resolved','not_affected'
    ));
  ```
- [x] 18.5 Migration `000017` — add indexes on `risk_context(epss_score, kev_listed)`;
  composite index `asset_graph_edges(from_node_id, edge_type)`
- [x] 18.6 Migration `000018` — add `sbom_documents.deleted_at TIMESTAMPTZ DEFAULT NULL`;
  partial index `idx_sbom_documents_active WHERE deleted_at IS NULL`
- [x] 18.7 Apply migrations locally; confirm `make verify-build` passes with new schema
- [x] 18.8 Register `adapter/store/` in `scripts/check-coverage.sh` (threshold ≥ 90%); confirm gate passes

## 19. EPSS + KEV adapter

- [x] 19.0 Add Phase 2a config sections (see design.md config key table for exact struct definitions):
  - `config.go`: add `EPSSKevConfig`, `ExploitDBConfig`, `VEXFeedConfig`, `IntelligenceConfig`,
    `LogConfig`, `GitHubConfig` structs; add fields to top-level `Config` struct
  - `config.go`: add defaults in `Default()` (all feeds default to public URLs, poll_interval=24h,
    blast_radius_cap=10, log.level=info)
  - `load.go`: add env var overrides in `applyEnvOverrides()` following the existing pattern:
    `THEMIS_EPSSKEV_EPSS_URL`, `THEMIS_EPSSKEV_KEV_URL`, `THEMIS_EPSSKEV_POLL_INTERVAL`,
    `THEMIS_EXPLOITDB_CSV_URL`, `THEMIS_EXPLOITDB_POLL_INTERVAL`,
    `THEMIS_VEXFEED_RHEL_URL`, `THEMIS_VEXFEED_ALPINE_OSV_URL`,
    `THEMIS_VEXFEED_ROCKY_OSV_URL`, `THEMIS_VEXFEED_WOLFI_OSV_URL`,
    `THEMIS_VEXFEED_POLL_INTERVAL`, `THEMIS_INTELLIGENCE_BLAST_RADIUS_CAP`,
    `THEMIS_LOG_LEVEL`, `THEMIS_GITHUB_TOKEN`
  - `load.go`: use `durationFromEnv` for all `poll_interval` fields (helper already exists)
  - `internal/infrastructure/http/logger.go`: read `cfg.Log.Level` at startup; switch log
    verbosity (debug emits per-PURL normalisation attempts and Layer 1 rule firings)
  - `config_test.go`: add unit tests for all new env var overrides and `Default()` values
- [x] 19.1 Implement `internal/adapter/epsskev/` satisfying `ThreatSignalFetcher` port;
  EPSS gzipped CSV parser (decompress `Content-Encoding: gzip` or `.csv.gz`) + CISA KEV JSON parser
- [x] 19.2 `epss_kev_signals` table upsert with `fetched_at`, `stale` flag, and TTL logic
  (not the generic `intelligence_signals` table — see migration 000015)
- [x] 19.3 Daily `time.NewTicker`-based scheduler in `internal/infrastructure/http/`
  (follow `StartWatchScheduler` pattern); wired in `api_wiring.go`; reads `EPSSKevConfig.PollInterval`
- [x] 19.4 `ReEnrichJob` enqueued after each successful sync (max 500 findings per batch)
- [x] 19.5 Stale flag set on `risk_context` after 25 hours without successful sync
- [x] 19.6 Unit tests: EPSS CSV parse, KEV JSON parse, upsert idempotency, stale TTL logic
- [x] 19.7 Unit test: KEV removal — CVE present in last sync but absent in current feed → `kev_listed` set to `false`
- [x] 19.8 Unit test (FR2): EPSS CSV returns < 50% of previous row count → sync aborted; prior data preserved; WARNING logged
- [x] 19.9 Unit test (FR1): EPSS endpoint returns HTTP 500 × 3 → retry exhausted; previous data unchanged; no panic
- [x] 19.10 Unit test (FR8): mock time advance past 25h TTL → `epss_kev_signals.stale = true` (status API wiring deferred to group 27)
- [x] 19.11 Integration test (AC-16): ingest SBOM with DETECTED finding; run KEV sync adding that CVE; confirm `risk_score` increased and `kev_listed = true` without re-ingesting SBOM
- [x] 19.12 Integration test: ReEnrichJob batch cap — seed 1200 open findings; trigger EPSS sync; confirm 3 separate batches of ≤ 500 enqueued
- [x] 19.13 Register `adapter/epsskev/` in coverage script (≥ 90%); `make clean-arch` passes

## 20. ExploitDB adapter

- [x] 20.1 Implement `internal/adapter/exploitdb/` satisfying `ExploitSource` port; `files_exploits.csv` fetcher + parser
- [x] 20.2 `exploit_records` upsert (deduplicated by `edb_id`) with `cve_id`, `exploit_type`, `published_date`, `title`
- [x] 20.3 Daily cron scheduler wired in `cmd/themis/main.go` (`exploitdb.sync_schedule` config key)
- [x] 20.4 `ExploitPublic` boolean derived from `exploit_records` existence; `ReEnrichJob` triggered after new records added
- [x] 20.5 Unit tests: CSV parse, upsert idempotency, ExploitPublic derivation
- [x] 20.6 Unit test: CVE field empty in a CSV row → `edb_id` stored, `cve_id = NULL`, no ExploitPublic signal emitted
- [x] 20.7 Unit test: multiple EDB-IDs for same CVE → all stored; `exploit_public = true` (any match is sufficient)
- [x] 20.8 Unit test (FR4): CSV fetch returns 0 rows → existing `exploit_records` unchanged; WARNING logged; no rows deleted
- [x] 20.9 Integration test: ExploitDB sync sets `exploit_public = true` on matching findings
- [x] 20.10 Integration test: ExploitPublic retroactive — pre-existing DETECTED finding updated after sync adds EDB record
- [x] 20.11 Register `adapter/exploitdb/` in coverage script (≥ 90%); `make clean-arch` passes

## 21. Asset graph store and registration APIs

- [x] 21.1 Implement `internal/adapter/assetgraph/` satisfying `GraphStore` port; SQL write operations (insert node + edges)
- [x] 21.2 `POST /api/v1/products/{id}/microservices` handler — create Microservice + graph node + Product→Microservice edge
- [x] 21.3 `POST /api/v1/microservices/{id}/deployments` handler — create Deployment + graph edges (Microservice→Deployment, Deployment→Customer)
- [x] 21.4 `POST /api/v1/customers` handler — create Customer + graph node
- [x] 21.5 Unit tests: node/edge creation, duplicate detection (409 response)
- [x] 21.6 Integration test: register product → microservice → deployment → customer; confirm graph edges present
- [x] 21.7 Register `adapter/assetgraph/` in coverage script (≥ 90%); `make clean-arch` passes

## 22. Layer 1 deterministic rule engine

- [x] 22.0 Add Layer 3 nil-safe no-op stub to `internal/usecase/enrichment/` per design D1:
  a `Layer3Enricher` interface with a single `Enrich(ctx, finding) error` method and a
  `NoOpLayer3{}` implementation that returns nil; wire it into `Handler` so Phase 2b can
  activate it by swapping the implementation without touching `service.go`
- [x] 22.1 Implement rule table in `internal/usecase/enrichment/` as a pure function (no I/O); write `risk_context.deterministic_level`
- [x] 22.2 Wire Layer 1 into the sync enrichment path so it runs before `202 Accepted` is returned
- [x] 22.3 Unit tests (table-driven, 100% branch coverage) — all rule conditions plus boundary values:
  - `TestRule_CriticalKEV`: CVSS 9.1 + KEV → Critical
  - `TestRule_CriticalExploit`: CVSS 9.1 + ExploitPublic (no KEV) → High+
  - `TestRule_HighKEVLowCVSS`: CVSS 5.0 + KEV → High
  - `TestRule_ElevatedEPSS`: CVSS 7.5 + EPSS 0.6 → Elevated
  - `TestRule_HighFloor`: CVSS 9.1, no other signals → High
  - `TestRule_Informational`: CVSS 4.0, no signals → Informational
  - `TestRule_BoundaryCVSS9_0`: CVSS exactly 9.0 → High (boundary inclusive)
  - `TestRule_BoundaryCVSS8_9`: CVSS 8.9 + KEV → High (KEV rule, not CVSS≥9 branch)
  - `TestRule_EPSS_0_499`: CVSS 7.0 + EPSS 0.499 → Informational (just below threshold)
  - `TestRule_EPSS_0_5`: CVSS 7.0 + EPSS 0.5 → Elevated (on threshold)
  - `TestRule_AllSignals`: CVSS 9.5 + KEV + ExploitPublic + EPSS 0.9 → Critical (first-rule-wins)
  - `TestRule_NullEPSS`: CVSS 7.0 + EPSS NULL → Informational (NULL treated as 0.0)
- [x] 22.4 Integration test (AC-20): ingest SBOM → `202 Accepted` → immediate query shows `deterministic_level` non-null on every finding
- [x] 22.5 `make clean-arch` passes; `make check` passes

## 23. Layer 2 graph blast-radius traversal

- [x] 23.1 Implement recursive CTE blast-radius query in `internal/adapter/assetgraph/` (depth ≤ 7, returns Customer IDs)
- [x] 23.2 Blast-radius score computation: 1 Customer = 1.0×; linear scale; cap 2.0× at 10+ Customers
- [x] 23.3 Wire Layer 2 into sync enrichment path so `blast_radius_score` and `affected_teams[]` are written before `202 Accepted`
- [x] 23.4 Team notification events enqueued deterministically in Layer 2
- [x] 23.5 `GET /api/v1/products/{id}/blast-radius` handler returning blast radius + affected team list
- [x] 23.6 Unit tests — multiplier scale, cap, dedup, depth limit:
  - `TestBlastRadius_NoGraph`: no Microservice/Deployment nodes → score 1.0
  - `TestBlastRadius_OneCustomer`: single Customer path → score 1.0
  - `TestBlastRadius_FiveCustomers`: 5 unique Customers → score 1.4
  - `TestBlastRadius_TenCustomers`: 10 unique Customers → score 2.0 (cap)
  - `TestBlastRadius_FifteenCustomers`: 15 unique Customers → score 2.0 (still capped)
  - `TestBlastRadius_SharedCustomerDedup` (C12/AC-21): 3 Deployments, same Customer → 1 unique → score 1.0
  - `TestBlastRadius_OrphanMicroservice`: Microservice with no Deployment → score 1.0 (traversal terminates)
  - `TestBlastRadius_DepthCap`: graph 8 levels deep → traversal terminates at depth 7; no infinite loop
  - `TestBlastRadius_Monotone` (S12): score is non-decreasing as unique Customer count increases
- [x] 23.7 Integration test (AC-21): register product → microservice → 10 deployments → 10 unique Customers → ingest SBOM → `blast_radius_score = 2.0`
- [x] 23.8 Integration test (AC-20): ingest SBOM → `202 Accepted` → immediate query shows `blast_radius_score` non-null
- [x] 23.9 Integration test (AC-22 partial): deleted SBOM components not counted in blast-radius traversal
- [x] 23.10 `make clean-arch` passes; `adapter/assetgraph/` coverage ≥ 90%

## 24. Composite risk score formula

- [x] 24.1 Add `ComputeRiskScoreV2(rawSeverity, effectiveState string, epssScore *float64, kevListed,
  exploitPublic bool, deterministicLevel string, blastRadiusScore float64) int` to `score.go`;
  update the single call site in `service.go:63` to call V2; keep `ComputeRiskScore` only for
  existing Phase 1 unit tests until those tests are updated to V2 in 24.5
- [x] 24.2 Wire EPSS adjustment (+30% max), KEV adjustment (+15), blast-radius multiplier into V2;
  implement `deterministic_level = Critical → return 100` override
- [x] 24.3 `deterministic_level = Critical` → `risk_score = 100` override
- [x] 24.4 `ReEnrichJob` invokes formula recomputation for all affected findings
- [x] 24.5 Unit tests — all formula branches (table-driven):
  - `TestFormula_CriticalOverride`: deterministic_level=Critical → score=100 regardless of EPSS/KEV/blast
  - `TestFormula_NullEPSSIsZero` (C14): EPSS=NULL → same result as EPSS=0.0
  - `TestFormula_Suppressed`: suppressed state → base × 0.1 applied before EPSS/blast (score remains low)
  - `TestFormula_Resolved`: resolved state → score=0 regardless of signals
  - `TestFormula_CapAt100`: high CVSS + EPSS=1.0 + KEV + blast=2.0 → clamped to 100
  - `TestFormula_KEVAdjustment`: KEV listed adds exactly +15 points to the sum
  - `TestFormula_EPSSAdjustment`: EPSS=1.0 adds 30% of base (upper bound of adjustment)
- [x] 24.6 Property tests (`tests/acceptance/score_phase2a_test.go`):
  - `TestCompositeScoreOracleProperty` (C9): for all valid inputs, score ∈ [0, 100]
  - `TestDeterministicCriticalAlwaysMax` (S8): deterministic_level=Critical → score=100 always
  - `TestSuppressionIsMonotonicallyDecreasing` (S10): suppressed.score < unsuppressed.score for same CVSS+signals
  - `TestEPSSAdjustmentBounds`: for base > 0 and EPSS ∈ [0,1], epss_adj ∈ [base, base×1.3]
  - `TestFormulaIsDeterministic`: same inputs always produce same output (no randomness)
- [x] 24.7 Integration test (AC-16 partial): EPSS sync → ReEnrichJob → `risk_score` updated; row count in `risk_context` unchanged (UPDATE not INSERT)
- [x] 24.8 Integration test: `TestReEnrichJob_Idempotent` (C14) — run same ReEnrichJob twice; `risk_context` unchanged on second run
- [x] 24.9 `usecase/enrichment/` coverage ≥ 90%; `make clean-arch` passes

## 25. Upstream vendor VEX feeds

- [x] 25.1 Implement `internal/adapter/vexfeed/` with `Matcher` interface and four-phase algorithm
- [x] 25.2 Red Hat CSAF 2.0 feed parser (PURL-based assertions)
- [x] 25.3 Alpine OSV feed parser (ecosystem + package name + version ranges)
- [x] 25.4 Rocky Linux and Wolfi OSV feed parsers
- [x] 25.5 Namespace alias normalisation table (Phase 2: rhel→redhat, rocky/linux→rocky, alma→almalinux)
- [x] 25.6 RPM errata direction check (EVR comparator; `version_inherited` vs `purl_mismatch`)
- [x] 25.7 Alpine build revision strip + apk version comparator for OSV range check
- [x] 25.8 `upstream_vex_coverage` set on `risk_context` for every matched/unmatched finding
- [x] 25.9 `purl_mismatch` cases logged at INFO level with SBOM PURL and VEX PURL for diagnostics
- [x] 25.10 `ReEnrichJob` enqueued for all matching `risk_context` rows after upsert
- [x] 25.11 Daily cron scheduler wired in `cmd/themis/main.go` (`vexfeed.sync_schedule` config key)
- [x] 25.12 Unit tests — four-phase matching matrix (one test per cell, see verification.md C13):
  - `TestPhase1_ExactMatch`: byte-for-byte PURL match → match_type=exact
  - `TestPhase2_RhelToRedhat` (AC-18): `rhel` namespace → `redhat` → match_type=namespace_normalised
  - `TestPhase2_RockyLinux`: `rocky/linux` namespace segment stripped → match_type=namespace_normalised
  - `TestPhase2_AlmaLinux`: `alma` → `almalinux` → match_type=namespace_normalised
  - `TestPhase3_ErrataInherited`: installed EVR ≥ assertion EVR after errata strip → match_type=version_inherited
  - `TestPhase3_ErrataTooOld`: installed EVR < assertion EVR → no match; upstream_vex_coverage=purl_mismatch
  - `TestPhase4_AlpineInRange`: version inside [introduced, fixed) → match_type=range_matched; status=affected
  - `TestPhase4_AlpineNotInRange_Fixed` (C13): version == fixed → match_type=range_matched; status=not_affected (fixed is exclusive)
  - `TestPhase4_AlpineNotInRange_Below`: version < introduced → status=not_affected
  - `TestAllPhasesFail` (C12): no phase matches → purl_mismatch; INFO log with sbom_purl, vex_purl, cve_id
  - `TestBackportAuthority_httpd` (AC-19): httpd@2.4.37-51.el8 + Red Hat not_affected → effective_state=NOT_AFFECTED; upstream 2.4.57 not consulted
  - `TestCaseNormalisation`: uppercase PURL namespace → lowercased before matching
- [x] 25.13 Unit tests — feed resilience (FR5, FR6):
  - `TestVendorFeed_HTTP429_Retry` (FR5): 429 on attempt 1, 200 on attempt 2 → sync succeeds
  - `TestVendorFeed_MalformedCSAF` (FR6): advisory missing required field → advisory skipped; ERROR logged with advisory ID; remaining advisories processed
  - `TestVendorFeed_FetchFailure`: endpoint unreachable × 3 → WARNING logged; cached data retained; no crash
- [x] 25.14 Integration test (AC-17): ingest Alpine SBOM → finding DETECTED; sync Alpine OSV advisory → ReEnrichJob → finding transitions to NOT_AFFECTED
- [x] 25.15 Integration test (AC-18): RPM SBOM with `rhel` namespace + Red Hat CSAF advisory → not_affected via Phase 2 namespace alias
- [x] 25.16 Integration test (AC-19): httpd@2.4.37-51.el8 (RHEL) + Red Hat VEX not_affected → NOT_AFFECTED despite upstream fix at 2.4.57
- [x] 25.17 Integration test (S9): vendor VEX matched → `upstream_vex_coverage=covered`; no vendor record → `not_covered`; all phases fail → `purl_mismatch`
- [x] 25.18 Register `adapter/vexfeed/` in coverage script (≥ 90%); `make clean-arch` passes

## 26. VEX export and coverage aggregate

- [x] 26.1 Implement `internal/usecase/vexgen/` — VEX document generation with VEX precedence logic
- [x] 26.2 CycloneDX 1.5+ serialiser: `vulnerabilities[]` with `bom-ref`, `analysis.state`, `ratings.score`, `x-themis-*` extensions
- [x] 26.3 OpenVEX 0.2+ serialiser
- [x] 26.4 `GET /api/v1/products/{id}/versions/{v}/vex` handler with `?format=` negotiation
- [x] 26.5 `GET /api/v1/products/{id}/versions/{v}/vex-coverage` handler (covered/not_covered/purl_mismatch counts)
- [x] 26.6 Unit tests: VEX precedence (human > user_supplied > ai_generated > upstream_vendor); both serialisers; coverage aggregate
- [x] 26.7 Integration test: export with human VEX + upstream VEX present → human VEX wins in output
- [x] 26.8 `usecase/vexgen/` coverage = 100%; `make clean-arch` passes

## 27. Management APIs — status and SBOM

- [x] 27.1 `GET /api/v1/status?top=N` handler with live SQL query (component counts, severity breakdown, top-N ranking)
- [x] 27.2 `GET /api/v1/sboms` and `GET /api/v1/products/{id}/sboms` handlers (cursor-based pagination)
- [x] 27.3 `DELETE /api/v1/sboms/{id}` soft-delete handler with `?force=true` guard
- [x] 27.4 Audit log write on SBOM delete
- [x] 27.5 `WHERE sbom_documents.deleted_at IS NULL` filter enforced at store layer on all list/get queries
- [x] 27.6 `GET /api/v1/status` returns `"signals_stale": true` when EPSS/KEV sync is overdue
- [x] 27.7 Unit tests — soft-delete 7-path isolation matrix (`TestSoftDelete_DataIsolation`):
  - Path 1 `TestSoftDelete_ExcludedFromStatusCounts`: deleted SBOM → component and finding counts decrease
  - Path 2 `TestSoftDelete_ExcludedFromSBOMList`: `GET /api/v1/sboms` cursor page does not include deleted
  - Path 3 `TestSoftDelete_ExcludedFromProductSBOMList`: product-scoped listing excludes deleted
  - Path 4 `TestSoftDelete_ExcludedFromBlastRadius`: blast-radius traversal ignores components from deleted SBOM
  - Path 5 `TestSoftDelete_ExcludedFromVEXExport`: VEX export does not include findings from deleted SBOM
  - Path 6 `TestSoftDelete_ExcludedFromTopComponents`: top-N components ranking excludes deleted SBOM components
  - Path 7 `TestSoftDelete_ExcludedFromFindings`: findings query excludes rows whose SBOM is soft-deleted
- [x] 27.8 Unit test — negative store filter: `TestSoftDelete_StoreFilterNotCallerFilter`:
  - introduce a stub store query that bypasses the `WHERE deleted_at IS NULL` clause;
    assert that data from deleted SBOM leaks through → proves filter must be at store layer
  - confirm real store implementations add filter; caller code does not add redundant filter
- [x] 27.9 Unit tests: `top=N` clamping (N>50 → clamped to 50), `force=false` guard → 409,
  audit log write on every delete (including `force=true`), `GET /api/v1/sboms` pagination cursor
- [x] 27.10 Integration test (AC-22): ingest SBOM, soft-delete it, confirm absent from
  all 7 paths above in a single transaction-rolled-back test
- [x] 27.11 Integration test (O14): `SELECT * FROM audit_log WHERE action='SBOM_DELETED'`
  returns exactly 1 row per delete call; row has correct `sbom_id` and `api_key_id`
- [x] 27.12 `adapter/store/` coverage ≥ 90%; `make clean-arch` passes

## 28. Layman-friendly error responses

- [x] 28.1 Implement error catalogue middleware in `internal/adapter/api/` mapping all domain errors
  to `{error: {code, message, hint}}`
- [x] 28.2 Apply middleware to all existing API handlers (Phase 1 endpoints)
- [x] 28.3 Apply middleware to all new Phase 2a handlers
- [x] 28.4 Verify no raw PostgreSQL error strings or Go error strings in any response body
- [x] 28.5 Implement all 12 error catalogue codes from the error-ux spec
- [x] 28.6 Unit tests — per-catalogue-code coverage (one test per code, codes from error-ux spec):
  - `TestErrorCode_SBOMNotFound` → 404 with `SBOM_NOT_FOUND`
  - `TestErrorCode_ProductNotFound` → 404 with `PRODUCT_NOT_FOUND`
  - `TestErrorCode_ImageNotFound` → 404 with `IMAGE_NOT_FOUND`
  - `TestErrorCode_CustomerNotFound` → 404 with `CUSTOMER_NOT_FOUND`
  - `TestErrorCode_CannotDeleteLatestSBOM` → 409 with `CANNOT_DELETE_LATEST_SBOM`
  - `TestErrorCode_DuplicateMicroservice` → 409 with `DUPLICATE_MICROSERVICE`
  - `TestErrorCode_DuplicateCustomer` → 409 with `DUPLICATE_CUSTOMER`
  - `TestErrorCode_InvalidSBOMFormat` → 422 with `INVALID_SBOM_FORMAT`
  - `TestErrorCode_InvalidRequest` → 400 with `INVALID_REQUEST`
  - `TestErrorCode_MissingAPIKey` → 401 with `MISSING_API_KEY`
  - `TestErrorCode_InvalidAPIKey` → 401 with `INVALID_API_KEY`
  - `TestErrorCode_InternalError` → 500 with `INTERNAL_ERROR`
  - `TestErrorCode_FallbackForUnhandledErrors`: panic/unknown error → `INTERNAL_ERROR`; no stack trace
- [x] 28.7 Unit test — no DB error leak: `TestAC23_NoRawDBErrorLeaks`:
  - inject a store that returns raw `pq.Error` or `pgx.PgError`;
    assert response body contains no `pq:` prefix, no table names, no constraint names
- [x] 28.8 `make clean-arch` passes; `make check` passes

## 29. Integration and acceptance gates

- [x] 29.1 Integration test (AC-16 full): EPSS/KEV sync → `ReEnrichJob` → `risk_score` updated for
  all pre-existing open findings; raw `component_vulnerabilities` rows unchanged
- [x] 29.2 Integration test (AC-17): ingest Alpine SBOM → findings DETECTED → sync Alpine OSV
  vendor VEX → `ReEnrichJob` → findings transition to NOT_AFFECTED; SBOM not re-uploaded
- [x] 29.3 Integration test (AC-18): RPM namespace alias — `rhel`→`redhat` Phase 2 match applies
  CSAF not_affected; Alpine fixed-version boundary — version==fixed treated as not_affected
- [x] 29.4 Integration test (AC-19): httpd backport authority — vendor VEX not_affected wins over
  upstream CVE version range; effective_state=NOT_AFFECTED confirmed
- [x] 29.5 Integration test (AC-20): POST SBOM → 202 Accepted → immediate GET shows non-null
  `deterministic_level` and `blast_radius_score` on every finding (no async delay needed)
- [x] 29.6 Integration test (AC-21): blast-radius — 3 Deployments, same Customer → unique count=1;
  multiplier cap=2.0× at 10+ unique Customers
- [x] 29.7 Integration test (AC-22): soft-delete → all 7 data paths exclude deleted SBOM data
- [x] 29.8 Integration test (AC-23): trigger all 12 catalogue codes via HTTP (codes from
  error-ux spec); confirm `{error:{code,message,hint}}` shape; confirm no raw DB error leaks
- [x] 29.9 Integration test (AC-24): VEX export CycloneDX 1.5+ — schema valid; precedence:
  human triage overrides vendor assertion; `x-themis-*` fields present
- [x] 29.10 Feed resilience integration tests (FR1–FR8):
  - `TestFeedResilience_EPSSUnreachable` (FR1): mock HTTP 500 × 3; data unchanged; WARNING logged
  - `TestFeedResilience_EPSSTruncated` (FR2): < 50% prior row count; sync aborted; data retained
  - `TestFeedResilience_KEVMalformed` (FR3): `text/html` response; ERROR logged; KEV data retained
  - `TestFeedResilience_ExploitDBEmpty` (FR4): empty body; existing records unchanged; WARNING
  - `TestFeedResilience_VendorFeed429` (FR5): 429 then 200; retry succeeds; advisory ingested
  - `TestFeedResilience_MalformedCSAF` (FR6): advisory missing field; skipped; rest processed
  - `TestFeedResilience_EPSSOutOfRange` (FR7): row with `epss=-0.1`; row rejected; valid rows upserted
  - `TestFeedResilience_StaleFlag` (FR8): mock time past 25h TTL; `stale=true`; status reflects it
- [x] 29.11 All existing Phase 1 integration tests still pass (`go test -tags=integration ./...`)
- [x] 29.12 `make check` passes clean (lint, vet, dead code, clean-arch)

## 30. Phase 2a completion

- [x] 30.1 All new packages registered in `scripts/check-coverage.sh` with correct thresholds:
  - `internal/usecase/enrichment/` ≥ 90%
  - `internal/usecase/vexgen/` ≥ 100%
  - `internal/adapter/vexfeed/` ≥ 90%
  - `internal/adapter/epsskev/` ≥ 85%
  - `internal/adapter/exploitdb/` ≥ 85%
  - `internal/adapter/assetgraph/` ≥ 90%
  - `internal/adapter/api/` ≥ 80%
  - `internal/adapter/store/` ≥ 90%
  - Note: per-package gates pass for Phase 2a packages listed above; full-repo `make coverage` still below threshold for `adapter/store`, `adapter/epsskev`, `infrastructure/http`, and `adapter/notify` — additional integration tests needed
- [x] 30.2 All Phase 2a Prometheus metric names registered in `internal/infrastructure/metrics/`:
  - `themis_epsskev_sync_total`, `themis_epsskev_stale`, `themis_reenrichjob_batches_total`
  - `themis_vexfeed_sync_total`, `themis_vexfeed_assertions_total`, `themis_vexfeed_purl_mismatch_total`
  - `themis_blast_radius_score` (histogram), `themis_layer1_rules_fired_total`
- [x] 30.3 `make verify-build` (`make clean && make all`) passes on full repo
- [x] 30.4 Update `verification.md`: confirm C9-C14, S7-S12, O9-O14, FR1-FR8 rows are current
- [x] 30.5 Update `docs/acceptance-criteria.md`: confirm AC-16..AC-24 test names match final test files
- [x] 30.6 Update `AGENTS.md` — Phase 2a status → complete; Phase 2b status → planned
- [x] 30.7 Merge `themis-phase-2` branch to `main`
- [x] 30.8 Git tag `v0.2.0`
- [x] 30.9 Write Phase 2a release notes (new capabilities, new API endpoints, breaking change: risk score formula)

## 31. Phase 2a — Feed reliability and signal-quality gaps (BLOCKING)

Identified during intel-source-tiers cross-check (`openspec/intel-source-tiers.md`).
All items below must complete before Phase 2b begins.

### 31a. OSV / Alpine CVE normalization

- [ ] 31.1 Normalize `ALPINE-CVE-*` IDs to `CVE-*` in `mapOSVVuln`
  (`internal/adapter/osv/`) so EPSS/KEV joins succeed for Alpine findings.
  Currently 592/592 Alpine findings show `with_epss: 0` because the ID form never
  matches the `epss_kev_signals` table (row 2.1 gap).
- [ ] 31.2 Fix `ParseOSVFeed.firstCVE()` Alpine ID extraction to strip the
  `ALPINE-CVE-` prefix and return the canonical `CVE-*` form before the EPSS lookup.
- [ ] 31.3 Fix OSV CVSS vector parsing: `fmt.Sscanf("%f")` fails on the full
  `CVSS:3.1/AV:N/...` string — base score is always 0. Replace with a proper CVSS
  vector parser or substring extraction so scores are populated (row 2.1 gap).

### 31b. Vendor feed URL fixes

- [ ] 31.4 Alpine OSV default URL returns HTTP 302 (GitLab login redirect); update
  default URL to the public GCS zip endpoint and wire `ZipOSVFeedSource` if not
  already present (row 2.4 gap).
- [ ] 31.5 Rocky Linux OSV default URL returns HTTP 404; update default URL to the
  public GCS zip endpoint (row 2.5 gap).
- [ ] 31.6 Red Hat CSAF default URL returns an HTML directory listing; implement
  `CSAFDirectoryFeedSource` to crawl the advisory index and fetch individual CSAF
  files (row 2.3 gap). Vendor VEX row 3.2 is unblocked once this lands.

### 31c. ExploitDB signal wiring

- [ ] 31.7 Expose ExploitDB exploit records in the scan findings API response so
  `exploit_public` signal is visible to consumers (row 2.7 gap — adapter exists,
  API surface incomplete).
- [ ] 31.8 Wire `themis_exploitdb_sync_total` Prometheus counter in the ExploitDB
  scheduler — metric was listed in Group 30.2 but not yet emitted (Group 30 note).
