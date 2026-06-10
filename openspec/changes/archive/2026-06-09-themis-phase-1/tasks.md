# Themis Phase 1 Tasks

## Definition of Done

Every task group MUST satisfy its gates before moving to the next group. **Coverage is checked task-wise (packages for that group only); the clean rebuild applies to the whole codebase.**

### Task-wise gates (per group, packages touched by that group)

1. **Build** — `go build ./...` passes with zero errors and zero warnings
2. **Unit tests** — `go test ./internal/<package>/...` passes; all tests green; no skipped tests without a documented reason
3. **Coverage** — `make coverage-pkg PKG=<path>` passes for each package in the group (e.g. `PKG=usecase/enrichment`). Thresholds: domain/business logic packages at **100%**; infrastructure packages at **≥ 90%**; register new packages in `scripts/check-coverage.sh`
4. **Dead code** — `make deadcode` passes when listed in the group
5. **Integration tests** — relevant integration tests against a real PostgreSQL instance pass; use `//go:build integration` tag
6. **Clean Architecture** — `make clean-arch` passes when listed in the group

### Full codebase (always after task-wise gates)

7. **Clean rebuild** — `make verify-build` (`make clean` then `make all`) on the **entire repo**

Full-repo `make coverage` is for Group 15 / CI sweeps, not required on every group completion.

A group is NOT complete until its task-wise gates and the clean rebuild pass. Coverage below threshold, dead code, and Clean Architecture import violations are hard blockers — not warnings.

**Coverage targets (from design.md Decision 17):**

| Package | Target |
| ------- | ------ |
| `internal/domain/`, `internal/usecase/enrichment/`, `internal/usecase/triage/`, `internal/usecase/ingestion/`, `internal/usecase/watch/`, `internal/adapter/parser/`, `internal/adapter/trust/`, `internal/adapter/notify/` | **100%** |
| `internal/adapter/store/`, `internal/adapter/api/`, `internal/infrastructure/db/`, `internal/infrastructure/queue/`, `internal/infrastructure/http/` | **≥ 90%** |
| `cmd/`, generated oapi-codegen stubs | Excluded |

---

## 1. Project Scaffolding

- [x] 1.1 Initialise Go module (`github.com/themis-project/themis`) with Go 1.22+
- [x] 1.2 Create Clean Architecture directory layout: `cmd/themis/`, `internal/domain/` (Layer 1), `internal/usecase/ingestion/`, `internal/usecase/enrichment/`, `internal/usecase/triage/`, `internal/usecase/watch/` (Layer 2), `internal/adapter/parser/`, `internal/adapter/store/`, `internal/adapter/notify/`, `internal/adapter/api/`, `internal/adapter/trust/` (Layer 3), `internal/infrastructure/db/`, `internal/infrastructure/queue/`, `internal/infrastructure/http/`, `internal/infrastructure/config/`, `internal/infrastructure/metrics/` (Layer 4)
- [x] 1.3 Add core dependencies: `chi` (router), `pgx/v5` (PostgreSQL driver), `golang-migrate` (migrations), `zap` (structured logging), `prometheus/client_golang` (metrics), `oapi-codegen` (OpenAPI)
- [x] 1.4 Set up `Makefile` with targets: `build`, `test`, `test-integration`, `lint`, `coverage`, `deadcode`, `check`, `migrate-up`, `migrate-down`, `generate-api`
- [x] 1.5 Configure `golangci-lint` with a project `.golangci.yml`: `depguard` rules enforcing Clean Architecture import direction (domain→stdlib only, usecase→domain only, adapter→domain+usecase only); `go-cleanarch` linter enabled; no format-package imports outside `internal/adapter/parser/`
- [x] 1.6 Add `golang.org/x/tools/cmd/deadcode` and `github.com/roblaszczak/go-cleanarch` to tooling dependencies in `Makefile` and `tools.go`
- [x] 1.7 Write `scripts/check-coverage.sh` — reads `coverage.txt`, fails with non-zero exit if any non-excluded package is below its threshold (100% for domain/usecase/adapter business-logic packages, 90% for infrastructure packages)
- [x] 1.8 Add `clean-arch` Makefile target: `go-cleanarch ./...` — fails on any import direction violation
- [x] 1.9 **Build gate**: `go build ./...` passes with zero errors
- [x] 1.10 **Unit test gate**: `go test ./...` passes (no application tests yet; module structure compiles cleanly)
- [x] 1.11 **Coverage gate**: `make coverage` passes; `scripts/check-coverage.sh` exits 0
- [x] 1.12 **Dead code gate**: `make deadcode` passes with zero findings
- [x] 1.13 **Clean Architecture gate**: `make clean-arch` passes with zero import direction violations

## 2. Configuration and Startup

- [x] 2.1 Define `Config` struct with all settings loadable from environment variables and a `themis.yaml` file (env vars override file values)
- [x] 2.2 Implement config sections: server (port, timeouts), database (DSN, pool size), worker pool (size, retry max), upload (max size, timeout), NVD/OSV (API key, rate limit, poll interval), SMTP, Teams webhook, trust policy defaults
- [x] 2.3 Implement startup sequence: load config → connect to DB → run pending migrations → verify DB schema version ≤ binary version → start worker pool → start HTTP server
- [x] 2.4 Implement `/healthz` (liveness) and `/readyz` (readiness — checks DB connectivity, CVE feed last success timestamp) endpoints
- [x] 2.5 Implement structured JSON logging with `zap`: fields `timestamp`, `level`, `component`, `request_id`, `product_id`, `project_id`
- [x] 2.6 Wire `request_id` middleware — generate UUID per request, propagate through context to all downstream operations
- [x] 2.7 **Build gate**: `go build ./...` passes with zero errors
- [x] 2.8 **Unit test gate**: `go test ./internal/...` — config parsing, env var override, missing required field errors, default values all tested
- [x] 2.9 **Coverage gate**: `make coverage` passes; config and startup packages at 100%; every config field, every override path, every validation error covered
- [x] 2.10 **Dead code gate**: `make deadcode` passes; no unused config fields, no unreachable startup paths
- [x] 2.11 **Integration test gate**: server starts against a real PostgreSQL instance; `/healthz` returns 200; `/readyz` returns 200 with DB connected, 503 when DB unreachable

## 3. Database Schema and Migrations

- [x] 3.1 Write migration 001: Layer 1 tables — `products`, `product_versions`, `artifacts`, `images`
- [x] 3.2 Write migration 002: Layer 1 tables — `sbom_documents` (with `raw_document` JSONB, `trust_status`, `is_latest`, `supersedes_id`)
- [x] 3.3 Write migration 003: Layer 1 tables — `components`, `component_versions`, `dependency_relationships`
- [x] 3.4 Write migration 004: Layer 1 tables — `vulnerabilities`, `component_vulnerabilities`
- [x] 3.5 Write migration 005: Layer 2 tables — `vex_documents`, `vex_assertions`
- [x] 3.6 Write migration 006: Layer 3 tables — `intelligence_signals`, `runtime_exposures`, `remediation_actions`
- [x] 3.7 Write migration 007: Convergence — `risk_context` table
- [x] 3.8 Write migration 008: Operational — `api_keys`, `notification_rules`, `cve_watch_findings`, `audit_log`, `ingestion_jobs`
- [x] 3.9 Add indexes: `components(purl)`, `component_vulnerabilities(component_version_id, vulnerability_id)`, `risk_context(component_vuln_id)`, `risk_context(effective_state)`, `vulnerabilities(cve_id)`, `sbom_documents(image_digest, checksum_sha256)` (unique), `vex_documents(sbom_checksum, checksum_sha256)` (unique)
- [x] 3.10 **Build gate**: `go build ./...` passes with zero errors
- [x] 3.11 **Unit test gate**: `go test ./internal/adapter/store/...` — migration file naming, version ordering, schema version comparison, startup refusal when schema ahead of binary
- [x] 3.12 **Coverage gate**: `make coverage` passes; `internal/adapter/store/` ≥ 90%; every migration helper function exercised; no dead migration utility function
- [x] 3.13 **Dead code gate**: `make deadcode` passes; no migration helper functions defined but never called
- [x] 3.14 **Clean Architecture gate**: `make clean-arch` passes; `internal/adapter/store/` imports only `internal/domain/` and `internal/usecase/`; no infrastructure imports
- [x] 3.15 **Integration test gate**: apply all migrations up on a fresh PostgreSQL instance; verify all tables and indexes exist; run every migration down in reverse order; verify clean teardown; re-run up to confirm idempotency

## 4. Job Queue Interface and Worker Pool

- [x] 4.1 Define `JobQueue` interface (`Enqueue`, `Consume`, `Ack`) and `Job` struct in `internal/domain/` (port interfaces); `Job` type is a plain domain type with no framework dependencies
- [x] 4.2 Implement `InProcessQueue` in `internal/infrastructure/queue/` using a buffered channel and goroutine pool; pool size configurable via env var
- [x] 4.3 Implement worker lifecycle: graceful shutdown on SIGINT/SIGTERM, drain in-flight jobs before exit
- [x] 4.4 Implement retry logic with exponential backoff (configurable base delay, max retries); persist retry count in `ingestion_jobs`
- [x] 4.5 **Build gate**: `go build ./...` passes with zero errors
- [x] 4.6 **Unit test gate**: `go test ./internal/domain/... ./internal/infrastructure/queue/...` — enqueue and consume ordering, worker pool concurrency, ack clears the job, retry increments counter, backoff timing, graceful shutdown drains in-flight jobs, max retries marks job as permanently failed
- [x] 4.7 **Coverage gate**: `make coverage` passes; `internal/domain/` at 100%; `internal/infrastructure/queue/` ≥ 90%; every `JobQueue` interface method, every error branch in `InProcessQueue`, the shutdown drain path, and the max-retry terminal path all covered
- [x] 4.8 **Dead code gate**: `make deadcode` passes; `JobQueue` interface has exactly one implementation exercised; no helper functions in `internal/infrastructure/queue/` unreachable from tests or production callers
- [x] 4.9 **Clean Architecture gate**: `make clean-arch` passes; `internal/infrastructure/queue/` imports only `internal/domain/`; `internal/domain/` imports stdlib only
- [x] 4.10 **Integration test gate**: worker pool enqueues 100 jobs concurrently against a real `ingestion_jobs` PostgreSQL table; all jobs reach terminal state; no duplicates; retry counts persisted correctly

## 5. Artifact Trust Gate

- [x] 5.1 Define `SignatureVerifier` interface and `TrustResult` type in `internal/domain/` (port interfaces)
- [x] 5.2 Implement `StubVerifier` in `internal/adapter/trust/` — accepts any artifact; assigns `trust_status=unsigned` if no signature field present, `trust_status=unverified` otherwise
- [x] 5.3 Implement JSON schema validation for CycloneDX 1.4/1.5/1.6, SPDX 2.3/3.0, OpenVEX, and CSAF formats using embedded schema files
- [x] 5.4 Implement SHA-256 hash computation and comparison against caller-provided checksum
- [x] 5.5 Implement deduplication check: query `UNIQUE(image_digest, checksum_sha256)` for SBOMs and `UNIQUE(sbom_checksum, checksum_sha256)` for VEX; return existing record if duplicate
- [x] 5.6 Implement provenance validation: check for `ci_job_id`, `ci_pipeline_url`, `supplier_identity`; log warnings if missing under standard policy; reject under strict policy
- [x] 5.7 Implement integrity chain validation: verify SBOM references known `image_digest`; verify VEX references known `sbom_checksum`
- [x] 5.8 Implement trust policy enforcement (`strict` / `standard` / `permissive`) per product
- [x] 5.9 Write audit log entries for all trust gate decisions (acceptance, rejection, security events)
- [x] 5.10 **Build gate**: `go build ./...` passes with zero errors
- [x] 5.11 **Unit test gate**: `go test ./internal/domain/... ./internal/adapter/trust/...` — each trust gate check tested in isolation; all three policy levels; valid and invalid schema for each format; hash mismatch; missing provenance; unknown supplier; integrity chain with missing parent
- [x] 5.12 **Coverage gate**: `make coverage` passes; `internal/adapter/trust/` at 100%; `StubVerifier` fully tested including both trust_status branches; every policy enforcement branch (strict/standard/permissive) covered; every rejection path covered; audit log write path covered
- [x] 5.13 **Dead code gate**: `make deadcode` passes; `SignatureVerifier` interface has one implementation exercised; no unexported helper in `internal/adapter/trust/` unreachable; no schema validation utility called from zero places
- [x] 5.14 **Clean Architecture gate**: `make clean-arch` passes; `internal/adapter/trust/` imports only `internal/domain/`; `internal/domain/` has no trust-specific external imports
- [x] 5.15 **Integration test gate**: full trust gate run against a seeded PostgreSQL instance; deduplication query returns existing record; integrity chain rejects SBOM with unregistered image digest; audit log entries written and queryable

## 6. SBOM Parser Layer

- [x] 6.1 Define `SBOMAdapter` interface in `internal/domain/` (port); define canonical types (`CanonicalSBOM`, `CanonicalComponent`, `CanonicalDependencyEdge`, `CanonicalVulnerability`) in `internal/domain/`
- [x] 6.2 Implement CycloneDX adapter in `internal/adapter/parser/` (versions 1.4, 1.5, 1.6): parse components, PURLs, dependencies, and vulnerability sections; CycloneDX structs MUST NOT leak outside this package
- [x] 6.3 Implement SPDX adapter in `internal/adapter/parser/` (versions 2.3, 3.0): parse packages, external refs (PURL derivation), relationships, and license data; SPDX structs MUST NOT leak outside this package
- [x] 6.4 Implement Trivy JSON output adapter in `internal/adapter/parser/`: parse `Results[].Vulnerabilities` and map to `CanonicalVulnerability`
- [x] 6.5 Implement adapter registry in `internal/adapter/parser/`: select adapter by `format` discriminator; return HTTP 422 for unsupported formats
- [x] 6.6 Enforce component count limit (default 50K) and parsing timeout (default 5 min); return `REJECTED` on breach
- [x] 6.7 `depguard` rule in `.golangci.yml` verifying no CycloneDX/SPDX package imports outside `internal/adapter/parser/`
- [x] 6.8 **Build gate**: `go build ./...` passes with zero errors; `golangci-lint run` passes with zero errors including the no-format-leakage rule
- [x] 6.9 **Unit test gate**: `go test ./internal/domain/... ./internal/adapter/parser/...` — table-driven tests for CycloneDX (valid 1.4/1.5/1.6, missing PURL, missing deps, vuln section, malformed JSON); SPDX (packages, external refs, relationships, licenses); Trivy (Results mapping, empty results, unknown severity); adapter registry (known formats, unknown format returns 422); component count limit; parsing timeout
- [x] 6.10 **Coverage gate**: `make coverage` passes; `internal/adapter/parser/` at 100%; every adapter method covered; every PURL derivation branch (present, absent, malformed) covered; component count limit and timeout paths covered; adapter registry unknown-format path covered
- [x] 6.11 **Dead code gate**: `make deadcode` passes; `SBOMAdapter` interface has three implementations all exercised; no unexported parsing helper unreachable; every canonical type field populated by at least one adapter and read by at least one consumer
- [x] 6.12 **Clean Architecture gate**: `make clean-arch` passes; `internal/adapter/parser/` imports only `internal/domain/`; CycloneDX/SPDX library imports confirmed absent from all other packages
- [x] 6.13 **Integration test gate**: parse real-world CycloneDX and SPDX fixture files (committed to `testdata/`); verify component counts, PURLs, and dependency edges match expected canonical output

## 7. Ingestion Service and Pipeline

- [x] 7.1 Define `IngestionService` interface in `internal/usecase/ingestion/` — `IngestSBOM(ctx, RawArtifact)` and `IngestVEX(ctx, RawArtifact)` methods; input/output structs are pure domain types with no HTTP or DB imports
- [x] 7.2 Implement pipeline stage orchestration: trust gate → parser → store → correlate → enrich → notify; persist lifecycle state after each stage
- [x] 7.3 Implement vulnerability correlation: for each `CanonicalComponent`, query `vulnerabilities` by PURL ecosystem + package name + version range; create `component_vulnerabilities` records for matches
- [x] 7.4 Implement NVD local cache: store fetched CVE data in `vulnerabilities` table; correlation queries the local cache (not NVD directly)
- [x] 7.5 Implement idempotency: check `Idempotency-Key` in `ingestion_jobs` before processing; return existing result if key matches
- [x] 7.6 Implement ingestion status persistence: write state transitions to `ingestion_jobs` with timestamps
- [x] 7.7 **Build gate**: `go build ./...` passes with zero errors
- [x] 7.8 **Unit test gate**: `go test ./internal/usecase/ingestion/...` — pipeline stage sequencing; state transition ordering; correlation match/no-match; idempotency key deduplication; retryable vs non-retryable error classification; each stage failure leaves the correct terminal state
- [x] 7.9 **Coverage gate**: `make coverage` passes; `internal/usecase/ingestion/` at 100%; every pipeline stage invoked in tests; retryable and non-retryable error branches both covered; idempotency fast-path covered; correlation no-match path covered
- [x] 7.10 **Dead code gate**: `make deadcode` passes; `IngestionService` interface has one implementation exercised; no pipeline stage function unreachable; NVD local cache read and write paths both reachable
- [x] 7.11 **Clean Architecture gate**: `make clean-arch` passes; `internal/usecase/ingestion/` imports only `internal/domain/`; no HTTP, DB, or framework imports in the use case layer
- [x] 7.12 **Integration test gate**: full pipeline run against a real PostgreSQL test database — POST a CycloneDX SBOM fixture → verify `ingestion_jobs.status=COMPLETED` → verify `component_vulnerabilities` rows exist → verify `risk_context` records populated → verify `audit_log` entries written; run duplicate POST and verify idempotent response

## 8. REST API and OpenAPI Spec

- [x] 8.1 Define OpenAPI 3.1 spec (`api/openapi.yaml`) covering all endpoints listed in the proposal
- [x] 8.2 Generate Go server stubs from `openapi.yaml` using `oapi-codegen`; implement handlers against the stubs
- [x] 8.3 Implement `POST /api/v1/sbom/upload` — validate, enqueue, return 202
- [x] 8.4 Implement `POST /api/v1/webhooks/scan` — validate HMAC-SHA256 signature, enqueue, return 202
- [x] 8.5 Implement `POST /api/v1/vex/upload` — validate, link to SBOM, enqueue re-enrichment, return 202
- [x] 8.6 Implement `GET /api/v1/ingestions/{id}` — return lifecycle status
- [x] 8.7 Implement product endpoints: `GET/POST /api/v1/products`, `GET /api/v1/products/{id}/projects`, `POST /api/v1/products/{id}/projects`, `GET /api/v1/products/{id}/versions`
- [x] 8.8 Implement scan endpoints: `GET /api/v1/projects/{id}/scans`, `GET /api/v1/scans/{id}`, `GET /api/v1/scans/{id}/vulnerabilities`
- [x] 8.9 Implement triage endpoint: `POST /api/v1/vulnerabilities/{id}/triage`, `GET /api/v1/vulnerabilities/{id}/triage/history`
- [x] 8.10 Implement component catalog endpoint: `GET /api/v1/components`
- [x] 8.11 Implement CVE watch findings endpoint: `GET /api/v1/cve-watch/findings`
- [x] 8.12 Implement notification config endpoints: `GET/PUT /api/v1/config/notifications`
- [x] 8.13 Implement scanner config endpoints: `GET/PUT /api/v1/config/scanners`
- [x] 8.14 Implement API key authentication middleware: validate `X-API-Key` header, resolve product scope, attach to request context
- [x] 8.15 Implement cursor-based pagination on all list endpoints
- [x] 8.16 Implement RFC 7807 Problem Details error response format across all error paths
- [x] 8.17 **Build gate**: `go build ./...` passes with zero errors; `oapi-codegen` generated stubs compile cleanly against handler implementations
- [x] 8.18 **Unit test gate**: `go test ./internal/adapter/api/...` — handler tests using `httptest`: 202 on valid upload; 401 on missing/invalid API key; 401 on invalid webhook signature; 404 on unknown resource; 422 on schema violation; 413 on oversized upload; pagination cursor round-trip; RFC 7807 error shape on every error path; product-scoped key returns 403 on other product's resources
- [x] 8.19 **Coverage gate**: `make coverage` passes; `internal/adapter/api/` ≥ 90%; every HTTP handler has at least one success test and one error test; every middleware branch (auth, pagination, error formatting) covered; 413, 422, 401, 403, 404, and 405 response paths all exercised
- [x] 8.20 **Dead code gate**: `make deadcode` passes; every handler registered in the router is reachable; no helper in `internal/adapter/api/` defined without a caller; every middleware wired to at least one route
- [x] 8.21 **Clean Architecture gate**: `make clean-arch` passes; `internal/adapter/api/` imports only `internal/domain/` and `internal/usecase/`; no direct DB or infrastructure imports in handlers
- [x] 8.22 **Integration test gate**: spin up full HTTP server with real PostgreSQL; run API test suite against live endpoints — create product → register image → upload SBOM → poll ingestion status → query scan → query vulnerabilities → submit triage → query triage history; verify all response shapes match OpenAPI spec

## 9. Intelligence Enrichment (VEX Overlay)

- [x] 9.1 Implement `EnrichmentService` in `internal/usecase/enrichment/`: `ApplyVEX(ctx, sbomDocumentID)` applies all matching VEX assertions and populates `risk_context`; depends only on `internal/domain/` repository interfaces
- [x] 9.2 Implement VEX assertion matching: for each `component_vulnerabilities` record, query `vex_assertions` by `(component_purl, cve_id)` scoped to the SBOM's VEX documents
- [x] 9.3 Implement effective state machine transitions; write audit log on every transition
- [x] 9.4 Implement risk score computation (Phase 1 formula: base from severity + modifier from effective state)
- [x] 9.5 Implement VEX-triggered re-enrichment job: enqueue `ReenrichVEX` when a new VEX document is ingested; update existing `risk_context` records without creating duplicates
- [x] 9.6 Implement "most recent VEX wins" resolution when multiple assertions apply to the same (purl, cve_id)
- [x] 9.7 **Build gate**: `go build ./...` passes with zero errors
- [x] 9.8 **Unit test gate**: `go test ./internal/usecase/enrichment/...` — every effective state transition (DETECTED→SUPPRESSED, DETECTED→CONFIRMED, SUPPRESSED→DETECTED on revocation, CONFIRMED→RESOLVED); risk score formula for all severity × state combinations; "most recent VEX wins" with two assertions at different timestamps; re-enrichment does not duplicate risk_context rows
- [x] 9.9 **Coverage gate**: `make coverage` passes; `internal/usecase/enrichment/` at 100%; every state machine branch covered; every risk score formula branch (all severity levels × all effective states) covered; re-enrichment idempotency path covered; "most recent VEX" tie-breaking covered; audit log write in every transition path covered
- [x] 9.10 **Dead code gate**: `make deadcode` passes; `EnrichmentService` interface exercised; every state transition function reachable; no risk score helper defined without being called; `ApplyVEX` and `ReenrichVEX` both reachable from job workers
- [x] 9.11 **Clean Architecture gate**: `make clean-arch` passes; `internal/usecase/enrichment/` imports only `internal/domain/`; risk score logic is pure Go with zero external dependencies
- [x] 9.12 **Integration test gate**: ingest a SBOM with known vulnerabilities → verify `effective_state=detected`; ingest a matching VEX document → verify `effective_state=suppressed` and `raw_severity` unchanged; ingest a superseding VEX revoking the assertion → verify `effective_state=detected`; confirm audit_log entries exist for every transition

## 10. CVE Triage Engine

- [x] 10.1 Implement triage decision handler: validate decision type and justification; update `risk_context.effective_state`; persist immutable triage record
- [x] 10.2 Implement themis-generated VEX creation from L4 decisions: create `vex_document` with `source=themis_generated` and appropriate assertion
- [x] 10.3 Implement triage history storage: append-only records in `triage_history` table (add migration); query history endpoint
- [x] 10.4 Implement `accepted_until` expiry handling: scheduler checks expired `accepted_risk` decisions and reverts `effective_state` to `detected`
- [x] 10.5 Implement escalation to `IN_TRIAGE` state with optional `assigned_to` field
- [x] 10.6 **Build gate**: `go build ./...` passes with zero errors
- [x] 10.7 **Unit test gate**: `go test ./internal/usecase/triage/...` — false_positive creates VEX with not_affected assertion; accepted_risk sets expiry; triage without justification returns validation error; history is append-only (second triage does not overwrite first); latest decision determines effective_state; expired accepted_risk reverts to detected
- [x] 10.8 **Coverage gate**: `make coverage-pkg PKG=usecase/triage` passes; `internal/usecase/triage/` at 100%; every triage decision type (false_positive, accepted_risk, confirmed, resolved, escalate) covered; VEX generation for each decision type covered; expiry reversion path covered; append-only history enforcement covered; every validation error path covered
- [x] 10.9 **Dead code gate**: `make deadcode` passes; triage handler, VEX generator, and history writer all reachable from production callers; expiry scheduler reachable from startup; no triage helper function without a caller
- [x] 10.10 **Clean Architecture gate**: `make clean-arch` passes; `internal/usecase/triage/` imports only `internal/domain/`; no HTTP handler logic or DB driver imports in the triage use case
- [x] 10.11 **Integration test gate**: full triage flow against real PostgreSQL — submit triage decision via API → verify risk_context updated → verify themis-generated VEX document created in vex_documents → verify triage_history record written → ingest a new SBOM with the same (purl, cve_id) → verify generated VEX auto-applied → verify history preserved

## 11. CVE Watch Agent

- [x] 11.1 Implement scheduler and watch orchestration in `internal/usecase/watch/` using a configurable cron expression (default: every 6 hours); NVD/OSV HTTP clients live in `internal/adapter/` — the use case only calls domain port interfaces
- [x] 11.2 Implement NVD API client: paginated fetch of CVEs modified since `last_success_timestamp`; respect rate limits (token-bucket); store fetched CVEs in `vulnerabilities` table
- [x] 11.3 Implement OSV API client as NVD fallback: batch queries by ecosystem; map OSV schema to `CanonicalVulnerability`
- [x] 11.4 Implement component catalog matching: group catalog components by ecosystem; batch-query NVD/OSV; match by PURL + version range
- [x] 11.5 Implement new finding creation: insert `component_vulnerabilities` and `risk_context` records for new matches; skip already-known findings
- [x] 11.6 Persist `last_success_timestamp` after each successful poll cycle; expose via `/readyz`
- [x] 11.7 Emit Prometheus metrics: `themis_cve_watch_cycles_total`, `themis_cve_watch_duration_seconds`, `themis_cve_watch_new_findings_total` (labelled by ecosystem)
- [x] 11.8 **Build gate**: `go build ./...` passes with zero errors
- [x] 11.9 **Unit test gate**: `go test ./internal/usecase/watch/...` — catalog matching with version range comparisons (affected, not affected, boundary versions); ecosystem batching groups components correctly; duplicate finding skipped; NVD rate limiter delays requests; OSV fallback triggered on NVD error; last_success_timestamp only updated on full success
- [x] 11.10 **Coverage gate**: `make coverage` passes; `internal/usecase/watch/` at 100%; NVD client success and error paths covered via mocked domain port; OSV fallback path covered; rate limiter token-bucket logic covered; version range matching boundary cases covered; duplicate-finding skip path covered; metrics emission covered
- [x] 11.11 **Dead code gate**: `make deadcode` passes; scheduler and catalog matcher all reachable from startup; no watch helper function without a caller; Prometheus metric registrations all referenced
- [x] 11.12 **Clean Architecture gate**: `make clean-arch` passes; `internal/usecase/watch/` imports only `internal/domain/`; NVD/OSV HTTP calls live in `internal/adapter/`; no net/http imports in the watch use case
- [x] 11.13 **Integration test gate**: seed a PostgreSQL database with known components; run a watch cycle against a mock NVD/OSV server returning a fixture CVE matching a seeded component; verify new `component_vulnerabilities` and `risk_context` rows created; verify notification enqueued; verify `last_success_timestamp` updated; run cycle again and verify no duplicate findings

## 12. Notification Service

- [x] 12.1 Define `NotificationSender` interface in `internal/domain/` (port); implement `NotificationService` routing logic in `internal/adapter/notify/` with `Dispatch(ctx, event Event)` method
- [x] 12.2 Implement routing rule evaluation: match event type, product scope, and severity threshold against configured rules
- [x] 12.3 Implement SMTP email delivery: TLS required; credentials from env vars; retry with exponential backoff; redact credentials from logs
- [x] 12.4 Implement Teams Adaptive Card delivery: POST to configured webhook URL; redact URL from logs; retry on failure
- [x] 12.5 Implement digest aggregation: collect multiple findings from same CVE watch cycle or ingestion into a single notification per channel
- [x] 12.6 Emit `themis_notifications_total` Prometheus counter with labels `channel_type` and `status`
- [x] 12.7 **Build gate**: `go build ./...` passes with zero errors
- [x] 12.8 **Unit test gate**: `go test ./internal/adapter/notify/...` — routing rule matching (event type, severity threshold, product scope, no-match suppression); digest aggregation batches multiple findings; credential fields absent from captured log output; retry increments on failure; max retries marks notification failed
- [x] 12.9 **Coverage gate**: `make coverage-pkg PKG=adapter/notify` passes; `internal/adapter/notify/` at 100%; every routing rule predicate (event type, severity, product scope) covered; digest aggregation single-item and multi-item paths covered; SMTP retry and max-retry paths covered; Teams retry path covered; credential-redaction logic covered; every metric increment path covered
- [x] 12.10 **Dead code gate**: `make deadcode` passes; `NotificationSender` interface exercised; SMTP and Teams delivery functions both reachable; digest builder reachable; routing rule evaluator reachable; no notify helper without a caller
- [x] 12.11 **Clean Architecture gate**: `make clean-arch` passes; `internal/adapter/notify/` imports only `internal/domain/` and `internal/usecase/`; no direct database imports in notification delivery code
- [x] 12.12 **Integration test gate**: spin up a mock SMTP server and mock Teams webhook server; dispatch notifications for all event types; verify each channel receives expected message shape; verify digest behaviour when 10 findings dispatched; verify webhook URL redacted in logs; verify `themis_notifications_total` incremented correctly

## 13. API Key Management

- [x] 13.1 Implement `themis admin create-key` CLI command: generate a random key, hash with bcrypt, store in `api_keys` with product scope and expiry
- [x] 13.2 Implement `themis admin revoke-key` CLI command: mark key as revoked in `api_keys`
- [x] 13.3 Implement HMAC-SHA256 webhook signature generation helper for CI integration documentation
- [x] 13.4 **Build gate**: `go build ./...` passes with zero errors
- [x] 13.5 **Unit test gate**: `go test ./internal/adapter/api/...` (auth middleware) — valid key accepted; revoked key returns 401; expired key returns 401; key scoped to Product A returns 403 on Product B resource; global admin key passes all product checks; HMAC signature valid and invalid cases
- [x] 13.6 **Coverage gate**: `make coverage-pkg PKG=adapter/api` passes; auth middleware branches covered; HMAC computation and comparison both covered; bcrypt comparison covered; `create-key` and `revoke-key` CLI command paths both covered
- [x] 13.7 **Dead code gate**: `make deadcode` passes; CLI commands both reachable from `cmd/`; HMAC helper reachable from webhook handler; auth middleware reachable from router setup; no key management function without a caller
- [x] 13.8 **Clean Architecture gate**: `make clean-arch` passes; auth middleware in `internal/adapter/api/` accesses the DB only through `internal/domain/` repository interfaces; no direct `pgx` or SQL calls in middleware
- [x] 13.9 **Integration test gate**: create key via CLI → use key to authenticate API call → revoke key via CLI → verify subsequent API call returns 401; verify bcrypt hash stored (not plaintext) in `api_keys` table

## 14. Observability

- [x] 14.1 Expose `GET /metrics` Prometheus endpoint covering: ingestion rate, queue depth, job duration histograms, CVE watch cycle metrics, notification delivery counters, active worker count
- [x] 14.2 Instrument ingestion pipeline stages with OpenTelemetry spans (trace: webhook receipt → trust gate → parse → correlate → enrich → notify)
- [x] 14.1 Expose `GET /metrics` Prometheus endpoint in `internal/infrastructure/metrics/` covering: ingestion rate, queue depth, job duration histograms, CVE watch cycle metrics, notification delivery counters, active worker count
- [x] 14.2 Instrument ingestion pipeline stages with OpenTelemetry spans in `internal/infrastructure/metrics/` (trace: webhook receipt → trust gate → parse → correlate → enrich → notify); span creation injected via context, not imported by use cases
- [x] 14.3 **Build gate**: `go build ./...` passes with zero errors
- [x] 14.4 **Unit test gate**: `go test ./internal/infrastructure/metrics/...` — verify all expected Prometheus metric names are registered and labelled correctly; verify span names match the pipeline stage names; verify no duplicate metric registrations panic at startup
- [x] 14.5 **Coverage gate**: `make coverage` passes; `internal/infrastructure/metrics/` ≥ 90%; every metric registration and increment call site reachable from test or production paths; no orphaned metric variable that is registered but never incremented
- [x] 14.6 **Dead code gate**: `make deadcode` passes; every Prometheus counter, histogram, and gauge registered in startup is incremented somewhere in production code; every OTel span started has a corresponding `span.End()` reachable; no telemetry helper without a caller
- [x] 14.7 **Clean Architecture gate**: `make clean-arch` passes; observability instrumentation is injected via context or middleware — use cases contain no direct Prometheus or OTel imports
- [x] 14.8 **Integration test gate**: start server; run a full ingestion; scrape `/metrics`; verify `themis_ingestion_jobs_total`, `themis_job_duration_seconds`, `themis_queue_depth`, and `themis_notifications_total` all present with correct label sets and non-zero values

## 15. Final Integration Tests and Acceptance Criteria

- [x] 15.1 **E2E**: POST a CycloneDX SBOM → pipeline reaches `COMPLETED` → vulnerabilities queryable → `risk_context` populated with `effective_state=detected`
- [x] 15.2 **E2E**: POST a VEX document referencing that SBOM → `risk_context.effective_state` transitions to `suppressed` → raw finding in `component_vulnerabilities` preserved and unchanged
- [x] 15.3 **E2E**: submit L4 triage `false_positive` decision → `vex_document` with `source=themis_generated` created → ingest a second SBOM with the same component → VEX auto-applied → `effective_state=suppressed` without manual re-triage
- [x] 15.4 **E2E**: upload duplicate SBOM (same `image_digest` + `checksum_sha256`) twice → second upload returns HTTP 200 with same `ingestion_id` → no new `sbom_documents` row created → no re-processing
- [x] 15.5 **E2E**: ingest VEX asserting `not_affected` → verify `suppressed`; ingest superseding VEX revoking assertion → verify `effective_state` reverts to `detected`; raw finding never deleted
- [x] 15.6 **E2E**: seed catalog with components; trigger CVE watch cycle against mock NVD; verify new `component_vulnerabilities` rows created; verify notification dispatched to mock SMTP server
- [x] 15.7 **Acceptance criteria sweep**: map each of the 15 acceptance criteria in proposal-initial.md to a passing test; all 15 MUST be covered
- [x] 15.8 **Build gate**: `go build ./...` passes with zero errors on the full codebase
- [x] 15.9 **Full unit test gate**: `go test ./...` — all unit tests pass; zero skipped without documented reason
- [x] 15.10 **Full integration test gate**: `make test-integration` — all integration tests pass against a clean PostgreSQL instance provisioned by the test harness
- [x] 15.11 **Full coverage gate**: `make coverage` passes on the complete codebase — business logic packages (`internal/domain/`, `internal/usecase/enrichment/`, `internal/usecase/triage/`, `internal/usecase/ingestion/`, `internal/usecase/watch/`, `internal/adapter/parser/`, `internal/adapter/trust/`, `internal/adapter/notify/`) all at **100%**; infrastructure packages (`internal/adapter/store/`, `internal/adapter/api/`, `internal/infrastructure/db/`, `internal/infrastructure/queue/`, `internal/infrastructure/http/`) all **≥ 90%**; `scripts/check-coverage.sh` exits 0; coverage report committed to repo as `coverage.txt`
- [x] 15.12 **Full dead code gate**: `make deadcode` passes with zero findings — no unreachable function, no exported symbol without a consumer, no interface method without an exercised implementation, no commented-out code blocks
- [x] 15.13 **Full Clean Architecture gate**: `make clean-arch` passes with zero violations across the entire codebase — `internal/domain/` imports stdlib only; `internal/usecase/` imports only `internal/domain/`; `internal/adapter/` imports only `internal/domain/` and `internal/usecase/`; confirmed by `go-cleanarch` and `depguard`
- [x] 15.14 **Lint gate**: `golangci-lint run` passes with zero errors; `go vet ./...` passes; no CycloneDX/SPDX imports outside `internal/adapter/parser/` confirmed by depguard rule; zero `TODO:` or `FIXME:` comments remaining

---

## Phase 1 status summary

**Original scope (groups 1–15):** **192 / 192 tasks complete** — all gates passed at Phase 1 tag (`themis-phase-1`).

**Post-bring-up hardening (group 16 below):** discovered during real SBOM testing (Alpine/nginx container images, Syft/Trivy output). Tracked separately so distro SBOMs (Alpine, Debian, Rocky/RHEL, etc.) do not repeat zero-finding or ingest-failure traps. Merge target: `themis-phase-2` → `main`.

---

## 16. Post-bring-up hardening (planned)

Correlation, OSV, and Linux-distro SBOM lessons from local verification. See README [SBOM correlation, OSV, and Linux distros](../../../README.md#sbom-correlation-osv-and-linux-distros).

### 16.1 CVE correlation and OSV (ingest + watch)

- [x] 16.1.1 Wire live OSV `ComponentFetcher` in ingestion pipeline (replace no-op `StaticVulnerabilityFetcher`)
- [x] 16.1.2 CVE watch: correlate against full stored vulnerability catalog, not only current NVD poll batch
- [x] 16.1.3 CVE watch: supplement each cycle with OSV batch queries for catalog ecosystems
- [x] 16.1.4 Structured vulnerability matching: `ecosystem` + `package_name` columns (migration `000013`), `PackageIdentityMatch`, version ranges
- [x] 16.1.5 Map PURL types to OSV ecosystem names (`apk`→`Alpine`, `deb`→`Debian`, etc.); skip unsupported types (`rpm`, `generic`, `oci`) without failing ingest
- [ ] 16.1.6 Normalize distro package names for OSV queries (e.g. Alpine PURL `alpine/openssl` → OSV `openssl`); extend `PackageIdentityMatch` for suffix alignment
- [ ] 16.1.7 Integration test: Alpine `apk` SBOM fixture → ingest reaches `NOTIFIED` → non-zero `component_vulnerabilities`
- [ ] 16.1.8 Integration test: unsupported `rpm` SBOM → ingest succeeds → components stored → OSV skipped (zero or sparse findings documented)

### 16.2 Operator experience and docs

- [x] 16.2.1 README: SBOM upload envelope, ingestion `stage_detail` debugging, trust-gate prerequisites (image digest registration)
- [x] 16.2.2 README: OSV ecosystem mapping table and per-distro expectations (Alpine, Debian, Rocky/RHEL `rpm`, nginx-on-Alpine)
- [ ] 16.2.3 REST API to register images (replace manual `INSERT INTO images` SQL documented in README step 4)
- [ ] 16.2.4 Optional upload helper script or `make upload-sbom` target wrapping `jq` envelope build
- [ ] 16.2.5 Merge `themis-phase-2` correlation/OSV/README changes to `main` and tag post-hardening release

### 16.3 Quality gates (follow-up)

- [ ] 16.3.1 `make coverage-pkg PKG=adapter/store` ≥ 90% (register packages touched by migration `000013` / vulnerability store if needed)
- [ ] 16.3.2 `make coverage-pkg PKG=adapter/osv` — register in `scripts/check-coverage.sh` if package grows beyond ad-hoc tests
- [ ] 16.3.3 Full `make check` on `main` after merge of group 16.1–16.2

---

## Explicitly deferred (Phase 2 / Phase 3 — not Phase 1 tasks)

These are documented in `design.md` and `proposal.md`. Do not add to Phase 1 completion criteria.

| Area | Deferred to | Notes |
| ---- | ----------- | ----- |
| AI enrichment (LLM risk analysis) | Phase 2 | L3 signals beyond VEX |
| EPSS / KEV sync | Phase 2 | Temporal scoring inputs |
| Real cosign / sigstore verification | Phase 2 | `StubVerifier` today |
| Git / GitHub / GitLab ingestion | Phase 2 | Same `IngestionService` pipeline |
| Jenkins shared library / CI automation | Phase 2 | Webhook exists for manual test |
| React SPA / native UI | Phase 3 | API-only in Phase 1 |
| Docker production stack / compose | Phase 3 | Standalone binary + Postgres |
| Redis job queue (durable async) | Phase 3 | `InProcessQueue` today |
| Row-level security (DB) | Phase 3 | API key scope at query layer |
| RPM / RHEL / Rocky Linux OSV correlation | Phase 2+ | `rpm` PURL type skipped; sparse NVD CPE match only |
| Configurable debug log level | Phase 2 | `runtime-observability` change |
| DefectDojo / external tool UI integrations | Phase 2+ | Out of OpenSpec Phase 1 |
