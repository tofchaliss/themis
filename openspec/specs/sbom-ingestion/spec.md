# SBOM Ingestion Specification

## Purpose
Orchestrate the asynchronous trust to parse to store to enrich to notify ingestion pipeline with idempotency and lifecycle tracking.
## Requirements
### Requirement: Manual SBOM upload endpoint
The system SHALL expose `POST /api/v1/sbom/upload` accepting a multipart or JSON body containing a pre-generated SBOM document (CycloneDX or SPDX) and optional VEX document. The endpoint SHALL return `202 Accepted` immediately and process the artifact asynchronously.

#### Scenario: Upload accepted and queued
- **WHEN** a caller posts a valid CycloneDX SBOM to `/api/v1/sbom/upload` with a valid `X-API-Key`
- **THEN** the system SHALL respond with HTTP 202, a JSON body containing `{"ingestion_id": "<uuid>", "status": "RECEIVED"}`, and enqueue the artifact for async processing

#### Scenario: Upload with idempotency key is safe to retry
- **WHEN** a caller posts the same SBOM twice with the same `Idempotency-Key` header
- **THEN** the second request SHALL return HTTP 200 with the same `ingestion_id` as the first, with no reprocessing

#### Scenario: Upload without API key rejected
- **WHEN** a caller posts to `/api/v1/sbom/upload` without an `X-API-Key` header
- **THEN** the system SHALL return HTTP 401

#### Scenario: Upload payload exceeding size limit rejected
- **WHEN** a caller posts an SBOM exceeding the configured max upload size (default: 50 MB)
- **THEN** the system SHALL return HTTP 413 before reading the body

---

### Requirement: CI webhook endpoint
The system SHALL expose `POST /api/v1/webhooks/scan` for receiving container image build notifications from CI/CD systems. The endpoint SHALL be callable manually for testing in Phase 1 and SHALL validate the `X-Themis-Signature` HMAC-SHA256 header before processing.

#### Scenario: Valid webhook accepted
- **WHEN** a CI system POSTs a webhook payload with a valid `X-Themis-Signature`
- **THEN** the system SHALL respond with HTTP 202 and enqueue the artifact for processing

#### Scenario: Webhook with invalid signature rejected
- **WHEN** a webhook request arrives with an incorrect `X-Themis-Signature`
- **THEN** the system SHALL return HTTP 401 and write a security audit log entry

#### Scenario: Webhook without signature rejected
- **WHEN** a webhook request arrives with no `X-Themis-Signature` header
- **THEN** the system SHALL return HTTP 401

---

### Requirement: Asynchronous ingestion pipeline via job queue
The system SHALL process every ingested SBOM and VEX document through a `JobQueue` interface. The HTTP handler SHALL enqueue the job and return immediately. A worker pool SHALL consume jobs and drive them through the full pipeline: validate → parse → correlate → enrich → notify. A single SBOM ingest SHALL persist composition and scan results as separate rows: one `sboms` row keyed `(artifact_id, sbom_checksum)` for the uploaded bill of materials, and one `scan_reports` row for the correlation run. Ingestion SHALL be idempotent: an identical re-submission SHALL NOT create duplicate `sboms` or `scan_reports` rows.

#### Scenario: Pipeline drives through all stages
- **WHEN** a SBOM ingestion job is dequeued by a worker
- **THEN** the worker SHALL invoke the ingestion pipeline stages in order: artifact-trust validation, sbom-parser normalization, vulnerability correlation, VEX overlay enrichment, risk_context population, and notification dispatch

#### Scenario: Ingest writes one sbom and one scan report
- **WHEN** an SBOM is ingested for an artifact for the first time
- **THEN** the system SHALL create one `sboms` row keyed `(artifact_id, sbom_checksum)` and one `scan_reports` row referencing it, with `component_vulnerabilities` linked to that `scan_reports` row

#### Scenario: Divergent SBOM creates a new composition row
- **WHEN** an SBOM with a different `sbom_checksum` (different tool/format or corrected upload) is ingested for the same artifact
- **THEN** the system SHALL create an additional `sboms` row for the new `(artifact_id, sbom_checksum)` and correlate the new scan against it

#### Scenario: Identical re-submission is idempotent
- **WHEN** the same SBOM content is re-submitted (matching `(sbom_id, scan_checksum)` and any honored `Idempotency-Key`), e.g. a client retry or at-least-once queue redelivery
- **THEN** the system SHALL return the existing `scan_reports` row and SHALL NOT append a duplicate scan or re-run correlation

#### Scenario: Genuine re-correlation appends a scan report
- **WHEN** an artifact's uploaded SBOM is deliberately re-correlated as the CVE database evolves (new `scan_checksum`)
- **THEN** the system SHALL reuse the existing `sboms` row and append a new `scan_reports` row, leaving prior scan reports intact

#### Scenario: Worker pool size is configurable
- **WHEN** Themis starts with `THEMIS_WORKER_POOL_SIZE=8` environment variable
- **THEN** the system SHALL maintain 8 concurrent goroutine workers consuming from the job queue

#### Scenario: Failed job marked retryable
- **WHEN** a pipeline stage returns a retryable error (e.g., database timeout, CVE feed timeout)
- **THEN** the system SHALL mark the ingestion status as `FAILED` and re-enqueue the job with exponential backoff up to a configurable maximum retry count (default: 3)

### Requirement: Ingestion status query endpoint
The system SHALL expose `GET /api/v1/ingestions/{id}` returning the current processing status, stage, and error detail (if any) for a given ingestion.

#### Scenario: Status returned for in-progress ingestion
- **WHEN** a caller queries `/api/v1/ingestions/{id}` while the job is being processed
- **THEN** the system SHALL return HTTP 200 with `{"status": "CORRELATING", "ingestion_id": "...", "started_at": "..."}`

#### Scenario: Completed ingestion returns scan reference
- **WHEN** a caller queries `/api/v1/ingestions/{id}` after completion
- **THEN** the system SHALL return HTTP 200 with `status=COMPLETED` and a `scan_id` reference for querying results

#### Scenario: Unknown ingestion ID returns 404
- **WHEN** a caller queries `/api/v1/ingestions/{id}` with an ID that does not exist
- **THEN** the system SHALL return HTTP 404 with RFC 7807 problem details

---

### Requirement: VEX document upload and linking
The system SHALL accept VEX documents (OpenVEX or CSAF format) via `POST /api/v1/vex/upload`. Each submitted VEX SHALL reference a known `sbom_checksum` (integrity chain requirement). Upon successful ingestion, the system SHALL trigger a re-enrichment of all `risk_context` records affected by the new VEX assertions.

#### Scenario: VEX document accepted and linked to SBOM
- **WHEN** a caller uploads a VEX document referencing a known `sbom_checksum`
- **THEN** the system SHALL store the VEX document, link it to the SBOM, and trigger async re-enrichment for affected (component, vulnerability) pairs

#### Scenario: VEX referencing unknown SBOM rejected
- **WHEN** a caller uploads a VEX document with a `sbom_checksum` not in the database
- **THEN** the system SHALL return HTTP 422 with the message "SBOM not found — ingest parent first"

---

### Requirement: Ingestion lifecycle state tracking
The system SHALL track and persist the lifecycle state of every ingestion through the states: `RECEIVED → VALIDATING → CORRELATING → ENRICHING → COMPLETED → NOTIFIED`. Terminal states `REJECTED` and `FAILED` SHALL be persisted with reason detail.

#### Scenario: State transitions persisted in order
- **WHEN** a SBOM moves through the pipeline stages
- **THEN** each state transition SHALL be persisted with a timestamp so the full lifecycle is queryable

#### Scenario: Rejected ingestion records reason
- **WHEN** an ingestion is rejected at the trust gate
- **THEN** the system SHALL persist `status=REJECTED`, the rejection reason, and the stage at which rejection occurred

---

### Requirement: Scan history endpoint
The system SHALL expose `GET /api/v1/projects/{id}/scans` returning paginated scan history for a project, and `GET /api/v1/scans/{id}` returning full scan detail including SBOM summary, vulnerability counts by severity, and ingestion metadata. Scan history SHALL be backed by `scan_reports` ordered by `scanned_at DESC`; "latest scan" SHALL be the most recent `scan_reports` row for the artifact, with no `is_latest` flag.

#### Scenario: Scan list paginated
- **WHEN** a caller queries scan history with `?limit=50`
- **THEN** the system SHALL return up to 50 scan records (from `scan_reports`, newest first) with a `next_cursor` for continuation

#### Scenario: Scan detail includes vulnerability summary
- **WHEN** a caller queries `GET /api/v1/scans/{id}`
- **THEN** the response SHALL include `vulnerability_counts` grouped by severity (critical, high, medium, low, none) and `trust_status` for the SBOM and VEX documents

#### Scenario: Latest scan is the most recent scan report
- **WHEN** an artifact has multiple scan reports
- **THEN** the system SHALL treat the row with the greatest `scanned_at` as the latest scan without consulting any `is_latest` column

### Requirement: Alpine package-name normalization for OSV correlation
The system SHALL normalize Alpine package names before querying OSV so that SBOM components
match OSV ecosystem entries. Normalization SHALL strip the shared-object `so:` prefix and map
`py3-<name>` to `python3-<name>` (and equivalent known Alpine naming conventions) prior to the
OSV lookup. This normalization SHALL apply to both ingest-time correlation and the background
CVE-watch correlation, which share the OSV adapter.

#### Scenario: so:-prefixed package normalized before lookup
- **WHEN** an Alpine SBOM component is named `so:libssl3` (a shared-object provider name)
- **THEN** the system SHALL query OSV with the normalized package name rather than the raw
  `so:`-prefixed string

#### Scenario: py3- package mapped to python3-
- **WHEN** an Alpine SBOM component is named `py3-requests`
- **THEN** the system SHALL query OSV using `python3-requests`

### Requirement: Alpine and rpm SBOM ingest correlation coverage
The system SHALL be covered by integration tests that ingest an Alpine `apk` SBOM and an rpm
SBOM end to end. The Alpine test SHALL assert non-zero `component_vulnerabilities` from OSV
correlation; the rpm test SHALL assert that ingestion succeeds and the unsupported OSV
ecosystem is skipped cleanly without failing the ingest.

#### Scenario: Alpine SBOM ingest produces OSV-matched findings
- **WHEN** an Alpine `apk` SBOM with known-vulnerable packages is ingested
- **THEN** the integration test SHALL observe non-zero `component_vulnerabilities` created via
  OSV correlation

#### Scenario: rpm SBOM ingest skips unsupported ecosystem cleanly
- **WHEN** an rpm-based SBOM is ingested
- **THEN** ingestion SHALL complete successfully and the rpm OSV-skip SHALL be logged without
  marking the ingestion FAILED

### Requirement: Component-mismatch correlation diagnostics are logged
The system SHALL log every condition under which a component is dropped or unmatched during
OSV correlation, so that no component silently disappears from the pipeline. The system SHALL
use structured fields (component PURL, ecosystem, name, version, and reason) and SHALL choose
levels that make real problems visible without flooding logs on expected skips:

- unsupported OSV ecosystem (e.g. `rpm`, `oci`, `generic`) SHALL be logged per component at
  `DEBUG`, and the system SHALL additionally emit one aggregate summary per ingest at `INFO`
  (count of skipped components grouped by ecosystem);
- a missing/empty component name or unparseable PURL SHALL be logged at `WARN` (data-quality
  signal), not silently dropped;
- package-identity and version-range non-matches SHALL be logged at `DEBUG`.

Correlation failures that abort a stage SHALL continue to be logged at `ERROR` with the stage
and cause. Logging SHALL NOT change correlation behaviour (no findings added or removed).

#### Scenario: Unsupported ecosystem skip is visible in logs
- **WHEN** an rpm SBOM is correlated and its components have no OSV ecosystem mapping
- **THEN** each skipped component SHALL be logged at `DEBUG` with `reason=unsupported_ecosystem`
  and one `INFO` summary SHALL report the total skipped grouped by ecosystem

#### Scenario: Malformed/empty PURL surfaced at WARN
- **WHEN** a component has an empty name or a PURL that cannot be parsed
- **THEN** the system SHALL log a `WARN` with the raw PURL and `reason=malformed_purl`, and
  ingestion SHALL continue

#### Scenario: Identity/version non-match is traceable at DEBUG
- **WHEN** an OSV record is returned but the package identity or version range does not match
  the component
- **THEN** the system SHALL log a `DEBUG` entry with the component and OSV identifiers and the
  specific reason (`identity_mismatch` or `version_no_match`)

