## MODIFIED Requirements

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
