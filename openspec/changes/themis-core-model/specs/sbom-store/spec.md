## ADDED Requirements

### Requirement: Composition and scan are stored in separate tables
The system SHALL store artifact composition and temporal scan results in two distinct tables:
`sboms` (an uploaded bill of materials, keyed `(artifact_id, sbom_checksum)`; Layer 1 immutable
inventory) and `scan_reports` (one correlation run's findings at a point in time — many rows per
artifact). `component_versions` and `dependency_relationships` SHALL reference `sboms`;
`scan_reports` SHALL reference the `sboms` row it correlated (`sbom_id`) and carry a denormalized
`artifact_id`; `component_vulnerabilities` SHALL reference `scan_reports`.

#### Scenario: Re-correlating an uploaded SBOM appends a scan report
- **WHEN** the same uploaded SBOM (same `(artifact_id, sbom_checksum)`) is re-correlated over
  time
- **THEN** the system SHALL reuse the existing `sboms` row and append a new `scan_reports` row
  for the new correlation run

#### Scenario: A divergent SBOM for the same artifact is a new composition
- **WHEN** a second SBOM with a different checksum (e.g. a different tool/format, or a corrected
  upload) is ingested for the same artifact
- **THEN** the system SHALL create an additional `sboms` row keyed on the new
  `(artifact_id, sbom_checksum)`, and SHALL NOT orphan its components or findings against a
  different composition

#### Scenario: Latest scan derived from scanned_at
- **WHEN** the system needs the latest scan for an artifact
- **THEN** it SHALL select `FROM scan_reports WHERE artifact_id = $1 ORDER BY scanned_at DESC
  LIMIT 1` without relying on any `is_latest` flag

#### Scenario: Findings link to a scan report
- **WHEN** a scan correlates vulnerabilities for an artifact
- **THEN** each `component_vulnerabilities` row SHALL reference the `scan_reports` row for that
  scan via `scan_report_id`

### Requirement: Durable enrichment is keyed on stable identity
The system SHALL key durable Layer-2/3 judgment records on the stable identity
`(artifact_id, component_purl, cve_id)` rather than on the per-scan `component_vulnerability_id`,
so that judgments survive rescans and are not recomputed. This SHALL apply to `risk_context`,
`triage_history`, `remediation_actions`, and `intelligence_signals`. `runtime_exposures` SHALL key
on `(artifact_id, component_purl, cve_id, environment)`. Only the raw finding
(`component_vulnerabilities`) remains per-scan. The contract SHALL hold for any future enrichment
table: artifact-specific judgments key on the stable identity; CVE-global knowledge keys on
`cve_id`.

#### Scenario: Remediation status survives a rescan
- **WHEN** a remediation action for a finding is `in_progress` and the artifact is rescanned
- **THEN** the system SHALL retain the `in_progress` `remediation_actions` row against
  `(artifact_id, component_purl, cve_id)` rather than resetting it for the new scan's finding row

#### Scenario: Triage history is continuous across rescans
- **WHEN** a finding's `(artifact_id, component_purl, cve_id)` has triage history and the artifact
  is rescanned
- **THEN** the system SHALL return the full prior `triage_history` for that identity, not a
  history fragmented per scan

#### Scenario: Intelligence signals attach to the stable identity
- **WHEN** an enrichment signal is recorded for a finding and the artifact is later rescanned
- **THEN** the signal SHALL remain associated with `(artifact_id, component_purl, cve_id)` and be
  visible on the latest scan's finding without recomputation

#### Scenario: Future enrichment tables follow the contract
- **WHEN** a new durable enrichment table is added (e.g. a Phase 2b AI output table)
- **THEN** it SHALL key artifact-specific judgments on `(artifact_id, component_purl, cve_id)` and
  CVE-global knowledge on `cve_id`, and SHALL NOT key on the per-scan `component_vulnerability_id`

### Requirement: Current findings are scoped to the latest scan report
The system SHALL define an artifact's "current findings" as exactly the
`component_vulnerabilities` whose `scan_report_id` is the latest `scan_reports` row for the
artifact. Every read path that counts or lists findings (status, SBOM/scan listing, VEX export,
blast-radius, scan detail) SHALL apply this latest-scan scope through a single shared filter (a
shared helper or SQL view), so prior scans' findings are never double-counted.

#### Scenario: Counts reflect only the latest scan
- **WHEN** an artifact has been scanned three times and a caller requests its vulnerability
  counts
- **THEN** the system SHALL count only the findings of the latest `scan_reports` row, not the sum
  across all three scans

#### Scenario: Read paths use the shared latest-scan filter
- **WHEN** any findings-bearing read path (status, listing, VEX export, blast-radius, scan
  detail) executes
- **THEN** it SHALL resolve current findings through the shared latest-scan filter rather than an
  ad-hoc per-query join

### Requirement: Finding identity is denormalized for triage
The system SHALL denormalize the version-qualified `component_purl` (reconstructed from
`components.purl` and `component_versions.version`, e.g. `pkg:apk/busybox@1.36`) and the `cve_id`
onto each `component_vulnerabilities` row at correlation time, so that `risk_context` — keyed on
`(artifact_id, component_purl, cve_id)` — can be formed without fragile multi-table joins and
without collapsing distinct installed versions of a package.

#### Scenario: Version-qualified purl recorded on the finding
- **WHEN** a finding is correlated for `busybox` version `1.36` against `CVE-2024-1234`
- **THEN** the `component_vulnerabilities` row SHALL store `component_purl = pkg:apk/busybox@1.36`
  and `cve_id = CVE-2024-1234`

#### Scenario: Distinct versions are distinct triage identities
- **WHEN** an artifact contains `busybox@1.35` and `busybox@1.36`, both matching the same CVE
- **THEN** the system SHALL treat them as two distinct `(artifact_id, component_purl, cve_id)`
  identities, so triaging one SHALL NOT suppress the other

### Requirement: Triage context keyed on artifact-relative identity
The system SHALL key `risk_context` on the primary key `(artifact_id, component_purl, cve_id)`
rather than `component_vulnerability_id`, so that triage and risk context attach to the
artifact-relative identity of a finding and persist across rescans.

#### Scenario: Risk context survives a rescan
- **WHEN** an artifact is rescanned, producing new `component_vulnerabilities` rows for the
  same `(component_purl, cve_id)`
- **THEN** the existing `risk_context` row keyed on `(artifact_id, component_purl, cve_id)`
  SHALL remain associated with the finding and SHALL NOT be orphaned

#### Scenario: Risk context upserted on identity
- **WHEN** risk context is written for a finding
- **THEN** the system SHALL upsert on `(artifact_id, component_purl, cve_id)` rather than
  inserting a new per-scan row

## MODIFIED Requirements

### Requirement: Three-layer PostgreSQL schema
The system SHALL implement the three-layer data model in PostgreSQL with Layer 1 (immutable
inventory), Layer 2 (mutable vulnerability intelligence), and Layer 3 (temporal exploitability
context) as distinct logical groups of tables. Schema migrations SHALL be managed with
`golang-migrate`. The base migrations are greenfield for the `v0.3.0` model; no in-place data
migration from the prior `sbom_documents` model is provided.

#### Scenario: Layer 1 entities are append-only
- **WHEN** the system attempts to update or delete a row in `sboms`, `scan_reports`,
  `components`, `component_versions`, `component_vulnerabilities`, or `vulnerabilities`
- **THEN** the operation SHALL be prevented (enforced via application logic; no content
  `UPDATE` or hard `DELETE` statements on Layer 1 tables). A `scan_report` is frozen once
  written; re-correlation and re-enrichment SHALL either append a new `scan_reports` row or
  update `risk_context` (Layer 2), never mutate an existing scan report

#### Scenario: Scan report soft-delete is a tombstone, not a mutation
- **WHEN** a `scan_reports` row is soft-deleted via the SBOM delete API
- **THEN** the system SHALL set `deleted_at` only, leaving the recorded scan facts unchanged,
  and SHALL NOT update the finding content of that scan report

#### Scenario: Migrations run on startup
- **WHEN** Themis starts and the database schema version is behind the binary version
- **THEN** the system SHALL apply pending migrations before accepting requests

#### Scenario: Startup fails on schema ahead of binary
- **WHEN** the database schema version is ahead of the binary version
- **THEN** the system SHALL refuse to start and log an actionable error message

#### Scenario: Upgrade from prior model requires re-initialisation
- **WHEN** an operator upgrades from a database created under the pre-`v0.3.0` `sbom_documents`
  model
- **THEN** the supported path SHALL be to re-initialise the database (drop and recreate, then
  `migrate-up`); in-place migration of existing data is not supported

### Requirement: Product and product version storage
The system SHALL store `products`, `projects`, and `versions` as the organizational hierarchy.
Products group projects; projects group versions (`versions.project_id` is NOT NULL); versions
group artifacts into a named release. A default project SHALL be auto-created on product
registration.

#### Scenario: Product created via API
- **WHEN** a caller posts to `POST /api/v1/products`
- **THEN** the system SHALL create a product record (and its default project) and return the
  product `id` and `name`

#### Scenario: Version created under a project
- **WHEN** a caller posts to `POST /api/v1/projects/{id}/versions`
- **THEN** the system SHALL create a `versions` record with `project_id` referencing the project

#### Scenario: Products listed with pagination
- **WHEN** a caller queries `GET /api/v1/products`
- **THEN** the system SHALL return a paginated list with cursor-based pagination

### Requirement: Image and artifact storage
The system SHALL store artifacts in a single `artifacts` table identified by their SHA-256
`image_digest`, which SHALL be globally UNIQUE (same digest = same physical content = same
artifact). Tags SHALL be stored as mutable aliases. The separate `images` table SHALL NOT
exist; image identity is the digest on `artifacts`.

#### Scenario: Artifact identity is digest-based and globally unique
- **WHEN** two registrations are submitted with the same `image_digest`
- **THEN** the system SHALL store one `artifacts` row and SHALL NOT create a duplicate; the
  digest UNIQUE constraint SHALL enforce single ownership by one version

#### Scenario: Artifact registered before SBOM ingestion
- **WHEN** an SBOM upload references an `image_digest` not yet present in `artifacts`
- **THEN** the system SHALL require artifact registration first (enforced by the integrity
  chain check)

### Requirement: SBOM and VEX raw document storage
The system SHALL store the complete raw SBOM and VEX documents as JSONB in `sboms.raw_document`
and `vex_documents.raw_document` respectively. These fields SHALL be immutable after first
write. `vex_documents` SHALL reference `artifacts` (not a scan-document row).

#### Scenario: Raw document stored on ingestion
- **WHEN** an SBOM is ingested and normalized
- **THEN** `sboms.raw_document` SHALL contain the exact bytes received, parseable as JSON

#### Scenario: Raw document not overwritten on duplicate
- **WHEN** a duplicate SBOM (same dedup key) is submitted for an existing artifact
- **THEN** the existing `sboms.raw_document` SHALL remain unchanged

### Requirement: Dependency graph storage
The system SHALL store SBOM dependency relationships in `dependency_relationships` with
`from_component_version_id`, `to_component_version_id`, `relationship_type`, `scope`, and
`depth` (1 = direct, 2+ = transitive). `dependency_relationships` SHALL reference `sboms` via
`sbom_id`.

#### Scenario: Direct dependency marked with depth 1
- **WHEN** a CycloneDX document contains a component listed in the root `dependencies` array
- **THEN** the system SHALL store the edge with `depth=1` and `scope=runtime` (unless scope is
  specified)

#### Scenario: Transitive dependency stored with depth
- **WHEN** a CycloneDX document contains nested `dependsOn` entries
- **THEN** the system SHALL resolve the transitive depth and store each edge with the correct
  `depth` value
