## ADDED Requirements

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
