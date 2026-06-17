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
