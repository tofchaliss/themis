## ADDED Requirements

### Requirement: Pluggable parser adapter interface
The system SHALL define a `SBOMAdapter` interface that all format-specific parsers implement. Core domain code SHALL only depend on this interface, never on format-specific structs. Adding a new adapter SHALL require zero changes to core domain logic.

#### Scenario: Adapter selected by format discriminator
- **WHEN** an SBOM document is submitted with `format=cyclonedx`
- **THEN** the system SHALL route it to the CycloneDX adapter exclusively

#### Scenario: Unsupported format rejected at parser
- **WHEN** an SBOM document is submitted with a format not registered in the adapter registry
- **THEN** the system SHALL reject with HTTP 422 and list the supported formats

---

### Requirement: CycloneDX adapter
The system SHALL implement a CycloneDX adapter supporting CycloneDX JSON format (spec versions 1.4, 1.5, and 1.6). The adapter SHALL normalize the document into the internal `CanonicalSBOM` model, extracting all components, PURLs, dependency relationships, and vulnerability data.

#### Scenario: CycloneDX component extracted with PURL
- **WHEN** a CycloneDX document contains a component with a valid PURL (`purl` field)
- **THEN** the adapter SHALL map it to a `CanonicalComponent` with `purl`, `name`, `version`, `ecosystem`, and `licenses` populated

#### Scenario: CycloneDX dependency graph extracted
- **WHEN** a CycloneDX document contains a `dependencies` array
- **THEN** the adapter SHALL extract all `dependsOn` relationships as `CanonicalDependencyEdge` records with `from_purl`, `to_purl`, and `relationship_type=depends_on`

#### Scenario: CycloneDX component without PURL skipped with warning
- **WHEN** a CycloneDX document contains a component without a `purl` field
- **THEN** the adapter SHALL skip that component and log a structured warning with the component name and version

#### Scenario: CycloneDX vulnerability metadata extracted
- **WHEN** a CycloneDX document contains a `vulnerabilities` section
- **THEN** the adapter SHALL extract each vulnerability as a `CanonicalVulnerability` with `cve_id`, `severity`, `cvss_score`, `cvss_vector`, and `affected_purls`

---

### Requirement: SPDX adapter
The system SHALL implement an SPDX adapter supporting SPDX JSON format (spec versions 2.3 and 3.0). The adapter SHALL normalize the document into the same `CanonicalSBOM` model used by the CycloneDX adapter.

#### Scenario: SPDX package extracted as component
- **WHEN** an SPDX document contains a `packages` entry with an `externalRefs` field of type `PACKAGE-MANAGER`
- **THEN** the adapter SHALL derive the PURL from the external reference and map it to a `CanonicalComponent`

#### Scenario: SPDX relationship extracted as dependency edge
- **WHEN** an SPDX document contains a `DEPENDS_ON` relationship between two packages
- **THEN** the adapter SHALL extract it as a `CanonicalDependencyEdge`

#### Scenario: SPDX license information preserved
- **WHEN** an SPDX package declares a `licenseConcluded` or `licenseDeclared`
- **THEN** the adapter SHALL include the license in the `CanonicalComponent.licenses` field

---

### Requirement: Trivy output adapter
The system SHALL implement an adapter for Trivy's JSON output format. This is the first scanner-specific adapter and SHALL demonstrate the pluggable pattern. The adapter SHALL parse Trivy vulnerability results and map them to `CanonicalVulnerability` records.

#### Scenario: Trivy vulnerability result mapped to canonical form
- **WHEN** a Trivy JSON output is ingested containing a `Results` array with `Vulnerabilities`
- **THEN** the adapter SHALL map each entry to a `CanonicalVulnerability` with `cve_id`, `severity`, `cvss_score`, `fix_versions`, and `affected_purl`

#### Scenario: Trivy target mapped to component
- **WHEN** a Trivy JSON output contains a `Target` field
- **THEN** the adapter SHALL derive the component `purl` from the target and its package metadata

---

### Requirement: Canonical model — no format leakage
The system SHALL ensure that no CycloneDX, SPDX, or Trivy type names, field names, or struct references appear in any package outside of their respective adapter packages. The internal domain SHALL operate exclusively on `CanonicalSBOM`, `CanonicalComponent`, `CanonicalDependencyEdge`, and `CanonicalVulnerability`.

#### Scenario: Core domain import test
- **WHEN** the codebase is compiled
- **THEN** no import of CycloneDX or SPDX format packages SHALL appear in `internal/domain`, `internal/store`, `internal/enrichment`, or `internal/triage` packages

---

### Requirement: Raw document preservation
The system SHALL store the original unmodified raw document (as received) alongside the normalized canonical form. The raw document SHALL be stored as JSONB in `sbom_documents.raw_document`.

#### Scenario: Raw document retrievable after normalization
- **WHEN** a SBOM has been parsed and normalized
- **THEN** the original byte-for-byte raw document SHALL be queryable via the scan detail endpoint

---

### Requirement: Component count limits
The system SHALL enforce a configurable maximum component count per SBOM (default: 50,000 components) and a configurable parsing timeout (default: 5 minutes). Documents exceeding either limit SHALL be rejected.

#### Scenario: Oversized SBOM rejected
- **WHEN** a SBOM document contains more components than the configured maximum
- **THEN** the system SHALL reject the ingestion with status `REJECTED` and a descriptive error message

#### Scenario: Slow parsing aborted
- **WHEN** parsing a SBOM exceeds the configured timeout
- **THEN** the system SHALL abort parsing, mark the ingestion as `FAILED`, and log the timeout with document size
