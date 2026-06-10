## ADDED Requirements

### Requirement: VEX export endpoint
The system SHALL provide `GET /api/v1/products/{id}/versions/{v}/vex` to export
the computed VEX state for all findings of a product version as a
standards-compliant document. The format is negotiated via the `?format=` query
parameter or the `Accept` header (default: `cyclonedx`).

#### Scenario: CycloneDX VEX document returned
- **WHEN** `GET /api/v1/products/{id}/versions/{v}/vex?format=cyclonedx` is called
- **THEN** the system SHALL return an HTTP 200 with `Content-Type: application/json`
  containing a CycloneDX 1.5+ VEX document. Each `risk_context` row for the
  product version SHALL appear as a `vulnerabilities[]` entry with `bom-ref`,
  `id` (CVE ID), `analysis.state`, and `ratings.score`

#### Scenario: OpenVEX document returned
- **WHEN** `GET /api/v1/products/{id}/versions/{v}/vex?format=openvex` is called
- **THEN** the system SHALL return an OpenVEX 0.2+ compliant JSON document
  containing all VEX statements for the product version

#### Scenario: Non-normative extension fields present in CycloneDX output
- **WHEN** a CycloneDX VEX export is generated for a finding with EPSS and
  KEV data available
- **THEN** the output SHALL include non-normative extension fields:
  `x-themis-epss-score` (float), `x-themis-kev-listed` (bool), and
  `x-themis-blast-radius` (integer)

#### Scenario: Product version not found → 404
- **WHEN** the `product_id` or version `v` does not exist in the database
- **THEN** the system SHALL return `404` with error code `PRODUCT_NOT_FOUND`

---

### Requirement: VEX precedence in export
The export SHALL reflect the VEX precedence order:
`human_triage > user_supplied > ai_generated > upstream_vendor`. Human VEX
assertions SHALL always take precedence over upstream vendor VEX for the same
`(component_purl, cve_id)` pair.

#### Scenario: Human VEX overrides upstream vendor VEX in export
- **WHEN** both a human triage decision (e.g. `not_affected`) and an upstream
  vendor VEX assertion (e.g. `affected`) exist for the same finding
- **THEN** the export SHALL reflect the human triage decision, not the
  upstream vendor assertion

#### Scenario: Upstream vendor VEX used when no human decision exists
- **WHEN** no human triage decision exists for a finding but an upstream vendor
  VEX assertion does
- **THEN** the export SHALL reflect the upstream vendor assertion state

---

### Requirement: VEX coverage aggregate endpoint
The system SHALL provide `GET /api/v1/products/{id}/versions/{v}/vex-coverage`
to return a summary of upstream VEX coverage across all findings for the product version.

#### Scenario: Coverage counts returned
- **WHEN** `GET /api/v1/products/{id}/versions/{v}/vex-coverage` is called
- **THEN** the response SHALL include integer fields `covered`, `not_covered`,
  and `purl_mismatch` representing the count of findings in each coverage state
