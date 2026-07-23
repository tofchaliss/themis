# ai-enrichment

## ADDED Requirements

### Requirement: Advisory AI summary for eligible findings

The system SHALL produce, for each eligible finding (severity high OR `kev_listed` OR
`exploit_public`) when AI enrichment is enabled, a structured advisory result containing a
plain-language summary (≤500 characters), a primary weakness (a CWE id present in the finding's
context, or null), and up to five key factors. The result SHALL be produced by an external AI
framework (`themis-ai`) grounded in the finding's authoritative context, not by the Go backend.

#### Scenario: Eligible finding is summarized

- **WHEN** AI enrichment is enabled and a finding is eligible by the gate
- **THEN** the system SHALL make the finding's context available to the AI framework, which SHALL
  produce a validated `{ summary, primary_weakness, key_factors }` result and store it

#### Scenario: Ineligible finding is not enriched

- **WHEN** a finding does not satisfy the gate (not high, not KEV, not exploit-public)
- **THEN** the system SHALL NOT enrich it, and its AI status SHALL read `ineligible`

### Requirement: AI enrichment is advisory-only

The system SHALL NOT allow AI enrichment to change a finding's `effective_state`. AI output is
context surfaced to analysts; state changes SHALL continue to require a human triage decision.

#### Scenario: Enrichment never suppresses a finding

- **WHEN** the AI framework produces a summary for a finding
- **THEN** the finding's `effective_state` SHALL be unchanged, and no VEX assertion SHALL be
  created from the AI output

### Requirement: AI enrichment status and detail are observable

The system SHALL expose an `ai_status` (and reason) on the finding enrichment object surfaced by
the findings endpoints, and SHALL provide a detail endpoint returning the latest full AI result for
a finding. The `disabled` and `ineligible` statuses SHALL be derived at read time.

#### Scenario: Status is visible on a finding

- **WHEN** a caller lists vulnerabilities for a scan, product, project, or version
- **THEN** each finding's enrichment object SHALL include an `ai_status` reflecting its enrichment
  lifecycle (or a derived `disabled`/`ineligible`)

#### Scenario: Full AI record is retrievable

- **WHEN** a caller requests `GET /api/v1/vulnerabilities/{id}/ai` for an enriched finding
- **THEN** the system SHALL return the latest AI result with its reproducibility record, and SHALL
  return 404 when no result exists

### Requirement: Graceful degradation when the AI framework is unavailable

The system SHALL keep all non-AI behaviour fully functional when the AI framework is unavailable.
Ingestion, correlation, L0/L1 enrichment, and findings queries SHALL NOT depend on the AI framework.

#### Scenario: AI framework down

- **WHEN** the `themis-ai` framework is unreachable
- **THEN** the backend SHALL continue to ingest, correlate, and serve findings, and affected
  findings SHALL report an AI status indicating enrichment is pending, not an error on the finding

### Requirement: AI results are reproducible

Every stored AI result SHALL carry a reproducibility record: the model identity and version, the
prompt version, the generation parameters, token counts, and a hash of the semantic input context.

#### Scenario: Stored result carries provenance

- **WHEN** an AI result is stored
- **THEN** it SHALL include the model version, prompt version, parameters, token counts, and the
  input-context hash sufficient to reproduce or audit the generation
