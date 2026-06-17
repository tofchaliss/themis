## ADDED Requirements

### Requirement: OSV CVSS vector parsing to numeric base score
The system SHALL parse CVSS vector strings returned by OSV (e.g. `CVSS:3.1/AV:N/AC:L/...`)
into a numeric base score and store both the numeric `cvss_score` and the original
`cvss_vector` on the vulnerability record. The system SHALL accept CVSS v3.x severity entries
and SHALL NOT leave `cvss_score = 0` when a parseable vector is present.

#### Scenario: v3.1 vector parsed to base score
- **WHEN** an OSV record provides `severity` as a `CVSS:3.1/...` vector string
- **THEN** the system SHALL compute the numeric base score, store it in `cvss_score`, and
  store the vector string in `cvss_vector`

#### Scenario: Status and risk reflect real CVSS after parsing
- **WHEN** a finding has a parsed CVSS base score and `GET /api/v1/status?top=N` is called
- **THEN** the affected component's `highest_cvss_score` SHALL reflect the parsed value rather
  than `0`

#### Scenario: Plain numeric score still accepted
- **WHEN** an OSV record provides a plain numeric severity (e.g. `"7.5"`)
- **THEN** the system SHALL store it as `cvss_score = 7.5` as before

#### Scenario: Unparseable severity does not block ingestion
- **WHEN** a severity entry is missing or cannot be parsed
- **THEN** the system SHALL store the vulnerability without a CVSS score and continue
  ingestion; the finding SHALL still be created
