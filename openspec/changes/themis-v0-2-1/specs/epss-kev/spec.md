## ADDED Requirements

### Requirement: Canonical CVE-ID normalization for signal matching
The system SHALL normalize vulnerability identifiers to canonical `CVE-YYYY-NNNN` form before
storing them in `vulnerabilities.cve_id` and before any EPSS, KEV, or ExploitDB signal lookup,
so that distro-prefixed identifiers (e.g. `ALPINE-CVE-2024-1234`) match the signal tables.
Normalization SHALL strip a known distro/OSV prefix only when the remainder is a syntactically
valid `CVE-*` identifier, and SHALL otherwise preserve the original identifier unchanged.

#### Scenario: Alpine-prefixed ID normalized before storage
- **WHEN** an OSV record has `id = "ALPINE-CVE-2024-1234"` (or that value only in `aliases`)
- **THEN** the system SHALL store `cve_id = "CVE-2024-1234"` in `vulnerabilities`

#### Scenario: Alpine finding receives EPSS and KEV after normalization
- **WHEN** an Alpine finding exists for a CVE that has EPSS and KEV signals, and a
  `ReEnrichJob` runs after normalization
- **THEN** `risk_context.epss_score` and `risk_context.kev_listed` SHALL be populated from
  `epss_kev_signals` for that canonical CVE ID (no longer `0` / `false` due to ID mismatch)

#### Scenario: Non-CVE identifier left unchanged
- **WHEN** an OSV record has an identifier whose remainder after prefix stripping is not a
  valid `CVE-*` (e.g. `GHSA-xxxx-yyyy-zzzz`)
- **THEN** the system SHALL store the identifier unchanged and SHALL NOT fabricate a CVE ID
