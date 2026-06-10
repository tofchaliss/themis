## ADDED Requirements

### Requirement: System status overview endpoint
The system SHALL provide `GET /api/v1/status` that returns a real-time
system-wide overview for operators. The endpoint requires no product scope — it
is intentionally a single global view. Query parameter `?top=N` controls the
top-component list (default 10, max 50). The response is computed at query time
from live data; it is not cached.

#### Scenario: Status endpoint returns component and vulnerability counts
- **WHEN** `GET /api/v1/status` is called
- **THEN** the response SHALL include `components.total_registered`,
  `components.with_vulnerabilities`, `components.clean`,
  `vulnerabilities.total_findings`, `vulnerabilities.unique_cves`,
  `vulnerabilities.by_severity` (critical/high/medium/low counts), and
  `vulnerabilities.by_state` (detected/not_affected/in_triage/false_positive counts)

#### Scenario: top_components list ordered by vulnerability count
- **WHEN** `GET /api/v1/status?top=5` is called
- **THEN** the response SHALL include a `top_components` array of at most 5 entries
  ordered by `vulnerability_count` descending, then `highest_cvss_score` descending.
  Each entry SHALL include `name`, `version`, `purl`, `product_name`,
  `vulnerability_count`, `highest_severity`, `highest_cvss_score`, and
  `highest_cve_id`

#### Scenario: Deleted SBOMs excluded from status counts
- **WHEN** one or more SBOMs have been soft-deleted (non-null `deleted_at`)
- **THEN** `GET /api/v1/status` SHALL exclude all components and findings
  from deleted SBOMs from all counts and rankings

#### Scenario: Suppressed findings excluded from active vulnerability counts
- **WHEN** a finding has `effective_state = NOT_AFFECTED` or `FALSE_POSITIVE`
- **THEN** it SHALL NOT be counted in `vulnerabilities.total_findings` or
  appear in `top_components` ranking

#### Scenario: top > 50 clamped to 50
- **WHEN** `GET /api/v1/status?top=200` is called
- **THEN** the system SHALL return at most 50 entries in `top_components`
  without returning an error

#### Scenario: as_of timestamp reflects query time
- **WHEN** the status endpoint is called
- **THEN** the `as_of` field in the response SHALL equal the timestamp
  at which the database query was executed (not a cached timestamp)
