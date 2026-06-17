## ADDED Requirements

### Requirement: Zip-archive and CSAF-directory feed sources
The system SHALL support vendor feed sources whose endpoint is not a single document: a
zip-archive source that downloads an OSV archive and parses each contained record, and a
CSAF-directory source that fetches an advisory index, follows each advisory link, and parses
each CSAF document. These sources SHALL reuse the existing `ParseOSVFeed` and `ParseCSAF`
parsers without modification, and feed default URLs SHALL point at working, unauthenticated
public sources.

#### Scenario: Alpine OSV loaded from zip archive
- **WHEN** the Alpine OSV feed is configured with the GCS `all.zip` archive URL
- **THEN** the system SHALL download the archive, parse each contained OSV record, and store
  the resulting assertions; the sync SHALL report success rather than an HTTP 302 error

#### Scenario: Rocky OSV loaded from zip archive
- **WHEN** the Rocky Linux OSV feed is configured with the GCS `all.zip` archive URL
- **THEN** the system SHALL parse and store the contained records; the sync SHALL NOT fail
  with HTTP 404

#### Scenario: Red Hat CSAF crawled from advisory directory
- **WHEN** the Red Hat feed points at the CSAF advisory directory index
- **THEN** the system SHALL fetch the index, retrieve each linked CSAF JSON, parse each via
  `ParseCSAF`, and store the assertions

#### Scenario: Feed fetch failure remains non-blocking
- **WHEN** any zip or CSAF-directory source is unreachable during a scheduled sync
- **THEN** the system SHALL log a WARNING, retain previously cached assertions, and continue
  other feeds; SBOM ingestion SHALL NOT be blocked

### Requirement: Alpine OSV advisory ID normalization
The system SHALL extract a canonical `CVE-*` identifier from Alpine OSV advisory records whose
`id` is `ALPINE-CVE-*` (and whose `aliases` may be empty), so vendor VEX assertions for those
advisories are stored against the canonical CVE ID and join other signals.

#### Scenario: ALPINE-CVE advisory yields canonical assertion
- **WHEN** `ParseOSVFeed.firstCVE()` processes an Alpine record with `id = "ALPINE-CVE-2024-1234"`
  and no `CVE-*` alias
- **THEN** the system SHALL derive `CVE-2024-1234` and store the vendor VEX assertion against it
  rather than dropping the advisory
