## ADDED Requirements

### Requirement: Vendor VEX feed ingestion
The system SHALL fetch, parse, and store VEX advisories from the following vendor
feeds on a daily schedule: Red Hat (CSAF 2.0), Alpine Linux (OSV), Rocky Linux
(OSV), and Wolfi (OSV). Each advisory SHALL be stored as a `vex_document` with
`source = upstream_vendor` and per-assertion rows in `vex_assertions`. Upserts
are idempotent per `(purl_normalised, cve_id, source)`.

#### Scenario: Red Hat CSAF advisory stored
- **WHEN** the daily vendor VEX scheduler runs and a Red Hat CSAF advisory
  references a CVE with a `not_affected` assertion for a PURL
- **THEN** the system SHALL store a `vex_document` row and a `vex_assertions` row
  with `source = upstream_vendor` and `status = not_affected`

#### Scenario: Alpine OSV advisory stored
- **WHEN** the Alpine OSV feed includes a vulnerability record with a `[introduced, fixed)`
  version range for a package
- **THEN** the system SHALL store the range in `vex_assertions` for PURL matching
  against installed Alpine package versions

#### Scenario: Vendor feed fetch failure does not block ingestion
- **WHEN** a vendor VEX feed endpoint is unreachable during the scheduled sync
- **THEN** the system SHALL log a WARNING, retry 3 times with exponential backoff,
  and continue with cached data; SBOM ingestion SHALL NOT be blocked

---

### Requirement: Four-phase PURL matching
The system SHALL match vendor VEX assertion PURLs to SBOM component PURLs using
a four-phase algorithm. Each match SHALL record a `match_type` field on
`vex_assertions`. Phase 2a scope: Alpine (apk) and RPM ecosystems only.

#### Scenario: Phase 1 — exact PURL match
- **WHEN** the SBOM component PURL exactly matches the vendor VEX assertion PURL
  byte-for-byte
- **THEN** the system SHALL apply the assertion with `match_type = exact`

#### Scenario: Phase 2 — namespace alias normalisation
- **WHEN** the SBOM PURL has namespace `rhel` and the VEX assertion PURL has
  namespace `redhat` for the same package name and version
- **THEN** the system SHALL normalise `rhel` to `redhat` and apply the assertion
  with `match_type = namespace_normalised`

#### Scenario: Phase 3 — RPM errata direction check (version_inherited)
- **WHEN** an RPM SBOM package version has an additional errata suffix
  (e.g. `1.1.1k-6.el8_5.1` vs VEX assertion `1.1.1k-6.el8_5`) and the installed
  EVR is greater than or equal to the assertion EVR after errata strip
- **THEN** the system SHALL apply the assertion with `match_type = version_inherited`

#### Scenario: Phase 3 — RPM errata direction check (no match when installed is older)
- **WHEN** the installed RPM EVR is less than the VEX assertion EVR after errata strip
- **THEN** the system SHALL NOT apply the assertion and SHALL set
  `upstream_vex_coverage = purl_mismatch`

#### Scenario: Phase 4 — Alpine OSV range check (not_affected)
- **WHEN** the installed Alpine package version falls outside the `[introduced, fixed)`
  range from the OSV advisory for that package name
- **THEN** the system SHALL apply `status = not_affected` with
  `match_type = range_matched`

#### Scenario: Phase 4 — Alpine OSV range check (affected)
- **WHEN** the installed Alpine package version falls within the `[introduced, fixed)`
  range from the OSV advisory
- **THEN** the system SHALL apply `status = affected` with
  `match_type = range_matched`

#### Scenario: No match after all four phases — purl_mismatch logged
- **WHEN** a vendor VEX assertion is found for a CVE but no PURL match succeeds
  after all four phases
- **THEN** the system SHALL set `upstream_vex_coverage = purl_mismatch` on the
  affected `risk_context` row and SHALL log the failure at INFO level with the
  SBOM PURL and VEX PURL for diagnostic purposes

---

### Requirement: Vendor VEX authority — no upstream version comparison after match
The system SHALL treat a matched vendor VEX assertion as authoritative and SHALL NOT
perform any additional comparison against upstream CVE version ranges once the
assertion is matched by any phase of the four-phase algorithm. Vendor VEX is the
authoritative source for backported patches.

#### Scenario: Vendor not_affected accepted for backported package
- **WHEN** a Red Hat VEX assertion says `not_affected` for
  `pkg:rpm/redhat/httpd@2.4.37-51.el8` and the assertion is matched by the
  four-phase algorithm
- **THEN** the system SHALL apply `effective_state = not_affected` regardless
  of whether the upstream CVE fix version (e.g. `httpd@2.4.57`) is higher than
  the installed version

---

### Requirement: Retroactive ReEnrichJob after vendor VEX sync
The system SHALL enqueue a `ReEnrichJob` after storing new or updated `vex_assertions`
rows from a vendor feed sync, covering every `risk_context` row where
`(component_purl_normalised, cve_id)` matches a newly added or changed assertion.

#### Scenario: Existing DETECTED finding suppressed after vendor VEX sync
- **WHEN** a vendor VEX sync adds a `not_affected` assertion that matches an
  existing `risk_context` row with `effective_state = DETECTED`
- **THEN** within one job-queue processing cycle the system SHALL update
  `risk_context.effective_state = NOT_AFFECTED` for that finding

---

### Requirement: VEX coverage visibility per finding
The system SHALL expose an `upstream_vex_coverage` field on every `risk_context`
row with one of three values: `covered`, `not_covered`, or `purl_mismatch`.

#### Scenario: covered — vendor VEX matched
- **WHEN** a vendor VEX assertion was successfully matched (any phase) for a
  `(component_purl, cve_id)` pair
- **THEN** `risk_context.upstream_vex_coverage = covered`

#### Scenario: not_covered — no vendor VEX record for this pair
- **WHEN** no vendor VEX advisory references the CVE or the SBOM component
- **THEN** `risk_context.upstream_vex_coverage = not_covered`

#### Scenario: purl_mismatch — record found but no phase matched
- **WHEN** a vendor advisory references the CVE but all four matching phases failed
- **THEN** `risk_context.upstream_vex_coverage = purl_mismatch`

#### Scenario: Aggregate coverage endpoint returns counts
- **WHEN** `GET /api/v1/products/{id}/versions/{v}/vex-coverage` is called
- **THEN** the response SHALL include integer counts for `covered`,
  `not_covered`, and `purl_mismatch` across all findings for that product version
