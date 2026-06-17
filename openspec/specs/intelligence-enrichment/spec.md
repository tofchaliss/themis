# Intelligence Enrichment Specification

## Purpose
Apply VEX overlay semantics, compute the effective-state machine, and derive risk scores without ever mutating raw findings.
## Requirements
### Requirement: VEX overlay — raw findings are never deleted
The system SHALL apply VEX assertions as a contextual overlay on top of raw vulnerability findings. Raw findings in `component_vulnerabilities` SHALL never be deleted, modified, or suppressed. Only the `risk_context` effective state SHALL change.

#### Scenario: VEX not_affected assertion suppresses effective state only
- **WHEN** a VEX assertion with `status=not_affected` applies to a (component_purl, cve_id) pair
- **THEN** the system SHALL set `risk_context.effective_state=suppressed`, `risk_context.vex_status=not_affected`, while `risk_context.raw_severity` remains unchanged

#### Scenario: Raw finding preserved after VEX overlay
- **WHEN** `risk_context.effective_state=suppressed`
- **THEN** the underlying `component_vulnerabilities` record SHALL still be queryable and SHALL show the original `severity` and `cvss_score`

#### Scenario: VEX revocation resurfaces finding
- **WHEN** a VEX assertion is revoked (new VEX document supersedes it with the assertion removed)
- **THEN** the system SHALL recompute `risk_context.effective_state=detected` and the raw finding SHALL resurface

---

### Requirement: VEX assertion matching by PURL and CVE
The system SHALL match VEX assertions to raw vulnerability findings using the composite key `(component_purl, cve_id)`. A VEX assertion applies to all `component_vulnerabilities` records matching this key within the scope of the referenced SBOM.

#### Scenario: VEX assertion matched to component finding
- **WHEN** a VEX document contains an assertion for `(pkg:npm/lodash@4.17.21, CVE-2024-1234)`
- **THEN** the system SHALL apply the assertion to every `component_vulnerabilities` record matching that (purl, cve_id) pair under the referenced SBOM

#### Scenario: VEX assertion from different SBOM scope not applied
- **WHEN** a VEX document references an SBOM checksum that does not contain the affected component
- **THEN** the system SHALL not apply the assertion and log a warning

---

### Requirement: Effective state machine
The system SHALL implement the following effective state transitions in `risk_context`:

```
  DETECTED
    → SUPPRESSED      (VEX status=not_affected applied)
    → CONFIRMED       (VEX status=affected applied)
    → IN_TRIAGE       (escalated for human review)
    → ACCEPTED_RISK   (human decision via triage API)
    → FALSE_POSITIVE  (human decision via triage API)
  CONFIRMED
    → RESOLVED        (remediation applied — version upgrade or patch)
  Any state
    → DETECTED        (VEX revoked, or new contradicting evidence arrives)
```

#### Scenario: State transitions are auditable
- **WHEN** any effective state transition occurs in `risk_context`
- **THEN** the system SHALL write an `audit_log` entry with the previous state, new state, triggering event, and timestamp

#### Scenario: Multiple VEX assertions — most recent wins
- **WHEN** multiple VEX assertions apply to the same (component_purl, cve_id) pair from different VEX documents
- **THEN** the system SHALL apply the assertion from the VEX document with the most recent `timestamp`

---

### Requirement: risk_context population on ingestion
The system SHALL create a `risk_context` record for every new `component_vulnerabilities` row created during ingestion. The initial effective state SHALL be `DETECTED` if no matching VEX assertion exists.

#### Scenario: risk_context created with DETECTED state on new finding
- **WHEN** a new (component_version, vulnerability) pair is correlated during ingestion
- **THEN** the system SHALL create a `risk_context` record with `effective_state=DETECTED`, `raw_severity` copied from the finding, and `risk_score` computed

#### Scenario: risk_context created with SUPPRESSED state when VEX pre-exists
- **WHEN** a new SBOM is ingested and a matching VEX assertion already exists in the database for a correlated finding
- **THEN** the system SHALL create the `risk_context` record with `effective_state=SUPPRESSED` immediately

---

### Requirement: VEX-triggered re-enrichment
The system SHALL re-enrich all affected `risk_context` records when a new VEX document is ingested. Re-enrichment SHALL be processed asynchronously via the job queue.

#### Scenario: New VEX document triggers re-enrichment
- **WHEN** a VEX document is ingested successfully
- **THEN** the system SHALL enqueue a `ReenrichVEX` job for all (component_purl, cve_id) pairs covered by the new assertions

#### Scenario: Re-enrichment does not duplicate risk_context records
- **WHEN** re-enrichment runs for an existing `risk_context` record
- **THEN** the system SHALL UPDATE the existing record (not insert a new one) and preserve the triage history

---

### Requirement: Suppression reason recorded
The system SHALL record a human-readable `suppression_reason` in `risk_context` whenever `effective_state=suppressed`, explaining which VEX assertion and justification caused the suppression.

#### Scenario: Suppression reason references VEX source
- **WHEN** a finding is suppressed by a VEX assertion
- **THEN** `risk_context.suppression_reason` SHALL include the VEX document ID, assertion status, and justification type (e.g., "VEX doc abc123: not_affected — code_not_reachable")

### Requirement: Phase 2a composite risk score computation
The system SHALL compute a `risk_score` (integer 0–100) for each `risk_context`
record using a composite formula that incorporates CVSS severity, VEX effective
state, EPSS probability score, KEV listing status, and blast-radius score.
The Phase 1 CVSS-only formula is replaced by this formula. The `deterministic_level`
from Layer 1 rules takes precedence for `Critical` findings.

```text
base      = f(raw_severity, effective_state)
              CRITICAL → 90; HIGH → 70; MEDIUM → 40; LOW → 10; NONE → 0
              SUPPRESSED / FALSE_POSITIVE / ACCEPTED_RISK → multiply by 0.1
              CONFIRMED → multiply by 1.2 (capped at 100)
              RESOLVED  → set to 0
              DETECTED / IN_TRIAGE → no modifier

layer1    = if deterministic_level = Critical then 100 else base

epss_adj  = base × (1 + epss_score × 0.3)    [up to +30%; 0.0 when epss_score is NULL]

kev_adj   = if kev_listed = true then +15 else 0

blast_adj = base × blast_radius_score          [multiplier 1.0–2.0×]

final     = min(100, layer1 + epss_adj + kev_adj + blast_adj)
```

The `ai_adj` term is absent in Phase 2a; it is added in Phase 2b.
The formula is applied at enrichment time and whenever a `ReEnrichJob` fires.

#### Scenario: Critical CVE with KEV scores 100 (layer1 override)
- **WHEN** a `risk_context` has `raw_cvss_score ≥ 9.0`, `kev_listed = true`, and
  therefore `deterministic_level = Critical`
- **THEN** `risk_score = 100` (layer1 override; additional adjustments do not
  exceed 100)

#### Scenario: High CVE with EPSS 0.8 and blast radius 1.5 amplifies score
- **WHEN** a `risk_context` has `raw_severity = HIGH` (base = 70), `epss_score = 0.8`,
  `kev_listed = false`, `exploit_public = false`, and `blast_radius_score = 1.5`
- **THEN** `risk_score = min(100, 70 + 70×(1+0.8×0.3) + 0 + 70×1.5)`
  which equals `min(100, 70 + 86.6 + 0 + 105) = 100` (capped)

#### Scenario: Suppressed finding scores near-zero regardless of EPSS
- **WHEN** a `risk_context` has `effective_state = SUPPRESSED` and `epss_score = 0.95`
- **THEN** `base = severity_base × 0.1` and all adjustments are applied to the
  suppressed base; the resulting score remains very low

#### Scenario: Missing EPSS data (NULL) treated as zero
- **WHEN** `risk_context.epss_score` is NULL (sync has not yet completed)
- **THEN** the formula SHALL use `epss_score = 0.0` (no EPSS adjustment applied)

#### Scenario: Layer 1 and Layer 2 run synchronously before risk_score written
- **WHEN** a new finding is enriched during SBOM ingestion
- **THEN** `deterministic_level` (Layer 1) and `blast_radius_score` (Layer 2)
  SHALL both be computed before `risk_score` is written, so the final score
  incorporates all Phase 2a signals in a single synchronous pass

