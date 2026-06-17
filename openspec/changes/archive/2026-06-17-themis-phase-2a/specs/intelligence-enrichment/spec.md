## REMOVED Requirements

### Requirement: Phase 1 risk score computation
**Reason**: Replaced by the Phase 2a composite risk score formula, which incorporates
EPSS, KEV, public-exploit, and blast-radius signals in addition to CVSS severity and
VEX state. The Phase 1 CVSS-only formula no longer exists.

## ADDED Requirements

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
