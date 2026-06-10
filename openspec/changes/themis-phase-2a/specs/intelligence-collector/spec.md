## ADDED Requirements

### Requirement: Layer 1 deterministic rules synchronous
The system SHALL evaluate a fixed set of deterministic rules against each new
or re-enriched `risk_context` row and write the result to
`risk_context.deterministic_level` before returning `202 Accepted`. No external
call and no model call is required. The rules always produce an output; they never
fail silently.

Rule table (evaluated in priority order; first match wins):

| Condition | Output |
| --- | --- |
| CVSS ≥ 9.0 ∧ kev_listed = true | Critical |
| CVSS ≥ 9.0 ∧ exploit_public = true | High+ |
| kev_listed = true ∧ CVSS < 9.0 | High |
| epss_score ≥ 0.5 ∧ CVSS ≥ 7.0 | Elevated |
| CVSS ≥ 9.0 (no other signals) | High |
| (no rule matches) | Informational |

#### Scenario: CVSS 9+ and KEV-listed → Critical
- **WHEN** a `risk_context` row has `raw_cvss_score ≥ 9.0` and `kev_listed = true`
- **THEN** `risk_context.deterministic_level = Critical` SHALL be written before
  the enrichment use case returns

#### Scenario: CVSS 9+ and ExploitPublic → High+
- **WHEN** a `risk_context` row has `raw_cvss_score ≥ 9.0` and `exploit_public = true`
  but `kev_listed = false`
- **THEN** `risk_context.deterministic_level = High+` SHALL be written

#### Scenario: KEV-listed with low CVSS → High
- **WHEN** `kev_listed = true` and `raw_cvss_score < 9.0`
- **THEN** `risk_context.deterministic_level = High`

#### Scenario: EPSS ≥ 0.5 and CVSS ≥ 7 → Elevated
- **WHEN** `epss_score ≥ 0.5` and `raw_cvss_score ≥ 7.0` and `kev_listed = false`
  and `exploit_public = false`
- **THEN** `risk_context.deterministic_level = Elevated`

#### Scenario: Layer 1 completes before 202 Accepted is returned
- **WHEN** a new SBOM is ingested and findings are correlated
- **THEN** `risk_context.deterministic_level` SHALL be non-null on all findings
  when the `202 Accepted` response is sent to the caller

---

### Requirement: Layer 2 SQL graph blast-radius traversal synchronous
The system SHALL traverse the asset graph from each newly correlated CVE to
compute a `blast_radius_score` and a list of `affected_teams` (Customer nodes
reachable from the CVE via Package → Product → Microservice → Deployment →
Customer edges). The traversal SHALL complete and results written to
`risk_context.blast_radius_score` before `202 Accepted` is returned.
Traversal depth SHALL be capped at 7 levels.

Blast-radius multiplier scale: 1 Customer = 1.0×; each additional Customer
adds 0.1× up to a cap of 2.0× at 10+ Customers.

#### Scenario: CVE affecting one customer deployment → score 1.0
- **WHEN** a CVE is found in a component used by exactly one Customer's Deployment
- **THEN** `risk_context.blast_radius_score = 1.0`

#### Scenario: CVE affecting 10 or more customer deployments → score capped at 2.0
- **WHEN** the graph traversal finds 10 or more Customer nodes reachable from a CVE
- **THEN** `risk_context.blast_radius_score = 2.0` (capped)

#### Scenario: CVE with no graph edges → score 1.0 (no amplification)
- **WHEN** no Microservice or Deployment nodes are linked to the CVE's Package node
- **THEN** `risk_context.blast_radius_score = 1.0` (baseline; no amplification)

#### Scenario: Affected teams queued for deterministic notification
- **WHEN** Layer 2 identifies at least one Customer node reachable from a CVE
- **THEN** the system SHALL enqueue a notification event for each affected Customer
  within the same synchronous enrichment transaction

#### Scenario: Layer 2 completes before 202 Accepted
- **WHEN** a new SBOM is ingested and findings are correlated
- **THEN** `risk_context.blast_radius_score` SHALL be non-null on all findings
  when the `202 Accepted` response is sent
