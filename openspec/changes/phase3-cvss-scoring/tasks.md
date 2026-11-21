# Tasks — phase3-cvss-scoring

No `specs/` deltas — archive with `openspec archive phase3-cvss-scoring --skip-specs -y`.
Every step waits for the owner's go and lands as its own PR.

## Group 0 — Record

- [ ] 0.1 EDR-SCORING-01 merged (status ACCEPTED); EDR-KNOWLEDGE-01 amendment note added.

## Group 1 — S1 kernel calculator

- [ ] 1.1 Parse 3.0 / 3.1 vectors to a metric set with X kept; refusal reasons.
- [ ] 1.2 Base / Temporal / Environmental with Roundup (3.1) and 3.0 rounding.
- [ ] 1.3 Candidate vectors (EDR section 11) checked against the FIRST reference calculator, then
  table tests; official examples; property tests. 100% coverage.

## Group 2 — S2 Knowledge source truth

- [ ] 2.1 Domain: observation, seen event, rating, rating event, validation, identity + link.
- [ ] 2.2 Feeds: NVD Secondary kept + `source` read (F10); Red Hat complete-revision withdrawal (F11);
  Rocky / Alpine severity word kept as metadata (O1); CVE.org feed opt-in (CNA + ADP).
- [ ] 2.3 Store + migrations (up / down), read API, wiring, tests.

## Group 3 — S3 Registry requirements

- [ ] 3.1 CR / IR / AR per Product / Project / Release with reason; per-metric resolution; API.

## Group 4 — S4 Governance assessment (shadow)

- [ ] 4.1 Domain: selection (4.1-4.1b), outcome / conditions / score status, roll-up (6).
- [ ] 4.2 Triggers (8.2) through existing events and read seams; idempotency (10.3).
- [ ] 4.3 Store + migration, provenance API, tests incl. every case in EDR section 11.

## Group 5 — S5 GUI (read only)

- [ ] 5.1 Finding page: score panel (roll-up, coverage, finality, per-component provenance).
- [ ] 5.2 CVE page: source ratings by publication, linked duplicates as one row.
- [ ] 5.3 VM check on a release with RPM and Alpine components.

## Group 6 — S6 to S8 (later steps, owner's go each)

- [ ] 6.1 GUI users and roles; governed changes and the change-vector form.
- [ ] 6.2 Shadow review with measured results; priority input switch.
- [ ] 6.3 Exports; CVSS 4.0 calculator.
