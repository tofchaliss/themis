# Design — phase3-cvss-scoring

The design of record is `docs/engineering/decisions/EDR-SCORING-01.md`. This file only records
how the steps map onto the code.

- **Kernel (S1).** A pure package beside `internal/kernel/value/cvss.go`: parse to a metric set
  that keeps X, compute the three scores with the 3.1 Roundup (3.0 rounding for 3.0 vectors),
  refuse with a reason. `BaseScoreFromVector` keeps its signature and is re-implemented on top.
  100% coverage; property tests (rapid) for monotonicity and X-equals-default; the official
  examples plus FIRST-checked vectors as table tests.
- **Knowledge (S2).** New tables beside the Proposals (append-only, never updated): observations,
  seen events, ratings, rating events, validations, identity links. Feed adapters report
  "complete revision" separately from "fetch succeeded" (EDR 3.4 item 7). The single headline
  (`EnterpriseView.CVSS`) stays for old readers. Read API `GET /faultlines/{id}/ratings`.
- **Registry (S3).** One requirements row per level with reason and actor; resolution per metric
  (component exception > Release > Project > Product > X) computed in the domain.
- **Governance (S4).** ComponentAssessment revisions keyed by (finding, purl), immutable, with the
  complete candidate snapshot (EDR 8.1) as JSONB; roll-up revisions per Finding. Triggers arrive
  through the existing Knowledge / Evidence / Registry events and read seams; no cross-context
  import. Read API `GET /findings/{id}/score`. Nothing reads it for priority yet (shadow).
- **GUI (S5).** Dashboard reads the provenance API; numbers are never computed in the browser.
