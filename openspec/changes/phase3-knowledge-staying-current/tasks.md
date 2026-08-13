# Tasks: phase3-knowledge-staying-current

One PR off `main` (carrying the two backlog filings), `make check-ci` green, ending with
`make vet-tags` green.

## 1. KN-SCAN-1 — wire scanner-report ingestion

- [x] 1.1 `ScannerReportService` gains the D7 split: `PlanIngest` (document read + translate,
      outside any tx) / `ApplyIngest` (fold + record, inside); `Ingest` stays as the compose;
      per-finding translation failures skip-and-count, never void the report
- [x] 1.2 `adapters/evidence.ScannerSource`: envelope schema (findings + component), kind
      verification, ACL reuse per finding — implements `app.ScannerReportSource`
- [x] 1.3 Coordinator: `case "scanner-report"` with the plan/apply shape of sbom/vex
- [x] 1.4 Wiring: build the source + service into the coordinator
- [x] 1.5 Tests: service plan/apply + skip-and-count (app, 100%), source adapter parsing/kind
      mismatch (90%), coordinator dispatch

## 2. KN-RECOR-1 — the re-discovery sweep

- [x] 2.1 Migration `000006_correlated_releases` (+down); store: `UpsertCorrelatedRelease`
      (tx-joining), `StaleReleases`, `TouchRelease`
- [x] 2.2 `ApplyCorrelation` upserts the ledger in its transaction (both the event path and
      the sweep refresh it)
- [x] 2.3 `RediscoveryService`: stale query → existing `Correlate` → touch; per-release
      failures skip, queue-read aborts
- [x] 2.4 `cmd/knowledge`: rediscovery loop, default ON; `THEMIS_REDISCOVERY_ENABLED=0` /
      `_INTERVAL` (1h) / `_STALE_AFTER` (24h) / `_LIMIT` (3)
- [x] 2.5 Tests: ledger store (integration), sweep behaviour incl. latest-evidence-wins (app,
      100%)

## 3. Docs + close-out

- [x] 3.1 TESTING.md: produce/convert/upload a scan report (jq recipe); watch a re-discovery
      sweep on a live estate
- [x] 3.2 node.env.example + CLAUDE.md notes; INSTALLATION.md scanner-report mention
- [x] 3.3 Backlog: KN-SCAN-1 + KN-RECOR-1 closed with evidence
- [ ] 3.4 `make check-ci` + `make vet-tags` green; archive this change
