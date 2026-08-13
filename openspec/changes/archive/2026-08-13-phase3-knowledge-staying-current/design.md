# Design: phase3-knowledge-staying-current

## KN-SCAN-1 — the scanner seam

### The document schema (the decision that was never made)

The scanner ACL's `scannerRecord` carries the vulnerability facts but NO component — yet the
service records a match per finding, which needs one. That unfinished schema is *why* the seam
was never wired. The curated scanner-report document (normalized at the Evidence border,
EDR-EVIDENCE-01 D4 — a scanner is a producer; CI converts Trivy/Grype output with a small jq)
is:

```json
{"findings": [
  {"cve": "CVE-…", "observed_at": "…", "scanner": "trivy", "severity": "HIGH",
   "cvss_score": 7.5, "cvss_vector": "…", "affected": ["…"], "fixed": ["…"],
   "component": {"purl": "pkg:rpm/rocky/openssl@3.0.7", "name": "openssl",
                  "version": "3.0.7", "ecosystem": "rpm", "source": "openssl"}}
]}
```

Each finding minus `component` is EXACTLY the existing `scannerRecord`, so the adapter feeds the
finding's raw bytes through the untouched ACL (unknown keys are ignored by its unmarshal) for
the (CVE, Proposal) half and parses `component` itself — the ACL stays the single place scanner
facts are interpreted.

### The seam

`adapters/evidence.ScannerSource`: `GetDocument(evidenceID)` (the same client method the VEX
door uses) → verify kind → parse envelope → per finding: ACL translate + component parse →
`[]app.ScannerProposal`. `ScannerReportService` gains the D7 read/write split
(`PlanIngest` outside the tx / `ApplyIngest` inside; `Ingest` remains the compose), the
coordinator gains `case "scanner-report"` beside sbom/vex, and wiring connects it. A finding
whose record fails translation is SKIPPED with the rest kept — one malformed finding must not
void a 400-finding report — and the count of skips is returned for the caller's log line.

## KN-RECOR-1 — the re-discovery sweep

### The ledger (where "what do we re-ask about?" comes from)

Knowledge holds matched components but not inventories; a component with no vulnerabilities yet
— exactly the one a new CVE will name — is invisible to it. The inventory lives in Evidence,
reachable by evidence id. So Knowledge remembers the one fact it already witnesses: migration
`000006_correlated_releases` — `(release_id PK, evidence_id, last_discovered_at)` — upserted
**in the same transaction as ApplyCorrelation** (a later SBOM for the release replaces the
evidence id, so the sweep always re-reads the LATEST inventory). No backfill: a pre-migration
release enters the ledger on its next upload; until then it is exactly as visible as it was.

### The sweep

`RediscoveryService` in the BackfillService mold: `StaleReleases(staleAfter, limit)` → for each,
the EXISTING `CorrelationService.Correlate(releaseID, evidenceID)` — the full read fan-out
(every component re-asked against OSV + NVD-when-enabled) plus the write path with its
range-gate and fixed-verdict checks, all already idempotent — then `Touch`. Nothing new decides
anything; the sweep is a scheduler around machinery that already converges. A release whose
evidence was deleted/unreadable is skipped (kept for the next sweep), not fatal.

### Cadence + defaults

Loop in `cmd/knowledge` beside the others. **Default ON** (like the reattribute sweep, it rides
the always-on OSV discovery source; the gap it closes is silent blindness, which must not be
opt-in): `THEMIS_REDISCOVERY_ENABLED=0` disables; `_INTERVAL` (default 1h) is the loop tick;
`_STALE_AFTER` (default 24h) is how old a release's last discovery may grow; `_LIMIT` (default
3) caps releases per tick so a large estate drains across ticks — worst-case feed load is
`limit × components-per-release` OSV queries per tick, proportional to the estate (D5).
