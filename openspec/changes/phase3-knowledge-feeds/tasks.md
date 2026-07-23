# Tasks — phase3-knowledge-feeds (Knowledge feed layer)

> Scope: make the Knowledge feed layer production-real + close the go-forward feed gaps, per `proposal.md` /
> `design.md`. **Additive** to the implemented `phase3-knowledge` (M7); decisions trace to
> `docs/engineering/decisions/EDR-KNOWLEDGE-01.md` (D5/D6) + EDR-EVIDENCE-01 D4, and close the go-forward
> equivalents of **D-NVD-2** / **D-FEED-2** (`docs/current-changes/project-backlog.md`). Each group ends with
> the six Themis gates (`make check`), extended to `internal/knowledge/`. Depends on `phase3-knowledge`
> (ports + ACL registry + `Reconcile`) and — for group 4 — Evidence accepting a `scanner-report` kind.

## 1. Real feed-fetch HTTP clients (PHASE3-BACKLOG §C · EDR-KNOWLEDGE-01 D5)

- [x] 1.1 OSV **query-by-package** client implementing `PackageVulnSource` (SBOM-time lazy discovery) behind
  the existing port; feeds the M7 OSV ACL. Config-driven endpoint (R2). — `adapters/feed/osv_client.go`
  (`OSVClient`): POSTs `/v1/query`, maps PURL→OSV ecosystem/name (Maven `group:artifact`, npm scope, distro
  skipped), hands each record to `osvACL`; GHSA-only records skipped (CVE-keyed, best-effort per record).
- [x] 1.2 NVD **modified-since** client implementing `ChangedVulnSource` (scheduled watch) + the
  `knowledge_watch_state` watermark; feeds the M7 NVD ACL. Rate-limit-aware (NVD 50/30s with a key). —
  `adapters/feed/nvd_client.go` (`NVDClient`): GETs `/rest/json/cves/2.0?lastModStartDate…`, paginated
  (`startIndex`, capped), `apiKey` header when set; the watermark stays owned by M7's `WatchService` /
  `WatchState` (the client is the `ChangedVulnSource` it calls).
- [x] 1.3 Tests: httptest fixtures per client → discovered Proposals; watermark advance + resume; helpful
  rejection on malformed responses. — `osv_client_test.go` / `nvd_client_test.go` + white-box
  `clients_internal_test.go`; non-200 → error, distro skip, pagination across pages.
- [x] 1.4 Gate: six Themis gates green. — `make check` exit 0; feed package 92.4% (90% tier).

## 2. CVSS v4.0 in the vuln-facts ACL + Reconcile (go-forward D-NVD-2 · D6/D2)

- [x] 2.1 Parse **CVSS v4.0** — NVD `cvssMetricV40` (computed base score + severity) and OSV `CVSS:4.0`
  vectors — in the `vuln-facts` ACL, so a v4.0-only CVE is not dropped to score 0 / `unknown`. — NVD:
  `extractNVDCVSS` now reads `cvssMetricV40`; OSV: `value.CVSS` takes the score as-given, so a v4.0 vector is
  stored (not re-computed) and severity resolves from the numeric score/label — the v0.3.x OSV vector-math
  bug cannot recur.
- [x] 2.2 Extend `Reconcile` headline precedence to **`v3.1 → v3.0 → v4.0 → v2`**, preferring **Primary**
  over **Secondary** within a version; order-independence preserved (the `rapid` property still holds). —
  The version precedence is applied **per record** in `extractNVDCVSS` (each feed record yields one resolved
  CVSS); `Reconcile` folds across *sources* by its existing source-precedence rule (unchanged), so the
  cross-fleet order-independence property is untouched.
- [x] 2.3 Tests: a CVE scored **only** under v4.0 (fixture mirroring `CVE-2025-8869`) reconciles to a real
  severity/score; a CVE with **both** v3.1 + v4.0 keeps the v3.1 headline; rapid order-independence green. —
  `TestNVDClient_{V40Only_ResolvesSeverity,V31BeatsV40,PrimaryBeatsSecondary}` +
  `TestOSVClient_CVSSv4VectorTolerated`; M7's reconcile rapid property unchanged + green.
- [x] 2.4 Gate: six Themis gates green.

## 3. Source-tier taxonomy → tier-aware feed health (go-forward D-FEED-2 · BCK-0051)

- [x] 3.1 Add a **tier** attribute to each feed in the ACL registry, sourced from
  `openspec/intel-source-tiers.md` (tier 1 critical … tier 4 planned); self-documented config (R2). —
  `adapters/feed/feed_tier.go`: `tierBySource` + `Registry.Tier(source)` (nvd/epsskev=Tier1, osv/redhat/
  exploitdb=Tier2, vexfeed=Tier3); a test asserts **every** registered source is classified.
- [x] 3.2 Make feed health + staleness **tier-aware**: a tier-1 feed failure escalates (stale + signal), a
  tier-3 "gold" feed failure stays informational — no longer one-size-fits-all "degraded". —
  `domain/feedtier.go`: pure `Tier` policy (`StaleThreshold` 25h/48h/none) + `FeedObservation.Evaluate` →
  `FeedStatus{healthy|stale|degraded|informational}` + `SetsSignalsStale` (Tier-1 only). Domain owns the
  policy, adapters own the classification; the running status-API / health-store wiring lands with M5.
- [x] 3.3 Tests: tier-1 failure → stale/escalated; tier-3 failure → informational; all-healthy → no signal. —
  `domain/feedtier_test.go` (every tier, overdue + failing paths, `SetsSignalsStale`) 100%;
  `feed_tier_test.go` (per-source classification + no-silent-gaps).
- [x] 3.4 Gate: six Themis gates green. — build + lint (0 issues) + domain 100% / feed 92.4%.

## 4. Scanner reports as source Proposals (EDR-KNOWLEDGE-01 D5/D6 — the deferred item)

- [x] 4.1 A **scanner-report ACL** translating a `scanner-report` Evidence kind (read via Evidence's read
  API) into `vuln-facts` Proposals (source = the scanner; **advisory** — CON-0002), reconciled by the same
  precedence as NVD/OSV/distro. Prereq: Evidence registers + serves the `scanner-report` kind. —
  `adapters/feed/scanner.go` (`scannerACL`, source `scanner`), registered in `NewRegistry` + classified
  **Tier-1** (scanner evidence); consumes a curated scanner finding → vuln-facts Proposal.
- [x] 4.2 Wire it into the correlation/fold path so a scanner report enriches cards + emits `ComponentMatched`
  like any other source; a scanner **never** sets truth (governed downstream). — `app/scanner.go`
  (`ScannerReportService.Ingest`): folds each finding via `FoldProposal` + records a match per finding
  (→ ComponentMatched), behind the fakeable `ScannerReportSource` port. The concrete Evidence
  `scanner-report` read adapter is the **documented prerequisite** (same fakeable-port pattern as M7's feed
  clients); the fold + match wiring itself is complete and tested now.
- [x] 4.3 Tests: a scanner report → advisory Proposals folded into the card; reconciliation grants the
  scanner **no special authority**; conflicting distro-authoritative data still wins by precedence. —
  `feed/scanner_test.go` (`TestScannerACL_NoSpecialAuthority`: a scanner critical + newer still loses to a
  Tier-2 distro headline by precedence) + `app/scanner_test.go` (ingest + idempotent + error paths, 100%).
- [x] 4.4 Gate: six Themis gates green.

## 5. Seam e2e + docs

- [x] 5.1 Per-context e2e: real feed clients (httptest) → discovered/enriched cards → CVSS-4.0 severity
  present → tier-aware health; scanner-report → advisory Proposal folded. — `feed/e2e_test.go`
  (`TestFeedsSeamE2E`): OSV client discovers a CVE, the NVD client resolves a v4.0-only CVE folded to a real
  severity (D-NVD-2), a scanner report folds with no authority, every feed is tier-classified; plus the
  `app/scanner_test.go` fold path.
- [x] 5.2 Update `PHASE3-STATUS.md` + `PHASE3-BACKLOG.md` (close the §C feed items) + `openspec/STATUS.md`;
  record the go-forward D-NVD-2 / D-FEED-2 resolutions. — STATUS rows now **Implemented** (19/19); §C marked
  ✅; D-NVD-2 / D-FEED-2 carry a "Go-forward status: ✅ realized in `phase3-knowledge-feeds`" note.
- [x] 5.3 Gate: six Themis gates green; `markdownlint-cli2` clean.
