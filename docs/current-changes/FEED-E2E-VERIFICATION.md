# Feed End-to-End Verification (v0.3.x)

**Run:** 2026-07-23 · **Instance:** local `./bin/themis` (:8080) + PostgreSQL `themis` ·
**Fixture:** `oamp` container SBOM (`scripts/oamp.json`, Trivy CycloneDX 1.6, 542 components →
**228 findings / 86 distinct CVEs**).

Purpose: confirm the original goal — *list open vulnerabilities **correctly*** — actually holds, i.e. every
enrichment feed fetched, populated, and flowed onto the findings. Anything broken is logged as a gap and, where
relevant, flagged for the Phase-3 OpenSpec tasks (the go-forward Knowledge feed adapters must handle the same).

## Method

- `feed_health` table (per-feed last success / failure streak).
- `GET /api/v1/status` (`components`, `top_components`, `signals_stale`, `degraded_feeds`).
- Direct DB population + linkage queries (`vulnerabilities`, `epss_kev_signals`, `exploit_records`,
  `vex_documents` / `vex_assertions`, `risk_context`).
- Overlap tests to distinguish *legitimately zero* from *broken join*.

## Feed health — all 7 schedulers green

| Feed (scheduler) | Role | Last success (UTC) | Failures |
| --- | --- | --- | --- |
| `cve_watch` | NVD CVE discovery/watch | 02:21 | 0 |
| `cvss_backfill` | NVD-by-CVE CVSS + severity | 02:21 | 0 |
| `distro_correlation` | OSV distro match (Rocky/Alpine/Wolfi) | 02:06 | 0 |
| `epss_kev` | EPSS scores + CISA KEV | 02:07 | 0 |
| `exploitdb` | ExploitDB public-exploit records | 02:06 | 0 |
| `redhat_vex` | Red Hat CSAF **VEX** (overlay) | 02:06 | 0 |
| `vendor_vex` | Vendor VEX documents | 02:06 | 0 |

`signals_stale = false`, `degraded_feeds = []`. (Note the `exploitdb` feed only works after the URL fix this
session — `themis.yaml` had the dead GitHub mirror; corrected to the GitLab raw URL.)

## Data population — healthy across the board

| Dataset | Volume | Notes |
| --- | --- | --- |
| `vulnerabilities` (CVE catalog) | **2005** (all `source=nvd`) | 1826 scored (`cvss_score>0`); 179 `unknown` |
| `epss_kev_signals` | **351,675** | 351,674 with EPSS; **1,653 KEV-listed** |
| `exploit_records` | **46,636** | 22,589 distinct CVEs |
| `vex_documents` | **40** (`upstream_vendor`) | + `vex_assertions` CVE↔status store |
| `component_vulnerabilities` (findings) | **228** | `distro_osv=193`, `osv=32`, `catalog=3` |

## Enrichment actually reaches the findings (`risk_context`, n=228)

| Signal | Applied | Verdict |
| --- | --- | --- |
| EPSS | **227 / 228** | ✅ flowing (the 1 gap is a CVSS-4.0 straggler, below) |
| KEV | 0 | ✅ **correct** — 0 of the 86 CVEs are in the KEV set (verified by overlap, not a broken join) |
| Public exploit | 0 | ✅ **correct** — 0 of the 86 CVEs are in ExploitDB (recent 2025/2026 CVEs; ExploitDB skews older) |
| Vendor VEX | **41 marked `affected`** | ✅ overlay applied (`upstream_vex_coverage` set on all 228; 41 carry `vex_status`) |
| Risk score | **221 / 228** (`>0`, max 100) | ✅ — the 7 unscored are exactly the CVSS-4.0 unknowns |

KEV = 0 and exploit = 0 were the two suspicious zeros; both are **genuine non-overlap**, confirmed by a direct
set-membership test — the enrichment joins are correct, this image simply has no KEV/ExploitDB CVEs.

## Gaps found

### G1 — CVSS v4.0 not parsed → 5 CVEs stuck `unknown` / `risk 0` (logged as **D-NVD-2**)

Recent CVEs scored **only** with CVSS 4.0 (`CVE-2025-8869`, `CVE-2026-1703/3219/6357/53533`, all PyPI) land
`severity=unknown`, `cvss_score=0`, `risk=0`. Root cause in two spots: `nvd/client.go extractNVDCVSS` reads
`v3.1→v3.0→v2` with no `cvssMetricV40`; `osv/cvss.go cvssV3BaseScore` implements the v3.1 formula only. They
**do not self-heal** (the `cvss_checked_at` back-off). Full detail + fix in
[`project-backlog.md`](project-backlog.md) **DEFECT D-NVD-2**. Phase-3 cross-ref: `PHASE3-BACKLOG.md` §C.

### G2 — Intel source-tier taxonomy is unimplemented (logged as **D-FEED-2**)

[`openspec/intel-source-tiers.md`](../../openspec/intel-source-tiers.md) defines a 4-tier feed classification
with **differentiated failure behavior** (tier 1 critical → `signals_stale` + notify; tier 2 → `WARN` +
`degraded_feeds`; tier 3 gold → `INFO` only). In code it is **entirely docs-only**: `feed_health.class`/`tier`
columns exist but are never written (`RecordFeedSuccess`/`Failure` omit them), and both `DegradedFeeds`
(`consecutive_failures > 0`) and `SignalsStale` are **tier-agnostic** — every feed is treated identically.
Not currently biting (all feeds healthy), but a tier-3 feed failure would surface exactly like a tier-1 one.
Full detail in [`project-backlog.md`](project-backlog.md) **DEFECT D-FEED-2**.

## What is confirmed correct (no action)

- NVD catalog + CVSS/severity backfill (except CVSS 4.0), EPSS, KEV, ExploitDB, distro-OSV correlation,
  Red Hat/vendor VEX overlay, composite risk scoring, and the `/status` aggregate all function end-to-end.
- The single wired SBOM → 228 enriched findings path is correct.

## OpenSpec / go-forward implications

- **G1 (CVSS 4.0)** and **G2 (source tiers)** both belong to the Phase-3 **Knowledge** context's feed ACL +
  reconciliation surface (`internal/knowledge/adapters/feed`, `domain/reconcile.go`). When Knowledge's real
  feed-fetch clients land (`PHASE3-BACKLOG.md` §C), fold in: CVSS-4.0 parsing in the severity precedence, and
  the tier taxonomy as feed-ACL metadata driving health/staleness. Promote to `openspec/changes/phase3-knowledge`
  tasks if/when that work is scheduled.
- No new **v0.3.x** OpenSpec change is required; both gaps are recorded as defects in the v0.3.x backlog.

## Fixes applied during this verification session

- `themis.yaml` `exploitdb.csv_url` → GitLab (dead GitHub mirror); `nvd.api_key` inlined-key flagged.
- Schema skew (missing `cvss_checked_at` / `feed_health` / CR-3 columns) resolved by drop + recreate from the
  current baseline.
- `scripts/upload-sbom.sh` payload key `image_id` → `artifact_id` (post artifacts/images merge).
- `scripts/list-open-vulns.sh` added (auto key + discovery + open-filter + day-over-day snapshot diff).
