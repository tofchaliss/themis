# Intelligence Source Tiers — Reference

_Cross-phase reference. Applies to Phase 2a, 2b, 2c, and beyond._
_Last updated: 2026-06-16._

---

## Purpose

Themis ingests intelligence from many external and internal sources. Not all sources
carry equal weight. When a source is unavailable or returns bad data, the severity of
the error should match the tier of the source. This document is the authoritative
classification. All feed adapters, schedulers, and error-handling code must emit errors
and metrics at the tier level defined here.

---

## Tier Table

| Tier | Name | Failure behaviour | Retry | Stale threshold |
| ---- | ---- | ----------------- | ----- | --------------- |
| 1 | **Critical — Mandatory** | `ERROR` log · `tier1_failure` metric · `signals_stale=true` in status API · operator notification if rules configured | 3× exponential backoff | 25 h |
| 2 | **Strongly Recommended** | `WARN` log · `tier2_failure` metric · `degraded_feeds[]` entry in status API | 2× backoff then skip | 48 h |
| 3 | **AI Enrichment Gold** | `INFO` log · `tier3_missing` metric · no status API impact | No retry (user-supplied or internal) | N/A |
| 4 | **Future / Planned** | Not yet implemented — `DEBUG` log if attempted · no metric | None | None |

---

## Tier 1 — Critical (Mandatory)

_System operates in a degraded, unreliable state without these sources.
Risk scores and findings MUST be marked stale if any Tier-1 feed fails past threshold._

### 1. SBOM Ingestion

| Source | Format | Notes |
| ------ | ------ | ----- |
| CycloneDX 1.4 / 1.5 / 1.6 | JSON or XML | Primary SBOM format. Rejection emits `INVALID_SBOM_FORMAT` error envelope. |
| SPDX 2.2 / 2.3 | JSON or tag-value | Accepted as secondary format; mapped to internal model on ingest. |

**Failure mode:** Malformed SBOM → synchronous `400 INVALID_SBOM_FORMAT` response.
Unsupported format → same. Parser panic → `500 INTERNAL_ERROR` with no raw details exposed.

### 2. Vulnerability Feeds

| Source | URL | What it provides |
| ------ | --- | ---------------- |
| CVE Program | `https://www.cve.org` | Canonical CVE IDs, reserved/published status, CNA assignment |
| NVD | `https://nvd.nist.gov` | CVSS v3/v4 base score, vector, description, CPE affected range |
| CISA KEV | `https://www.cisa.gov/known-exploited-vulnerabilities-catalog` | Confirmed in-the-wild exploitation flag; KEV due date |
| EPSS | `https://api.first.org/epss` | Exploit probability score (0–1); updated daily |

**Failure mode:** Any feed fails past its stale threshold (25 h) →

- `risk_context.kev_listed` and `risk_context.epss_score` values become unreliable.
- Status API response: `"signals_stale": true`.
- Prometheus: `themis_feed_sync_total{tier="1", feed="<name>", status="error"}`.
- Log: `ERROR` with feed name, HTTP status or network error, retry attempt count.

### 3. Scanner Evidence

| Source | Integration point |
| ------ | ----------------- |
| Trivy | SBOM upload (`POST /api/v1/artifacts/{id}/sboms`) — CycloneDX output accepted directly |
| Blackduck / Anchore | Same endpoint — export as CycloneDX before upload |

**Failure mode:** Scanner output rejected as malformed SBOM → same as §1 above.

---

## Tier 2 — Strongly Recommended

_System continues operating but with reduced ecosystem coverage.
Operators should be informed; hard failures should not block new ingestions._

| Source | URL | What it provides | Phase |
| ------ | --- | ---------------- | ----- |
| OSV Database | `https://osv.dev` | Multi-ecosystem advisories (npm, PyPI, Go, Maven, apk, RPM, …) | 2a |
| GitHub Security Advisory (GHSA) | `https://github.com/advisories` | Ecosystem-precise fix versions; Go, npm, PyPI, Maven, Rust, Kotlin | 2b (config key `THEMIS_GITHUB_TOKEN` wired in 2a) |
| Red Hat CSAF Advisories | `https://access.redhat.com/security/security-updates` | Vendor VEX for RHEL, Fedora, CentOS Stream; CSAF v2 format | 2a |
| Alpine OSV | `https://storage.googleapis.com/osv-vulnerabilities/Alpine/all.zip` | Vendor advisories for Alpine Linux packages | 2a (working URL; default URL returns 302) |
| Rocky Linux OSV | `https://storage.googleapis.com/osv-vulnerabilities/Rocky%20Linux/all.zip` | Vendor advisories for Rocky Linux packages | 2a (working URL; default URL returns 404) |
| Wolfi OSV | `https://packages.wolfi.dev/os/security.json` | Vendor advisories for Wolfi/Chainguard packages | 2a — works today |
| ExploitDB CSV | `https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv` | Public proof-of-concept exploit index | 2a (GitHub `offensive-security` mirror archived → 404; moved to GitLab `main`) |
| Ubuntu Security Notices (USN) | `https://usn.ubuntu.com` | Vendor advisories for Ubuntu packages (dpkg ecosystem) | Post-2a — needs `dpkg` version comparator |
| SUSE Security Advisories | `https://www.suse.com/security/cve/` | Vendor advisories for SUSE/openSUSE packages | Post-2a |
| Debian Security Advisories (DSA) | `https://www.debian.org/security/` | Vendor advisories for Debian packages | Post-2a — needs tilde-epoch version ordering |

**Failure mode:** Any Tier-2 feed fails →

- Prometheus: `themis_feed_sync_total{tier="2", feed="<name>", status="error"}`.
- Log: `WARN` with feed name, HTTP status, skip reason.
- Status API: `"degraded_feeds": ["alpine_osv", ...]` — informational, does not set `signals_stale`.
- Ingestion continues; findings from the missing ecosystem show `upstream_vex_coverage: not_covered`.

---

## Tier 3 — AI Enrichment Gold

_These sources elevate AI enrichment accuracy. None are external feeds in the traditional
sense — they are user-supplied artefacts, internal analyst decisions, registration data,
and deployment context. Missing Tier-3 data degrades AI output quality (Phase 2b+) but
does not affect the deterministic signal pipeline (Phase 2a)._

### 1. VEX Documents

| Source | Format | Authority |
| ------ | ------ | --------- |
| User-uploaded VEX | CycloneDX VEX (JSON) | Human — highest precedence |
| Vendor CSAF | CSAF v2 JSON | Vendor — second precedence |
| Upstream vendor VEX | Alpine / Rocky / Wolfi OSV `not_affected` assertions | Upstream vendor |
| Themis-generated VEX | OpenVEX 0.2+ | AI-assisted (Phase 2c) |

**Failure mode (missing VEX):** `risk_context.upstream_vex_coverage = not_covered`.
Prometheus: `themis_tier3_missing_total{source="vex_<type>"}`. Log: `INFO`.

### 2. Internal Analyst Decisions

| Decision type | Storage | How it affects enrichment |
| ------------- | ------- | ------------------------- |
| Analyst approval | `vex_assertions.source = manual` | Highest precedence over all external VEX |
| Risk acceptance | `risk_context.effective_state = accepted_risk` | Suppresses finding from active queue |
| False positive classification | `risk_context.effective_state = false_positive` | Feeds FP Analyzer KB in Phase 2b |
| Historical VEX decisions | `triage_history` | KB retrieval corpus for Phase 2b RAG |

**Failure mode (missing decisions):** AI workers run without KB context; confidence scores
lower. Prometheus: `themis_tier3_missing_total{source="analyst_decisions"}`. Log: `INFO`.

### 3. Project Metadata

| Entity | Required for |
| ------ | ------------ |
| Product | All API paths; blast-radius root |
| Project | Version scoping (mandatory since `themis-core-model`) |
| Version | VEX export (`GET .../versions/{v}/vex`); release tracking |
| Release status | `release_status=released` gates compliance reports |

**Failure mode (missing metadata):** VEX export returns empty or 404 until version is
registered. Prometheus: `themis_tier3_missing_total{source="project_metadata"}`. Log: `WARN`
(elevated because it blocks a user-visible API endpoint).

### 4. Asset Context

| Context | Field | Effect on scoring |
| ------- | ----- | ----------------- |
| Internet-facing deployment | `deployment.internet_facing` (Phase 2b field) | Layer 1 rule: `internet_facing AND CVSS ≥ 7 → Elevated` |
| Customer count | `risk_context.blast_radius_score` | Computed from graph; 1.0×–2.0× multiplier |
| Environment | `deployment.environment` | Scopes blast-radius traversal |

**Failure mode (missing context):** Blast-radius defaults to 1.0× (single customer);
no internet-facing rule fires. Prometheus: `themis_tier3_missing_total{source="asset_context"}`.
Log: `INFO`.

---

## Tier 4 — Advanced Intelligence (Future)

_Not yet implemented. These sources require new adapters, paid API access, or significant
infrastructure. Once implemented, failure behaviour is: `WARN` log if the source is
configured but fails; `INFO` if not configured (expected for optional sources). No
`signals_stale` impact. Metrics registered only after the adapter ships._

### 1. Exploit Intelligence

Sources that provide richer exploit context beyond the basic ExploitDB CSV already in
Tier 2. These distinguish between "a PoC exists" and "a mature, weaponised exploit is
in active use."

| Source | URL | What it provides | Notes |
| ------ | --- | ---------------- | ----- |
| ExploitDB (enriched) | `https://www.exploit-db.com` | Full exploit record: code, reliability rating, platform, author; more fields than CSV | Tier 2 already ingests the CSV; this is the richer API/web source |
| Metasploit References | `https://github.com/rapid7/metasploit-framework` | CVEs that have a working Metasploit module — the highest weaponisation signal | Git crawl of `modules/**/*.rb` `references:` blocks; or Rapid7 API |
| Public PoC Repositories | `https://github.com` | GitHub search for CVE-YYYY-NNNN repos; nuclei templates; trickest/cve catalogue | GitHub API token required; high noise — needs quality filter |

**When implemented — failure mode:**

- Configured but failing: `WARN` + `themis_feed_sync_total{tier="4", feed="<name>", status="error"}` +
  `degraded_feeds[]` entry in status API.
- Not configured: `INFO` log only; no metric; no status impact.
- New Layer 1 rule enabled: `metasploit_module = true → Critical override` (alongside KEV).

### 2. Threat Intelligence

Sources that provide threat actor context, campaign attribution, and early-warning signals.
These are mostly enterprise/paid and require explicit operator configuration.

| Source | Category | What it provides | Notes |
| ------ | -------- | ---------------- | ----- |
| Commercial TI feeds | Paid (e.g. Recorded Future, Mandiant, CrowdStrike Intel) | Threat actor TTPs, CVE weaponisation dates, dark-web exploit mention, campaign tags | Requires vendor API key; `THEMIS_TI_*` env vars |
| SOC Intelligence | Internal (SIEM / EDR export) | Observed exploitation events in the operator's own environment | Internal feed; operator-defined schema; highest context signal for their estate |
| CERT Advisories | Public (CERT/CC, US-CERT / CISA alerts, BSI, NCSC, JPCERT) | National-level threat bulletins; sometimes precede NVD/KEV publication | CERT/CC RSS/JSON; NCSC API; similar fetch pattern to Tier 2 OSV |

**When implemented — failure mode:**

- Commercial TI: `WARN` if API key present but request fails; `INFO` if no key configured.
  Prometheus: `themis_feed_sync_total{tier="4", feed="commercial_ti", status="error"}`.
- SOC Intelligence: `INFO` if no SIEM export path configured; `WARN` if path exists but
  file/endpoint unreachable.
- CERT Advisories: same degraded pattern as Tier-2 vendor VEX feeds (WARN + degraded entry).

**Data model impact (when implemented):** New `threat_intelligence_signals` table keyed by
`cve_id`; new `threat_actor_tags TEXT[]` column on `risk_context`; new Layer 1 rule:
`ti_weaponised = true AND CVSS ≥ 7 → Critical override`.

---

## Prometheus Metric Convention

All feed sync operations emit a single counter with consistent labels:

```text
themis_feed_sync_total{tier, feed, status}
```

| Label | Values |
| ----- | ------ |
| `tier` | `"1"`, `"2"`, `"3"`, `"4"` |
| `feed` | feed name e.g. `"epss"`, `"kev"`, `"alpine_osv"`, `"vendor_vex"` |
| `status` | `"success"`, `"error"`, `"stale"`, `"skipped"` |

Tier-3 missing sources use a separate gauge (no sync cycle, so no rate makes sense):

```text
themis_tier3_context_present{source}   gauge, 0 = missing, 1 = present
```

---

## Status API Behaviour

`GET /api/v1/status` response fields driven by tier:

```json
{
  "signals_stale": false,          // true if any Tier-1 feed exceeds stale threshold
  "degraded_feeds": [],            // Tier-2 feeds with recent errors
  "tier3_context": {
    "vex_coverage":    "partial",  // "full" | "partial" | "none"
    "decisions_in_kb": 142,        // count of triage_history rows (Phase 2b KB)
    "metadata_complete": true,     // all registered products have a version
    "asset_graph_nodes": 38        // microservices + deployments + customers
  }
}
```

---

## Code Conventions

When writing a feed adapter or sync scheduler, use this pattern to emit the correct
tier of error:

```go
// Tier 1 — hard failure, mark stale
if err != nil {
    slog.Error("tier-1 feed sync failed", "feed", "epss", "attempt", attempt, "error", err)
    metrics.FeedSyncTotal.WithLabelValues("1", "epss", "error").Inc()
    // caller sets system_state stale flag
    return err
}

// Tier 2 — degraded, continue
if err != nil {
    slog.Warn("tier-2 feed sync failed, skipping", "feed", "alpine_osv", "error", err)
    metrics.FeedSyncTotal.WithLabelValues("2", "alpine_osv", "error").Inc()
    return nil  // do not propagate; caller continues
}

// Tier 3 — missing context, log only
if noDecisions {
    slog.Info("tier-3 context absent", "source", "analyst_decisions", "artifact_id", artifactID)
    metrics.FeedSyncTotal.WithLabelValues("3", "analyst_decisions", "skipped").Inc()
}
```

---

## Relationship to Existing Design Decisions

| Decision | Reference | Tier alignment |
| -------- | --------- | -------------- |
| D12 — Intelligence Source Priority | `openspec/changes/themis-phase-2/design.md` | D12 "Mandatory" = Tier 1; D12 "Recommended" = Tier 2; this document extends and supersedes D12 for error behaviour |
| D1 — Three-Layer Intelligence Collector | Phase 2 design | Layer 1 (deterministic) feeds from Tier 1+2; Layer 2 (graph) feeds from Tier 3 asset context; Layer 3 (AI) feeds from Tier 3 analyst decisions |
| Error catalogue (12 codes) | `openspec/changes/themis-phase-2a/specs/error-ux/spec.md` | `INTERNAL_ERROR` for unhandled Tier-1 failures; no new error codes added by this document |

---

## Implementation Status Checklist

_Last updated: 2026-06-16._

**Legend:**

| Symbol | Meaning |
| ------ | ------- |
| ✅ | Available and working |
| ⚠️ | Implemented but broken or incomplete — known gap |
| 🔧 | Config / interface wired; adapter not yet built |
| ❌ | Not started |

---

### Tier 1 — Critical (Mandatory)

| # | Source | Status | Since | Gap / Next Step |
| - | ------ | :----: | ----- | --------------- |
| 1.1 | SBOM — CycloneDX 1.4 / 1.5 / 1.6 | ✅ | Phase 1 | — |
| 1.2 | SBOM — SPDX 2.2 / 2.3 | ✅ | Phase 1 | — |
| 1.3 | CVE Program (cve.org) | ⚠️ | Phase 1 | No direct cve.org API integration; CVE IDs arrive via NVD/OSV. D12 classifies as Mandatory with NVD fallback — that pattern is satisfied by the NVD adapter (row 1.4). |
| 1.4 | NVD (nvd.nist.gov) | ✅ | Phase 1 | CVSS vector strings not parsed in the OSV path (`fmt.Sscanf` bug); NVD adapter itself works. |
| 1.5 | CISA KEV | ✅ | Phase 2a | — |
| 1.6 | EPSS (first.org) | ✅ | Phase 2a | — |
| 1.7 | Scanner — Trivy | ✅ | Phase 1 | — |
| 1.8 | Scanner — Blackduck / Anchore | ⚠️ | Phase 1 | No native adapter; scanner must export CycloneDX before upload. |

---

### Tier 2 — Strongly Recommended

| # | Source | Status | Since | Gap / Next Step |
| - | ------ | :----: | ----- | --------------- |
| 2.1 | OSV Database (osv.dev) | ⚠️ | Phase 1 | `ALPINE-CVE-*` IDs not normalised → EPSS/KEV join misses Alpine findings. CVSS vector strings not parsed → scores = 0. |
| 2.2 | GitHub Advisory (GHSA) | 🔧 | — | `THEMIS_GITHUB_TOKEN` env var wired in config; adapter not built (Phase 2b). Note: D12 classifies GHSA as Mandatory — superseded by this tier system (Tier 2 Strongly Recommended). |
| 2.3 | Red Hat CSAF Advisories | ⚠️ | Phase 2a | Default URL is an HTML directory listing; needs `CSAFDirectoryFeedSource` to crawl advisory index. |
| 2.4 | Alpine OSV | ⚠️ | Phase 2a | Default URL returns HTTP 302 (GitLab login redirect). Working source: GCS zip. Fix: `ZipOSVFeedSource` or update default URL. |
| 2.5 | Rocky Linux OSV | ⚠️ | Phase 2a | Default URL returns HTTP 404. Working source: GCS zip. Fix: update default URL. |
| 2.6 | Wolfi OSV | ✅ | Phase 2a | — |
| 2.7 | ExploitDB CSV | ✅ | Phase 2a | Spec: `openspec/changes/themis-phase-2a/specs/exploitdb/spec.md`; adapter: `internal/adapter/exploitdb/`. Not exposed in scan findings API; `themis_exploitdb_sync_total` metric not yet wired (Group 30). |
| 2.8 | Ubuntu Security Notices (USN) | ❌ | — | Not started. Needs `dpkg` version comparator and USN feed adapter. |
| 2.9 | SUSE Security Advisories | ❌ | — | Not started. |
| 2.10 | Debian Security Advisories (DSA) | ❌ | — | Not started. Needs tilde-epoch `dpkg` version ordering. |

---

### Tier 3 — AI Enrichment Gold

| # | Source | Status | Since | Gap / Next Step |
| - | ------ | :----: | ----- | --------------- |
| 3.1 | VEX — User-uploaded CycloneDX VEX | ✅ | Phase 1 | — |
| 3.2 | VEX — Vendor CSAF | ⚠️ | Phase 2a | Same directory-crawl gap as 2.3 (Red Hat CSAF). |
| 3.3 | VEX — Upstream vendor OSV `not_affected` (Alpine / Rocky / Wolfi) | ⚠️ | Phase 2a | Alpine and Rocky broken (same as 2.4 / 2.5); Wolfi assertions work. |
| 3.4 | VEX — Themis AI-generated (OpenVEX) | ❌ | — | Phase 2c — requires Phase 2b AI workers to be healthy first. |
| 3.5 | Analyst decision — approval | ✅ | Phase 1 | — |
| 3.6 | Analyst decision — risk acceptance | ✅ | Phase 1 | — |
| 3.7 | Analyst decision — false positive | ✅ | Phase 1 | — |
| 3.8 | Analyst decision — historical VEX | ✅ | Phase 1 | — |
| 3.9 | Project metadata — Product | ✅ | Phase 1 | — |
| 3.10 | Project metadata — Project | ✅ | Phase 1 | — |
| 3.11 | Project metadata — Version | ⚠️ | Phase 1 | No REST endpoint to create versions (Group 16.10 open). Schema changes with `themis-core-model`. |
| 3.12 | Project metadata — Release status | ⚠️ | Phase 1 | `release_status` in domain model + REST API (`mappers.go`, `gen/api.gen.go`, `catalog.go`); no lifecycle promotion endpoint. |
| 3.13 | Asset context — Internet-facing flag | ❌ | — | `deployment` table has no `internet_facing` column. Phase 2b field; Layer 1 rule not yet wired. |
| 3.14 | Asset context — Customer count / blast-radius | ✅ | Phase 2a | — |
| 3.15 | Asset context — Environment | ✅ | Phase 2a | — |
| 3.16 | Internal KB — pgvector similarity search | ❌ | — | Phase 2b; no embedding or pgvector code exists. D12 classifies as Critical (blocks AI enrichment). Gates all Phase 2b AI workers. |

---

### Tier 4 — Advanced Intelligence (Future)

| # | Source | Status | Gap / Next Step |
| - | ------ | :----: | --------------- |
| 4.1 | ExploitDB enriched (exploit-db.com) | ❌ | Tier 2 CSV adapter exists. Richer API/web source (exploit code, reliability rating) needs a new adapter. |
| 4.2 | Metasploit References | ❌ | Needs git crawl of `rapid7/metasploit-framework` `modules/**/*.rb` reference blocks, or Rapid7 API. |
| 4.3 | Public PoC Repositories | ❌ | Needs GitHub API token + search + noise filter. High false-positive risk without quality scoring. |
| 4.4 | Commercial TI feeds | ❌ | Enterprise feature. Requires paid API keys (`THEMIS_TI_*` env vars to add). Recorded Future / Mandiant / CrowdStrike patterns. |
| 4.5 | SOC Intelligence | ❌ | Internal feed; operator-defined schema; SIEM / EDR export integration. Highest-context signal for the operator's own estate. |
| 4.6 | CERT Advisories | ❌ | Public feeds available (CERT/CC RSS, NCSC API, JPCERT JSON). Similar fetch pattern to Tier-2 OSV. Low complexity once Tier-2 gaps are resolved. |

---

### Summary Counts

| Tier | ✅ Available | ⚠️ Broken / Partial | 🔧 Wired | ❌ Not started | Total |
| ---- | :----------: | :-----------------: | :------: | :------------: | :---: |
| 1 — Critical | 6 | 2 | 0 | 0 | 8 |
| 2 — Recommended | 2 | 4 | 1 | 3 | 10 |
| 3 — AI Gold | 7 | 5 | 0 | 2 | 14 |
| 4 — Advanced | 0 | 0 | 0 | 6 | 6 |
| **Total** | **15** | **11** | **1** | **11** | **38** |
