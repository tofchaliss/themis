## Context

Phase 1 produces risk scores with `f(severity, vex_state)`. All findings with the
same CVSS score look identical. Phase 2a adds the external signal feeds (EPSS, KEV,
ExploitDB, vendor VEX), graph entities, deterministic rule engine, and management APIs
that make those scores actionable — without any AI dependency. Everything in Phase 2a
is synchronous and deterministic.

All architectural decisions for Phase 2a are fully specified in the master design:
`openspec/changes/themis-phase-2/design.md` Decisions 1 (L1+L2), 2, 10, 12, 13,
14, 15, 16, 18, and 19. This document summarises them for implementation context.

**Carrying over from Phase 1:**

- Single binary + PostgreSQL; no new runtime services in 2a
- Clean Architecture import rule absolute; `make clean-arch` gates every task group
- `InProcessQueue` remains the job backend (Redis deferred to Phase 3)
- All 15 Phase 1 acceptance criteria remain in force
- Coverage gate: `make coverage-pkg PKG=<path>`; new packages registered in
  `scripts/check-coverage.sh` before first gate check

## Goals / Non-Goals

**Goals:**

- Wire EPSS + KEV daily sync and ExploitDB CSV ingestion as intelligence signals
- Implement Layer 1 deterministic rule engine (synchronous, runs before `202 Accepted`)
- Implement Layer 2 SQL graph blast-radius traversal (synchronous, runs before `202 Accepted`)
- Add `Microservice`, `Deployment`, `Customer`, `ExploitRecord` domain entities
- Implement upstream vendor VEX feed scheduler with four-phase PURL matching
- Deliver VEX export endpoint (CycloneDX + OpenVEX)
- Deliver system status, SBOM list, and SBOM soft-delete APIs
- Apply layman-friendly error envelope to all endpoints

**Non-Goals:**

- AI workers, Ollama, pgvector, GHSA adapter — Phase 2b
- AI-assisted VEX auto-apply, false-positive automation — Phase 2c
- Debian/Ubuntu VEX feed matching — post-2a increment
- Apache AGE / Cypher graph queries — Phase 3
- Redis job queue, RBAC, Docker, Web UI — Phase 3+

## Decisions

All decisions listed here are fully specified in the master design document. The
notes below highlight implementation-relevant implications for Phase 2a specifically.

**D1 — Three-Layer Intelligence Collector (L1+L2 in 2a)**
Both layers run in the `usecase/enrichment/` sync path before `202 Accepted` is
returned. Layer 1 writes `risk_context.deterministic_level`; Layer 2 writes
`risk_context.blast_radius_score`. Neither layer calls Ollama. Layer 3 (async, 2b)
is wired as a stub that does nothing in Phase 2a but must exist as a nil-safe no-op
so Phase 2b can activate it without touching the use case.
See arch-ref Decision 1 for rule table and traversal pattern.

**D2 — Five-Layer Data Model (migrations 000014 + 000017 + 000018 in 2a)**
Phase 2a adds L1a (asset graph tables) to the L0 tables from Phase 1. L1b (knowledge
graph traversal) is implemented via SQL CTEs over L1a tables. L1c (pgvector, Phase 2b)
and L2 (AI output tables, Phase 2b) are not created in 2a.
The composite risk score formula confirmed:

```text
base      = f(severity, vex_state)          [Phase 1 formula]
layer1    = if deterministic_level=Critical → 100, else base
epss_adj  = base × (1 + epss_score × 0.3)  [up to +30%]
kev_adj   = if kev_listed → +15 points
blast_adj = base × blast_radius_score        [1.0–2.0×]
final     = min(100, layer1 + epss_adj + kev_adj + blast_adj)
```

`ai_adj` term (Phase 2b) is absent in 2a; formula extends cleanly.
See arch-ref Decision 2 for full five-layer schema.

**D10 — SQL Graph Tables (implemented in 2a)**
`asset_graph_nodes` and `asset_graph_edges` store the L1b graph. Blast-radius
traversal uses `WITH RECURSIVE ... UNION ALL` CTE with depth ≤ 7. Blast-radius
score: 1 Customer = 1.0×, 2–9 Customers scale linearly, 10+ Customers cap at 2.0×.
Phase 3 migrates to Apache AGE without data changes.
See arch-ref Decision 10 for the exact CTE pattern.

**D12 — Intelligence Source Priority (all external feeds in 2a)**
CISA KEV and Vendor Advisories are Mandatory (retry 3× with backoff; stale flag on
`risk_context` if sync fails for > 1h). EPSS and ExploitDB are Recommended (skip
gracefully; log gap; no alert). GitHub SA auth: `THEMIS_GITHUB_TOKEN` env var wired
in config in 2a even though the GHSA adapter itself ships in Phase 2b (OQ-8 resolved
for 2a config purposes).
See arch-ref Decision 12 for the full tier table.

**D13 — ExploitDB via CSV Download (2a)**
Daily scheduler at 02:00 UTC fetches
`https://raw.githubusercontent.com/offensive-security/exploitdb/master/files_exploits.csv`.
Parses EDB-ID, CVE, type, date, title. Upserts into `exploit_records` (append-only,
deduplicated by EDB-ID). `ExploitSource` domain port allows config swap to local
mirror in Phase 3 with no business logic change.
See arch-ref Decision 13 for air-gap path.

**D14 — Microservice, Deployment, Customer Entities (2a)**
Three new domain types with explicit registration APIs. OQ-9 resolved: explicit
`POST` endpoints only in Phase 2a; auto-discovery from SBOM `metadata.component.name`
is a post-2a improvement. `Customer` = internal team/owner of a Deployment; not a
B2B customer. `notification_rules` from Phase 1 extended to Deployment scope.
See arch-ref Decision 14 for field definitions.

**D15 — PURL Matching + VEX Export (2a)**
Two separable concerns under one decision in the master design:

1. *Four-phase PURL matching* (`adapter/vexfeed/`): exact → namespace alias →
   errata direction (RPM EVR compare) → OSV range (apk version comparator). Phase 2a
   scope: Alpine (apk) and RPM only. Each match phase sets a `match_type` field.
   Normalisation failures logged as `purl_mismatch`, never silently dropped.
   Vendor VEX authority principle: once matched, do not consult upstream version ranges.
2. *VEX export endpoint*: CycloneDX 1.5+ and OpenVEX 0.2+. Non-normative `x-themis-*`
   extension fields carry EPSS, KEV, and blast-radius metadata. AI justification text
   is added in Phase 2c.
See arch-ref Decision 15 for format schemas and the httpd backport example.

**D16 — Clean Architecture Ports (2a+2b+2c)**
Phase 2a adds these ports to `internal/domain/ports.go`:
`ThreatSignalFetcher`, `ExploitSource`, `GraphStore`. Ports `AIWorkerRuntime`,
`AdvisorySource`, `EmbeddingStore` are added in Phase 2b. Import rule absolute:
`domain/` → stdlib only; `usecase/` → `domain/` only; `adapter/` → `domain/` +
`usecase/`; `cmd/` → `infrastructure/` only.
See arch-ref Decision 16 for the complete port interface list.

**D18 — Status, SBOM List, SBOM Delete APIs (2a)**
`GET /api/v1/status?top=N` queries live data (no cache). `?top=N` defaults to 10,
max 50. `DELETE /api/v1/sboms/{id}` sets `deleted_at = NOW()`; requires `?force=true`
to delete the latest SBOM for a product. Audit log entry written on every delete.
All store-layer list/get queries must filter `WHERE sbom_documents.deleted_at IS NULL`
enforced at the store layer, not per-caller.
See arch-ref Decision 18 for full response shapes and SQL pattern.

**D19 — Layman-Friendly Error Responses (2a+2b+2c)**
Three-field envelope `{error: {code, message, hint}}` applied to all endpoints
(existing + new). Twelve catalogue entries cover all Phase 2a domain error classes.
Two hard rules: (1) no raw DB errors or Go error strings in any response body;
(2) plain language only — "couldn't find" not "404 Not Found".
See arch-ref Decision 19 for the full error catalogue.

## Risks / Trade-offs

**ReEnrichJob fanout on first EPSS/KEV sync** → A fresh deployment with 10,000+
existing findings triggers a `ReEnrichJob` for every `DETECTED`/`IN_TRIAGE` row
when EPSS/KEV data first arrives. `InProcessQueue` processes these serially;
a large backlog can delay new ingestion by minutes. Mitigation: batch size limit
(max 500 per sync job) with continuation tokens; new ingestion jobs take priority.

**RPM errata direction check false negatives** → If an RPM errata package version
is *lower* than the VEX assertion version (e.g. a point-release update was applied
on top of the fix), the EVR comparator returns `purl_mismatch`. Mitigation: the
`purl_mismatch` coverage field surfaces this to operators; normalisation rules can be
improved without changing the four-phase algorithm contract.

**Vendor VEX feed rate limits** → Red Hat's CSAF feed has no documented rate limit
but is a public CDN. Alpine/Rocky/Wolfi OSV feeds are Git repositories. Mitigation:
daily scheduler (not continuous polling); per-feed HTTP client with exponential
backoff; stale-data TTL flag rather than hard failure.

**SQL graph CTE performance** → `WITH RECURSIVE` CTEs with depth ≤ 7 on
`asset_graph_edges` are fast when the graph is sparse (< 10k nodes). Deployments
with many Products × Microservices × Deployments × Customers may see query times
> 500ms. Mitigation: `asset_graph_edges` composite index `(from_node_id, edge_type)`;
blast-radius result cached on `risk_context.blast_radius_score` (recomputed only on
graph mutation or `ReEnrichJob`).

**soft-delete performance** → Partial index `WHERE deleted_at IS NULL` on
`sbom_documents` keeps active-SBOM queries fast. Risk: if the partial index is not
created or a new query is added without the filter, a full-table scan includes
tombstoned rows. Mitigation: store layer enforces filter centrally; `make check`
includes a dead-code lint that would surface unused table columns.

## Migration Plan

**Database migrations (applied in order at startup via `golang-migrate`):**

1. `000014` — new L1a tables: `microservices`, `deployments`, `customers`,
   `asset_graph_nodes`, `asset_graph_edges`, `exploit_records`. Additive; no
   existing table changes.
2. `000015` — new `epss_kev_signals` table keyed by `cve_id`
   (`cve_id TEXT PK`, `epss_score`, `kev_listed`, `fetched_at`, `stale`). Additive.
   Note: the existing `intelligence_signals` table (migration 000006) uses a
   generic schema keyed by `component_vulnerability_id`. Phase 2a introduces
   `epss_kev_signals` as a separate purpose-built table; the old table remains
   for forward compatibility.
3. `000016` — add Phase 2a columns to `risk_context`: `epss_score`, `kev_listed`,
   `exploit_public`, `deterministic_level`, `blast_radius_score`,
   `upstream_vex_coverage`; add `not_affected` to the `effective_state` CHECK
   constraint (required for vendor VEX suppression). Additive.
4. `000017` — indexes: `risk_context(epss_score, kev_listed)`;
   `asset_graph_edges(from_node_id, edge_type)`. Additive.
5. `000018` — add `sbom_documents.deleted_at TIMESTAMPTZ DEFAULT NULL`;
   partial index `idx_sbom_documents_active WHERE deleted_at IS NULL`. Additive;
   existing rows get `deleted_at = NULL` automatically.

All five migrations are additive and backwards-compatible. Rollback: drop the new tables/columns and revert the `effective_state` constraint.

**New configuration keys (all optional with sane defaults):**

Added to `internal/infrastructure/config/config.go` alongside existing `NVDConfig`/`OSVConfig`.
Uses `time.Duration` poll intervals consistent with the existing `time.NewTicker` scheduler
pattern (`StartWatchScheduler`, `StartTriageExpiryScheduler`) — no cron library required.
All fields are overridable via `THEMIS_*` env vars in `load.go` using the existing helpers.

```go
// EPSSKevConfig controls EPSS and KEV feed sync.
type EPSSKevConfig struct {
    EPSSUrl      string        `yaml:"epss_url"`      // env: THEMIS_EPSSKEV_EPSS_URL
    KEVUrl       string        `yaml:"kev_url"`       // env: THEMIS_EPSSKEV_KEV_URL
    PollInterval time.Duration `yaml:"poll_interval"` // env: THEMIS_EPSSKEV_POLL_INTERVAL
}

// ExploitDBConfig controls ExploitDB CSV sync.
type ExploitDBConfig struct {
    CSVURL       string        `yaml:"csv_url"`       // env: THEMIS_EXPLOITDB_CSV_URL
    PollInterval time.Duration `yaml:"poll_interval"` // env: THEMIS_EXPLOITDB_POLL_INTERVAL
}

// VEXFeedConfig controls vendor VEX feed sync.
type VEXFeedConfig struct {
    RHELUrl       string        `yaml:"rhel_url"`        // env: THEMIS_VEXFEED_RHEL_URL
    AlpineOSVUrl  string        `yaml:"alpine_osv_url"`  // env: THEMIS_VEXFEED_ALPINE_OSV_URL
    RockyOSVUrl   string        `yaml:"rocky_osv_url"`   // env: THEMIS_VEXFEED_ROCKY_OSV_URL
    WolfiOSVUrl   string        `yaml:"wolfi_osv_url"`   // env: THEMIS_VEXFEED_WOLFI_OSV_URL
    PollInterval  time.Duration `yaml:"poll_interval"`   // env: THEMIS_VEXFEED_POLL_INTERVAL
}

// IntelligenceConfig controls blast-radius and enrichment tuning.
type IntelligenceConfig struct {
    BlastRadiusCap int `yaml:"blast_radius_cap"` // env: THEMIS_INTELLIGENCE_BLAST_RADIUS_CAP
}

// LogConfig controls structured logging behaviour.
type LogConfig struct {
    Level string `yaml:"level"` // env: THEMIS_LOG_LEVEL  (debug|info|warn|error; default: info)
}
```

Top-level `Config` struct additions:
```go
EPSSKev      EPSSKevConfig      `yaml:"epsskev"`
ExploitDB    ExploitDBConfig    `yaml:"exploitdb"`
VEXFeed      VEXFeedConfig      `yaml:"vexfeed"`
Intelligence IntelligenceConfig `yaml:"intelligence"`
Log          LogConfig          `yaml:"log"`
GitHub       GitHubConfig       `yaml:"github"` // THEMIS_GITHUB_TOKEN (OQ-8; GHSA adapter in 2b)
```

Default values (in `Default()`):
```text
epsskev.epss_url:             https://epss.cyentia.com/epss_scores-current.csv.gz
epsskev.kev_url:              https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
epsskev.poll_interval:        24h
exploitdb.csv_url:            https://raw.githubusercontent.com/offensive-security/exploitdb/master/files_exploits.csv
exploitdb.poll_interval:      24h
vexfeed.rhel_url:             https://access.redhat.com/security/data/csaf/v2/advisories/
vexfeed.alpine_osv_url:       https://gitlab.alpinelinux.org/alpine/infra/osv-db/-/raw/main/v1/
vexfeed.rocky_osv_url:        https://apollo.build.resf.org/vulns/rocky-linux-osv.json
vexfeed.wolfi_osv_url:        https://packages.wolfi.dev/os/security.json
vexfeed.poll_interval:        24h
intelligence.blast_radius_cap: 10
log.level:                    info
```

Note: EPSS URL returns a gzip-compressed CSV (`Content-Encoding: gzip`); the adapter must
decompress it. No config field needed — the adapter always decompresses.

**Rollback strategy:**

All migrations are additive. Rolling back 2a means: (1) remove `deleted_at` column
add-migration from the migration chain; (2) drop new tables. No data is mutated by
the 2a migrations.

The `ReEnrichJob` retroactive fanout can be re-triggered at any time by re-running
the EPSS/KEV or vendor VEX scheduler — idempotent upserts mean re-running is safe.

## Open Questions

| # | Question | Status |
| --- | --- | --- |
| OQ-1 | Composite risk score weights | ✅ Decided — confirmed formula (arch-ref Decision 2) |
| OQ-8 | GitHub SA API auth | ✅ Decided for 2a — `THEMIS_GITHUB_TOKEN` env var; GHSA adapter itself ships in 2b |
| OQ-9 | Microservice registration workflow | ✅ Decided for 2a — explicit `POST` API only; auto-discovery post-2a |
| — | Vendor VEX stale TTL | Open — how long before a stale KEV/EPSS sync triggers an operator alert? Proposed: 25h (one sync cycle + 1h grace). |
| — | blast_radius_score linear scale | Open — confirm 1-to-2× linear over 1–10 customers is the right multiplier curve or use a log scale. Recommended: linear for Phase 2a, revisit with real data. |
