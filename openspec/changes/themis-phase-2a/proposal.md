## Why

Phase 1 produces risk scores based solely on CVSS severity and VEX state — every
`DETECTED` finding with the same CVSS score looks identical regardless of whether
a public Metasploit module exists, CISA has listed it as actively exploited, or the
vendor has already backported the fix into the installed package version. Phase 2a
wires in the external signal feeds, graph entities, and deterministic rules that
make those scores actionable, without any AI dependency.

## What Changes

- **BREAKING** — Composite risk score formula replaces the Phase 1 CVSS-only formula.
  `h(severity, vex_state, epss_score, kev_flag, exploit_public, blast_radius_score)`
  replaces `f(severity, vex_state)`. Any consumer that hard-codes thresholds against
  the old score range must recalibrate.
- Daily EPSS (FIRST.org) and CISA KEV sync populates `intelligence_signals`;
  scores retroactively update all open `DETECTED`/`IN_TRIAGE` findings via
  `ReEnrichJob` (fixes G2).
- ExploitDB CSV ingestion provides the `ExploitPublic` signal consumed by Layer 1 rules.
- Scheduled vendor VEX fetch for Red Hat CSAF, Alpine OSV, Rocky Linux OSV, and
  Wolfi OSV. Four-phase PURL matching (exact → namespace alias → errata direction
  check → OSV range) applies `not_affected` suppressions retroactively via
  `ReEnrichJob` (fixes G11/G12). VEX coverage endpoint added (fixes G13).
  Vendor VEX is the authoritative source for backported patches — once matched,
  upstream CVE version ranges are not consulted.
- Layer 1 deterministic rules run synchronously before every `202 Accepted`,
  computing `deterministic_level` from CVSS + KEV + EPSS + ExploitPublic.
- Layer 2 graph traversal runs synchronously before every `202 Accepted`,
  computing `blast_radius_score` and queueing deterministic team notifications by
  traversing the CVE → Package → Product → Microservice → Deployment → Customer graph.
- New domain entities: `Microservice`, `Deployment`, `Customer` (internal team/owner),
  `ExploitRecord`. Registration APIs added for graph population.
- VEX export endpoint serialises `risk_context` + `vex_assertions` into CycloneDX
  VEX or OpenVEX format.
- System status endpoint (component count, CVE match count, top-N most-vulnerable
  components) and SBOM management endpoints (list, soft-delete with tombstone).
- Layman-friendly error envelope (`code`, `message`, `hint`) applied to all endpoints;
  no raw database errors or Go error strings in any response.

**Non-goals (deferred):**

- AI workers, Ollama, pgvector — Phase 2b
- AI-assisted VEX auto-apply, false-positive automation — Phase 2c
- GitHub Security Advisories (GHSA) — Phase 2b
- Debian/Ubuntu VEX feed matching (dpkg version ordering, DSA/USN format) — post-2a increment
- Redis job queue, rate limiting, RBAC, Docker, UI — Phase 3+

## Capabilities

### New Capabilities

- `epss-kev`: Daily FIRST.org EPSS + CISA KEV sync; TTL-aware `intelligence_signals`
  storage; retroactive `ReEnrichJob` for all open `DETECTED`/`IN_TRIAGE` findings on
  every sync cycle (G2 fix); composite risk score update
- `exploitdb`: Daily ExploitDB CSV ingestion (`files_exploits.csv`); `exploit_records`
  table; CVE-to-EDB-ID lookup; `ExploitPublic` boolean signal fed to Layer 1 rules
- `upstream-vex-feeds`: Scheduled vendor VEX fetch (Red Hat CSAF, Alpine/Rocky/Wolfi
  OSV); four-phase PURL matching algorithm; retroactive `ReEnrichJob` per matched
  `risk_context` row (G11/G12 fix); per-finding `upstream_vex_coverage` field;
  `/vex-coverage` aggregate endpoint (G13 fix); vendor-authoritative backport principle
- `intelligence-collector`: Layer 1 deterministic rules (CVSS+KEV+EPSS+ExploitPublic
  → `deterministic_risk_level`, sync); Layer 2 SQL graph blast-radius traversal
  (CVE → Package → Product → Microservice → Deployment → Customer, sync);
  team notification queue populated deterministically
- `asset-graph`: `Microservice`, `Deployment`, `Customer` domain entities; SQL graph
  tables (`asset_graph_nodes`, `asset_graph_edges`); registration APIs
  (`POST /api/v1/products/{id}/microservices`, `POST /api/v1/microservices/{id}/deployments`,
  `POST /api/v1/customers`); resolves OQ-9
- `vex-export`: `GET /api/v1/products/{id}/versions/{v}/vex?format=cyclonedx|openvex`;
  serialises `risk_context` + `vex_assertions` into standards-compliant document;
  human and upstream vendor VEX justification text included; AI justification added
  in Phase 2c
- `system-status`: `GET /api/v1/status?top=N` — total components, total CVE matches,
  severity breakdown, triage-state breakdown, top-N components by open CVE count
  (name, product, CVE count, highest CVSS, highest CVE ID)
- `sbom-management`: `GET /api/v1/sboms`, `GET /api/v1/products/{id}/sboms` —
  paginated SBOM inventory; `DELETE /api/v1/sboms/{id}` — soft-delete with
  `deleted_at` tombstone; `?force=true` required to delete the latest SBOM for a
  product; data never hard-deleted via API; partial index `WHERE deleted_at IS NULL`
  keeps all active queries fast
- `error-ux`: Three-field error envelope `{error: {code, message, hint}}` applied
  to all existing and new endpoints; twelve-entry error catalogue covers all domain
  error classes; no raw DB errors, Go error strings, or stack traces in any response

### Modified Capabilities

- `intelligence-enrichment`: Risk score formula changes from `f(severity, vex_state)`
  to `h(severity, vex_state, epss_score, kev_flag, exploit_public, blast_radius_score)`
  (**BREAKING** — score values and thresholds change); Layer 1 deterministic rules
  now execute synchronously within the enrichment use case before `202 Accepted`
  is returned (previously CVSS-only, no Layer 1 rules existed)

## Impact

**New packages:**

- `internal/adapter/epsskev/` — EPSS + KEV HTTP fetcher + daily scheduler
- `internal/adapter/exploitdb/` — ExploitDB CSV ingester + CVE-to-EDB-ID index
- `internal/adapter/vexfeed/` — vendor VEX fetcher + four-phase PURL matcher +
  precedence resolver
- `internal/adapter/assetgraph/` — graph store adapter (nodes + edges SQL)
- `internal/usecase/vexgen/` — VEX document generation + CycloneDX/OpenVEX serialiser

**Modified packages:**

- `internal/domain/` — new types: `Microservice`, `Deployment`, `Customer`,
  `ExploitRecord`; new ports: `ThreatSignalFetcher`, `ExploitSource`,
  `GraphStore`; risk score formula constants
- `internal/usecase/enrichment/` — Layer 1 rule engine; Layer 2 graph call;
  `ReEnrichJob` trigger for EPSS/KEV and upstream VEX sync
- `internal/adapter/api/` — new endpoints (status, sboms list/delete, vex-export,
  blast-radius, microservice/deployment/customer registration); layman-friendly
  error middleware; SBOM active-filter enforcement
- `internal/adapter/store/` — `sbom_documents.deleted_at`; partial index;
  active-SBOM filter on all list/get queries
- `internal/infrastructure/config/` — EPSS/KEV/ExploitDB/VEX feed config;
  `THEMIS_GITHUB_TOKEN` env var (OQ-8)

**Database migrations:**

- `000014` — `microservices`, `deployments`, `customers`, `asset_graph_nodes`,
  `asset_graph_edges`, `exploit_records`
- `000015` — `epss_kev_signals` table keyed by `cve_id` (separate from the
  existing generic `intelligence_signals` table from Phase 1)
- `000016` — add Phase 2a columns to `risk_context` (`epss_score`, `kev_listed`,
  `exploit_public`, `deterministic_level`, `blast_radius_score`,
  `upstream_vex_coverage`); add `not_affected` to `effective_state` constraint
- `000017` — indexes on `risk_context(epss_score, kev_listed)`; `asset_graph_edges`
  composite index
- `000018` — `sbom_documents.deleted_at TIMESTAMPTZ DEFAULT NULL`;
  partial index `WHERE deleted_at IS NULL`

**New API endpoints:**

- `GET /api/v1/status?top=N`
- `GET /api/v1/sboms`
- `GET /api/v1/products/{id}/sboms`
- `DELETE /api/v1/sboms/{id}`
- `GET /api/v1/products/{id}/versions/{v}/vex`
- `GET /api/v1/products/{id}/blast-radius`
- `POST /api/v1/products/{id}/microservices`
- `POST /api/v1/microservices/{id}/deployments`
- `POST /api/v1/customers`
- `GET /api/v1/products/{id}/versions/{v}/vex-coverage`

**External dependencies (all public, no auth unless noted):**

- FIRST.org EPSS API
- CISA KEV JSON feed
- ExploitDB CSV (`offensive-security/exploitdb`)
- Red Hat CSAF feed
- Alpine, Rocky Linux, Wolfi OSV feeds
- GitHub token (`THEMIS_GITHUB_TOKEN`) required for GHSA rate limit > 60 req/hr
  (OQ-8; GHSA adapter itself is Phase 2b but config key wired in 2a)
