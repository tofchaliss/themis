# Themis — Project Backlog

All deferred proposals and unimplemented items, organised by phase. Each entry records:
what it is, why it was deferred, which Phase 1 hooks or interfaces are already in place,
and the target phase.

---

## Phase decision log

The original `proposal-initial.md` defined:

- Phase 2 = Native React SPA (Web UI)
- Phase 3 = Full-Featured Platform (Docker, RBAC, HA)

**These boundaries were changed during Phase 1 design, then refined further before Phase 2
started.** The current plan:

- Phase 2 = AI enrichment, EPSS/KEV, upstream VEX feeds, VEX export — split into three
  sub-phases (2a, 2b, 2c) because the full scope is too large to implement reliably as one
  change and the AI layer depends on signals being healthy before meaningful testing is possible
- Phase 3 = Rate limiting + runtime observability + cosign/sigstore + CI/CD ingestion +
  deployment + UI + enterprise features

Rationale for sub-phase split: Phase 2a (signals + graph + VEX export) delivers standalone
value and validates the data foundation. Phase 2b (AI workers + RAG + pgvector) can only be
meaningfully tested after EPSS/KEV/ExploitDB are healthy. Phase 2c (auto-apply thresholds)
requires the KB to be seeded with real analyst decisions before confidence thresholds are
tunable. Splitting also lets each sub-phase be tagged as a release (v0.2.0, v0.3.0, v0.4.0).

---

## Intelligence Source Tiers — Reference

**Canonical classification of all Themis intelligence sources by importance tier.**
Reference document: `openspec/intel-source-tiers.md`.
All feed adapters and schedulers must emit errors at the tier level defined there.

| Tier | Name | Failure behaviour |
| ---- | ---- | ----------------- |
| 1 | Critical — Mandatory | `ERROR` + `signals_stale=true` + operator notification |
| 2 | Strongly Recommended | `WARN` + `degraded_feeds[]` in status API |
| 3 | AI Enrichment Gold | `INFO` + metric counter, no status API impact |
| 4 | Future / Planned | `DEBUG` only — not yet implemented |

See `openspec/intel-source-tiers.md` for the complete source list, Prometheus metric
convention, status API response shape, and Go code conventions per tier.

---

## HIGHEST PRIORITY (schema work) — Core Data Model Restructure (`themis-core-model`)

**Decided: 2026-06-16. All decisions confirmed. This is the next breaking change and ships as
`v0.3.0` together with Phase 2b.**

It gates everything that depends on the schema: the artifact/version registration endpoints
(Group 16.4 / 16.10), the G3 "VEX export without SQL" fix, and Phase 2b planning. It does
**not** gate the `v0.2.1` maintenance release — Group 31 feed fixes and the Group 16 hardening
remainder (16.1–16.3, 16.5–16.8) touch no schema and ship first, ahead of this restructure.
See "Release versioning — reconciliation" below.

### Why now

The current model conflates two distinct concerns inside `sbom_documents`:

- **Composition** — what is in the artifact (stable; determined by the image digest)
- **Vulnerability scan** — what was found at a point in time by a specific scanner
  (temporal; evolves as CVE databases are updated)

This conflation causes three concrete problems that compound with each phase built on top:

1. **Silent triage loss on rescan.** `risk_context` keys off
   `component_vulnerability_id`, which is tied to a specific scan document row. Every
   rescan creates new `component_vulnerabilities` rows → new `risk_context` rows →
   all previous `accepted_risk` / `false_positive` decisions are silently orphaned.
2. **`is_latest` / `supersedes_id` anti-pattern.** The linked-list chain on
   `sbom_documents` makes it impossible to cleanly answer "how many scans exist for
   this artifact?" and is not used consistently across the codebase.
3. **Phase 2b lock-in.** AI workers in Phase 2b will reference
   `component_vulnerability_id → sbom_document_id`. After Phase 2b ships, fixing
   `risk_context` means migrating all AI enrichment output tables too.

### Confirmed decisions (no open questions)

| # | Question | Decision |
| - | -------- | -------- |
| Q1 | Does `version` always require a `project` parent? | **Yes — mandatory.** A default project is auto-created on product registration. `version.project_id NOT NULL` always. No optional FK. |
| Q2 | Is `artifact.image_digest` globally UNIQUE? | **Yes — globally.** Same digest = same physical content = same artifact. One artifact can only belong to one version. No join table needed. |

### New entity hierarchy

```text
product
  └── project  (product_id)               ← unchanged
        └── version  (project_id)          ← was: version.product_id
              └── artifact  (version_id,   ← merges current artifact + images tables
                              image_digest TEXT UNIQUE)
                    │
                    ├── sbom         (artifact_id)            1 per artifact
                    │     └── component_versions  (sbom_id)
                    │     └── dependency_relationships (sbom_id)
                    │
                    └── scan_report  (artifact_id, scanner)   N per artifact
                          └── component_vulnerabilities (scan_report_id)
                                └── risk_context  ← PK moves to (artifact_id, purl, cve_id)
```

`sbom` = the bill of materials (what is installed — stable for a given digest; Layer 0
immutable inventory). `scan_report` = one scanner's findings at one point in time
(temporal; ordered by `scanned_at DESC`). "Latest scan" = `ORDER BY scanned_at DESC
LIMIT 1` — no `is_latest` flag needed.

### Tables replaced / merged

| Old table | New table | Change |
| --------- | --------- | ------ |
| `product_versions` | `versions` | `project_id FK` replaces `product_id FK` |
| `artifacts` + `images` | `artifacts` | Merged into one table; `image_digest` moves here; `images` table dropped |
| `sbom_documents` | `sboms` + `scan_reports` | Split: composition → `sboms`; temporal scan → `scan_reports` |

### FK column renames (same logic, different target table)

| Column | Was | Now |
| ------ | --- | --- |
| `component_versions.sbom_document_id` | `sbom_documents` | `sboms` |
| `dependency_relationships.sbom_document_id` | `sbom_documents` | `sboms` |
| `component_vulnerabilities.sbom_document_id` | `sbom_documents` | `scan_reports` |
| `vex_documents.sbom_document_id` | `sbom_documents` (nullable since mig 000019) | `artifacts` |

### `risk_context` key change — the triage persistence fix

```text
Before: UNIQUE component_vulnerability_id   ← tied to one scan document row; lost on rescan
After:  PRIMARY KEY (artifact_id, component_purl, cve_id)   ← identity-based; survives rescans
```

A triage decision means "for CVE-X in component pkg:apk/busybox@1.36 running in this
artifact, we accept the risk." That identity does not change when the artifact is
rescanned. The new PK makes this explicit.

### Eliminated anti-patterns

- `sbom_documents.is_latest` — **removed.** Latest scan = `ORDER BY scanned_at DESC LIMIT 1`.
- `sbom_documents.supersedes_id` — **removed.** No more linked-list chain.

### What does NOT change (entire Phase 2a intelligence layer preserved)

All Phase 2a business logic — EPSS/KEV sync, ExploitDB, Layer 1 deterministic rules,
Layer 2 blast-radius, VEX matching algorithms, VEX export — is unchanged. Only the FK
traversal is updated (different column names pointing to new tables).

Tables that survive without structural change: `vulnerabilities`, `epss_kev_signals`,
`exploit_records`, `vex_assertions`, `triage_history`, `audit_log`, `api_keys`,
`notification_rules`, `ingestion_jobs`, `system_state`, `microservices`, `deployments`,
`customers`, `asset_graph_nodes`, `asset_graph_edges`, `intelligence_signals`,
`runtime_exposures`, `remediation_actions`.

### Implementation scope

- Replace migrations 000001–000004 with new migrations for `versions`, `artifacts`,
  `sboms`, `scan_reports`; adjust FK references in migrations 000005–000019 (additive
  ALTER TABLE changes per affected table — no data mutations)
- ~24 non-test `.go` files updated: domain types, store layer, use cases, adapters,
  API handlers (FK column rename propagation only — no algorithm changes)
- ~30 test files updated: SQL fixture references to `sbom_document_id`, `image_id`
- `risk_context` store queries updated for new PK shape
- Ingestion use case: one ingest call produces one `sboms` row + one `scan_reports` row
  (split from current single `sbom_documents` insert)

### Impact on Group 16 items

- **16.4** (`POST /api/v1/products/{id}/images`) — replaces with `POST /api/v1/products/{id}/artifacts`
  under the new merged table; same intent, updated path and payload.
- **16.10** (`POST /api/v1/products/{id}/versions`) — `product_versions` becomes `versions`
  with `project_id` FK; endpoint becomes `POST /api/v1/projects/{id}/versions`. The auto-create
  default project on product registration satisfies the single-project case without SQL workarounds.

---

## Release versioning — reconciliation (2026-06-17)

Phase 2a was tagged `v0.2.0` before Phase 1's Group 16 hardening finished, which
stranded the planned `v0.1.0` milestone *below* an already-published release. This was
reconciled as follows:

- **`v0.1.0`** — created retroactively on the Phase 1 completion commit (`a94f3ba`,
  PR #10), replacing the old `themis-phase-1` tag. Tag history now reads
  `v0.1.0 → v0.2.0`. `v0.1.0` is **done** — it is no longer a future gate.
- **`v0.2.0`** — Phase 2a Signal Foundation (released).
- **`v0.2.1`** — new maintenance release: Group 31 feed-reliability fixes + the Group 16
  hardening remainder (see below). No breaking changes.
- **`v0.3.0`** — `themis-core-model` (breaking schema restructure) + Phase 2b.
- **`v0.4.0`** — Phase 2c.

Nothing below `v0.2.0` will ever be tagged again.

---

## Group 16 — Phase 1 hardening remainder (now targets v0.2.1)

These post-completion tasks close gaps found after the main Phase 1 build. The original
"gate before tagging `v0.1.0`" framing is retired (`v0.1.0` is tagged). The hardening
tasks now ship in the **v0.2.1** maintenance release; the two new registration endpoints
moved under `themis-core-model` because that change redefines both.

| # | Task | Status |
| - | ---- | ------ |
| 16.1 | OSV query: normalise Alpine package names before lookup (strip `so:` prefix, map `py3-foo` → `python3-foo`) | **Done** (v0.2.1) |
| 16.2 | Integration test: Alpine SBOM ingest with OSV-matched CVEs | **Done** (`TestV021AlpineSBOMOSVCorrelation`) |
| 16.3 | Integration test: rpm-based SBOM ingest with unsupported ecosystem skipped cleanly | **Done** (`TestV021RPMSBOMIngestSkipsUnsupportedOSV`) |
| 16.4 | REST endpoint to register an artifact before SBOM upload | **Moved → `themis-core-model`** (`POST /api/v1/products/{id}/artifacts`) |
| 16.5 | Upload helper script (curl-based) for local testing and CI pipelines | **Done** (`scripts/upload-sbom.sh`, `scripts/alpine-e2e-gate.sh`) |
| 16.6 | `make check` run clean after all hardening items | **Done** (v0.2.1) |
| 16.7 | Coverage: `adapter/store/` reaches ≥90% | **Done** (91.6%) |
| 16.8 | Coverage: `adapter/osv/` reaches ≥90% | **Done** (93.6%) |
| 16.9 | Git tag `v0.1.0` and Phase 1 release notes | **Done** (retroactive tag, 2026-06-17) |
| 16.10 | REST endpoint to register a version | **Moved → `themis-core-model`** (`POST /api/v1/projects/{id}/versions`) |

---

## Phase 2 backlog

Phase 2 is split into three sub-phases. Master architecture reference:
`openspec/changes/themis-phase-2/proposal.md` and `design.md`.
Current implementation status: `openspec/STATUS.md`.

---

### Phase 2a — Signal Foundation (`themis-phase-2a`) — Complete (Archived 2026-06-17)

**Gate:** none outstanding (shipped ahead of the Group 16 hardening; see Release
versioning reconciliation above).
**Released as:** v0.2.0 (merged to `main` 2026-06-17; PR #16)
**OpenSpec change:** `openspec/changes/archive/2026-06-17-themis-phase-2a/`
**Progress:** 140/140 tasks complete (Groups 17–30). Archived.

**Implemented (Groups 17–29):**

- Domain types, migrations 000014–000019, Phase 2a config structs + env overrides
- **EPSS/KEV sync** — daily FIRST.org EPSS + CISA KEV fetch; `epss_kev_signals` table;
  retroactive `ReEnrichJob`; stale flag after 25h; `signals_stale` on status API
- **ExploitDB CSV** — `files_exploits.csv`; `exploit_records`; Layer 1 `ExploitPublic` rule
- **Layer 1 deterministic rules** — CVSS/KEV/EPSS/ExploitPublic → `deterministic_level`
- **Asset graph** — Microservice / Deployment / Customer entities + registration APIs
- **Layer 2 blast-radius** — graph traversal, score multiplier, team notifications,
  `GET /api/v1/products/{id}/blast-radius`
- **Composite risk score V2** — EPSS +30%, KEV +15, blast-radius multiplier, Critical override
  (**BREAKING** vs Phase 1 score thresholds)
- **Upstream VEX feeds** — Red Hat (CSAF), Alpine / Rocky / Wolfi (OSV); four-phase PURL
  matcher (apk + RPM); `upstream_vex_coverage` on `risk_context`; daily poll scheduler
- **VEX export** — `GET .../versions/{v}/vex` (CycloneDX 1.5+ / OpenVEX 0.2+);
  `GET .../vex-coverage`; precedence human > user > AI > upstream vendor
- **System status API** — `GET /api/v1/status?top=N` (live counts, top-N, `signals_stale`)
- **SBOM management** — `GET /api/v1/sboms`, `GET /api/v1/products/{id}/sboms`,
  `DELETE /api/v1/sboms/{id}?force=true` (soft-delete + audit log)
- **Error UX** — `{error: {code, message, hint}}` envelope on all endpoints; 12 catalogue codes
- **Acceptance gates** — AC-16..AC-24 integration tests; feed resilience FR1–FR8 mapped
- **Group 30 complete** — coverage gates, Prometheus metrics wiring, `verification.md` sync,
  `AGENTS.md` update, release notes, merge to `main`, `v0.2.0` tag

**Deferred from Phase 2a scope (see follow-ons below):**

- **GHSA integration** — config key `THEMIS_GITHUB_TOKEN` wired; adapter ships in Phase 2b
- **Debian/Ubuntu VEX feed matching** — separate matchers; apk/RPM path first

**What (original scope reference):**

- **EPSS/KEV sync** — daily CISA KEV + FIRST.org EPSS fetch; updates
  `intelligence_signals` with TTL; incorporates into risk score formula
- **ExploitDB CSV** — ingests `files_exploits.csv` from public GitHub mirror;
  CVE-to-EDB-ID lookup; feeds Layer 1 `ExploitPublic` rule
- **GHSA integration** — GitHub Security Advisories for ecosystem-precise fix
  versions (npm, Go, PyPI, Maven, etc.); extends the Phase 1 correlator
- **Upstream VEX feeds** — scheduled fetch from Red Hat, Alpine, Rocky Linux, Wolfi;
  applied as `vex_documents` with `source=upstream_vendor`; four-phase PURL normalisation
  for apk + RPM ecosystems (see Decision 15); Debian/Ubuntu deferred to follow-on (see below)
- **Layer 1 deterministic rules** — CVSS ≥ 9 ∧ KEV → Critical; CVSS ≥ 9 ∧
  ExploitPublic → High+; EPSS ≥ 0.5 ∧ CVSS ≥ 7 → Elevated; etc.
- **Microservice / Deployment / Customer entities** — new domain entities; registration
  APIs; resolves OQ-9 (registration workflow)
- **Layer 2 graph reasoning** — SQL traversal CVE → Package → Product → Microservice
  → Deployment → Customer; blast-radius scoring; team-level notifications
- **VEX export** — `GET /api/v1/products/{id}/versions/{v}/vex` CycloneDX or OpenVEX
- **System status API** — `GET /api/v1/status?top=N`: total components, CVE counts by
  severity/state, top-N components with most open vulnerabilities (name, product, CVE
  count, highest CVSS); answers "what is in Themis and what's most urgent?" in one call
- **SBOM management APIs** — `GET /api/v1/sboms`, `GET /api/v1/products/{id}/sboms`
  (paginated listings); `DELETE /api/v1/sboms/{id}` (soft-delete with force flag for
  latest SBOM; `deleted_at` tombstone; audit log entry)
- **Layman-friendly error responses** — three-field error envelope (`code`, `message`,
  `hint`) across all API endpoints; no raw DB errors or Go strings in responses
- **Cold-start fixes** — G2 (EPSS/KEV retroactive score update), G6 (NVD warmup)

**Why deferred from Phase 1:** risk score formula change and graph entity additions
are breaking changes that require the Phase 1 pipeline to be stable first.

**Phase 1 hooks:**

- `intelligence_signals` table has `signal_type`, `score`, `expires_at` columns
- `vex_documents.source` column distinguishes source tiers
- `watch/` scheduler pattern cloneable for EPSS/KEV + vendor VEX sync
- `JobQueue` interface for async tasks already in place
- `risk_context` has `epss_score`, `kev_listed` columns (populated NULL today)

**Database migrations:** 000014–000019 (graph entities, `epss_kev_signals`, Phase 2a
`risk_context` columns, indexes, SBOM soft-delete, vendor VEX feed tables)

**Post-2a follow-on — Vendor VEX feed operations:**

| Item | Why deferred | Phase 1 / 2a hooks |
| ---- | ------------ | -------------------- |
| Per-feed enable/disable (`vexfeed.rhel_enabled`, etc.) — **now folded into `themis-feed-registry`** (see Candidate change below) | Phase 2a wires all four feeds; operators may want to disable Wolfi/Rocky in non-RHEL shops | `VEXFeedConfig` URLs already per-feed; add bool flags in config + skip in `api_wiring.go` |
| Red Hat CSAF directory crawl | Default `rhel_url` points at the CSAF advisories *directory*; production may need a manifest/bundle URL or crawler over individual `.json` files | `URLFeedSource` + `ParseCSAF` accept single-document bodies today |
| Alpine vendor OSV feed URL returns 302 | Default `alpine_osv_url` (`gitlab.alpinelinux.org/.../v1/`) redirects to GitLab sign-in (HTTP 302), not public JSON. Observed: `themis_vexfeed_sync_total{feed="alpine",status="error"}` while Wolfi succeeds. `vex-coverage` stays `{covered:0, not_covered:N}` for Alpine SBOMs. | `URLFeedSource` in `api_wiring.go`; `themis.yaml.example` `alpine_osv_url` |
| Rocky vendor OSV feed URL 404 | Default `rocky_osv_url` (`apollo.build.resf.org/vulns/rocky-linux-osv.json`) returns HTTP 404. Working sources exist elsewhere (see fix below). | `rocky_osv_url` default in `config.go` / `themis.yaml.example` |
| `ParseOSVFeed` skips `ALPINE-CVE-*` advisory IDs | `firstCVE()` only accepts `aliases` or `id` starting with `CVE-`. Alpine OSV records use `id: ALPINE-CVE-YYYY-NNNN` with empty `aliases` — assertions are dropped even when feed body parses. Companion to OSV ingestion CVE normalization. | `adapter/vexfeed/osv.go` `firstCVE()` |
| Cron-style `sync_schedule` (vs poll interval) | Schedulers use `time.NewTicker` + `poll_interval` (same as EPSS/ExploitDB); cron strings not implemented | `StartVEXFeedScheduler`, `StartEPSSKevScheduler` |
| README + `themis.yaml.example` Phase 2a config docs | Operator discoverability | **Done** — see README Configuration and `themis.yaml.example` |

**How to fix vendor VEX feed fetch (Alpine / Rocky / RHEL):**

Themis `URLFeedSource` does one `GET` and expects a single JSON/CSAF document. Default URLs are
directories, login redirects, or dead links — not documents.

| Feed | Broken default | Working source (verified) | Code / config fix |
| ---- | -------------- | ------------------------- | ----------------- |
| **Alpine** | GitLab `.../v1/` → 302 | `https://storage.googleapis.com/osv-vulnerabilities/Alpine/all.zip` (200, zip of OSV JSON) or per-advisory `https://storage.googleapis.com/cve-osv-conversion/alpine/ALPINE-CVE-*.json` | Add `ZipOSVFeedSource` (download + unzip + `ParseOSVFeed` each file) **or** periodic sync from GCS; update default `alpine_osv_url` / env `THEMIS_VEXFEED_ALPINE_OSV_URL`. GitLab raw tree is not a public unauthenticated feed. |
| **Rocky** | `apollo.../rocky-linux-osv.json` → 404 | `https://storage.googleapis.com/osv-vulnerabilities/Rocky%20Linux/all.zip` (200) or `https://storage.googleapis.com/resf-osv-data/{RLSA-id}.json` | Same zip/crawl pattern; update default `rocky_osv_url`. Optional: Apollo `GET /api/v3/osv/` list + per-id fetch (needs new `ListFeedSource`). |
| **RHEL** | Directory URL → 301 + HTML index | `https://security.access.redhat.com/data/csaf/v2/advisories/` returns HTML listing of `*.json` files | Add `CSAFDirectoryFeedSource`: fetch index, parse advisory links, fetch each CSAF JSON, merge via existing `ParseCSAF`. Cannot fix with URL override alone. |
| **Wolfi** | — | `https://packages.wolfi.dev/os/security.json` (200) | No change — already works. |

**Operator workaround (until code ships):** none for Alpine/RHEL/Rocky — all require fetch-model
changes. Wolfi-only sync does not cover `apk` SBOMs.

**After feeds load — still required for Alpine SBOM end-to-end:**

1. **`ParseOSVFeed.firstCVE()`** — extract `CVE-*` from `ALPINE-CVE-*` (and use `aliases` when present).
2. **`mapOSVVuln` CVE normalization** — store canonical `CVE-*` in `vulnerabilities.cve_id` (see follow-on below).
3. **OSV CVSS vector parsing** — populate severity + `cvss_score` (see follow-on below).
4. **Re-sync / re-enrich** — restart server or wait for poll; optional backfill SQL for existing rows.

**Verify after fix:**

```sh
curl -s "$BASE_URL/metrics" | grep themis_vexfeed_sync_total
# expect: alpine/rhel/rocky status="success"

curl -s "$BASE_URL/api/v1/products/$PRODUCT_ID/versions/1.0.0/vex-coverage" -H "X-API-Key: $API_KEY" | jq .
# expect: covered + purl_mismatch > 0 (not all not_covered)
```

**Post-2a follow-on — Debian/Ubuntu VEX feed matching:**

Debian (DSA format, dpkg version ordering with tilde rules and epochs) and Ubuntu
(USN format, per-series version ranges per `jammy`/`focal`/`noble`) are excluded from
Phase 2a scope because they use formats and version comparators that differ from
apk/RPM. The four-phase `Matcher` interface defined in Phase 2a supports adding
Debian/Ubuntu as new `Matcher` implementations with no changes to the shared matching
logic or VEX assertion storage. Implement after Phase 2a ships and the apk/RPM path
is validated in production.

**Post-2a follow-on — OSV CVSS vector parsing:**

| Item | Why deferred / impact | Phase 1 / 2a hooks |
| ---- | --------------------- | -------------------- |
| Parse CVSS vector strings from OSV `severity[].score` | OSV (Alpine, npm, GHSA, etc.) returns `CVSS:3.1/AV:N/...` vectors, not numeric scores. `mapOSVVuln` in `adapter/osv/client.go` uses `fmt.Sscanf("%f")` and only accepts plain floats — real feed data leaves `vulnerabilities.cvss_score = 0` and `severity = unknown`. `GET /api/v1/status?top=N` then reports `highest_cvss_score: 0` in `top_components` even when `vulnerability_count` is correct (status reads raw catalog CVSS, not composite `risk_score`). Layer 1 rules and enrichment fallbacks also miss CVSS-derived severity until fixed. | `ComponentFetcher` + `mapOSVVuln`; `vulnerabilities.cvss_score` / `cvss_vector` columns; status query `MAX(v.cvss_score)` in `adapter/store/status.go`; unit test uses simplified numeric `"7.5"` score only |

**Fix:** In `internal/adapter/osv/client.go`, detect vector-form scores (prefix `CVSS:`), compute or
look up the base score (CVSS v3/v4 parser or NVD backfill), store numeric score and vector on
upsert. Optionally accept `CVSS_V4` severity type. Re-upsert or migration backfill for existing
catalog rows.

**Post-2a follow-on — OSV Alpine CVE ID normalization:**

| Item | Why deferred / impact | Phase 1 / 2a hooks |
| ---- | --------------------- | -------------------- |
| Normalize OSV Alpine IDs (`ALPINE-CVE-YYYY-NNNN`) to canonical `CVE-YYYY-NNNN` | Alpine OSV returns vulnerability IDs with an `ALPINE-` prefix. `mapOSVVuln` stores them as-is in `vulnerabilities.cve_id`. EPSS, KEV, and ExploitDB feeds key on standard `CVE-*` IDs — `GetEPSSForCVE` / `IsKEVListed` / `HasPublicExploit` in `ReEnrichSignalsBatch` do exact-match lookup and miss every Alpine finding. Observed on real Alpine SBOM bring-up: 592/592 export IDs prefixed `ALPINE`, `with_epss: 0` and `with_kev: 0` in VEX export despite successful sync metrics (`themis_epsskev_sync_total{status="success"}`, `themis_reenrichjob_batches_total ≥ 1`). Vendor VEX and CVE watch correlation may also fail to join on the same CVE across sources. | `mapOSVVuln` in `adapter/osv/client.go`; `vulnerabilities.cve_id` (unique constraint); `ReEnrichSignalsBatch` + `CombinedSignalReader`; `epss_kev_signals.cve_id`; VEX export `x-themis-epss-score` / `x-themis-kev-listed` via `risk_context` |

**Fix:** In `mapOSVVuln` (or a shared `NormalizeCVEID` helper in `domain/`), strip known OSV
ecosystem prefixes (`ALPINE-`, and similar) when the remainder is a valid `CVE-*` ID; store
canonical `cve_id` on upsert. Optionally retain the OSV-native ID in `description` or a future
alias column. Add lookup fallback in signal readers (`GetEPSSForCVE`) for defence in depth.
Backfill existing `ALPINE-CVE-*` rows via one-off migration or re-ingest. **Companion fix:** CVSS
vector parsing (above) — both gaps must land for Alpine SBOMs to show non-zero risk and EPSS in
VEX export.

**Post-2a follow-on — Operator onboarding (product / image model):**

| Item | Why deferred / impact | Phase 1 / 2a hooks |
| ---- | --------------------- | -------------------- |
| Product version not created on SBOM upload | README walkthrough creates product → project → image → upload but never `product_versions`. `GET /api/v1/products/{id}/versions` returns empty; `GET .../versions/{v}/vex` 404 until operator runs SQL to insert a version and set `artifacts.product_version_id`. SBOM list shows `product_version: ""` until wired. Blocks VEX export and `vex-coverage` without manual DB steps. | `product_versions` table (migration 000001); VEX export join in `adapter/store/vexexport.go`; `ListProductSBOMs` reads `pv.version`; OpenAPI has `listProductVersions` only — no create. **Fix:** Group 16.10 — `POST /products/{id}/versions` plus optional auto-version on upload (e.g. from CI tag or default `1.0.0`) and link `artifacts.product_version_id` from `image_id`. |
| Image registration still SQL-only | Same README path; no REST until Group 16.4. Operators must `INSERT INTO images` before upload or trust gate rejects. | Group 16.4; `images` + `artifacts` tables |

**Post-2a follow-on — Scan findings API (Phase 2a enrichment fields):**

| Item | Why deferred / impact | Phase 1 / 2a hooks |
| ---- | --------------------- | -------------------- |
| `GET /api/v1/scans/{id}/vulnerabilities` omits Phase 2a fields | Response includes only `id`, `cve_id`, `severity`, `effective_state`, `component_purl`, `product_id`. Operators verifying Step 4 (EPSS/KEV/Layer 1) must use SQL on `risk_context`, VEX export (`x-themis-*`), or `/metrics` — not the primary findings API. README testing path ends at scan vulnerabilities list, so Phase 2a value is invisible there. | `domain.ScanVulnerability`; `PostgresScanQueryRepository.ListScanVulnerabilities`; `handlers_catalog.go` + OpenAPI `ScanVulnerability` schema. **Fix:** join `risk_context` in list query; expose `risk_score`, `epss_score`, `kev_listed`, `exploit_public`, `deterministic_level`, `blast_radius_score`, `upstream_vex_coverage` (or a nested `enrichment` object). Update OpenAPI + mapper tests. |

**Post-2a follow-on — ExploitDB signal observability:**

| Item | Why deferred / impact | Phase 1 / 2a hooks |
| ---- | --------------------- | -------------------- |
| ExploitDB sync not visible on JSON APIs; no dedicated metric | ExploitDB CSV sync populates `exploit_records` and drives `exploit_public` + Layer 1 via `ReEnrichSignalsBatch`, but unlike EPSS/KEV there is no `signals_stale`-style flag, no `themis_exploitdb_*` Prometheus counter in Group 30 wiring, and no field on scan or VEX export responses. Operators cannot confirm ExploitDB impact with curl-only Step 4 checks. | `adapter/exploitdb/`; `CombinedSignalReader.HasPublicExploit`; `risk_context.exploit_public`. **Fix:** add `themis_exploitdb_sync_total` metric; optionally include `x-themis-exploit-public` on VEX export and/or scan list field `exploit_public`. |

**Post-2a — Alpine SBOM bring-up release gate (manual E2E checklist):**

Validates the README upload path on real Alpine images before claiming `v0.2.0` is operator-ready.
Integration tests (AC-16..24) use synthetic CVE IDs and stub feeds — they do not catch these gaps.

| # | Check | Pass criteria | Known failure today (Jun 2026 bring-up) |
| - | ----- | ------------- | ---------------------------------------- |
| G1 | EPSS/KEV sync | `themis_epsskev_sync_total` success for `epss` and `kev` feeds; `signals_stale: false` | **Pass** |
| G2 | Vendor VEX sync | `themis_vexfeed_sync_total{feed="alpine",status="success"} ≥ 1` | **Fail** — alpine/rhel/rocky `error`; wolfi only |
| G3 | VEX export reachable | `GET .../versions/{v}/vex` returns `total > 0` without manual SQL | **Fail** until Group 16.10 / SQL wiring |
| G4 | EPSS on findings | VEX export `with_epss > 0` OR scan API shows `epss_score` | **Fail** — `with_epss: 0` (592 × `ALPINE-CVE-*`) |
| G5 | Risk scores | VEX export `with_risk > 0` OR scan API shows `risk_score > 0` | **Fail** — CVSS vectors not parsed |
| G6 | Vendor VEX coverage | `vex-coverage` has `covered > 0` or export states include `not_affected` | **Fail** — `{covered:0, not_covered:592}` |
| G7 | Status CVSS | `top_components[].highest_cvss_score > 0` when findings exist | **Fail** — same CVSS gap |
| G8 | Layer 1 visible | Scan or export shows non-`informational` `deterministic_level` where KEV/EPSS/CVSS warrant | **Fail** — blocked by G4/G5 |

**Code fixes required to clear G2–G8 on Alpine:** vendor feed fetch (zip/crawl — see above),
`ParseOSVFeed.firstCVE()`, `mapOSVVuln` CVE normalization, OSV CVSS vector parsing; optional
Group 16.1 (package names) for higher vendor match rate.

**Operator-only workarounds until code ships:** SQL for product version (G3); no workaround for
G2/G4/G5/G6/G7/G8 on Alpine OSV findings.

---

### Pre-Phase 2b Gate — Feed Reliability and Signal Quality (Group 31 — 8 tasks BLOCKING)

Identified during the intel-source-tiers cross-check after Phase 2a was declared complete.
All 8 tasks must close before Phase 2b implementation begins. Tracked in
`openspec/changes/archive/2026-06-17-themis-phase-2a/tasks.md` §31.
Reference: `openspec/intel-source-tiers.md`.

#### 31a — OSV / Alpine CVE normalization

| # | Task | Root cause |
| - | ---- | ---------- |
| 31.1 | Normalize `ALPINE-CVE-*` IDs to `CVE-*` in `mapOSVVuln` (`internal/adapter/osv/`) | 592/592 Alpine findings show `with_epss: 0` — EPSS/KEV join never matches `ALPINE-CVE-*` form |
| 31.2 | Fix `ParseOSVFeed.firstCVE()` to strip `ALPINE-CVE-` prefix | Alpine advisories silently dropped because `firstCVE()` only accepts `CVE-*` prefix |
| 31.3 | Fix OSV CVSS vector parsing — replace `fmt.Sscanf("%f")` with proper vector parser | `CVSS:3.1/AV:N/...` strings not parsed; all CVSS scores = 0; Layer 1/G5/G7 blocked |

#### 31b — Vendor feed URL fixes

| # | Task | Root cause |
| - | ---- | ---------- |
| 31.4 | Alpine OSV: update default URL to GCS zip; wire `ZipOSVFeedSource` | Default URL returns HTTP 302 (GitLab login redirect) |
| 31.5 | Rocky Linux OSV: update default URL to GCS zip | Default URL returns HTTP 404 |
| 31.6 | Red Hat CSAF: implement `CSAFDirectoryFeedSource` to crawl advisory index | Default URL returns HTML directory listing; cannot fix with URL override alone |

#### 31c — ExploitDB signal wiring

| # | Task | Root cause |
| - | ---- | ---------- |
| 31.7 | Expose `exploit_public` in scan findings API response | Adapter exists; `exploit_public` invisible to operators via primary API |
| 31.8 | Wire `themis_exploitdb_sync_total` Prometheus counter in ExploitDB scheduler | Listed in Group 30.2 but counter not emitted; sync success unverifiable via `/metrics` |

#### Alpine E2E bring-up gate (G1–G8)

**v0.2.1 code landed** (OpenSpec `themis-v0-2-1`); verified 2026-06-17 via integration tests
(`TestV021*`) + local `./scripts/run-alpine-e2e-local.sh` (G2 metrics) + `./scripts/alpine-e2e-gate.sh`:

| Check | Pre-v0.2.1 | v0.2.1 (expected after deploy + backfill) | Verified 2026-06-17 |
| ----- | ---------- | ------------------------------------------- | ------------------- |
| G1 EPSS/KEV sync | PASS | PASS | **PASS** (metrics; local run may need ≥120s warm-up) |
| G2 Vendor VEX sync (Alpine/Rocky/RHEL) | **FAIL** | **PASS** (zip + CSAF directory sources) | **PASS** (`themis_vexfeed_sync_total{feed="alpine",status="success"}`) |
| G3 VEX export without manual SQL | **FAIL** | **FAIL** — still requires `themis-core-model` | **FAIL** (404 without product-version wiring) |
| G4 EPSS on Alpine findings | **FAIL** | **PASS** (CVE normalize + backfill + re-enrich) | **PASS** (`TestV021AlpineEPSSAfterReEnrich`) |
| G5 Risk scores > 0 | **FAIL** | **PASS** (CVSS vector parsing) | **PASS** (integration + OSV CVSS unit tests) |
| G6 Vendor VEX coverage > 0 | **FAIL** | **PASS** (after G2 + PURL match) | **PASS** (`TestV021ZipVendorVEXFeedLoadsAssertions`) |
| G7 Status `highest_cvss_score > 0` | **FAIL** | **PASS** | **PASS** (CVSS vector parsing in `mapOSVVuln`) |
| G8 Layer 1 `deterministic_level` non-informational | **FAIL** | **PASS** (after G4 + G5) | **PASS** (integration re-enrich with KEV/EPSS stubs) |

**Operator checklist:** `./scripts/run-alpine-e2e-local.sh` (embedded Postgres + server) or
`./scripts/alpine-e2e-gate.sh` against an existing deployment after Alpine SBOM upload.

---

### v0.2.1 — Maintenance release (feed reliability + Phase 1 hardening) — Planned

**Type:** patch release on the v0.2.x line. No breaking changes, no schema changes.
**Releases as:** v0.2.1
**Contents:**

- **Group 31 (8 tasks)** — feed-reliability and signal-quality fixes (Alpine CVE ID
  normalization, OSV CVSS vector parsing, vendor feed URLs, ExploitDB API/metric wiring).
  Clears Alpine E2E gate checks G2, G4–G8.
- **Group 16 hardening remainder** — 16.1 Alpine package-name normalization, 16.2/16.3
  integration tests, 16.5 upload helper, 16.6 `make check`, 16.7/16.8 coverage gates.

**Excluded (require breaking change):** 16.4 / 16.10 registration endpoints and the G3
VEX-export-without-SQL fix — these land with `themis-core-model` in v0.3.0.

**Why a separate patch:** ships the Alpine/feed correctness fixes to operators sooner,
without waiting for the breaking `themis-core-model` restructure and Phase 2b. `v0.2.1`
can be cut as soon as Group 31 + the Group 16 hardening remainder are green.

---

### Candidate change — Feed observability (`themis-feed-observability`) — Proposed

**Type:** additive new capability (schema change — new table). Targets v0.3.0-era.
**Problem:** feed failures are easily missed. Today the only user-visible feed health is
`signals_stale` for EPSS/KEV, and it is **pull-only** (`GET /api/v1/status`). Vendor VEX and
ExploitDB sync failures persist nothing — they produce a single `WARN`/`ERROR` log line per
8–24h cycle plus a Prometheus counter that only helps if the operator scrapes it and wrote an
alert rule. The `degraded_feeds[]` design in `openspec/intel-source-tiers.md` was specced but
never implemented.

**Current state (verified in code):**

| Feed (tier) | Persisted status | In `/status` API | Metric | Notification |
| ----------- | ---------------- | ---------------- | ------ | ------------ |
| EPSS / KEV (T1) | `epss_kev_signals.stale` + 25 h TTL on `fetched_at` | `signals_stale` | `themis_epsskev_sync_total`, `themis_epsskev_stale` | none |
| Vendor VEX RHEL/Alpine/Rocky/Wolfi (T2) | none | none | `themis_vexfeed_sync_total` | none |
| ExploitDB (T2) | none | none | none (wired in v0.2.1, Group 31.8) | none |

**Proposed scope:**

- **Persist per-feed health** — new `feed_health` table (`feed`, `tier`, `last_success_at`,
  `consecutive_failures`, `last_error`, `last_attempt_at`). Each scheduler upserts on every
  cycle. Replaces the derived-only EPSS/KEV staleness with real, queryable history.
- **Surface in status API** — implement `degraded_feeds[]` on `GET /api/v1/status` per the
  tier doc, so one call shows every feed's health (not just EPSS/KEV).
- **Push, don't just store** — reuse the existing `NotificationSender` (SMTP/Teams) to send a
  `FEED_STALE` / `FEED_DEGRADED` alert when a Tier-1 feed goes stale or any feed fails N
  consecutive cycles. Turns a buried 24 h log into an actual notification (the "won't miss
  it" fix). Threshold + routing configurable.
- Optional: degraded signal on `/readyz` when a Tier-1 feed is stale.

**Hooks:** `NotificationSender` already exists (SMTP + Teams); per-tier error behavior is
defined in `openspec/intel-source-tiers.md`; metric names already registered.
**Why deferred from v0.2.1:** v0.2.1 is a non-breaking patch; the `feed_health` table is a
schema change and the notification path is new behaviour.

---

### Candidate change — Feed registry / user-defined feeds (`themis-feed-registry`) — Proposed

**Type:** additive capability + config-shape change. Targets v0.3.0-era.
**Problem:** the feed set is fixed. `VEXFeedConfig` is hardcoded struct fields
(`RHELURL`, `AlpineOSVURL`, `RockyOSVURL`, `WolfiOSVURL`). Operators can **override** each
URL and poll interval (`themis.yaml` / env) but **cannot add, remove, or disable** a feed.

**Proposed scope:**

- Refactor vendor feed config from fixed fields to a **feed registry**: built-in defaults
  plus a user **delta list** in `themis.yaml`, merged by `name` (add custom feed, override a
  default, or disable one). Example:

  ```yaml
  vexfeed:
    feeds:
      - name: my-distro-osv
        type: zip-osv          # url | zip-osv | csaf-dir
        url: https://.../all.zip
        ecosystem: mydistro
        tier: 2
        enabled: true
        poll_interval: 12h
      - name: rocky-osv         # override/disable a default by name
        enabled: false
  ```

- Each entry carries its **tier**, so the error/observability behaviour from
  `themis-feed-observability` applies automatically to custom feeds.
- Subsumes the existing "Per-feed enable/disable" follow-on (see Vendor VEX feed operations
  table above) — that item folds into this registry model.
- Builds on the `ZipOSVFeedSource` / `CSAFDirectoryFeedSource` source abstraction introduced
  in v0.2.1 (the `type` field selects the fetch model).

**Why deferred from v0.2.1:** changes the config contract (`vexfeed` shape) and is broader
than the bug-fix scope; sequence it after v0.2.1 lands the source abstractions it builds on.

---

### Phase 2b — AI Intelligence (`themis-phase-2b`) — Planned

**Gate:** Phase 2a archived + Group 31 complete + signal feeds confirmed healthy (G1–G8 pass).
**Releases as:** v0.3.0
**OpenSpec change:** `openspec/changes/themis-phase-2b/` (to be created)

**Hardware prerequisites (operator must verify before deploying Phase 2b):**

- RAM: 16 GB minimum (Ollama model ~4.5 GB + PostgreSQL ~4 GB + pgvector + OS)
- GPU: strongly recommended — CPU-only inference is 60–180 s per model call
  (vs 1–8 s with GPU); CPU-only deployments set `ai.worker_concurrency=1`
- Disk: NVMe SSD; model weights ~4.5 GB; grow with pgvector KB size
- CyberPal-2.0 may not be in Ollama's public registry — most deployments will
  use the automatic Qwen2.5-7B fallback (see design.md Decision 3)
- PostgreSQL must have the `pgvector` extension installed before migration 000015

**What:**

- **Ollama integration** — HTTP client for CyberPal-2.0 / Qwen2.5-7B; model health check
- **pgvector + L1c Semantic Memory** — embedding table; HNSW index; nomic-embed-text model
- **KB-first optimisation** — pgvector similarity ≥ 0.92 → apply past decision, skip model
- **7 AI skill workers** — CWE Mapper, CVE Summarizer, Exploitability Analyzer, Context
  Analyzer, VEX Recommender, Remediation Advisor, False Positive Analyzer
- **Async JobQueue wiring** — AI enrichment jobs triggered for CVSS ≥ 7.0 OR KEV OR ExploitPublic
- **RAG context assembly** — per-finding context built from L0/L1/external sources + KB
- **Risk Explanation synthesis** — headline + narrative from all worker outputs
- **AI enrichment status in API** — `enrichment_status: pending|complete` in findings response
- **Cold-start fixes** — G1 (VEX overlay re-trigger), G7 (batch throttle), G9 (enrichment_status)

**Why deferred from 2a:** AI workers are only meaningfully testable when EPSS/KEV/ExploitDB
signals are present. Building 2b on an empty signal foundation makes it impossible to
distinguish AI errors from missing data errors.

**Phase 2a hooks:**

- Layer 1 + Layer 2 provide the deterministic signals AI workers consume
- Microservice/Deployment entities provide service descriptions for Context Analyzer
- `risk_context` has `ai_exploitability`, `ai_reachability_confidence` columns (NULL until 2b)

**Database migrations:** 000015 (pgvector extension + embeddings table),
000016 (ai_summaries, ai_cwe_mappings, ai_exploitability, ai_vex_recommendations,
ai_remediation_advice, ai_fp_analysis)

---

### Phase 2c — AI-Assisted VEX (`themis-phase-2c`) — Planned

**Gate:** Phase 2b running; KB has ≥ 50 seeded analyst decisions (threshold tunable).
**Releases as:** v0.4.0
**OpenSpec change:** `openspec/changes/themis-phase-2c/` (to be created)

**What:**

- **VEX auto-apply** — VEX Recommender confidence ≥ threshold auto-creates
  `vex_document(source=ai_generated)`; resolves OQ-5 (default 0.85)
- **FP auto-apply** — FP Analyzer confidence ≥ threshold auto-sets
  `effective_state=FALSE_POSITIVE`; resolves OQ-6 (default 0.90)
- **Four-eyes rule** — `trust_policy=strict` requires human confirmation before
  auto-apply fires; resolves OQ-10
- **FINDING_AUTO_SUPPRESSED notification** — new event type when AI suppresses a
  finding; fixes G4 (silent suppression)
- **Confidence threshold config** — `config.ai.vex_auto_apply_threshold`,
  `config.ai.fp_auto_apply_threshold` configurable per deployment
- **AI justification in VEX export** — enriches the 2a vex-export with AI-generated
  justification text and confidence scores

**Why after 2b:** Confidence thresholds (0.85, 0.90) are only meaningful when the KB
has real analyst decisions to retrieve. Tuning auto-apply against an empty KB
would result in under- or over-suppression — either missing real issues or drowning
analysts in false positives.

**Phase 2b hooks:**

- VEX Recommender + FP Analyzer workers already produce `auto_apply` bool and
  `confidence` float in their JSON output
- `vex_documents.source` enum already includes `ai_generated`
- `trust_policy` enum in domain already has `strict`, `standard`, `permissive`

---

## Phase 3 backlog

Phase 3 scope: Rate limiting, runtime observability, cosign/sigstore SBOM verification,
CI/CD ingestion (GitHub, GitLab, Bitbucket), deployment packaging, Redis queue, Web UI,
enterprise access control (RBAC/OIDC), high-availability deployment, admin CLI.

### Rate limiting

**What:** Per-API-key rate limiter on all ingestion endpoints. Configurable burst and
steady-state limits. Return `429 Too Many Requests` with a `Retry-After` header.

**Why deferred from Phase 2:** A single-tenant Phase 2 deployment has no rate-limiting
need. Rate limiting becomes important when multiple teams or CI pipelines share an
instance — a Phase 3 concern once CI/CD integration lands.

**Phase 1 hooks:**

- chi middleware stack in `infrastructure/http/` is the right injection point
- API key model already scopes keys to products; rate limits can be per-key or per-product

---

### Runtime observability

**What:** Structured log level configurable at runtime (no restart needed). Export OTel
traces to a configurable OTLP endpoint (Jaeger, Honeycomb, etc.). Add trace IDs to all
HTTP error responses.

**Why deferred from Phase 2:** `go.opentelemetry.io/otel` is already in `go.mod` and span
keys are defined in `domain/tracing.go`. The OTel exporter wiring is straightforward but
adds config surface area. Deferred to Phase 3 to keep Phase 2 config minimal.

**Phase 1 hooks:**

- OTel SDK and `domain/tracing.go` span key types already present
- `infrastructure/metrics/` has the OTel setup stub ready for the exporter wiring
- Zap logger already structured; adding `level` to config YAML is a 3-line change

---

### Real signature verification (CosignVerifier)

**What:** Replace `StubVerifier` in `adapter/trust/` with a real cosign/sigstore verifier.
Verify SBOM artifact signatures against the Rekor transparency log. Strict trust policy
enforcement gains real cryptographic teeth — unsigned or tampered SBOMs are rejected.

**Why deferred from Phase 2:** Cosign adds a significant external dependency
(`github.com/sigstore/cosign/v2` pulls in the sigstore ecosystem). Phase 2 already
introduces AI model integrations and a new risk score formula. Deferring cosign keeps Phase
2 self-contained and gives the trust gate logic another phase of real-world use before
cryptographic enforcement is turned on.

**Phase 1 hooks:**

- `SignatureVerifier` interface is defined in `internal/domain/`
- `StubVerifier` implements it and records `trust_status` correctly — no API or pipeline
  changes needed, only the implementation at the DI root changes
- Trust policies (`strict`, `standard`, `permissive`) already enforced by the gate

---

### CI/CD integration (GitHub, GitLab, Bitbucket)

**What:** SCM webhook receivers for GitHub (`push` / `release`), GitLab (`pipeline`), and
Bitbucket Cloud/Server (`repo:push`). Each webhook extracts or receives the committed SBOM
and submits it to the same `IngestionService.IngestSBOM` use case as manual upload. A new
`scm_webhook_configs` table stores per-product SCM configuration (provider, repo, SBOM path,
branch pattern). Git ref is recorded in `ingestion_jobs` metadata.

**Why deferred from Phase 2:** Phase 2 focuses on pure signal quality (AI enrichment,
EPSS/KEV, upstream VEX). CI/CD ingestion requires its own new infrastructure (SCM webhook
config table, branch-to-version mapping, SBOM discovery strategy) that is cleaner as a
focused Phase 3 workstream once the enriched risk signals are stable and the API contract
is settled.

**Phase 1 hooks:**

- `IngestionService.IngestSBOM` is format-agnostic — all ingestion sources call the same use case
- Webhook HMAC verification (`X-Themis-Signature`) middleware in `adapter/api/` is the pattern
- `ingestion_jobs` table can record the git ref as job metadata

---

### Docker Compose deployment

**What:** `docker-compose.yml` that starts `themis` + PostgreSQL in one command. Multi-stage
Dockerfile that produces a minimal image (~15 MB via Alpine or distroless).

**Why deferred:** Phase 1 and 2 target the binary-on-bare-metal deployment model. Docker
packaging is a packaging concern, not a functionality concern. Adding it before the feature
set is stable means the image will change frequently.

**Phase 1 hooks:**

- Config loading (`infrastructure/config/`) uses env vars — Docker-native
- Database URL, API port, and all config are already env-var driven

---

### Redis-backed job queue

**What:** Replace `InProcessQueue` with a Redis-backed queue. Workers can run in separate
processes. Supports horizontal scaling.

**Why deferred:** In-process queue with a goroutine pool handles Phase 1 and Phase 2 load.
Redis adds operational complexity (another service to deploy, monitor, and back up) that is
not justified until multi-instance deployment is needed (Phase 3).

**Phase 1 hooks:**

- `JobQueue` interface in `internal/domain/` is the swap point
- `InProcessQueue` in `internal/infrastructure/queue/` is one implementation
- Swap requires only a new struct implementing `JobQueue` + a DI root change in `cmd/themis/main.go`

---

### Web UI (React SPA)

**What:** Native React SPA providing: product / version / image inventory views, SBOM upload
drag-and-drop, vulnerability dashboard with filters (severity, state, component), triage
workflow (accept, dismiss, escalate), notification rule editor.

**Why deferred:** Originally Phase 2 in `proposal-initial.md`. Moved to Phase 3 so that
Phase 2 can focus on AI enrichment and threat intelligence — the signal quality that makes a
dashboard useful. A dashboard of unscored noise is not worth building.

**Phase 1 hooks:**

- REST API is the only data source the UI will need
- OpenAPI spec (`api/openapi.yaml`) can generate a typed TypeScript client
- All list endpoints are already paginated (cursor-based)

---

### RBAC + OIDC

**What:** Replace the Phase 1 `X-API-Key` auth with OIDC (OpenID Connect) tokens.
Role-based access control with roles: `reader`, `analyst`, `admin`. Integrate with
corporate identity providers (Okta, Azure AD, Google Workspace).

**Why deferred:** Single-tenant Phase 1/2 deployments don't need OIDC. Multi-tenant or
enterprise deployments do. Adding OIDC before the feature set is stable creates auth churn.

**Phase 1 hooks:**

- Auth middleware in `adapter/api/` is a single injection point
- API key auth and OIDC token auth can coexist via a middleware chain
- Product-scoped keys already establish the authorization model foundation

---

### High-availability deployment

**What:** Kubernetes Helm chart. Horizontal pod autoscaling on ingestion workers.
Leader election for scheduled watch/EPSS jobs (only one pod runs the scheduler at a time).
Health endpoints already exist (`/health`, `/ready`).

**Why deferred:** Requires Redis queue (Phase 3) and Docker packaging (Phase 3). Phase 1/2
are single-instance deployments.

**Phase 1 hooks:**

- `/health` and `/ready` HTTP endpoints are already implemented
- All config is env-var driven — K8s ConfigMap/Secret compatible

---

### Enhanced `themis-cli`

**What:** Expand the admin CLI (`infrastructure/cli/`) beyond `create-key` / `revoke-key`
to include: `list-products`, `trigger-rescan`, `export-vex`, `purge-stale-signals`. Package
as a standalone binary (`themis-cli`) distributed alongside the server.

**Why deferred:** Phase 1 admin CLI exists for key management only. Richer CLI operations
depend on Phase 2 features (EPSS, AI enrichment, VEX export) being available.

**Phase 1 hooks:**

- `infrastructure/cli/` package exists with the cobra/urfave command structure already in place
- DI root can expose the same use-case interfaces to CLI commands as to HTTP handlers

---

## Items from `proposal-initial.md` not yet assigned

These items appear in `proposal-initial.md` but were not included in Phase 1–3 planning.
They are captured here as unscheduled proposals.

| Item | Original location | Notes |
| ---- | ----------------- | ----- |
| Dependency graph visualisation | proposal ADR §7 | Requires UI (Phase 3 minimum) |
| Scan comparison (two `scan_reports` for same artifact) | proposal ADR §8 | Becomes `GET /api/v1/artifacts/{id}/scan-reports/{a}/diff?compare_to={b}` once `themis-core-model` lands; natural with the `scan_reports` table — no schema change required |
| Policy-as-code (OPA integration) | proposal ADR §9 | Replaces or extends trust policies in Phase 3+ |
| Notification webhook outbound (POST to 3rd party) | proposal feature | Currently SMTP + Teams only |
| CSV/Excel vulnerability export | proposal feature | Low priority; VEX export (Phase 2) covers the main case |
| CVE comment / annotation by analyst | proposal feature | Triage note field exists; no dedicated annotation endpoint |
