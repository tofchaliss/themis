## Context

Phase 2a (`v0.2.0`) implemented EPSS/KEV, ExploitDB, upstream vendor VEX, Layer 1/2
enrichment, and the composite risk score — all verified by AC-16..24 integration tests that
use synthetic CVE IDs and stub feeds. Real Alpine SBOM bring-up exposed gaps those stubs
never hit:

- Alpine OSV records use `id: ALPINE-CVE-YYYY-NNNN`; `mapOSVVuln` stored that verbatim in
  `vulnerabilities.cve_id`. EPSS/KEV/ExploitDB key on canonical `CVE-*`, so every Alpine
  finding missed enrichment (`with_epss: 0`, `with_kev: 0`) despite successful sync metrics.
- OSV severity arrives as a CVSS **vector** (`CVSS:3.1/AV:N/...`); `mapOSVVuln` used
  `fmt.Sscanf("%f")`, which only accepts plain floats, leaving `cvss_score = 0`.
- Vendor VEX default URLs are not single documents: Alpine OSV → HTTP 302 (GitLab login),
  Rocky OSV → HTTP 404, Red Hat CSAF → HTML directory listing. Only Wolfi (a single JSON)
  loaded. `URLFeedSource` does one GET and expects one document.
- `exploit_public` is computed and stored but absent from the scan findings API, and
  ExploitDB sync emits no Prometheus counter — operators cannot confirm impact via curl.

All of this is bug-fix / hardening against existing requirements plus a few sharpened
requirements. No schema change is needed, which is what lets `v0.2.1` ship before the
breaking `themis-core-model` restructure.

## Goals / Non-Goals

**Goals:**

- Alpine/Rocky/Red Hat findings receive EPSS/KEV/exploit signals and real CVSS scores.
- All four vendor VEX feeds load from working, unauthenticated public sources.
- `exploit_public` and the ExploitDB sync metric are observable.
- Existing catalog rows are corrected (backfill), not only new ingests.
- `make check` clean; `adapter/store/` and `adapter/osv/` coverage ≥ 90%.

**Non-Goals:**

- No schema/migration changes; no risk-score formula change (non-breaking patch).
- No new registration endpoints (16.4/16.10) — those belong to `themis-core-model`.
- No Debian/Ubuntu/SUSE feed support; no GHSA adapter (Phase 2b+).
- No AI / pgvector work.

## Decisions

### D1 — Canonical CVE-ID normalization in one shared helper

Add `domain.NormalizeCVEID(id string) string` that strips known OSV distro prefixes
(`ALPINE-`, and any `*-CVE-` wrapper) when the remainder is a valid `CVE-YYYY-NNNN`, and
prefers an `aliases` entry that is already canonical. Call it from `mapOSVVuln`
(`adapter/osv/`) and `ParseOSVFeed.firstCVE()` (`adapter/vexfeed/`) on upsert.

- **Why a domain helper:** the same rule is needed in two adapters (OSV correlation and
  vendor VEX); centralizing avoids drift and is unit-testable in `domain/` (100% gate).
- **Alternative considered:** add fallback lookups in the signal readers (`GetEPSSForCVE`)
  to try both forms. Rejected as primary fix — it scatters the workaround across every
  consumer and leaves the catalog storing non-canonical IDs. May still add as defence in
  depth, but normalization-on-write is the source-of-truth fix.
- **Backfill:** one-off idempotent UPDATE (or re-ingest) to canonicalize existing
  `ALPINE-CVE-*` rows so already-stored findings enrich on the next `ReEnrichJob`.

### D2 — CVSS vector parsing → numeric base score

Detect vector-form scores by the `CVSS:` prefix and compute the base score with a proper
CVSS v3.x parser; store both the numeric `cvss_score` and the original `cvss_vector`. Accept
`CVSS_V3`/`CVSS_V4` severity types from OSV.

- **Why compute, not look up:** avoids a second network dependency (NVD) on the ingest path;
  the base-score algorithm is deterministic from the vector.
- **Alternative considered:** NVD backfill of scores. Rejected for the hot path; may be a
  later enrichment. v4 vectors, if present, store the vector and best-effort base score.
- **Scope guard:** parser lives in `adapter/osv/` (or a small shared util); no external lib
  unless one is already vendored — a focused v3.1 base-score computation is small and
  testable.

### D3 — Pluggable feed fetch sources

Introduce two new `FeedSource` implementations alongside the existing `URLFeedSource`:

- `ZipOSVFeedSource` — downloads a zip (Alpine/Rocky GCS `all.zip`), iterates entries, runs
  the existing `ParseOSVFeed` per file.
- `CSAFDirectoryFeedSource` — fetches the Red Hat advisory index, extracts advisory links,
  fetches each CSAF JSON, merges via the existing `ParseCSAF`.

Update default URLs/config to the verified working sources. Wolfi stays on `URLFeedSource`.

- **Why a source abstraction:** parsing logic (`ParseOSVFeed`, `ParseCSAF`) is already
  correct; only the *fetch/iterate* model differs. New sources reuse parsers unchanged.
- **Verified sources:** Alpine `…/osv-vulnerabilities/Alpine/all.zip`,
  Rocky `…/osv-vulnerabilities/Rocky%20Linux/all.zip`,
  Red Hat `https://security.access.redhat.com/data/csaf/v2/advisories/` (HTML index).

### D4 — Additive API + metric for ExploitDB visibility

Join `risk_context` in the scan findings list query and expose `exploit_public` (plus the
other enrichment fields already on `risk_context`: `epss_score`, `kev_listed`,
`risk_score`, `deterministic_level`, `blast_radius_score`, `upstream_vex_coverage`) as an
additive `enrichment` object on `ScanVulnerability`. Register
`themis_exploitdb_sync_total{status}` and increment it in the ExploitDB scheduler.

- **Additive only:** new response fields and a new metric — no breaking contract change.

### D5 — Component-mismatch logging seam in OSV correlation

Today `osv.ComponentFetcher` drops components silently at four points (unsupported ecosystem,
empty/malformed name, package-identity mismatch, version non-match) and the ingestion
correlation path injects no logger — so components vanish invisibly. Introduce a small logging
seam following the existing `vexfeed.MismatchLogger` pattern: a `CorrelationLogger` interface
(with a `NoOp` default and an slog-backed implementation) passed into `ComponentFetcher`, plus
an aggregate skip summary emitted once per ingest.

- **Levels (see spec):** unsupported ecosystem → per-component `DEBUG` + one `INFO` aggregate
  per ingest; malformed/empty PURL → `WARN`; identity/version non-match → `DEBUG`; stage-abort
  errors → `ERROR` (unchanged). This keeps expected skips (e.g. hundreds of rpm components)
  out of the default INFO stream while still surfacing one visible summary and flagging real
  data-quality problems.
- **Why a seam, not direct slog in the adapter:** keeps the adapter testable (capture logger in
  unit tests, matching `vexfeed`), avoids a hard slog dependency in pure-ish code, and lets the
  DI root choose the logger.
- **Logging-stack consistency:** the codebase mixes `zap` (infrastructure/HTTP) and `slog`
  (adapters). v0.2.1 stays on the per-adapter `slog` seam (consistent with `vexfeed`/`notify`);
  unifying zap/slog is out of scope and tracked separately (see Risks / Open Questions).
- **Alternative considered:** thread the use-case logger into `ingestion.service`. Rejected for
  v0.2.1 — larger blast radius into the use-case layer; the adapter seam covers every mismatch
  site with the smallest change.

## Risks / Trade-offs

- **Over-stripping CVE prefixes** → only strip when the remainder matches the strict
  `CVE-\d{4}-\d+` shape; otherwise keep the original ID. Covered by table-driven unit tests.
- **CVSS v4 vectors** → if a robust v4 base-score computation isn't feasible in scope, store
  the vector and mark severity from the OSV `severity`/database_specific field; do not block
  ingest. Tracked as a follow-up, not a v0.2.1 blocker.
- **Remote feed sources change shape/URL** → keep URLs in config (env-overridable) so an
  operator can repoint without a code change; feed failure stays non-blocking (Tier-2 WARN).
- **Backfill on a large catalog** → idempotent, batched UPDATE; safe to re-run; no lock on
  the ingest path.
- **Coverage gates (16.7/16.8)** → may require additional unit tests for the new feed
  sources and parser; scoped into tasks.

## Migration Plan

No DB migration. Deploy is binary-only. After deploy: existing `ALPINE-CVE-*` rows are
canonicalized by the one-off backfill (or natural re-ingest), then the next EPSS/KEV/vendor
`ReEnrichJob` populates signals and scores. Rollback = redeploy previous binary; no data
shape changed, so rollback is clean (canonicalized CVE IDs remain valid `CVE-*`).

## Open Questions

- Is a CVSS **v4** base-score computation in scope for `v0.2.1`, or vector-store-only with a
  v3-only numeric score? (Lean: v3 numeric now, v4 vector-store + follow-up.)
- Backfill mechanism: one-off SQL migration-style script vs an admin CLI subcommand vs
  relying on natural re-ingest. (Lean: idempotent script invoked once; documented in README.)
- Logging-stack unification (`zap` infrastructure vs `slog` adapters) — defer to a dedicated
  change? (Lean: yes; v0.2.1 only adds the `slog` correlation seam, consistent with `vexfeed`.)
