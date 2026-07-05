# Themis v0.3.0 — Core model + Layer-0 correctness & observability

Release tag: `v0.3.0` (**breaking** — schema restructure; no in-place upgrade from a pre-`v0.3.0`
database — drop & recreate, see README § Full database reset)

## Highlights

`v0.3.0` bundles two bodies of work:

1. **`themis-core-model`** — the breaking schema restructure (`sbom_documents` → `sboms` +
   `scan_reports`; merged `artifacts`/`images` with globally-unique `image_digest`;
   `versions.project_id`; the Durable-Enrichment Identity Contract re-keying `risk_context` and the
   judgment tables on `(artifact_id, component_purl, cve_id)`; squashed `000001_v030_baseline`;
   startup schema-skew guard).
2. **Layer-0 Correctness & Observability refactor (CR-1…CR-10)** — rebuilds the
   correlation/feeder/observability core so Themis tells the truth and operators can see it.
   Closes defects **D-CVSS-1, D-FEED-1, D-NVD-1, D-LOG-1**.

> Phase 2b (AI Intelligence) was originally bundled into `v0.3.0`; it moved to `v0.4.0` so the
> Layer-0 hardening could ship first. Phase 2c → `v0.5.0`.

## Layer-0 refactor (CR-1…CR-10)

- **CR-1 — one version engine.** `domain.CompareVersionsEco` (generic / apk / rpm incl. rpmvercmp
  `~`), `VersionConstraintSet`, `BuildConstraintGroup`. osv/nvd/vexfeed/watch all use it; the three
  forked vexfeed comparators are gone.
- **CR-2 — one correlation core.** `domain.CorrelationSource` port + `usecase/correlation.Correlator`
  (multi-source, provenance, distro-authoritative precedence merge), used by **ingest and watch**.
- **CR-3 — finding provenance.** `source` / `source_severity` / `source_cvss_score` /
  `source_cvss_vector` / `source_fixed_version` on `component_vulnerabilities`.
- **CR-4 — feed taxonomy + re-layering.** `rhel_vex_url` (true VEX → overlay) vs `rhel_csaf_url`
  (advisories → correlation); Alpine/Rocky/Wolfi OSV + RHSA advisories are correlation sources
  carrying severity + fixed version (RHSA NEVRA extraction); the overlay carries only true vendor
  VEX. `rhel_url` is a deprecated alias.
- **CR-5 — CVSS/severity enrichment.** NVD `FetchByCVEID` + a CVSS backfill job (`cvss_checked_at`
  back-off) that propagates into `risk_context` and re-enriches; `themis_cvss_backfill_total`
  metric; an interim risk floor for KEV/exploit/confirmed findings with unknown severity.
- **CR-6 — NVD CPE correctness.** Lower bound preserved (no more `[2.0,2.5)` matching 1.x),
  `versionStartExcluding`, no `vendor==product→npm`, multi-version CVSS (v3.1→v3.0→v2.0).
- **CR-7 — logging.** `domain.Logger` port over zap, DI-injected; schedulers/feeders log
  per-cycle success/failure; `slog.Default()` retired in osv/vexfeed.
- **CR-8 — feed health.** `feed_health` table + `degraded_feeds[]` on `GET /api/v1/status`.
- **CR-9 — parser integrity.** Trivy one-component-per-package, CycloneDX bom-ref→purl edges,
  shared PURL-qualifier helper; dead embedded-vulnerability parsing removed (pure re-correlator).
- **CR-10 — regression harness.** `internal/testutil/findingset` finding-set diff harness + golden
  distro corpus; property tests for the version engine and the correlator merge.

## Breaking changes

- **Schema:** no in-place upgrade from a pre-`v0.3.0` database (drop & recreate).
- **Config:** `vexfeed.rhel_url` → `vexfeed.rhel_vex_url` + `vexfeed.rhel_csaf_url` (old key kept
  as a deprecated alias for one release). New env vars `THEMIS_VEXFEED_RHEL_VEX_URL` /
  `THEMIS_VEXFEED_RHEL_CSAF_URL`.
- **API:** `upstream_vex_coverage` now reflects *only* true VEX coverage (no longer version-range
  math); `GET /api/v1/status` gains `degraded_feeds[]`.

## Validation

All gates green: build · unit · integration (embedded Postgres) · coverage (every per-package
threshold) · clean-arch.

## Post-release follow-ups (see `project-backlog.md`)

- Operational **G1–G8** verification on a live Alpine + RPM deployment.
- **User-defined feed registry** (`vexfeed.feeds:` add/remove/disable) — CR-4 delivered the feed
  *class* taxonomy, not per-feed on/off.
- Golden-corpus expansion with real sanitised feed slices.
