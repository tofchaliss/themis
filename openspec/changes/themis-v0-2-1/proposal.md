## Why

Phase 2a shipped as `v0.2.0`, but live Alpine SBOM bring-up showed the signal pipeline
silently failing on real distro data: 592/592 Alpine findings carried no EPSS/KEV scores,
all OSV CVSS scores were `0`, and three of four vendor VEX feeds never loaded. The
intelligence is implemented but invisible on real images. `v0.2.1` is a non-breaking
maintenance release that makes the existing Phase 2a/Phase 1 signals actually work on
Alpine/Rocky/Red Hat content, with no schema changes — so the fixes reach operators ahead
of the breaking `themis-core-model` restructure (`v0.3.0`).

## What Changes

- **CVE-ID normalization** — strip distro prefixes (`ALPINE-CVE-*` → `CVE-*`) to canonical
  form so EPSS/KEV/ExploitDB joins match Alpine findings (Group 31.1, 31.2).
- **OSV CVSS vector parsing** — parse `CVSS:3.1/AV:N/...` vector strings into numeric base
  scores instead of leaving them `0` (Group 31.3).
- **Vendor feed fetch models** — handle real-world sources: zip archives for Alpine/Rocky
  OSV (GCS), and a CSAF advisory-directory crawler for Red Hat; fix dead default URLs
  (Group 31.4, 31.5, 31.6).
- **ExploitDB observability** — expose `exploit_public` on the scan findings API and emit
  the `themis_exploitdb_sync_total` Prometheus counter (Group 31.7, 31.8).
- **OSV correlation hardening** — normalize Alpine package names for OSV queries; add
  integration coverage for Alpine and rpm SBOM ingest (Group 16.1, 16.2, 16.3).
- **Quality gates** — upload helper script; `make check` clean; `adapter/store/` and
  `adapter/osv/` coverage ≥ 90% (Group 16.5–16.8).

Non-breaking: no migrations, no schema changes, no risk-score formula changes.

**Out of scope (deferred to `themis-core-model` / `v0.3.0`):** artifact registration
endpoint (16.4), version registration endpoint (16.10), and the "VEX export without manual
SQL" gate (G3) — all require the schema restructure.

## Capabilities

### New Capabilities

_None._ All changes modify behaviour of existing Phase 1 / Phase 2a capabilities.

### Modified Capabilities

- `epss-kev`: CVE identifiers are normalized to canonical `CVE-*` form before signal
  lookup, so distro-prefixed findings (e.g. `ALPINE-CVE-*`) receive EPSS/KEV/exploit signals.
- `upstream-vex-feeds`: feed sources support real-world fetch models — zip-archive OSV
  feeds (Alpine, Rocky) and a Red Hat CSAF advisory-directory crawler — and normalize Alpine
  OSV advisory IDs to canonical CVE IDs.
- `intelligence-enrichment`: OSV CVSS vector strings are parsed into numeric base scores and
  severity, so risk scores and status CVSS reflect real values instead of `0`.
- `exploitdb`: the public-exploit signal (`exploit_public`) is exposed on the scan findings
  API and ExploitDB sync emits a `themis_exploitdb_sync_total` Prometheus counter.
- `sbom-ingestion`: OSV correlation normalizes Alpine package names before lookup and is
  covered by Alpine and rpm SBOM ingest integration tests.

## Impact

**Code (no new packages):**

- `internal/adapter/osv/` — `mapOSVVuln` CVE-ID normalization + CVSS vector parsing;
  Alpine package-name normalization for OSV queries (shared by ingest + CVE watch).
- `internal/adapter/vexfeed/` — `ZipOSVFeedSource` (Alpine/Rocky GCS zip),
  `CSAFDirectoryFeedSource` (Red Hat advisory index), `ParseOSVFeed.firstCVE()` prefix strip;
  default URL updates in `internal/infrastructure/config/`.
- `internal/adapter/api/` — `exploit_public` (and related enrichment fields) on the scan
  findings response; OpenAPI `ScanVulnerability` schema + mappers.
- `internal/infrastructure/metrics/` + ExploitDB scheduler — `themis_exploitdb_sync_total`.
- `scripts/` — upload helper script.

**Tests / gates:** Alpine + rpm SBOM ingest integration tests; `adapter/store/` and
`adapter/osv/` coverage ≥ 90%; `make check` clean.

**Success gate:** Alpine E2E bring-up checks G2 (vendor VEX sync), G4 (EPSS on findings),
G5 (risk scores > 0), G6 (vendor VEX coverage), G7 (status CVSS), G8 (Layer 1 visible) pass.
No external/breaking API contract changes; additive response fields only.
