## Implementation order

1 (domain helper) → 2 / 3 / 4 (adapters, parallel) → 5 (backfill) → 6 (integration tests +
E2E gate) → 7 (quality gates + docs). Each group ends with the standard gates
(unit tests → coverage → dead code → integration tests → clean-arch → `make verify-build`).

---

## 1. Shared CVE-ID normalization (domain)

- [x] 1.1 Add `domain.NormalizeCVEID(id string) string` — strip known distro/OSV prefixes
  (`ALPINE-`, generic `*-CVE-` wrapper) only when the remainder is a valid `CVE-YYYY-NNNN`;
  otherwise return the input unchanged (D1)
- [x] 1.2 Unit tests (table-driven): `ALPINE-CVE-*` → `CVE-*`, plain `CVE-*` unchanged,
  `GHSA-*` unchanged, malformed remainder unchanged; `domain/` coverage stays 100%
- [x] 1.3 `make clean-arch` + `make check` pass

## 2. OSV adapter — normalization, CVSS parsing, package names

- [x] 2.1 `mapOSVVuln` (`internal/adapter/osv/`): apply `domain.NormalizeCVEID` to the stored
  `vulnerabilities.cve_id`; prefer an already-canonical `aliases` entry (Group 31.1)
- [x] 2.2 `mapOSVVuln`: detect `CVSS:` vector strings, compute the CVSS v3.x numeric base
  score, store `cvss_score` + `cvss_vector`; keep accepting plain numeric scores (Group 31.3)
- [x] 2.3 OSV query path: normalize Alpine package names (`so:` strip, `py3-` → `python3-`)
  before lookup; shared by ingest + CVE-watch correlation (Group 16.1)
- [x] 2.4 Unit tests for 2.1–2.3 incl. vector→score cases and Alpine name mapping;
  `adapter/osv/` coverage ≥ 90% (Group 16.8)
- [x] 2.5 `make check` passes

## 3. Vendor VEX feed sources (zip + CSAF directory)

- [x] 3.1 `ParseOSVFeed.firstCVE()` (`internal/adapter/vexfeed/`): derive canonical `CVE-*`
  from `ALPINE-CVE-*` ids via `domain.NormalizeCVEID` (Group 31.2)
- [x] 3.2 Implement `ZipOSVFeedSource` — download zip, iterate entries, run existing
  `ParseOSVFeed` per file (D3)
- [x] 3.3 Implement `CSAFDirectoryFeedSource` — fetch advisory index, follow links, run
  existing `ParseCSAF` per advisory (Group 31.6, D3)
- [x] 3.4 Update default URLs/config: Alpine GCS `all.zip`, Rocky GCS `all.zip`, Red Hat CSAF
  advisory directory; env-overridable; Wolfi unchanged (Group 31.4, 31.5)
- [x] 3.5 Unit tests for both sources (fixtures: small zip, mock advisory index) + Alpine ID
  normalization; failures remain non-blocking
- [x] 3.6 `make check` passes

## 4. ExploitDB observability

- [x] 4.1 Join `risk_context` in the scan findings list query; expose additive `enrichment`
  fields (`exploit_public`, `risk_score`, `epss_score`, `kev_listed`, `deterministic_level`,
  `blast_radius_score`, `upstream_vex_coverage`) on `ScanVulnerability` (Group 31.7)
- [x] 4.2 Update OpenAPI `ScanVulnerability` schema + mappers; mapper unit tests
- [x] 4.3 Register and increment `themis_exploitdb_sync_total{status}` in the ExploitDB
  scheduler (`internal/infrastructure/metrics/` + scheduler) (Group 31.8)
- [x] 4.4 `make check` passes

## 4b. Component-mismatch correlation logging

- [x] 4b.1 Add a `CorrelationLogger` seam (interface + `NoOp` default + slog impl) in
  `internal/adapter/osv/`, following the `vexfeed.MismatchLogger` pattern; wire it into
  `ComponentFetcher` at the DI root (`api_wiring.go`) (D5)
- [x] 4b.2 Log every mismatch/drop site in `component_fetcher.go` with structured fields
  (purl, ecosystem, name, version, reason): unsupported ecosystem → `DEBUG`; empty/malformed
  PURL → `WARN`; identity mismatch → `DEBUG`; version non-match → `DEBUG`
- [x] 4b.3 Emit one aggregate skip summary per ingest at `INFO` (count grouped by ecosystem)
  so unsupported-ecosystem skips are visible without per-component noise
- [x] 4b.4 Unit tests with a capture logger: assert each reason is logged at the specified
  level and the aggregate summary is emitted; assert logging does not change which findings
  are produced
- [x] 4b.5 `make check` passes

## 5. Backfill existing catalog rows

- [x] 5.1 Idempotent, batched backfill that canonicalizes existing `ALPINE-CVE-*` rows in
  `vulnerabilities.cve_id` (one-off script; safe to re-run) (D1 backfill)
- [x] 5.2 Document the backfill step in README (operator runs once after upgrade); confirm a
  subsequent `ReEnrichJob` populates EPSS/KEV/exploit on previously-stranded Alpine findings

## 6. Integration tests + Alpine E2E gate

- [x] 6.1 Integration test: Alpine `apk` SBOM ingest → non-zero `component_vulnerabilities`
  via OSV correlation (Group 16.2)
- [x] 6.2 Integration test: rpm SBOM ingest → succeeds, unsupported OSV ecosystem skipped
  cleanly (not FAILED) (Group 16.3)
- [x] 6.3 Integration test: Alpine findings show `epss_score`/`kev_listed` after sync +
  `ReEnrichJob` (verifies G4 via canonical CVE IDs)
- [x] 6.4 Integration test: vendor VEX zip/CSAF sources load assertions; `vex-coverage`
  reports `covered > 0` for an Alpine SBOM (verifies G2, G6)
- [x] 6.5 Verify Alpine E2E gate G2, G4, G5, G6, G7, G8 pass (record in
  `project-backlog.md` Alpine bring-up table); G3 remains blocked on `themis-core-model`

## 7. Quality gates, tooling, docs

- [x] 7.1 Upload helper script (curl-based) for local testing and CI (Group 16.5)
- [x] 7.2 `adapter/store/` coverage ≥ 90% (Group 16.7)
- [x] 7.3 `make check` clean across the repo (Group 16.6)
- [x] 7.4 Register any new packages/metrics in `scripts/check-coverage.sh` and metrics docs
- [x] 7.5 Update README (feed source config, backfill step, new findings-API enrichment
  fields) and `docs/` as needed
- [x] 7.6 `make verify-build` (`make clean && make all`) passes on the full repo
- [ ] 7.7 Write `v0.2.1` release notes (`docs/release-notes-v0.2.1.md`); merge to `main`; tag `v0.2.1` *(release notes done; merge/tag manual pending)*
