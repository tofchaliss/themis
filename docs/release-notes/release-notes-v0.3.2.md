# Themis v0.3.2 — Correlation correctness (canonical CVE + el8/el9 release streams) & feeder resilience

Release tag: `v0.3.2` (**non-breaking** — no schema change; rebuild + re-correlate).
Covers every change since `v0.3.0`; the interim `v0.3.1` working line was never tagged and is
folded in here.

## Highlights

`v0.3.2` is a correctness release for Layer-0 correlation and the intelligence feeders. Three of
the four items were found and verified against a real Rocky Linux 8 Trivy SBOM.

1. **Canonical-CVE keying (GHSA/RLSA → CVE).** Findings were stored under the OSV *advisory id*
   (`GHSA-…`, `RLSA-…`) instead of the real `CVE-…`, which structurally excluded them from every
   CVE-keyed enrichment (CVSS backfill, EPSS, KEV) — a large block of findings sat permanently at
   `unknown` severity. Fixed at the format level: OSV.dev live moves from `/v1/querybatch` to
   `/v1/query` (full records: real CVE alias, severity, version ranges), and the distro feed reads
   the CVE from `aliases ∪ upstream ∪ related` (Rocky records it in `upstream`), emitting one
   finding per CVE.

2. **RPM release-stream scoping (el8 ≠ el9).** All RPM ecosystems collapsed to one
   `VersionClassRPM` and the distro-OSV index keyed only on class + package name, so an **el8
   package matched el9/el10 fix versions** (`6.1-…el8 < 6.2-…el9` read as *affected*). On the test
   SBOM this was **237 cross-stream false positives** — findings fell from **435 → 198** with
   `cross_stream = 0`. The installed stream is read from the version **or the purl**; the
   assertion stream from the **fixed NEVRA first** (its `.elN` is authoritative), then introduced,
   then the coarser ecosystem label. Unknown stream on either side falls through to the version
   math (no false negatives), so apk/generic correlation is untouched.

3. **Feeder resilience & severity hygiene.**
   - **ExploitDB** default moves to the GitLab mirror (the `offensive-security/exploitdb` GitHub
     mirror was archived and 404s); `themis_exploitdb_sync_total` reports success.
   - **NVD** gets key-aware, NVD-compliant rate limiting (≈1.5/s keyed, ≈0.15/s unkeyed) plus
     retry/backoff, body truncation, and a consecutive-failure circuit breaker — no more Cloudflare
     `503` storms during the CVSS backfill.
   - **Blank severity** is normalized to `unknown` (no more empty-string `""` bucket on the status
     API).
   - Startup logs `nvd client configured` (`api_key`, `rate_limit_rps`, `poll_interval`) so the
     loaded config is observable.

4. **Guardrails.** A sanitized golden Trivy/Rocky CycloneDX corpus + parser test (mixed UUID/purl
   bom-refs, percent-encoded rpm names, epoch + modular `+el8.X` versions, duplicate purls, no-purl
   OS component); percent-decode of purl path segments in the name/version fallback
   (`libstdc%2B%2B` → `libstdc++`); and rpm-comparator regressions for epoch / modular / el-stream
   shapes.

## Fixes (since v0.3.0)

- `fix(feeds)` — ExploitDB GitLab URL, NVD rate-limit/retry/circuit-breaker, blank-severity → `unknown`, startup NVD config log.
- `fix(correlation)` — key findings by canonical CVE, not advisory id (GHSA/RLSA); OSV.dev `/v1/query`; distro feed `aliases∪upstream∪related`.
- `fix(correlation)` — scope RPM findings to their release stream (el8 vs el9).
- `fix(correlation)` — read the RPM release stream from the purl + fixed NEVRA (hardening so the guard fires when Trivy drops the dist tag from the version field and Rocky OSV uses a coarse ecosystem label).
- `test(correlation)` — golden Trivy/Rocky SBOM fixture + rpm-shape regressions.

## Upgrade

No schema change — **rebuild and restart** is enough to run the new code.

To apply the correlation fixes to **existing** data, do a **clean re-ingest** (a correlation sweep
never rewrites or deletes already-stored findings):

```sh
git checkout main && git pull --ff-only && make clean && make build   # restart the service
# clear ingestion data (keeps products/projects/versions/artifacts/API keys), then re-upload:
psql "$THEMIS_DATABASE_DSN" -c "BEGIN; TRUNCATE TABLE \
  triage_history, intelligence_signals, runtime_exposures, remediation_actions, risk_context, \
  vex_assertions, vex_documents, component_vulnerabilities, dependency_relationships, \
  component_versions, scan_reports, sboms, ingestion_jobs RESTART IDENTITY CASCADE; COMMIT;"
```

## Verification

```sh
# canonical-CVE keying — advisory_keyed should be ~0
psql "$THEMIS_DATABASE_DSN" -c "SELECT
  COUNT(*) FILTER (WHERE cve_id LIKE 'CVE-%')     AS canonical,
  COUNT(*) FILTER (WHERE cve_id NOT LIKE 'CVE-%') AS advisory_keyed
  FROM component_vulnerabilities;"

# release-stream scoping — cross_stream should be 0
psql "$THEMIS_DATABASE_DSN" -c "SELECT COUNT(*) AS cross_stream FROM component_vulnerabilities
  WHERE source='distro_osv' AND component_purl ~ '\.el[0-9]+' AND source_fixed_version ~ 'el[0-9]+'
    AND substring(component_purl from '\.el([0-9]+)') <> substring(source_fixed_version from 'el([0-9]+)');"
```

## Known gap (tracked in `project-backlog.md`)

**The Red Hat CSAF VEX overlay never ingests.** `CSAFDirectoryFeedSource` is a one-level
`href="*.json"` crawler, but Red Hat's CSAF repo serves year subdirectories with no top-level
`.json` links — so `vex_assertions` is empty and `upstream_vex_coverage` is always `not_covered`.
Vendor verdicts (e.g. Red Hat marking ncurses CVE-2022-29458 *Not affected* on el8, or its lower
vendor severity) therefore never reach findings. Two fix options are recorded in the backlog
(on-demand Red Hat Security Data API per CVE, recommended; or bulk `tar.zst` archive ingestion).
Deferred to a follow-on.
