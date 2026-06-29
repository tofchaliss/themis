# Themis v0.3.3 — distro-authoritative correlation, NVD backfill robustness, remediation surfacing

Release tag: `v0.3.3` (**non-breaking** — no schema change; rebuild + clean re-ingest to apply
to existing data). A correctness/observability patch on the v0.3.x line, found and verified
against a live Rocky Linux 8 deployment.

## Highlights

Three Layer-0 fixes. The first closes a regression where RPM findings inflated over time (a
single el8 `openssl` showed **46** findings, and the `unknown`-severity count climbed across
background cycles); the second unblocks severity enrichment; the third makes the remediation
target a first-class API field.

1. **Distro-authoritative package identity (the over-match).** An NVD catalog row stored
   without an ecosystem (e.g. `openssl:openssl`, because NVD's self-named CPE products map to no
   ecosystem) **name-matched** `rpm`/`apk` components and flagged **every upstream CVE** on a
   build whose fix the vendor had **backported** — using upstream version ranges that know
   nothing about the el8 backport. The local/NVD catalog path also bypassed the backport-aware
   distro Correlator via a catalog-first short-circuit. `PackageIdentityMatch` now requires a
   distro (apk/rpm) component's record to **share its distro class**, so empty/upstream-ecosystem
   rows are rejected for distro components and the distro feed's verdict (and fixed NEVRA) wins.
   Application ecosystems (npm/PyPI/Go/…) are unchanged. On the test SBOM, el8 `openssl` dropped
   **46 → 2** (now `source = distro_osv`), total findings fell to ~**198**, and the count holds
   steady instead of climbing.

2. **NVD CVSS backfill robustness.** `FetchByCVEID` treated an empty `vulnerabilities` array on
   a `2xx` (a throttle/transient response — unkeyed NVD returns empty 200s and Cloudflare
   interstitials under load) as a verdict of "NVD has no CVSS", marking the CVE *checked* with a
   **7-day back-off** — which poisoned hundreds of catalog rows during a throttle window so their
   severity stayed `unknown` for a week. An empty result is now a **transient error** (retried
   next cycle); only a record-present-but-genuinely-unscored result backs off.

3. **Remediation surfaced on the findings API (Layer 0 → Layer 1).** `component_vulnerabilities`
   already stored the authoritative fix (`source_fixed_version`); the findings API now returns
   **`fixed_version`** and **`installed_version`** on each item, so the upgrade target — for a
   distro package, the vendor's backported fix NEVRA in the same release stream — is visible
   without SQL. Empty `fixed_version` means no fix has been published. Additive; **no schema
   change**.

## Fixes (since v0.3.2)

- `fix(correlation)` — distro-authoritative package identity: empty/upstream-ecosystem catalog
  rows can no longer name-match apk/rpm components, so the backport-aware distro feed is
  authoritative for distro packages (kills the upstream over-match and its background regrowth).
- `fix(nvd)` — treat an empty NVD by-CVE response as transient (retry), not a 7-day "checked"
  back-off, so a throttle window no longer suppresses CVSS for a week.
- `feat(api)` — surface `fixed_version` + `installed_version` on `GET /api/v1/scans/{id}/vulnerabilities`.

## Upgrade

No schema change — **rebuild and restart** runs the new code. To apply the correlation fix to
**existing** data (raw findings are append-only, so prior over-matched rows persist until a new
scan supersedes them), do a **clean re-ingest**, and set an NVD API key so the backfill is not
throttled:

```sh
git checkout main && git pull --ff-only && make clean && make build   # restart the service
export THEMIS_NVD_API_KEY="<your-nvd-key>"        # 1.5 rps keyed; avoids the throttle behind fix #2

# unstick any throttle-poisoned backfill candidates (catalog UPDATE, not a finding delete)
psql "$THEMIS_DATABASE_DSN" -c "UPDATE vulnerabilities SET cvss_checked_at = NULL \
  WHERE severity='unknown' OR cvss_score IS NULL OR cvss_score = 0;"

# clear ingestion data (keeps products/projects/versions/artifacts/API keys), then re-upload.
# For a guaranteed-clean catalog (recommended after this fix), a full reset also works:
#   psql "$THEMIS_DATABASE_DSN" -c "DROP SCHEMA public CASCADE; CREATE SCHEMA public;" && make migrate-up
psql "$THEMIS_DATABASE_DSN" -c "BEGIN; TRUNCATE TABLE \
  triage_history, intelligence_signals, runtime_exposures, remediation_actions, risk_context, \
  vex_assertions, vex_documents, component_vulnerabilities, dependency_relationships, \
  component_versions, scan_reports, sboms, ingestion_jobs RESTART IDENTITY CASCADE; COMMIT;"
```

> **NVD rate note:** `nvd.rate_limit_rps` defaults to `0` (auto — ≈1.5/s with a key, ≈0.15/s
> without). An explicitly configured positive value **overrides** the key-aware default; leave it
> at `0` (or unset `THEMIS_NVD_RATE_LIMIT_RPS`) to get the keyed rate. Confirm at startup:
> `nvd client configured ... api_key=present rate_limit_rps=1.5`.

## Verification (results from the v0.3.3 E2E on the Rocky 8 SBOM)

```sh
# distro-authoritative + cross-stream — cross_stream is 0
psql "$THEMIS_DATABASE_DSN" -c "SELECT COUNT(*) AS cross_stream FROM component_vulnerabilities
  WHERE component_purl ~ '\.el8' AND source_fixed_version ~ 'el9';"                 # → 0

# openssl is the distro verdict, not the upstream over-match
psql "$THEMIS_DATABASE_DSN" -c "SELECT source, COUNT(*) FROM component_vulnerabilities
  WHERE component_purl LIKE 'pkg:rpm/rocky/openssl@%' GROUP BY source;"             # → distro_osv | 2

# remediation visible; el8 installs show el8 fixes (or none), never el9
curl -s "$BASE_URL/api/v1/scans/$SCAN_ID/vulnerabilities" -H "X-API-Key: $API_KEY" \
  | jq '.items[] | {cve_id, installed_version, fixed_version}'

# headline holds steady (was 432/495 and climbing)
curl -s "$BASE_URL/api/v1/status?top=10" -H "X-API-Key: $API_KEY" | jq '.vulnerabilities.total_findings'  # → ~203
```

`unknown` severities drain as the CVSS backfill cycles (keep an NVD key set and the rate at auto);
a residual handful of genuinely-unscored very recent CVEs correctly stay `unknown`.

## Known gaps (tracked in `project-backlog.md`)

- **Red Hat CSAF VEX overlay never ingests** — the directory crawler finds no top-level `.json`
  links, so `vex_assertions` is empty and vendor verdicts never reach findings. Recommended fix:
  on-demand Red Hat Security Data API per RPM-family CVE. Deferred.
- **OSV.dev app-ecosystem version-range quirks** (found during this release's E2E) — `GIT`-type
  OSV ranges over-match and surface a commit SHA as the "fix" (e.g. Jinja2 `CVE-2016-10745` on a
  3.1.6 install), and independent major lines can cross-match (urllib3 1.26.x vs 2.x). Distinct
  from the distro work here; tracked as an app-ecosystem correlation-accuracy follow-on.
