# Themis v0.2.1 — Alpine signal reliability patch

Release tag: `v0.2.1` (non-breaking maintenance release)

## Highlights

Fixes Phase 2a signal pipeline gaps discovered during real Alpine SBOM bring-up: canonical CVE IDs,
OSV CVSS vector parsing, working vendor VEX feed sources, scan API enrichment fields, and ExploitDB
sync observability. No schema migrations.

## Fixes

### OSV / Alpine correlation

- **`ALPINE-CVE-*` → `CVE-*`** normalization on ingest (`domain.NormalizeCVEID`)
- **CVSS vector parsing** — `CVSS:3.1/AV:N/...` strings produce numeric `cvss_score` and severity
- **Alpine package names** — `so:` strip and `py3-` → `python3-` before OSV lookup
- **Backfill script** — `scripts/backfill-alpine-cve-ids.sql` for existing catalog rows

### Vendor VEX feeds

- **`ZipOSVFeedSource`** — Alpine and Rocky default to GCS `all.zip` archives
- **`CSAFDirectoryFeedSource`** — Red Hat CSAF advisory directory crawler
- **`ParseOSVFeed.firstCVE()`** — normalizes Alpine OSV advisory IDs

### Observability

- **`GET /api/v1/scans/{id}/vulnerabilities`** — additive `enrichment` object with Phase 2a signal fields
- **`themis_exploitdb_sync_total{status}`** Prometheus counter
- **OSV correlation logging** — structured skip/mismatch logs + per-ingest ecosystem summary

### Tooling

- **`scripts/upload-sbom.sh`** — curl-based SBOM upload helper

## Configuration changes (defaults)

| Feed | New default |
| ---- | ----------- |
| Alpine | `https://storage.googleapis.com/osv-vulnerabilities/Alpine/all.zip` |
| Rocky | `https://storage.googleapis.com/osv-vulnerabilities/Rocky%20Linux/all.zip` |
| Red Hat | `https://security.access.redhat.com/data/csaf/v2/advisories/` |

Wolfi unchanged. All URLs remain env-overridable via `THEMIS_VEXFEED_*`.

## Upgrade notes

1. Deploy the new binary (no migration step).
2. If Alpine SBOMs were ingested before v0.2.1, run `scripts/backfill-alpine-cve-ids.sql` once.
3. Wait for or trigger EPSS/KEV/ExploitDB sync so `ReEnrichJob` attaches signals to backfilled CVE IDs.
4. Verify vendor feeds: `curl -s localhost:8080/metrics | grep themis_vexfeed_sync_total`

## Out of scope (unchanged)

Product/version registration APIs and VEX export without manual SQL remain deferred to
`themis-core-model` (`v0.3.0`).
