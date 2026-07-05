# Themis v0.3.4 — preserve backfilled CVSS (no catalog clobber)

Release tag: `v0.3.4` (**non-breaking** — no schema change; rebuild + restart, plus a one-line
SQL to unstick already-clobbered rows). A focused correctness patch on the v0.3.x line.

## The bug

After v0.3.3, RPM findings are correctly sourced from the distro OSV feed, and the NVD-by-CVE
CVSS backfill (CR-5) fills in their severity/score. But the two were fighting:

1. The backfill writes a real CVSS into the `vulnerabilities` catalog and stamps `cvss_checked_at`.
2. A watch cycle re-correlates the distro feed and `UpsertVulnerability`'s `ON CONFLICT DO UPDATE`
   **unconditionally overwrote** `severity`/`cvss_score`/`cvss_vector`. Distro OSV records carry
   no numeric CVSS, so the upsert wiped the backfilled score back to `0`/`unknown`.
3. Because `cvss_checked_at` was already set, the row then fell inside the retry back-off, so the
   backfill would not re-fill it — it stayed `unknown`.

A server restart fired the watch's startup cycle, which is exactly when the overwrite happened,
so freshly-scored findings would visibly revert to `severity: unknown` (and the status
`by_severity` `unknown` count climbed back up). On the test SBOM this left ~60 catalog rows in a
"checked but unscored" state.

## The fix

`UpsertVulnerability` now **preserves an existing real CVSS/severity** and only overwrites
`severity`/`cvss_score`/`cvss_vector` when the incoming feed actually supplies a better value; the
correlation metadata (affected ranges, fixed versions, ecosystem) still refreshes on every
upsert. The NVD backfill is authoritative for the numeric score; the distro feed fills gaps. The
two no longer fight, and severities stop reverting.

## Fixes (since v0.3.3)

- `fix(correlation)` — preserve backfilled CVSS in the catalog upsert (no clobber with an
  empty/zero feed record); integration regression test covers preserve, metadata refresh, and a
  legitimate re-score overwrite.

## Upgrade

No schema change — **rebuild and restart** runs the new code. Then unstick any rows that the old
behaviour already clobbered (catalog `UPDATE`, not a finding delete) so the backfill re-fills them
— and with this fix they stay scored:

```sh
git checkout main && git pull --ff-only && make clean && make build   # restart the service
psql "$THEMIS_DATABASE_DSN" -c "UPDATE vulnerabilities SET cvss_checked_at = NULL \
  WHERE cvss_score = 0 OR cvss_score IS NULL OR severity = 'unknown';"
```

Keep an NVD API key set (`THEMIS_NVD_API_KEY`) and leave `nvd.rate_limit_rps` at `0` (auto → 1.5/s
keyed) so the backfill clears quickly.

## Verification

```sh
# pick a CVE the backfill scored, then watch it survive a watch cycle / restart
psql "$THEMIS_DATABASE_DSN" -c "SELECT cve_id, severity, cvss_score FROM vulnerabilities WHERE cvss_score > 0 LIMIT 5;"

# 'checked but unscored' should trend to ~0 (only genuinely-unscored very recent CVEs remain)
psql "$THEMIS_DATABASE_DSN" -c "SELECT COUNT(*) FROM vulnerabilities \
  WHERE cvss_checked_at IS NOT NULL AND (severity='unknown' OR cvss_score=0 OR cvss_score IS NULL);"

# by_severity holds its spread across restarts (no revert to all-unknown)
curl -s "$BASE_URL/api/v1/status?top=10" -H "X-API-Key: $API_KEY" | jq '.vulnerabilities.by_severity'
```
