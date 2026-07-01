# Themis v0.3.7 — OSV GIT-range over-match fix

Release tag: `v0.3.7` (**non-breaking** — no schema change; rebuild + restart, then re-ingest to
refresh existing scans). A focused correctness patch on the v0.3.x line: the OSV.dev live
correlation path turned `GIT`-type ranges into version constraints, producing false positives on
application-ecosystem (pypi/npm/…) findings and leaking commit hashes as fixed versions.

## The bug

An OSV record's `affected[].ranges[]` carries a **`type`** — `SEMVER`, `ECOSYSTEM`, or `GIT`. The
client never read it, so a `GIT` range (whose `introduced`/`fixed` events are **commit hashes**, not
versions) was fed to the version-constraint builder like any other range.

Concretely, for Jinja2 `CVE-2016-10745` the OSV `/v1/query` record (`PYSEC-2019-220`) carries a
`GIT` range `{introduced: 0} → {fixed: 9b53045c…}` **alongside** the real `ECOSYSTEM < 2.8.1`. The
GIT range became the constraint `< 9b53045c…`; since a semver like `3.1.6` sorts below a hex commit
id (`3` < `9b…`), **Jinja2 3.1.6 (2025) was flagged for a 2016 CVE fixed in 2.8.1**, and its
`fixed_version` surfaced as the **commit hash** instead of a version.

## The fix

- `osvRange` now carries `type`, and `isUnusableRangeType` skips `GIT` ranges in both
  `extractAffectedVersions` and `extractFixVersions` (`internal/adapter/osv/client.go`).
- OSV always attaches a `SEMVER`/`ECOSYSTEM` range (or an explicit `versions` list) whenever an
  ecosystem fix exists, so skipping GIT ranges is safe: the `ECOSYSTEM < 2.8.1` remains and Jinja2
  3.1.6 is correctly **not** matched. A GIT-only entry with no versions list **fails closed**
  (`none` sentinel) rather than over-matching on commit hashes; an explicit `versions` list is
  still honoured. No commit hash can leak as a `fixed_version`.

### On the "major-line crossing" symptom (urllib3)

Verified against the real OSV `/v1/query` data: multi-line packages (e.g. urllib3
`CVE-2024-37891`) are published as **separate `affected` entries** (`< 1.26.19` and
`>= 2.0.0, < 2.2.2`), which the existing code already turns into correct OR-groups — a `1.26.20`
install matches neither. A residual over-match only occurs when OSV itself provides an unbounded
`introduced:0 → fixed:X.Y.Z`, i.e. Themis is *faithfully* applying OSV's own range. A "major-line
suppression" heuristic was **declined** — it would hide real findings, contradicting the OSV path's
deliberate recall-first stance ("a false positive is safer than hiding a real finding"). If OSV's
range is wrong, the correction belongs upstream in OSV.

## Fixes (since v0.3.6)

- `fix(osv)` — read `ranges[].type`; skip `GIT`-type ranges so commit hashes never become a version
  bound or a `fixed_version` (fail closed when only a GIT range is present). Adds named
  `osvPackage`/`osvAffected`/`osvRange` types.

## Upgrade

No schema change — **rebuild and restart**. New ingests immediately stop creating the false
positives. Existing scans keep their raw findings until the artifact is re-ingested (a fresh scan
re-runs correlation under the fixed code):

```sh
git checkout main && git pull --ff-only && make clean && make build   # restart the service
# then re-upload the affected SBOM(s) so the latest scan re-correlates
```

## Verification

```sh
# No fixed_version should be a 40-char commit hash any more
psql "$THEMIS_DATABASE_DSN" -c "
SELECT cve_id, component_purl, source_fixed_version
FROM component_vulnerabilities
WHERE source_fixed_version ~ '^[0-9a-f]{40}$';"   # → 0 rows after re-ingest

# Jinja2 CVE-2016-10745 must not appear on a modern 3.x install
psql "$THEMIS_DATABASE_DSN" -c "
SELECT component_purl, cve_id FROM component_vulnerabilities
WHERE cve_id = 'CVE-2016-10745' AND component_purl LIKE '%jinja2@3.%';"   # → 0 rows
```
