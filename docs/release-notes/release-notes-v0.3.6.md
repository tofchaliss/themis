# Themis v0.3.6 — Red Hat VEX minor-stream false-resolution fix

Release tag: `v0.3.6` (**non-breaking** — no schema change; rebuild + restart, and the Red Hat
overlay self-corrects on its next cycle). A security-critical correctness patch on the v0.3.x
line: the v0.3.5 Red Hat VEX overlay was marking genuinely-vulnerable RPM findings as `fixed`
(→ `effective_state = resolved`, risk 0), **hiding live vulnerabilities**.

## The bug

Red Hat's per-CVE document lists a fix for the **main** stream (`cpe:/…:enterprise_linux:8`,
dist-tag `el8_10`) *and* separate back-ports for the minor-version-locked subscription streams
(`rhel_aus:8.4`, `rhel_eus:8.6`, `rhel_e4s:8.8`, …). Those minor streams are **independent
maintenance lines** whose release numbers are not comparable to the rolling main stream.

`RedHatCVEReport.VerdictForStream` collapsed every `el8.*` CPE to major `"8"` and kept the **last**
`affected_release` it iterated — almost always an older minor-stream back-port with a *lower*
release number. The comparison then ran a main-stream install against that back-port:

```text
libtiff installed 4.0.9-36.el8_10   vs   last el8 match 4.0.9-29.el8_8.2 (rhel_e4s:8.8)
rpmvercmp(36, 29) = +1  →  installed >= "fixed"  →  status fixed  →  effective_state resolved
```

The real main-stream fix is `4.0.9-37.el8_10` (release 37), so an `el8_10` install at release 36
is **affected**, not fixed. On a live Rocky-8 deployment this falsely resolved **25 findings** —
including 11 `python3`, 6 `openssh`, plus `libtiff`/`compat-libtiff3`, `glib2`, `libxml2` — every
one an install exactly one release below the correct main-stream fix.

A second, latent bug masked it for some packages: the RPM epoch is carried as a PURL **qualifier**
(`…?arch=x86_64&epoch=2`), not in `@version`, and `rpmInstalledVersion` dropped it. An epoch-2
install then read as epoch 0 and compared *below* any epoch-2 fix — which accidentally produced the
"right" (`affected`) answer for `libpng` while the real bug went unnoticed.

## The fix

- `VerdictForStream` now resolves verdicts against the **main `enterprise_linux:N` stream only**
  (new `redHatMainStreamMajor`), excluding the minor-locked `rhel_aus/eus/e4s/tus` and
  `enterprise_linux_eus` back-port lines. Among main-stream fixes it keeps the **highest** EVR
  (order-independent), so an install must clear every published main-stream fix to count as fixed —
  it errs toward over-reporting, never toward hiding.
- `rpmInstalledVersion` folds the `epoch=` PURL qualifier back into the EVR, so the comparison is
  correct by design rather than by accident.

After the fix, the main-stream fix EVR equals the distro feed's `source_fixed_version` (Rocky/Alma
rebuild RHEL 1:1), so each of the 25 findings resolves to `affected` → **`confirmed`**.

## Fixes (since v0.3.5)

- `fix(vex)` — scope Red Hat verdict resolution to the main `enterprise_linux:N` stream; never
  compare a rolling install against a minor-locked AUS/EUS/E4S/TUS back-port (false `fixed`).
- `fix(vex)` — read the `epoch=` PURL qualifier when resolving the installed RPM EVR.
- Tests: real Red Hat fixtures for the libtiff false-resolution, the el9 multi-z-stream max-fix,
  and the libpng epoch-qualifier path; an end-to-end regression asserting no finding resolves to
  `fixed` against a minor-locked back-port.

## Upgrade

No schema change — **rebuild and restart**. On startup the Red Hat VEX cycle re-fetches every
open-finding CVE and `UpsertAssertions` **deletes and replaces** the feed's assertions, then
re-applies the overlay, so the 25 stale `fixed` assertions are overwritten with correct verdicts
automatically — no manual SQL.

```sh
git checkout main && git pull --ff-only && make clean && make build   # restart the service
```

## Verification

```sh
# Before upgrade this listed the false resolutions; after, it should be ~empty
# (only installs genuinely at/above the main-stream fix remain resolved).
psql "$THEMIS_DATABASE_DSN" -c "
SELECT f.cve_id, split_part(f.component_purl,'@',2) AS installed, cv.source_fixed_version AS fix
FROM v_latest_findings f
JOIN risk_context rc              ON rc.artifact_id=f.artifact_id AND rc.component_purl=f.component_purl AND rc.cve_id=f.cve_id
JOIN component_vulnerabilities cv ON cv.id=f.id
WHERE rc.effective_state='resolved' ORDER BY f.cve_id;"

# libtiff (and the other 24) flip resolved → confirmed
psql "$THEMIS_DATABASE_DSN" -c "
SELECT rc.effective_state, rc.upstream_vex_coverage
FROM risk_context rc WHERE rc.cve_id='CVE-2026-4775' AND rc.component_purl LIKE '%libtiff%';"

# Verdict distribution: the 'fixed' counter stops climbing; 'affected' rises
curl -s "$BASE_URL/metrics" | grep themis_redhat_vex_total
```
