# Case file — why MRF/cdmrf-oamp/20.1.0.0-125 shows 634 open findings and zero clearances

**Status:** FIX LIVE-VERIFIED 2026-09-10 (main `daec9a1`) — 96 cleared incl. both proven CVEs;
queue impact blocked by the stale mis-attributed siblings (**KN-SCAN-4**, §8b)
**Date:** 2026-09-10 · **Release under investigation:** `7bc21a1b-e898-47e4-b784-f2242fa983a4`
(MRF → cdmrf-oamp → 20.1.0.0-125) · **Estate:** Rocky 8 container image, Cortex + SPDX evidence
**Related:** KN-VERDICT-1 · KN-MODULE-4 (fixed) · **KN-MODULE-5 (open — the blocker)** · KN-SCAN-3b

> **If you read one paragraph.** The verdict machinery is healthy and running. It clears nothing on
> this release because, for the packages that matter, **it is never handed a number it can compare**.
> Red Hat and Rocky state the fix for a modular package as a *module stream identifier*
> (`httpd:2.4-8000020190405071959.55190bc5`) which contains no version. The real build
> (`httpd-0:2.4.37-11.module+el8.0.0+2969+90015743`) exists, publicly, one HTTP hop away in the
> advisory document — and nothing in Themis fetches it. That hop is **KN-MODULE-5**, and it is the
> reason repeated fixes have not moved the number.

---

## 1. What was measured (all live, this release, 2026-09-10)

| Fact | Value | How obtained |
| --- | --- | --- |
| Open occurrences | **634** | `faultline_matches` where `release_id = <REL>` |
| Cleared occurrences | **0** | same |
| Stale verdict stamps | **0** | `verdict_card_version < faultlines.version` |
| httpd open CVEs | **87** | one component row, `pkg:rpm/rocky/httpd@2.4.37-65.module+el8.10.0+40257+286895ef.9` |
| Re-verdict sweep | drained, `rejudged:0 changed:0` sustained | `journalctl -u themis@knowledge` |
| Rocky RLSA for CVE-2019-0211 | **none** | apollo.build.resf.org returned no advisories |
| SBOM components on this release | 489, **489 with no `source`** | `canonical_inventory` |

**The stale count is the load-bearing measurement.** Zero stale means the sweep re-judged every
occurrence against current card knowledge and concluded "open". This is not a sweep that failed to
run; it is a sweep that ran, asked a question that cannot be answered, and honestly recorded nothing.
Any future investigation should re-check this number FIRST — it separates "machinery broken" from
"machinery starved of input", and those have opposite fixes.

## 2. Ground truth — the findings are provably false

Run against the image itself:

```
$ docker run --rm --entrypoint sh <image> -c 'rpm -q --changelog httpd | grep CVE-2019-0211'
- Resolves: #1695432 - CVE-2019-0211 httpd: privilege escalation
```

The installed `httpd-2.4.37-65.module+el8.10.0+40257+286895ef.9` carries the vendor's backported fix
and its changelog names the CVE. CVE-2019-0211 is KEV-listed with EPSS 0.65, so it ranks at the top
of the queue while being provably not applicable. That combination — highest-ranked and wrong — is
what erodes trust in the tool fastest.

## 3. Root cause chain for httpd (the 87)

Three links. **Two are now fixed; the third is the blocker.**

### Link 1 — blank ecosystem closed the verdict path ✅ FIXED (operator-side)

Cortex reports httpd as `package_type: APP` with purl `app:httpd@2.4.37-65.module+el8...` — no `pkg:`
prefix, therefore no ecosystem. `StrictFixesFor` returns `nil` without a positive ecosystem, so **no
vendor-fix verdict could fire at all**. This is KN-SCAN-3b, and the 87 measured here are the same 87
in that filing.

Fixed in `scripts/cortex-csv-to-scan-report.sh` (option (b) of that entry): an `APP` row whose
version carries an RPM release marker (`.el8`/`+el8`/`.module+el8`) is labelled `rpm`. That is a
statement about the version's SHAPE, not a guess about scanner intent; rows without the marker stay
blank. The Themis-side asymmetry (SPDX skips unreadable purls, the scanner path admits them) remains
filed on its own merits.

### Link 2 — the source-package field held a file path ✅ FIXED (operator-side)

The converter mapped Cortex's `file_path` into `component.source`. `componentPackage()` PREFERS
source over name when asking a feed "what fixes this package?", so 144+ findings asked the feeds
about a package literally named **`Managed by the Package Manager`** (and httpd's asked about
`/usr/sbin/httpd`). Every such lookup returned nothing, permanently.

Fixed to `origin_package_name`. Verified: 0 source values now contain a path or a space.

### Link 3 — no comparable fix bound exists on the card ✅ FIX BUILT 2026-09-10 (was the blocker; live verification pending)

> **Update 2026-09-10 (same day, later):** implemented on `fix/kn-module-5-redhat-errata-bounds`
> as the two-hop CSAF resolution INSIDE `RedHatClient.FetchCVE` — same `redhat` source and queue
> (a second BackfillService would re-create the KN-MODULE-4 queue-keying defect). See the
> BACKLOG KN-MODULE-5 entry for the full shape. §5's design constraints were all honored; the
> §5 text below is the pre-implementation analysis, kept as written.

What the card actually holds for CVE-2019-0211 (`view->'fixes'`, rpm entries only):

```json
{ "package": "httpd", "version": "httpd:2.4-8000020190405071959.55190bc5", "ecosystem": "rpm" }
```

That is a module stream identifier: a name, a stream, and a build context timestamp. It contains no
package version. `RPMReleaseMajor()` extracts `""` from it (no `.elN`/`+elN` marker), so
`RPMFixedByStream` cannot place it in a stream and correctly refuses to decide. **The comparator is
behaving exactly as designed. The input is not a version.**

Verified on two CVEs, same shape both times:

| CVE | Red Hat CVE record states | Advisory | Real NEVRA in the advisory's CSAF doc |
| --- | --- | --- | --- |
| CVE-2019-0211 | `httpd:2.4-8000020190405071959.55190bc5` | RHSA-2019:0980 | `httpd-0:2.4.37-11.module+el8.0.0+2969+90015743` |
| CVE-2019-0220 | `httpd:2.4-8010020190829143335.cdc1202b` | RHSA-2019:3436 | `httpd-0:2.4.37-16.module+el8.1.0+4134+e6bad0ed` |

Installed is `-65` on `el8.10`. Against `-11` or `-16` on the same el8 stream, the EXISTING
comparator clears both immediately. **No comparator change is needed — only the fetch.**

## 4. Why the previous fixes did not move the number

This is the question to answer first when returning to this.

- **KN-MODULE-4 (shipped 2026-09-09)** solved exactly this gap **for Rocky**, by reading RLSA
  advisories which state real NEVRAs. It works. It cannot help here: **Rocky has no RLSA for a 2019
  advisory** — Rocky 8 did not exist in 2019, and those fixes were inherited from Red Hat's stream.
  Verified live: the Rocky errata API returns nothing for CVE-2019-0211.
- **`THEMIS_ROCKY_BACKFILL_LIMIT` raised + node restarted (2026-09-10)** drained the RLSA queue
  fully (`rejudged:0` sustained). `changed:0` throughout. The sweep is healthy; there is simply no
  Rocky data for these CVEs to find.
- **The two converter fixes above** unblocked the *path* (link 1) and repaired *attribution*
  (link 2). Neither supplies a bound. httpd stays open until link 3 is built.

**The trap to avoid on return:** each fix was correct and each left the number unchanged, which
reads as "nothing works". The chain is sequential — links 1 and 2 were genuinely blocking and had to
be cleared, but only link 3 produces a clearance.

## 5. KN-MODULE-5 — the fix that is not built

The backlog entry assumes "same shape, different base URL" as KN-MODULE-4. **That assumption is
wrong and the entry should be corrected.** Red Hat's Hydra CVE endpoint restates the same useless
module stream — verified 2026-09-10. Swapping the base URL buys nothing.

The resolution is **two hops**:

1. The CVE record yields a module stream **and its advisory id** (`RHSA-2019:0980`) — already fetched today.
2. Fetch that advisory's CSAF document and extract the real NEVRAs.

Both endpoints are **public, no subscription** (verified):

```
https://security.access.redhat.com/data/csaf/v2/advisories/2019/rhsa-2019_0980.json
https://access.redhat.com/hydra/rest/securitydata/csaf/RHSA-2019:0980.json
```

Product ids look like `AppStream-8.0.0.Z:httpd-0:2.4.37-11.module+el8.0.0+2969+90015743.src::httpd:2.4`
— strip the product prefix and the `::httpd:2.4` module suffix; take `.src` entries only.

**Design constraints (mirroring KN-MODULE-4, which are why it was safe):**

- Hop 2 fires **only** when hop 1 yields a module stream — normal NEVRAs already work, no extra requests.
- **Source packages only** (`.src`), as `rockyFixFromNVRA` does: a binary list is rebuild SCOPE, not N claims (EDR-CORRELATION-01).
- Driven by the existing `BackfillService` on `THEMIS_REDHAT_ENABLED` — per-CVE, staleness-bounded, capped. No new config surface.
- **Thin adapter**: query → select → extract → `FixedVersion`. No version comparison, stream reasoning, applicability, severity or dedup policy. `RPMFixedByStream` untouched.
- An additional evidence source for **bounds**, never a second authority.
- Safety tests mirroring KN-MODULE-4: `-65` clears / `-30` does not; el7↛el8 and el9↛el8; and no malformed bound (`httpd:2.4`, bare `2.4`, `""`) can ever clear. Mutation-verify both filters.

**Scope:** 87 CVEs on this release. Not the 600 below — those are a different problem.

## 6. The wider estate — a SEPARATE and larger problem

httpd is 16 of ~600 open rpm occurrences that have no usable fix bound keyed to their own name.
Top of that list (estate-wide, `verdict_state='open'`, ecosystem `rpm`):

```
kernel-core 136 · python3-pyyaml 79 · binutils 77 · compat-libtiff3 59 · python3-ply 52
libtiff 19 · curl 18 · jq 16 · httpd 16 · python3.12 14 · libarchive 11 · openssh 10 ...
```

These are **not** module-stream cases. They are **source-package vs binary-package naming**:

- `kernel-core` is built from source `kernel`; `perl-Errno` from `perl`; `glibc-common` from `glibc`.
- `FixesFor` (`internal/knowledge/domain/reconcile.go:386`) matches package names with
  `strings.EqualFold` — **exact equality, no normalization** — even though `NormalizeProduct` exists
  in the same package and maps `python3-setuptools` and `python-setuptools` both to `setuptools`.
- Where the SBOM carries `source` (other releases do: `kernel-core|kernel`), attribution works.
  **This release's SBOM carries `source` on 0 of 489 components**, so `componentPackage()` falls back
  to the binary name and the lookup misses.

**Two candidate fixes, both unbuilt, deliberately not bundled with KN-MODULE-5:**

1. **Regenerate this release's SBOM with source-RPM metadata.** Other releases have it, so the
   generator can produce it. Likely the single biggest lever, and possibly no Themis change at all.
2. **Normalized-equality matching in `FixesFor`/`StrictFixesFor`.** Would catch the `python3-*`
   family (~130 CVEs) without source data. **Must use normalized EQUALITY, never `relatedProduct`
   containment** — containment would let `python3-pip` match a fix for `python3-pip-wheel`, and a
   wrong clearance is a FALSE NEGATIVE, the one direction the design forbids. `StrictFixesFor`
   (fail-closed, verdict-grade) needs more care here than `FixesFor` (fail-open, display).

Measured blast radius of (2) alone, with module-stream entries and cross-EL fixes excluded: **6
component/fix pairs, 3 CVEs — and all three stay open**, because the installed build is genuinely
below the fix:

| Installed | Fix requires | Verdict |
| --- | --- | --- |
| `libcurl 7.61.1-34.el8_10.11` | `curl 0:7.61.1-34.el8_10.13` | still vulnerable |
| `libnghttp2 1.33.0-6.el8_10.2` | `nghttp2 0:1.33.0-6.el8_10.3` | still vulnerable |
| `libattr 2.4.48-3.el8` | `attr 0:2.6.0-1.el8_10` | still vulnerable |

So (2) is **correctness hygiene, not queue reduction**: it removes a blind spot that would otherwise
hide these clearances after you patch. Do not expect it to lower the count today.

## 7. The pypi shadow problem (KN-VERDICT-1 link (a)) — also open

`setuptools@39.2.0 (pypi)`, `pip@23.2.1`, `pyyaml@3.12` are flagged while the SAME inventory holds
the patched `python3-setuptools 39.2.0-9.el8_10` and `platform-python-setuptools 39.2.0-9.el8_10`.
The ownership bridge (`app/verdict.go` `bridgeObserved`/`bridgeInferred`) exists and is armed by
default, but cannot fire because `FixesFor(sibling)` misses for the same exact-match reason as §6 —
the fix is filed under source name `python-setuptools`.

Note `NormalizeProduct("python3-setuptools") == NormalizeProduct("python-setuptools") == "setuptools"`
(verified by running the real function). **The codebase already contains the function that would
make this match; `FixesFor` simply does not call it.** `platform-python-setuptools` does NOT
normalize (one prefix stripped, and the name begins `platform-`), which is a second, narrower gap.

## 8. Recommended order when returning

1. **KN-MODULE-5** (two-hop CSAF errata) — 87 CVEs, evidence complete, pattern proven by KN-MODULE-4,
   both endpoints verified public. Highest confidence, self-contained.
2. **Regenerate this release's SBOM with source metadata** — plausibly the largest single reduction
   (`kernel-core`'s 136 and the perl/glibc families), and may need no code change.
3. **Normalized-equality in `FixesFor`/`StrictFixesFor`** — unblocks the `python3-*` family and the
   pypi bridge. Domain change to a 100%-coverage package touching the fail-safe direction: needs its
   own EDR delta and careful tests.
4. **Re-measure before doing more.** After 1–3, re-run the §6 query. Several entries there may
   resolve for free, and the remainder will be a different, smaller list.

## 8b. LIVE VERIFICATION — 2026-09-10 evening (same day)

Deployed to the VM (main `daec9a1`), knowledge node restarted; the restart's full Red Hat sweep
folded **1592** proposals with the second hop live.

**Result: 96 occurrences `cleared_vendor_fix` (was 0 throughout this case):**

| Component | Cleared | Note |
| --- | --- | --- |
| httpd | 74 | the KN-MODULE-5 mechanism, end to end |
| libxml2 | 14 | bonus — fresh direct bounds from the full sweep |
| libssh | 7 | same |
| curl | 1 | same |

CVE-2019-0211's cleared row reads, verbatim: *"vendor fix
0:2.4.37-11.module+el8.0.0+2969+90015743 present: installed
2.4.37-65.module+el8.10.0+40257+286895ef.9 is at/above the same-stream bound for httpd"* — the
resolved RHSA-2019:0980 bound, the exact chain §5 designed. CVE-2019-0220 likewise (`-16`,
RHSA-2019:3436).

**Honest residue — 13 httpd CVEs stay open on the corrected row** (2019-17567, 2024-24795/38472/
43204/43394, 2025-59775, and seven 2026-*): each is either fixed in a build newer than `-65`
(a REAL finding) or carries no main-stream RHSA bound. This is the queue working, not failing.

**New blocker found by the verification itself: the stale poisoned siblings — filed as
KN-SCAN-4.** Every cleared httpd row has an open twin recorded with `source=/usr/sbin/httpd`
(the pre-fix converter output), and 492 more rpm rows estate-wide carry `source="Managed by the
Package Manager"`. Recorded identity is immutable, so they can never clear, and re-uploading the
corrected report minted the cleared rows as NEW occurrences instead of healing the old ones —
so the stale twins still hold every cleared httpd Finding in the triage queue. The queue-count
payoff of this whole case now waits on KN-SCAN-4, not on any feed.

## 9. Reproduction queries

`PGBASE` = `postgres://themis:<pw>@localhost:5432`, `REL` = the release UUID.
Use `psql -f` with a quoted heredoc; bash history expansion mangles `!~` and `\+` in `-c` strings.

```sql
-- verdict state + staleness (the FIRST thing to check)
select m.verdict_state, coalesce(nullif(m.verdict_grade,''),'-') as grade, count(*),
       sum(case when m.verdict_card_version < f.version then 1 else 0 end) as stale
from faultline_matches m join faultlines f on f.id=m.faultline_id
where m.release_id = '<REL>' group by 1,2 order by 3 desc;

-- what a card actually offers as fixes
select jsonb_pretty(f.view->'fixes') from faultlines f where f.cve='CVE-2019-0211';

-- open rpm occurrences with no usable same-name bound (the §6 list)
select m.component_name, count(distinct m.faultline_id) as cves, count(distinct m.release_id) as releases
from faultline_matches m join faultlines f on f.id=m.faultline_id
where m.verdict_state='open' and m.component_ecosystem='rpm'
  and not exists (select 1 from jsonb_array_elements(f.view->'fixes') fx
                  where fx->>'ecosystem'='rpm' and fx->>'version' ~ '(\.|\+)el[0-9]'
                    and lower(coalesce(fx->>'package','')) = lower(m.component_name))
group by 1 order by 2 desc limit 30;

-- source attribution actually reaching the match rows
select m.component_name, coalesce(nullif(m.component_source,''),'(none)') as src,
       count(distinct m.faultline_id) as cves
from faultline_matches m where m.verdict_state='open' and m.component_ecosystem='rpm'
group by 1,2 order by 3 desc limit 20;
```

Vendor lookups (both public):

```sh
curl -s "https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2019-0211.json" \
  | jq -r '.affected_release[]? | select(.product_name|test("Enterprise Linux 8"))
           | "\(.product_name) | \(.package // "-") | \(.advisory)"'

curl -s "https://security.access.redhat.com/data/csaf/v2/advisories/2019/rhsa-2019_0980.json" \
  | jq -r '[.. | objects | select(has("product_id")) | .product_id]
           | map(select(test("httpd-0:"))) | map(select(test("\\.src::"))) | unique | .[]'
```

## 10. Corrections to the record

Recorded because each was believed and acted on before being disproved:

- **"Missing `source` attribution is the root cause"** — wrong as stated. `NormalizeProduct` would
  have handled `python3-setuptools`; and Syft's `sourceRpm` is a filename, not a bare package name.
  Source attribution IS the fix for `kernel-core`/`perl-Errno` (§6), but not for setuptools.
- **"The name mismatch explains the bulk of pending CVEs"** — wrong. Measured blast radius is 3
  CVEs, none of which clear (§6).
- **"KN-MODULE-5 is the same shape as KN-MODULE-4, different base URL"** — wrong, and the backlog
  entry still says this. It is a two-hop resolution through the advisory (§5).
- **"httpd is where the false positives live"** — incomplete. httpd is 16 of ~600 in the no-usable-bound
  state; the dominant pattern is source-vs-binary naming (§6).
