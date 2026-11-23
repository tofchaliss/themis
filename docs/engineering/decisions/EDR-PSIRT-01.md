# EDR-PSIRT-01 — Product severity per CVE on the Overview (PSIRT view)

Status: **PROPOSED — 2026-11-23. Owner choices 1-6 answered 2026-11-23; the owner OK'd the
Knowledge change (P1a), the Governance read (P1) and this design PR the same day ("let us see
how it performs, if not we will revert").**
Date: 2026-11-23
Author: the design discussion of 2026-11-23 (thread "Add PSIRT product severity view").

## Purpose

The owner's ask (2026-11-23): as part of PSIRT, teams need one page that shows **the latest
issues (CVEs) of each product, with a severity for the product**. That severity does not exist
yet. It must be **derived from the components of the product**, across all its projects and
releases. It lives in the new GUI's **Overview** page (EDR-GUI-02).

This record says what "product severity" means, what the Overview shows, and which read the
backend must add. It changes no stored truth and no decision: it is a read-side roll-up.

## What Themis has today (measured 2026-11-23, main `64cafd1`)

1. **A Finding is one (release, CVE).** It has `created_at` (first time this CVE was filed on
   that release) and a current Position (stance, decided by, decided at).
2. **Each Finding already has two severities** (EDR-GUI-02 owner amendment, PR #239):
   `original_score` / `original_severity` (the source's own CVSS Base rating) and
   `expert_score` / `expert_severity` / `expert_status` / `score_state` (EDR-SCORING-01 roll-up:
   the highest Environmental score over the open, eligible components of that release).
3. **The component level is already rolled up once.** EDR-SCORING-01 section 6 takes the highest
   Environmental score over the components of one release (scope components excluded, cleared
   components left out, provisional if the maximum is provisional). So the product level only has
   to roll up **release rows**, never components again. This keeps one rule per level.
4. **Release to product** is Registry's. Governance already walks it in one pass
   (`ReleaseProducts`, used by the remediation metrics, EDR-REMEDIATION-01 D6).
5. **Cross-release read of one CVE** exists: `GET /faultlines/{id}/findings` (EDR-GUI-02 D13).
   There is **no read of "every CVE of one product"**. The Overview's estate donut today reads
   every release's posture one call at a time from the browser (`sweepEstate`).
6. **Registry stores no release date and no release order.** "Newest release of a project"
   cannot be told today without a Registry change. Releases, projects and products do have tags.
7. **Knowledge** keeps the card's first-seen time (`/faultlines/recent`) and the exploit signals
   (band, KEV). The world's publish date is not stored (`/faultlines/published-recently` is live).

## Proposed model (each item has an owner choice below)

### Rule: product severity of one CVE

For one product P and one CVE C:

1. **Rows** = every Finding of C on a release of P (choice 1 decides which releases).
2. **Live rows** = rows that still affect the product (choice 3): the Position is not
   `not_affected`, and the release's roll-up state is not `no_open_occurrences` (every eligible
   component cleared by a vendor fix) and not `no_carrier` (scope only).
3. **Row severity** = the row's Original (source CVSS Base) severity (owner choice 2,
   2026-11-23; the first draft said Expert). A row with no source rating is "not scored": it is
   counted but does not set the severity.
4. **Product severity** = the **highest** row severity over the live rows, with its score. The
   release that sets it is the "worst release".
5. **No live rows** = no severity number. The row shows why, by name: "not affected" (all
   rows decided `not_affected`), "cleared" (all cleared by a vendor fix), or "scope only". Never 0,
   never "fixed" unless that is what the rows say.

Why the highest (proposed; the owner chose the source rating as the basis, the max over releases is to confirm): a PSIRT answer is "how bad is this for the product we ship". If one release in
the field carries the flaw at High, the product is exposed at High. It is the same max rule the
component level already uses, so the two levels never disagree in kind.

### What the Overview shows

A new card **"Product security (PSIRT)"** on the Overview, below the top row, kept separate from
the screens the GUI move-over (G3-G5) is changing:

1. A **product picker** (All products, or one) and a **"latest" window** (7 / 30 / 90 days,
   default 30).
2. Per product, a **strip of counts**: Critical, High, Medium, Low, Not scored, for CVEs whose
   product severity is live.
3. A **table, one row per (product, CVE)**, sorted by product severity, then newest first:
   CVE (with the Knowledge band badge and a KEV mark), **Product severity** (with "prov." or
   "source" marks), **Releases affected** ("4 of 9"), **Decided** ("3 of 4"), **First seen in
   product**, and **Worst release** (the release that sets the maximum, as a link).
4. A row click opens the existing per-CVE releases dropdown (EDR-GUI-02 D13), so a team goes
   from "product is High" to the release and component that make it High in one click. No new
   drill-down screen.

### Columns of one PSIRT entry (owner, 2026-11-23)

The owner set (2026-11-23) what each PSIRT entry lists: **original score, severity, CVE number,
issue type (such as remote code execution), published / updated, and the component when
known**. Measured against main `64cafd1`:

| Column | Source | Stored today? | What is needed |
| --- | --- | --- | --- |
| CVE number | Finding `cve` | yes | nothing |
| Original score | posture `original_score` (source CVSS Base) | yes, per release | the read takes the highest over the product's live releases |
| Severity | product severity (rule above) beside `original_severity` | per release yes; product level no | the product roll-up (P1) |
| Component | posture `components` (PURL, name, version, claim class) | yes | the read lists the carrier components that set the maximum; "not known" when only scope |
| Updated | source rating `updated_at` (NVD `lastModified`, CVE.org update time) in `source_ratings` | yes, per rating | the read takes the newest over the CVE's ratings |
| Published | the CVE's publish date (CVE.org `datePublished`, NVD `published`) | **no**: the feeds parse it, Knowledge does not keep it | Knowledge keeps it on the card (P1a) |
| Issue type | the CVE's weakness (CWE) from CVE.org / NVD records | **no**: not parsed, not kept | Knowledge keeps the CWE ids (P1a); the GUI shows a short type word from a fixed CWE-to-type table (choice 6) |

Nothing is guessed: a missing publish date shows "not known", never the date Themis first saw
the CVE; a CVE with no CWE, or only `NVD-CWE-noinfo` / `NVD-CWE-Other`, shows "not stated".

### Backend read (API change, needs the owner's approval)

One new **Governance** read, owned by Governance because it rolls up Governance rows:

```
GET /api/v1/products/{productId}/cves?days=30        one product
GET /api/v1/psirt/cves?days=30                        every product (the "All" picker)
```

Each row: `product_id`, `product_name`, `faultline_id`, `cve`, `product_severity`,
`product_score`, `severity_basis` (`expert` | `source` | `none`), `status`
(`provisional` | `final`), `state` (`live` | `not_affected` | `cleared` | `scope_only`),
`releases_total`, `releases_live`, `releases_decided`, `worst_release_id`,
`first_seen` (earliest Finding `created_at` of C in P), `last_changed`.

- The rule is a **pure domain function** in `internal/governance/domain` (100% coverage tier),
  so the GUI, a CLI script, or a later Teams alert get the same answer from one place.
- Release to product comes from the existing `ReleaseProducts` walk; scores come from the same
  newest-assessment read the posture already uses. One query per product, never one per row.
- Read scope; no write; nothing stored. Band and KEV stay Knowledge's: the GUI joins them as it
  does on the release page.

Why not compute it in the browser: the current sweep is one call per release and has no
"first seen" date, and the rule would live in TypeScript where no other consumer can reuse it.

### Discovery health beside posture (owner direction, 2026-11-23)

The owner set (2026-11-23) that **source freshness is per source**, owned by Knowledge, and that
the Overview shows **two separate signals**: *discovery health* (are the sources meeting their
freshness objectives?) and *product security posture* (this record). A product with no new
issues must never read as "all clear" while one of its sources is delayed or unavailable.

For this card that means: the PSIRT table never states coverage, and when any source is not
healthy the card shows "No new issues, but N sources are behind" instead of an empty "all
clear". The freshness model itself (per-source objective, feed-check freshness vs
publication-to-ingestion latency, the latency split source -> Knowledge -> Governance ->
Overview, and the reconciliation contract) is a Knowledge decision and gets its own record.

Measured 2026-11-23 against that direction: `feed_health` keeps per source `last_success_at`,
`last_failure_at`, `consecutive_failures`; the stale threshold is per **tier** (25 h Tier 1,
48 h Tier 2, none for Tier 3/4), not per source; a successful poll with nothing new already
counts as success. The source's own publish or modify time is **not** stored, so
publication-to-ingestion latency cannot be measured yet. Finding `created_at` is stored, so the
Knowledge -> Governance step can be measured for new matches.

## Owner choices

Each choice lists the recommendation first.

1. **Which releases count for a product?** **SETTLED by the owner 2026-11-23: (a).**
   - **(a) Every release of every project of the product (recommended).** Works today. Any
     release still in the field can expose the product.
   - (b) Only releases with a tag the owner picks (for example `in-field`). Uses existing tags;
     someone must keep the tags right.
   - (c) Only the newest release of each project. Needs a Registry change first (release date
     or order is not stored).
2. **How is the product severity made from the releases?** **SETTLED by the owner 2026-11-23: a new option, the ORIGINAL (source) severity.** The product severity is the highest Original (source CVSS Base) severity over the live releases. The Expert score is not the basis. **Assumed until the owner confirms (2026-11-23):** (A) when releases differ, the highest source severity wins; (B) the Expert severity still shows as a small second column. **Open (C):** a "new in product" filter beside "published recently", so an old CVE that reaches the product today is also listed.
   - **(a) Highest severity over the live releases (recommended).** Same max rule as the
     component level.
   - (b) The severity of most releases (majority). Hides a bad outlier release.
   - (c) The severity of the newest release only. Needs choice 1 (c).
3. **Which releases still "affect" the product?** **SETTLED by the owner 2026-11-23: (a).**
   - **(a) All except `not_affected` and fully cleared or scope-only (recommended).** An
     `accepted_risk`, `mitigated` or `deferred` release still counts, because the product still
     ships the flaw; the table shows it as "Decided".
   - (b) Also leave out `accepted_risk` and `mitigated` (the residual view, like
     `residual_priority`). Shows only what nobody has handled yet.
   - (c) Count everything, decided or not.
4. **What does "latest" mean?** **SETTLED by the owner 2026-11-23: (b), published by the world in the last N days.** Needs P1a (publish date kept by Knowledge). A CVE published long ago that first reaches the product today is not "latest" under this rule.
   - **(a) First seen in this product in the last N days (recommended).** From Finding
     `created_at`; no new data.
   - (b) Published by the world in the last N days. Not stored today; would need Knowledge to
     keep the publish date.
   - (c) Changed in the last N days (new release hit, severity change, or decision). Needs a
     "last changed" time per Finding that covers assessment revisions.
5. **No Expert score yet: what shows?** **SETTLED by the owner 2026-11-23: (a).** With choice 2 the source severity is the basis anyway; a release with no source rating is "not scored".
   - **(a) Fall back to the source (Original) severity, marked "source" (recommended).**
   - (b) Show "not scored" and no severity.

6. **How is the issue type shown?** **SETTLED by the owner 2026-11-23: (a).**
   - **(a) A short type word from a fixed CWE table (recommended)**: for example CWE-78/94/502
     -> "Remote code execution", CWE-400/770 -> "Denial of service", CWE-200 -> "Information
     disclosure", CWE-269 -> "Privilege escalation", anything else -> the CWE name. The table is
     in the code with tests, versioned, and the CWE id is always shown beside the word.
   - (b) The CWE id and name only (standard, no Themis mapping).
   - (c) Ask the AI to name the type. Not recommended: the type would be model output.

## Steps (each its own PR, each on the owner's go)

- **P0** this record (docs only).
- **P1a** Knowledge: keep the CVE publish date and CWE ids from the CVE.org and NVD records
  (migration + feed parsing + read). Needs the owner's OK (domain model change).
- **P1** Governance: domain roll-up function + the read(s) + OpenAPI + tests (unit, property:
  the product severity is never below any live row's severity; integration over embedded
  Postgres).
- **P2** GUI: the Overview card, types regenerated from the spec, tests.
- **P3** VM check, written back here as realization notes.

## Not in scope

- A product-level **decision** or override. The product severity is a read; decisions stay per
  Finding, and a wider scope is EDR-SYNC-01's job.
- Customer-facing publication of a product severity (CSAF/VEX mapping is EDR-SCORING-01 O6).
- A Teams or mail alert when a product severity rises (a later step; it would reuse this read).
- Weighting by blast radius or customers. Priority stays EDR-SCORING-01 section 9.1.

## Owner approvals this record asks for (CLAUDE.md "Must ask")

1. **API change:** new Governance read(s) above. Why: no read gives "every CVE of one product";
   alternative (browser sweep) is slow and keeps the rule out of reach of other consumers.
   Impact: read-only, no migration. Files: `api/governance.openapi.yaml`,
   `internal/governance/{domain,app,adapters/http}`, generated handlers, `web/dashboard/src/
   routes/overview.tsx`, `web/dashboard/src/lib/queries.ts`, `web/dashboard/src/types/api/`.
2. **Domain addition:** one new pure function (product roll-up) in Governance's domain. No
   change to the Finding aggregate or to any stored record.
