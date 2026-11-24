# EDR-PSIRT-01 — PSIRT early alert on the Overview: newly published critical and high CVEs per product

Status: **PROPOSED — 2026-11-23, revision 2.** The owner answered choices 1-6 and A-C on 2026-11-23.
The same day the owner approved the Knowledge change, a new read API and this design PR ("let us
see how it performs, if not we will revert"). Revision 2 follows the owner's reframing at 15:43Z
(below). Q1 answered 2026-11-24: (a) name match. P1 built 2026-11-24 (see Realization notes).
Date: 2026-11-23
Author: the design discussion of 2026-11-23 (thread "Add PSIRT product severity view").

## Purpose

The owner's ask (2026-11-23): as part of PSIRT, teams need a page on the Overview that shows **the
latest issues in the world that may hit our products**, each with a severity.

**Revision 2 (owner, 2026-11-23 15:43Z).** The page is an **early alert, the first bucket before
the Themis engine**. It is not a view of Themis's own Findings:

1. It lists CVEs **the world published recently** with a **critical or high original (source)
   score**, including CVEs that Themis has **not yet** filed against any product.
2. It shows **no Themis (Expert) score**. The team assesses after the alert, so a Themis score
   adds nothing here.
3. "Latest" means **latest in the world**. A CVE that a scan brings in is already handled by the
   scanner intake and the Themis engine, so there is no "new in product" view.

Revision 1 rolled up existing Findings per product. That shape is withdrawn: it only shows what
the engine has already filed.

## What Themis has today (measured 2026-11-23, main `6eb71cc`)

1. **A live world read already exists.** `GET /api/v1/faultlines/published-recently?days=N`
   (Knowledge, GUI-16) asks NVD for the CVEs published in the last N days (at most 30). For each
   one it returns the CVE, publish time, summary, severity, score, and whether the estate holds a
   card for it. It stores nothing ("Gathering Is Not Knowing", EDR-KNOWLEDGE-01 D5).
2. **The NVD record behind that read carries the rest.** Each record also has `lastModified`,
   `weaknesses` (CWE ids) and `configurations` (CPE products). Today the read drops all three.
3. **A brand-new NVD record often has no CPE products yet.** NVD's analysis ("Awaiting
   Analysis") can take days. The CNA's CVE.org record usually names the `affected` vendor, product
   and package from day one. Knowledge already reads CVE.org records (`CVEOrgClient`,
   EDR-SCORING-01 S2).
4. **Product components are known.** Evidence keeps the inventory of every release, with
   component names and PURLs. Knowledge already reads it (`adapters/evidence`) for discovery.
   Registry maps each release to its project and product.
5. **Cards do not keep the publish date or the CWE.** That only matters once a CVE enters the
   engine. The alert page reads the world record directly.

## Proposed model

### What one alert row shows (owner, 2026-11-23)

| Column | Comes from |
| --- | --- |
| CVE number | the world record |
| Original score and severity | the source's CVSS Base score (NVD, else the CNA's rating in CVE.org) |
| Issue type | a short word from a fixed CWE table, with the CWE id beside it (choice 6-a) |
| Published / updated | the source's publish time and last-modified time |
| Component | the product component(s) that the CVE's affected names matched (Q1), or "not known" |
| Product(s) | the product(s) that hold the matched component |
| In Themis | whether Themis already has a card or Findings for it, as a link when it does |

The default filter is **critical and high** only and the **last 7 days** (1, 7 and 30 to pick).
Rows sort by score, then newest first. No Themis score appears anywhere on the page.

### Product severity (choices 1-a, 2, A)

When one CVE hits several products, each product row shows the CVE's **original score**. When
sources differ, the **highest** source score wins (A). The page lists world records, not
Findings, so choices 3 and 5 have no effect here. Decisions come after the alert, in the engine.

### Discovery health beside the alert (owner direction, 2026-11-23)

Source health shows as its **own** signal beside the list. When a source is behind, the page says
"No new issues, but N sources are behind" and never shows an empty "all clear". The freshness
model belongs to Knowledge and gets its own record. That covers per-source objectives,
feed-check freshness versus publication-to-ingestion latency, and the reconciliation contract.

Measured 2026-11-23: `feed_health` keeps `last_success_at`, `last_failure_at` and
`consecutive_failures` for each source. The stale threshold is set per **tier** (25 h for Tier 1,
48 h for Tier 2), not per source.

### Q1: how is a world CVE tied to a product before any Finding exists? (SETTLED by the owner 2026-11-24: (a))

- **(a) Name match (recommended).** Match the CVE's affected names against the component names in
  the product's releases, by normalized name, ignoring version. The affected names are NVD's CPE
  products plus the CNA's `affected` vendor, product and package from CVE.org, which covers the
  days before NVD analyses the record. The row says which component matched and on what. Expect
  some false alarms. That is the right direction for an alert: the team assesses next, and the
  engine decides.
- (b) Name match plus version range, where the source gives one. This raises fewer false alarms,
  but a distro backport or a missing range hides a real hit, and doing this well is the Themis
  engine's job.
- (c) No product tie. List every critical or high CVE in the world and let the team filter by
  text. This is simple, but a busy day means hundreds of rows.

With (a), a CVE that matches no product still appears under an **"All world"** tab, so a weak name
match never hides anything critical.

### Backend read (API change, which the owner agreed to on 2026-11-23)

One **Knowledge** read, because Knowledge owns the world feed and already reads the inventory:

```
GET /api/v1/psirt/alerts?days=7&min_severity=high
```

Each row: `cve`, `published`, `modified`, `summary`, `original_score`, `original_severity`,
`score_source`, `cwes`, `issue_type`, `matches` (each with `product_id`, `product_name`,
`component`, `matched_on`), and `carded`.

- **Live and relevance-bounded**, like `published-recently`: nothing from the world feed is stored
  (EDR-KNOWLEDGE-01 D5). An operator's gather stays the one act that creates a card.
- The **CWE table** is a pure domain function in Knowledge (`IssueType`, versioned, 100% coverage
  tier).
- **Product names** come from Registry. This needs a small read client in Knowledge (a new client
  seam), and its release-to-product walk mirrors Governance's `ReleaseProducts`. Component names
  come from the existing Evidence client, cached per poll, never one call per row.
- The same read can later feed a Teams alert ("a new critical CVE may hit product X"). That is a
  later step.

## Steps (each is its own PR, and each waits for the owner's go)

- **P0** This record (docs only).
- **P1** Knowledge: carry `lastModified`, CWE ids and affected names on the live world read; add
  the CWE table; add the CVE.org affected names for records NVD has not analysed yet.
- **P2** Knowledge: product matching (Q1) and `GET /psirt/alerts`, with the Registry client.
- **P3** GUI: the PSIRT card on the Overview: Critical/High, a 1/7/30-day window, a product
  picker, an "All world" tab and the source-health strip.
- **P4** VM check, written back here as realization notes.

## Not in scope

- A Themis score, decision or Position on this page. Those come after the alert, in the engine.
- Storing the world feed. Only matched rows might ever be kept, and only if the owner asks.
- A stored or exported product severity.
- The freshness model and the reconciliation contract. Those go in a separate Knowledge record.

## Owner choices (record)

| # | Choice | Answer (2026-11-23) |
| --- | --- | --- |
| 1 | Which releases count | (a) every release of every project |
| 2 | Severity basis | the **original (source)** severity, not Expert |
| 3 | Which releases still affect | (a), no effect in revision 2 |
| 4 | "Latest" | (b) published by the world |
| 5 | No Expert score | (a), no effect in revision 2 |
| 6 | Issue type | (a) fixed CWE table, with the CWE id shown |
| A | Highest source score wins | yes |
| B | Show the Themis score | **no**: the page is an alert, and the team assesses after it |
| C | "New in product" filter | **no**: scanned CVEs are already in the engine |
| Q1 | Tie a world CVE to a product | (a) name match (2026-11-24) |

## Realization notes

### P1 (2026-11-24, owner "yes" to P1)

- The live world read `GET /faultlines/published-recently` now carries, from the same NVD
  record it already fetched: `modified` (NVD `lastModified`; absent when not stated, never the
  fetch time), `cwes` (normalized, sorted, NVD placeholders dropped), `issue_type` +
  `issue_type_table` (the fixed table, version `1`), and `affected_products` (NVD CPE
  application parts, the same filter as the carrier products, so an OS that bundles a library is
  not named). Still live, still stores nothing.
- The CWE table is `domain.IssueType` in `internal/knowledge/domain/weakness.go`, 100% covered.
  When a CVE has several CWEs the first table row any of them maps to wins (worst type first);
  an unmapped CWE reads "Other". The CWE id is always on the wire beside the word.
- Not in P1, moved to P2: the CVE.org `affected` names for records NVD has not analysed yet.
  They need one CVE.org fetch per fresh critical/high CVE, which belongs behind the alert read's
  own cache, not on every page view of this read.

