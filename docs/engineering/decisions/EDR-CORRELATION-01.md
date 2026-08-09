# EDR-CORRELATION-01 — Advisory scope is not a vulnerability claim (CORR-1)

Status: **Accepted — design decided 2026-08-08** (grounded on measured VM data, not intuition)
Date: 2026-08-08
Author: clean-slate VM verification session (CORR-1 cluster)

## Purpose

Engineering Decision Record for **what a distro advisory's package list means**. A Rocky/RHEL module-stream
advisory covers every RPM built in the stream. Themis currently reads that list as a per-package
vulnerability claim, so a CPython flaw is recorded as a vulnerability of `python3-pyyaml`. This EDR decides
which of those two readings Themis makes, and where the distinction lives.

Ground rule: **ADR/EDR wins; the PoC is reference only.** This EDR is subordinate to EDR-KNOWLEDGE-01
(D3 correlation ownership, D5 relevance bound, D6 one-ACL-per-feed) and to EDR-VEX-01's principle that a
vendor statement is *gathered, not obeyed*. It refines correlation; it does not reopen those.

## What the measurement decided (before intuition)

The first hypothesis was "genuine CVEs name one package, stream artifacts name many". **The data refuted
it**, and recording that here is the point of this section — the obvious filter would have deleted real
vulnerabilities.

| CVE | packages OSV names | NVD | reality |
| --- | --- | --- | --- |
| CVE-2023-24329 (CPython `urllib.parse`) | 62 | 0 | artifact |
| CVE-2020-26137 (urllib3) | 42 | 0 | artifact |
| **CVE-2020-1747 (a real PyYAML CVE)** | **23** | 0 | **genuine — and still names 23** |
| CVE-2017-18342 (real PyYAML CVE) | 1 | 0 | upstream PyPI record, not a distro advisory |

A genuine PyYAML CVE pulls in babel, Cython, mod_wsgi, numpy, scipy and eighteen more, because the advisory
rebuilds the stream. **Breadth does not separate genuine from artifact**, so no threshold on package count
can work. And **NVD names zero packages in every case**, exactly as `VulnFacts.Fixes` documents. There is no
upstream package identity stored anywhere today: this is a **gathering** question before it is a filtering
one.

Scale on one release: of 120 cards, 27 name a single package, ~85 name 23–66, five name 112–113, and
**three name 183**.

## The defect, stated precisely

The mechanism is in `osvACL.Translate`, in a comment that *justifies* it:

```go
// Gather EVERY addressed CVE, not just the first: a distro advisory keys its CVEs in
// `upstream` (id is an RHSA), and one advisory can fix several — a component the advisory
// covers is affected by each until it is patched, so each must be carded.
cves := allCVEs(append(append([]string{rec.ID}, rec.Aliases...), rec.Upstream...)...)
```

Correlation queries OSV **by component**. OSV returns the RLSA covering that component. The ACL cards every
CVE the RLSA addresses. Correlation then records the queried component as matching **all of them**.

**What is NOT wrong — and this correction matters.** The Finding count is right. 120 Faultlines produce 120
Findings, one per CVE, and a release running the superseded `python38` stream genuinely *is* exposed to every
CVE that stream's advisory fixes. An earlier framing of CORR-1 said "one advisory becomes one Finding per
package"; that was wrong and is corrected here.

**What is wrong** is narrower: **each Finding names every package in the advisory as its matched
components.** On one release, 78 of 120 Findings list `PyYAML` as a component — for CVEs in CPython,
urllib3 and lxml. The consequences are all downstream of that attribution:

- `plan_remediation` reports "upgrade PyYAML — closes 78 findings". Upgrading PyYAML closes about four.
- `recommend_position` is grounded on a component list naming PyYAML for a urllib3 CVE — and **Grounding
  Verification will VERIFY it**, because the projection genuinely says so. T8 checks consistency with our
  record, never whether our record is right. This is the limit of any grounding check, not a flaw in T8.
- The per-component fixed-verdict (`FixesFor`) and the range gate operate on packages that were never the
  subject of the CVE.

**It is also the half of A1 that stayed open.** A1 drops a match when a component is *provably out of range*,
failing open on `RangeUndecidable`. For a module-stream advisory the range is decidable and **satisfied** for
every RPM in the stream, so A1 passes them all. A1 asks "is this version affected?"; the missing question is
"is this package the one that carries the flaw?"

## Confirmed live, 2026-08-09

D6 predicted that the AI would cite a package the flaw does not live in, and that Grounding
Verification would verify it. The first successful `recommend_position` invocation did exactly that,
unprompted:

> *"The **CVE-2019-10086** vulnerability affects the **Java packages filesystem** component version
> 5.3.0-2, which is included in the release … CVSS score of 7.3 … it is still recommended to update
> the component to a fixed version as soon as possible."* — confidence **0.95**

`CVE-2019-10086` is **Apache Commons BeanUtils**. `javapackages-filesystem` is a bystander in the
same module rebuild. The recommendation is fluent, internally consistent, correctly scored, and
about the wrong package — and it PASSED the grounding gate, because the projection genuinely lists
that component.

This is the clearest available statement of why D6 restricts the projection rather than tightening
the validator: **there is no gate that catches a well-formed wrong premise.** The model reasoned
faithfully from what it was given. Fixing the reasoning is impossible; fixing what it is given is
the whole remedy.

## Decisions

### D1 — A distro advisory's package list is SCOPE, not N vulnerability claims

An RLSA/RHSA says: *these builds are superseded; the replacement fixes these CVEs.* It does not say each
listed package contains each flaw. Reading the list as N independent assertions is obeying the vendor in a
shape it never made — the direct application of EDR-VEX-01's **"gathering is not knowing"**.

**Alternative rejected — status quo ("a component in a superseded stream is affected").** It is not *false*:
the old `python3-pyyaml` build does need replacing. But it answers a packaging question with a vulnerability
verb, and every consumer downstream reads the verb.

### D2 — The matches are KEPT. Nothing is dropped

The work is real: an old build inside a superseded stream must be updated. Dropping the match would delete
a true obligation, and — per the measurement above — no available discriminator can tell which to drop
without also deleting genuine findings. **Correlation stays fail-open**, consistent with A1.

**This is the decision that keeps the change safe.** Every option that reduces the record was rejected.

### D3 — A matched component carries a CLAIM CLASS: `carrier` | `scope` | `unknown`

The distinction is recorded, not resolved by deletion.

- **`carrier`** — evidence says this package carries the flaw.
- **`scope`** — this package was in the advisory's rebuild set, with no evidence it carries the flaw.
- **`unknown`** — no attribution evidence available.

`unknown` is **treated as `carrier` by every consumer**. A gap in evidence must never hide a live
vulnerability; the same fail-safe direction as A1's `RangeUndecidable` and D2.

**Alternative rejected — a boolean `is_scope`.** Two states cannot distinguish "we know it is scope" from
"we do not know", and that difference is exactly what decides whether a consumer may act on it.

### D4 — The discriminator is UPSTREAM product identity, and NVD's CPE is the source

A distro record cannot answer this: OSV's RLSA entry carries no CVE→package mapping *within* the advisory.
The answer has to come from a source that describes the flaw rather than the shipment.

**NVD CPE configurations are that source, and Themis already parses them.** `cpeProduct()` and
`nvdConfigsMatchProduct()` exist in `nvd_client.go`, built for the A2 discovery gate — they extract the
product and then **discard it**. D4 persists it: the per-CVE NVD backfill (D5a) already fetches each carded
CVE, so this adds a field, not a feed.

Secondary source: an OSV record whose ecosystem is **not** a distro (PyPI, npm, Go…) names the true package
directly — that is why `CVE-2017-18342` returned exactly one.

**Alternative rejected — pattern-matching `.module+el` on the fix version.** It detects a *module build*, not
a *flaw carrier*, so it cannot tell `python3-libs` from `python3-pyyaml` inside the same stream. It is also
RPM-specific, where the problem is not.

**Consequence to accept honestly:** NVD's CPE product names upstream projects (`python`, `urllib3`), while
components are distro packages (`python3-libs`, `python3-urllib3`). D4 requires a normalization seam, and it
will be imperfect. That is why D3 has an `unknown` state and why D2 keeps everything.

### D5 — Classification happens in Knowledge, at correlation time

EDR-KNOWLEDGE-01 D3 gives correlation to Knowledge. The class is a fact about the *match*, so it is decided
where the match is made and rides `ComponentMatched` to Governance, alongside `Source`, `Priority` and
`Fixes`.

**Alternative rejected — deriving it in Governance or in the Intelligence runtime.** Either would need a
second copy of the attribution policy, and two copies of a policy eventually disagree — the same reasoning
that put trust classes on the wire in EDR-TRUST-01 rather than re-deriving them downstream.

### D5a — Classification is REVISITED when carrier attribution arrives late

D5 puts classification at correlation. That is where the match is made — but not where the
evidence lands. NVD enriches on its own cadence (`THEMIS_NVD_STALE_AFTER`, default 168h), so on a
fresh card the sequence is: correlate (no carriers → `unknown`), then enrich (carriers arrive).
Nothing revisited the classes already stamped.

**Measured on the VM the day this shipped: 370 components, every one `unknown`, while the cards
were being enriched around them.** On a stable estate no new correlation ever runs, so the class
stamped at match time is the class forever — step 2 would have shipped inert.

Knowledge therefore **re-announces** a card's recorded matches when its carrier products go from
empty to non-empty: `MatchesForFaultline` lists the occurrences, each is re-classified, and a
`ComponentMatched` is emitted per occurrence.

- Scoped to the **empty→non-empty transition**, so it fires once per card rather than on every
  enrichment.
- Idempotent downstream: re-delivering a match adds no component, and Governance's upsert only
  overwrites a class with a **non-empty** one — an `unknown` can never erase a decided class.
- Classification stays in Knowledge (D5 intact). Governance receives a verdict, never a policy.

**This is the third appearance of one shape** — BUG-3 (`base_score`), BUG-3b (`band`/`fixes`), and
now the claim class. A derived value written at one event, whose inputs arrive at another, is
stale forever unless something revisits it. The question to ask of any new derived field is not
"where is it computed?" but **"what happens if its inputs arrive later?"**

### D6 — Consumers use `carrier` for ACTION and the full set for OBLIGATION

- **`plan_remediation`** groups by carrier. "Upgrade PyYAML — closes 78" becomes "update the `python38`
  module stream — closes 62" plus "upgrade PyYAML — closes 4".
- **The AI's grounding projection** carries carriers only. A recommendation must not be able to cite a
  package the flaw does not live in — the defect that Grounding Verification structurally cannot catch.
- **The posture** keeps every component, with the class visible. The obligation to update those builds is
  real and stays on the record.

### D7 — The Finding count does not change

One Finding per (Release, Faultline) is unchanged (EDR-GOVERNANCE-01 D1). 120 CVEs remain 120 Findings.
This EDR changes **which components a Finding names as its reason**, not how many Findings exist.

Recorded explicitly because the original CORR-1 write-up claimed otherwise, and a reader arriving at the
code expecting the count to drop would conclude the change had failed.

### D8 — Rollout is two ordered steps, and step 1 ships without new data

1. **Scope-faithful grouping (no new gathering).** The stream id is already on the fix version
   (`python38:3.8-8030020200818121840.4190259b`, `.module+el8.4.0+570+…`). Group a plan step by stream, so
   the headline becomes actionable immediately. Note `mergeSiblings`'s own comment says it could not do this
   because "the posture deliberately does not carry [the fix version] yet" — **PLAN-3/DASH-2 means it carries
   it now**, so the premise that forced the CVE-set heuristic has expired.
2. **Flaw-faithful attribution (D3/D4).** Persist the CPE product, classify matches, and switch the plan and
   the AI projection to carriers.

Step 1 is presentation and reversible. Step 2 changes a fact on the wire and is additive/omitempty per
EVENTBUS D9.

## Consequences

- **Wire:** `ComponentMatched.Components[].ClaimClass` and `FaultlineEnriched` gain an optional field;
  additive + omitempty, so an older payload reads `unknown` — which every consumer treats as `carrier`, i.e.
  exactly today's behaviour. **The migration is a no-op by construction.**
- **Storage:** a `claim_class` column on `finding_components` and `faultline_matches`; a `carrier_products`
  fact on the card from NVD.
- **What gets better:** the plan becomes actionable; the AI stops being grounded on packages that do not
  carry the flaw; "which of these is actually a PyYAML problem" becomes answerable.
- **What does not:** the Finding count, deliberately (D7). And any CVE with no NVD CPE data stays `unknown`
  and behaves exactly as it does today.

## What this EDR does NOT decide

- **Whether a `scope` match should ever auto-suppress.** It must not, under this EDR: that is a governed
  decision and belongs to EDR-GOVERNANCE-01's authority line. `scope` is a *label*, never a suppression.
- **The upstream→distro package normalization table.** D4 requires one; its construction (heuristic,
  curated, or feed-provided) is an implementation decision, and its failure mode is bounded by `unknown`.
- **GOV-15** (the blast multiplier saturating triage order). Adjacent — both attach a container's attribute
  to each member — but a separate decision.

## Traceability

- **CORR-1** — `docs/BACKLOG.md`, with the measured tables reproduced above.
- **A1 / A2** — `EDR-KNOWLEDGE-01` realization notes (2026-07-31); this closes the half A1 left open.
- **KN-FIX-1** — the same root instinct one level down: a fix version must name its package. CORR-1 is that
  question asked of the *match* rather than the *fix*.
- **EDR-VEX-01** — "gathering is not knowing"; D1 is its direct application to advisory scope.
- **EDR-TRUST-01 T8/T10** — why grounding cannot catch this, and why the class must ride the wire rather
  than be re-derived.
- **PLAN-4 / PLAN-5 / PLAN-6** — plan defects that were real but downstream of this premise.
