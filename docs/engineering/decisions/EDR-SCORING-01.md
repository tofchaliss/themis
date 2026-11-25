# EDR-SCORING-01 — Layered CVSS: source ratings, per-component assessment, provisional scores

Status: **ACCEPTED — 2026-11-21 (owner merged PR #229).** Domain model accepted by the owner on 2026-11-19 after review rounds v1 to v4.9.7
(decision of 2026-11-19: selection details and ingestion details SETTLED, O1-O7 closed, lifecycle and
integration items left OPEN for this record, section 10.3). S1 built 2026-11-21 (kernel calculator). S2 built 2026-11-21 (Knowledge source truth; realization notes in 12.1). S3 built 2026-11-21 (Registry requirements; 12.2). S4 built 2026-11-21 (Governance assessment in shadow; 12.3). S5 built 2026-11-21 (read-only GUI: the Finding drawer's "How Themis got this score" panel and the CVE page's source ratings, one row per assessment; VM check pending). Owner-set severity (section 7.1, OS1-OS6) PROPOSED 2026-11-25: the first part of S6, design only.
Date: 2026-11-20
Author: the CVSS scoring design discussion of 2026-11-17 to 2026-11-19.

## Purpose

Engineering Decision Record for **how Themis scores a vulnerability with CVSS**, so that the score a
person sees matches what CVE.org (the CNA) and the platform vendor published for THAT component,
can be changed by an authorised person (by changing the vector, never by typing a number), and
explains itself ("how Themis got this score").

Today (section 1) Themis keeps one CVSS headline per CVE for the whole estate (precedence
`redhat > nvd > osv`), applies a vendor's score to every component, does not read CVE.org, computes
only the 3.x Base score, and has no temporal, environmental, override or release requirement inputs.

This record replaces that with three separate truths (what each source published; what Themis
calculates for one component of one Finding; what a person governed), a per-component assessment
inside the existing Finding aggregate, a class-first source selection with explicit `contested` /
`unresolved` outcomes and conservative provisional scores, and a Finding roll-up equal to the
highest Environmental score among eligible, open components. CVSS stays separate from Themis
priority: the first release runs in **shadow** (computed and shown, not used by priority or SLA).

Amends EDR-KNOWLEDGE-01 (source observations, publications, rating events and validations sit beside
today's Proposals; the single headline stays for old readers). Depends on EV-CURRENT-SBOM-1,
EDR-CORRELATION-01, EDR-VERDICT-01, EDR-SYNC-01 and the GUI users-and-roles item (section 10.1).

Decision ids: Q1-Q3, Part A, B1-B5 and D1-D28 are the decisions of the design rounds; each rule below
carries its label. "Owner vX review" in the audit (section 13) names the review round that settled it.

How to read this document. Every rule carries one of five labels:

| Label | Meaning |
| --- | --- |
| **SETTLED** | explicitly confirmed by the owner in review; goes into EDR-SCORING-01 as written |
| **PROPOSED** | raised in review and sound, but not yet explicitly confirmed. **None remain** since the owner's decision of 2026-11-19 13:06 (section 13) |
| **FACT** | how the code works today, with the file it was read from (main 970fd8a) |
| **DEPENDS** | needs another EDR or backlog item; its future behaviour is NOT assumed here |
| **OPEN** | not decided; listed in section 10 |

---

## 1. Existing implementation facts

These facts were read from main 970fd8a and are **migration inputs**. They are tied to that commit and its files, and the domain-model reviews did not verify them. Re-check each one against the code before the build step that relies on it.

| # | Fact | Where |
| --- | --- | --- |
| F1 | A Finding is keyed by (Release, Faultline); the CVE is an alias. | `internal/governance/domain/finding.go` `NewFinding` |
| F2 | Components are content of the Finding, many per Finding, keyed by PURL. | `finding.go` `components`; `finding_components` PK `(finding_id, purl)` in `internal/governance/adapters/store/migrations/000001_governance.up.sql` |
| F3 | Adding a component appends it and bumps the version; it never changes stage or Position. | `finding.go` `AbsorbComponent` |
| F4 | Membership only grows. Nothing removes a component when a newer SBOM arrives. | `AbsorbComponent`; no delete path in Governance |
| F5 | Claim class: `carrier`, `scope`, empty = unknown. `ActsAsCarrier()` = class is not `scope`. Unknown clears a recorded `scope` on re-delivery (safety-monotone). | `internal/governance/domain/component.go:68`; `finding.go` `AbsorbComponent`; EDR-CORRELATION-01 |
| F6 | Occurrence verdict per component: `VerdictState` (`open`, `cleared_vendor_fix`), `VerdictGrade` (`observed`, `inferred`), `VerdictReason`. Anything not an affirmative clearance is open. Decided by Knowledge. | `component.go:42`, `:58`; `internal/knowledge/domain/verdict.go`; EDR-VERDICT-01 |
| F7 | Positions are per Finding, versioned, append-only. | `internal/governance/domain/position.go` |
| F8 | Knowledge keeps one headline CVSS per CVE, picked by fixed order `redhat > nvd > osv`, others last. | `internal/knowledge/adapters/wiring/wiring.go:249`; `internal/knowledge/domain/reconcile.go` |
| F9 | Per-source Proposals are kept (append-only); a verbatim restatement is dropped. | `internal/knowledge/domain/proposal.go` (~line 211) |
| F10 | NVD: one rating kept per CVE (v3.1 > v3.0 > v4.0 > v2; Primary over Secondary). The metric's `source` (assessor) field is not read. | `internal/knowledge/adapters/feed/nvd_client.go` `nvdMetric`, `extractNVDCVSS` |
| F11 | Red Hat: a score record is emitted only when `cvss3` is present. If Red Hat later drops it, the old record keeps winning. `observed_at` = fetch time. | `internal/knowledge/adapters/feed/redhat_client.go:140` |
| F12 | Rocky and Alpine feeds give fix bounds only, no score. | `rocky_client.go`, `alpine_client.go` (`SeverityUnknown`) |
| F13 | CVE.org (CNA, CISA ADP) is not read. | none |
| F14 | Only the CVSS 3.x **base** score is computed; temporal and environmental metrics are ignored. | `internal/kernel/value/cvss.go` `BaseScoreFromVector` |
| F15 | No score override; no CR/IR/AR anywhere. | Knowledge and Governance APIs; Registry domain |
| F16 | Priority 0-100 is built from the severity word (90/70/40/10) + EPSS + KEV; Governance copies it to `base_score`; SLA buckets and Jira/Teams counts use it. | `internal/knowledge/domain/priority.go`; `internal/governance/domain/sla.go`, `release_evaluation.go` |
| F17 | GUI users have no roles; API keys have `admin`, `read`, `product:<id>`. | `internal/dashboard/migrations/000001_dashboard_users.up.sql`; `internal/platform/auth/auth.go` |
| F18 | Registry Microservice links to a Product only. | `internal/registry/domain/microservice.go` |
| F19 | The all-scope case already has a distinct AI outcome (`no_subject`, vs `no_grounding`). | `internal/intelligence/domain/grounding.go` |

---

## 2. Model overview (SETTLED)

Three truths, never mixed:

| Truth | Owner | What |
| --- | --- | --- |
| Source truth | Knowledge | what each source published (observations and ratings) |
| Calculated assessment | Governance | what Themis computes for one component in one Finding |
| Governed assessment | Governance | what an authorised person changed, with reason |

Four dimensions on each component, never mixed:

| Dimension | Existing concept | Purpose |
| --- | --- | --- |
| Eligibility | claim class (F5) | can the component contribute to the roll-up |
| Applicability | occurrence verdict (F6) | is the occurrence still active for scoring |
| Assessment | ComponentAssessment (new) | source selection, vectors, scores, inputs, provenance |
| Governance | Finding Position (F7) | an authorised decision about the whole Finding |

```
Knowledge: CVE card
  SourceObservation (immutable source revision)
     + SourceObservationSeenEvent[]   (append-only fetches)
     --has--> SourceRating[]          (immutable, ONE PER PUBLICATION, with its own applicability context)
                + SourceRatingEvent[] (append-only lifecycle of each publication: superseded | withdrawn)
                + RatingValidation[]  (derived, Knowledge-owned: validation of each publication per calculator version)
  AssessmentIdentity                  (links equivalent publications: assessor x version x vector x context)
        | read API only
        v
Governance: Finding (Release, CVE)                         identity unchanged (F1)
  lifecycle + Proposals + Positions                         unchanged (F7)
  components[PURL]  claim class (F5), verdict (F6)          from Knowledge / Evidence
  componentAssessments[PURL]  revisions (immutable)
       source selection -> rating selection -> metrics -> scores
       governed changes (3 kinds)
  rollUp revisions: state + score + contributors + coverage
        v
  priority / SLA / exports   (shadow first: R-P3 SETTLED, R-P4 OPEN for EDR-SCORING-01)

Registry: CR / IR / AR on Product > Project > Release
Evidence: current membership (DEPENDS EV-CURRENT-SBOM-1)
```

---

## 3. Source truth (Knowledge)

### 3.1 Observation and rating (SETTLED Q1)

**SourceObservation** = one source revision as Themis received it.

| Field | Note |
| --- | --- |
| source, document reference | e.g. Red Hat CVE document, CVE.org record, NVD CVE |
| source revision | the source's own revision id or update count, when present |
| source updated at | the source's own modified date (NVD lastModified, CVE.org dateUpdated, Red Hat document date), kept as **three values** (SETTLED 2026-11-19, owner v4.9.4 review): (1) the **original** value exactly as received; (2) the **normalised UTC instant**, when an interpretation is valid; (3) **interpretation metadata**: `zone_stated`, `zone_assumed_utc` (the ingestion contract read a zone-less value as UTC), or `unparseable` (no instant; treated as missing). The normalised value is never presented as the source's own assertion. The interpretation rule is part of the feed adapter's ingestion contract and versioned with it |
| content fingerprint | when the source has no revision id; hashed over a **canonical form** (parsed fields that carry meaning, sorted keys, normalised whitespace and dates; transport and formatting noise removed), so a reformatted but identical document is not a new revision |
| completeness | complete parsed revision vs not (see 3.4) |
| observation applicability | the overall products / packages the document describes. Used for discovery and display. Never used **on its own** to select or reject a rating: it reaches selection only as the **inherited context** of a publication that states none (SETTLED D12) |
| first observed at | when Themis first received this revision |

A SourceObservation is **immutable**. Fetches are recorded separately:

**SourceObservationSeenEvent** (append-only): fetched at, fetch outcome (success / not_modified / http error / timeout / parse failure / incomplete), feed metadata (endpoint, HTTP status, ETag or last-modified when given), and the observation it confirmed (when the outcome was a success on an unchanged revision).

An unchanged document produces a new SeenEvent only: no new SourceObservation, no SourceRating, no assessment revision, no recalculation (R-S7). A failed fetch produces a SeenEvent with its failure outcome and nothing else (feeds feed-health, see 3.4 item 3). This keeps three times apart: the source's own update time, Themis's first observation, and every later fetch.

**SourceRating** = one CVSS assessment inside an observation.

| Field | Note |
| --- | --- |
| asserted context | the product / package / ecosystem / distro family **this publication itself** states the rating is for; may be empty (= unstated) |
| inherited context | the observation's applicability, copied when the asserted context is empty; marked `inherited` |
| effective context | asserted if present, else inherited; used for component applicability and selection class (4.1), **never** for identity |
| assessor | who produced it (CNA org, NVD, vendor) |
| publisher | where it was published (CVE.org, NVD, vendor site) |
| feed | how Themis collected it |
| NVD type | Primary / Secondary, when from NVD |
| CVSS version | 2.0 / 3.0 / 3.1 / 4.0, all kept |
| raw vector, stated score | as received |
| severity word + normalised band | "Important" + "High" |

A SourceRating is **immutable**: nothing on it ever changes after it is recorded. Its lifecycle is kept separately:

**SourceRatingEvent** (append-only): `superseded` or `withdrawn`, with the source revision that caused it, the source's time, and the time Themis learned it.

**Current status** of a rating (active / superseded / withdrawn) is **derived** from the rating plus its events (rules in 3.4), never stored on the rating.

A SourceRating holds **only what the source published**. Anything Themis computes from it lives in a RatingValidation (3.5). This lets Themis answer both "what did the source publish, and when" and "when did we learn it was withdrawn".

### 3.2 Linking the same assessment seen twice (SETTLED Q2)

Two layers:

**Three contexts per publication (SETTLED 2026-11-19):**

| Context | Meaning | Used for |
| --- | --- | --- |
| asserted | what the assessor or this publication itself states the rating is for; may be empty | identity |
| inherited | the observation's broader applicability, copied when asserted is empty | filtering only |
| effective | asserted if present, else inherited | filtering, selection class |

**D12 (SETTLED):** the only path from observation applicability into selection is: observation applicability -> inherited context of a publication with no asserted context -> that publication's effective context -> applicability (4.1 step 2) and class (step 3). A publication that asserts a context never uses the observation's applicability, even when the observation covers more.

Contexts are normalised before any comparison. Normalisation is **policy-versioned** (part of the linking / class policy version), and the examples below are **examples, not universal rules**. A normalisation rule must never merge distinct packages or ecosystems; when in doubt, two contexts stay distinct (owner v4.9 review). Examples: ecosystem canonicalised (`value.CanonicalEcosystem`), package names lower-cased, CPE products reduced to vendor:product, distro families mapped (rhel / rocky / alma -> one family where the policy says so).

**Assessment identity (SETTLED 2026-11-19)** = assessor + CVSS version + normalised vector + **asserted** context (empty counts as "unstated", not as a value).

**Linking rule:**

| Publication X vs Y (same assessor, version, vector) | Result |
| --- | --- |
| both asserted, equal | same identity |
| both asserted, different | **two identities** (a rating stated for two products stays two assessments) |
| X asserted, Y unstated, and X's is the **only** identity of that assessor + version + vector for this CVE | Y links to X's identity |
| X asserted, Y unstated, and the assessor has **several** identities with that vector for this CVE | Y is **not** linked; it keeps its own identity, flagged `ambiguous_link` |
| both unstated | same identity |

- **Publication** = one SourceRating, i.e. that assessment as carried by one observation. Each publication has its own lifecycle (3.4) and its own effective context.

| Case | Treatment |
| --- | --- |
| same assessment identity, several publications | one assessment, several publications; GUI shows one row ("CNA 7.5, also in NVD as Secondary") |
| same assessor, different vector, same asserted context | kept separately, flagged `self_inconsistent` for reconciliation (one copy is stale); in selection it is treated like `contested` (4.1a) |
| different assessor | independent assessment |

Why this resolves the v4.3 example: the vendor document asserts a package context; the NVD Secondary copy asserts none. Same assessor, version and vector, and the vendor has one identity with that vector, so the NVD copy **links** (same assessment, Q2). Its **effective** context is the inherited NVD one, so for a given component it can land in a different selection class (4.1). One assessment, two publications, two possibly different classes: identity is about who said what; class is about how it applies here.

Original publication and observation references are kept even when linked. Note: a vendor can also be the CNA for a CVE; the same rule prevents counting it twice.

### 3.2a Identity linking over time (D6, D11 SETTLED; the rest SETTLED 2026-11-19)

Publications arrive in any order, so links are not decided once at arrival.

1. **Deterministic:** the identity grouping is a pure function of the **set** of publications for one CVE + assessor + version + normalised vector, and the linking-policy version. Same set -> same grouping, whatever the arrival order.
2. **Re-evaluation:** the grouping of a set is recomputed when a publication is added to it, when one becomes terminal, **and when the linking-policy version changes** (then every set the policy affects is recomputed, with or without new publications; SETTLED D6).
3. **AssessmentLink** (append-only, SETTLED D6): each event records the **complete grouping** of the affected set (every publication and the identity it belongs to, including `ambiguous_link` members), plus the change against the previous grouping (`linked`, `unlinked`, `marked_ambiguous`, `ambiguity_resolved`) for readability, the linking-policy version, the cause and time. The current grouping is the latest event's grouping, so any past grouping is read directly, never replayed from pairwise edits. A SourceRating is never modified by linking.
4. Example, both orders give the same result:
   - Order A: vendor publication (asserted package) arrives, then the NVD copy (unstated) -> `linked`.
   - Order B: NVD copy arrives first (own identity), then the vendor publication -> recompute -> `linked`. The NVD copy now belongs to the vendor identity.
5. **Viability (SETTLED D11):** a candidate identity stays a viable link target while it still has **at least one active publication** whose asserted context supports it under the linking policy. A publication becoming terminal removes that publication, not the identity. A linking-policy change recomputes **viability** as well as grouping (D6).
   - `ambiguous_link` resolves (`ambiguity_resolved` + `linked`) only when the recomputation leaves **exactly one** viable candidate identity.
   - Example: identity A has publications A1 and A2, identity B has B1; an unstated NVD copy is ambiguous between A and B. A1 is withdrawn, A2 stays active: A is still viable, the NVD copy **stays ambiguous**. Only when A2 is also terminal does it link to B.
   - The reverse (a second viable identity appears) -> `unlinked` + `marked_ambiguous`.
6. A change of grouping is a `identity_relinked` trigger for affected ComponentAssessments (8.2); earlier revisions keep the grouping they used.

### 3.3 Requirements

- **R-S1** Every observation and rating immutable; never deleted.
- **R-S2** Fields as in 3.1.
- **R-S3** Stated vs computed score both kept; mismatch flagged; source never "fixed". The stated score is on the SourceRating; the computed score and mismatch are on a RatingValidation (3.5).
- **R-S4** Keep NVD Secondary (CNA) ratings; read the NVD `source` field (F10); add a CVE.org feed (CNA + CISA ADP).
- **R-S5** Separate "source updated at" from "seen at".
- **R-S6** Keep assessor, publisher and feed separate; link reproduced assessments (3.2).
- **R-S7** Repeated polling of an unchanged revision creates nothing new.
- **R-S8** Many ratings per observation (versions, assessors).
- **R-S9** Rating immutable; lifecycle in append-only SourceRatingEvent; status derived (3.1).
- **R-S10** Assessment identity vs publication (3.2); withdrawal is per publication (3.4).
- **R-S11** SourceObservation immutable; fetches in append-only SourceObservationSeenEvent (3.1).
- **R-S12** One terminal lifecycle outcome per publication (3.4).
- **R-S13** Source data and Themis validation are separate records; a validation is reproducible from the rating and the calculator version (3.5).

### 3.4 Withdrawal and correction (SETTLED: B3 rules, plus the event model accepted in the v4.1-v4.4 reviews)

1. Nothing is deleted. A withdrawn **publication** stays visible and is never selectable again.
2. A successfully fetched, parsed and **complete** new revision that no longer carries a rating records a `withdrawn` SourceRatingEvent for **that publication only**.
2a. Other publications of the same assessment identity are untouched. Example: Red Hat removes its CNA rating from a complete document revision, NVD still carries the same CNA rating as Secondary. The Red Hat publication is withdrawn; the NVD publication stays active; the assessment stays selectable **through the NVD publication**, in the CNA layer (the vendor layer now has no active rating for it).
2b. Selection only ever uses an **active, applicable publication**.
3. Fetch failure, 404, timeout, parse failure or incomplete document is a feed-health event only. It never changes rating state.
4. An explicit withdrawal marker from the source withdraws the rating.
5. A correction is a new SourceRating in the same lineage plus a `superseded` event on the old publication; the old vector and score stay.
5a. **Lifecycle rules for one publication:**
   - `superseded`: in a complete new revision of the same source document, the old rating is absent **and** a rating with the same lineage (same assessor, CVSS version and **asserted** context; unstated counts as a value of its own here) is present with different content. The new rating is its replacement.
   - `withdrawn`: in a complete new revision, the old rating is absent **and** no rating of the same lineage is present; or the source gives an explicit withdrawal marker.
   - A publication has **at most one** terminal event. Once `superseded` or `withdrawn`, later observations that confirm it is still absent create **no** further event.
   - the owner's sequence: A published, then a complete revision carries B in A's lineage and not A: A is `superseded` (by B). A later complete revision without A: no event (A is already terminal).
   - If a source later republishes content identical to a terminal rating, that is a **new publication** (new SourceRating, linked to the same assessment identity per 3.2). The old terminal event stands.
   - Current status: no terminal event = active; otherwise the terminal event's kind.
6. A rejected CVE (REJECTED state) is a card-level Knowledge event (existing `Superseded` stage), outside this EDR.
7. Consequence for ingestion: each feed adapter must report "complete revision" separately from "fetch succeeded". F11 is the first case to fix.

### 3.5 RatingValidation (derived; split SETTLED 2026-11-19, owner SETTLED)

What Themis computes about one source rating, independent of any Finding or component:

| Field | Note |
| --- | --- |
| rating reference | the SourceRating (publication) validated |
| calculator version, CVSS spec version | as in R-C6 |
| result | `valid` / `invalid_vector` (with reason) / `unsupported_cvss_version` |
| computed Base, Temporal scores | Base always; Temporal only from metrics the source itself put in its vector |
| stated vs computed | equal / differs (with both values) |
| validated at | time |

1. Immutable; a new calculator version creates a new RatingValidation, never edits the old one.
2. Reproducible from the rating plus the calculator version.
3. Not part of ComponentAssessment. A ComponentAssessment **references** the RatingValidation it used and then does its own component-specific calculation (temporal from evidence, environmental from requirements).
4. Owner (SETTLED by the owner, O10): **Knowledge**, as a derived, immutable, rebuildable record, calculated with the shared kernel. Governance reads it through Knowledge's read API and never owns or modifies it. ComponentAssessment stays responsible for component-specific Temporal and Environmental calculation.

---

## 4. Selection and calculation (Governance + kernel)

### 4.1 Selection hierarchy (principles SETTLED in Q3 / R-L1..R-L6; algorithm and class table SETTLED 2026-11-19)

Runs per ComponentAssessment. Every candidate gets exactly one **disposition** and, where 4.1b requires it, one **reason**. The disposition names in the steps below are the canonical ones of 4.1b.

**Step 1. Candidates.** All publications of the CVE. Not `active` (3.4) -> `rejected`, reason `inactive`.

**Step 2. Applicability** from the publication's **effective** context (D12) against the component (PURL ecosystem, distro family from the purl qualifiers, package / source package):

| Outcome | Meaning | Next |
| --- | --- | --- |
| `applies` | context covers the component | continues |
| `does_not_apply` | context names a different ecosystem / family / package | `rejected`, reason `does_not_apply` |
| `unresolved` | context too broad or missing to decide (e.g. a bare CPE product with no ecosystem mapping) | kept as **unresolved candidate** (disposition `unresolved`), never selected |

**Step 3. Selection class** per (publication, component), from the class policy table. Every active publication is classed **on its own**, with its own effective context, even when it is linked to others (SETTLED D1):

| Class | Assigned when |
| --- | --- |
| `vendor_platform` | assessor = the vendor of the component's platform (vendor map below) **and** effective context names that platform or package |
| `cna` | assessor = the CNA of the CVE (CNA source below), and `vendor_platform` does not apply |
| `adp` | assessor = CISA ADP |
| `nvd_analyst` | assessor = NVD (a Primary rating authored by NVD) |
| `other_assessor` | assessor known but none of the above (e.g. an advisory database such as a language-ecosystem advisory DB, or a distro that is not this component's platform) |
| `unattributed` | assessor unknown (e.g. a scanner report or OSV record that does not say who scored it) |

Rules:
1. **A feed or aggregator never sets the class.** A CNA vector found in an OSV record is `cna`; a vector a scanner copied from NVD is `nvd_analyst` if the scanner says so, otherwise `unattributed`. OSV, scanners and similar are recorded as **publisher / feed**, not assessor. (`osv_derived` and `scanner` classes from v4.3 are removed.)
2. A score Themis computes from a vector is never a rating; it is a RatingValidation (3.5).
3. **Class basis** recorded with each assignment, e.g. "assessor org X = CNA per CVE record revision N" or "assessor org Y = vendor of family rhel per vendor map v3".
4. **Class policy version** recorded; a change of the table or the maps is a `selection_policy_changed` trigger (8.2).

**Where the relationships come from (SETTLED 2026-11-19):**

| Relationship | Authoritative source | Versioning | When unknown |
| --- | --- | --- | --- |
| CNA of a CVE | the CVE.org record's assigner org (part of a SourceObservation) | follows that observation's revision | no rating gets `cna`; ratings by that assessor fall to `other_assessor`; when the CNA becomes known, classes are recomputed (trigger `classification_changed`) |
| vendor of a platform | the **vendor map**: a small policy table distro family -> assessor org ids (e.g. family rhel -> that vendor's org id; family alpine -> Alpine) | part of the class policy version | no rating gets `vendor_platform` for that platform; nothing is guessed from names |
| assessor org identity | the org id stated by the publication (CVE.org org id, NVD `source`, vendor document) | per publication | assessor unknown -> `unattributed` |

**Step 4. Deciding class.** Take the highest class, in order `vendor_platform`, `cna`, `adp`, `nvd_analyst`, `other_assessor`, `unattributed`, that has at least one **applicable** (any CVSS version) or **unresolved** candidate. This is the **deciding class**. It is fixed here: capability filtering in step 5 never moves it lower (D2).
- Candidates in **lower** classes do not affect the outcome. Applicable supported ones are `available_not_selected`; unresolved ones are `unresolved`, reason `lower_class`; unsupported ones are `available_not_compared`. Whatever conflicts they have are recorded on them, never as conditions (4.1a rule 6).
- Whether the deciding class ends `selected`, `contested` or `unresolved` is decided **after** step 5 (step 5a, D13).

**Step 5. Version, inside the same assessor.** Within the deciding class, for each assessor that has identities in both a supported version and an unsupported one (4.0, 2.0), keep the supported ones and set the unsupported ones aside (`available_not_compared`, reason `unsupported_same_assessor`). This runs **before** identity competition, so a newer 4.0 identity never beats an older 3.1 one from the same assessor. Among supported versions of one assessor, 3.1 is preferred over 3.0. That is a **supported-version preference**, not recency: publication dates never order versions, and recency between publications applies only in step 7.

**Lower supported version (SETTLED D27 principle; reason name SETTLED 2026-11-19).** When the same assessor has applicable, calculable 3.1 and 3.0 identities in the deciding class, the 3.1 ones take precedence. Each 3.0 identity then:
- has identity role `not_selected`. This sits beside publication-level dispositions that can differ (for example `unresolved`), **on purpose** (D19, D26): the identity is out of competition, while each publication's applicability stays what it is;
- **publication level (SETTLED principle, owner v4.9.5 review):** its **applicable, calculable** publications in the deciding class get disposition `not_selected`, reason `lower_supported_version`. Its other publications keep their own dispositions: `available_not_compared` (`invalid_vector` / unsupported), `rejected` (`inactive` / `does_not_apply`), or a disposition in another class (4.1b rule 1). An **unresolved** publication of that identity, or of any other 3.0 identity of the same assessor, stays `unresolved`, with reason `lower_supported_version_unresolved` (name SETTLED 2026-11-19). It sets no `same_class_unresolved`, because even if it applied, D27 would set it aside in favour of the applicable 3.1 identity. This is a rule of D27 itself, not D14;
- is kept in provenance but takes **no part** in identity competition (step 6);
- never creates disagreement, even when its vector differs from the 3.1 one, never sets a condition, and never adds to any provisional maximum (contribution none).
The preference is only between versions of **one** assessor. A 3.0-only assessor still competes normally with another assessor's 3.1 rating.

**D27 boundary (competition rule only; SETTLED principle).** The version preference decides only which of one assessor's applicable, calculable identities takes part in step 6. It never:
- makes an invalid 3.0 vector valid, converts a vector between versions, or re-scores anything (validation stays in RatingValidation, 3.5);
- changes an unresolved publication into anything but `unresolved` (only the explicit rule above gives its reason);
- suppresses, outranks or affects an **independent** assessor's rating;
- overrides publication lifecycle (3.4) or applicability (step 2).
It applies only when the assessor has at least one **applicable, calculable** 3.1 identity in the deciding class. If the 3.1 one is only unresolved, invalid or inactive, D27 does nothing: the 3.0 identity takes part in step 6 normally, and the unresolved 3.1 one is handled by D10 / D14.

**Capability rule (SETTLED Q3 + D2):**
1. Unsupported versions (4.0, 2.0) **never take part in score competition**. Their provenance is kept ("available, not used: unsupported version").
2. Inside the selected class, another assessor's **supported** rating may still be considered (step 6).
3. If no supported rating remains in the highest present class, **do not fall to a lower class**: score `unavailable`, reason `unsupported_cvss_version`; lower-class supported ratings are shown "available, not used".
4. The choice moves for capability only inside the same class. Withdrawal, inactivity or `does_not_apply` are different: they remove a candidate and step 4 runs again.
5. Case 2 with an unsupported independent peer: condition `unscorable_peer_assessment`, score provisional (D9, 4.1a). An **invalid** independent peer does not do this (D20).

**Step 5a. Outcome basis (SETTLED D13).** After step 5, the deciding class's **scoring candidates** are its applicable candidates with a supported version and a valid vector. Unsupported candidates do **not** count as applicable scoring candidates when the outcome is decided. Then:

| Deciding class after step 5 | Outcome | Next |
| --- | --- | --- |
| at least one scoring candidate | `selected` or `contested` | step 6 on the scoring candidates; the class's unresolved candidates are handled as `same_class_unresolved` (D10, with D14 in step 6.2) |
| no scoring candidate, at least one unresolved candidate | `unresolved`, condition `higher_class_unresolved` | 4.1a rule 3 (D4 if nothing unresolved is calculable) |
| no scoring candidate, no unresolved candidate (only unsupported or invalid) | none ("no outcome", 4.1a) | score `unavailable`, reason `unsupported_cvss_version`, `invalid_vector` or `no_calculable_rating` (4.1a table); capability rule 3, no fallback |

Unsupported and invalid candidates stay in provenance (`available_not_compared`). An **unsupported** one sets `unscorable_peer_assessment` **only** when it belongs to an assessor **other than** the one whose assessment is selected or competing, inside the deciding class, and that class has a scoring candidate. An **invalid** one never sets a condition (SETTLED D20, below). In the `unresolved` row, neither sets a condition: they are recorded only.

the owner's example: `vendor_platform` A applies but is 4.0; `vendor_platform` B is unresolved and 3.1; `cna` C applies, 3.1. Step 4 fixes `vendor_platform`. Step 5 sets A aside. Step 5a finds no scoring candidate and one unresolved candidate: outcome `unresolved`, condition `higher_class_unresolved`, score provisional (rule 3), C `available_not_selected`, A `available_not_compared` with no condition.

**Step 6. Identity competition.**
1. Group the class's remaining candidates by **AssessmentIdentity** (3.2a). Linked publications are one assessment here, never two assessors or two competing vectors. The identity's publications in this class are the ones step 3 put there; a linked publication in another class is not part of this class's competition but stays a candidate in its own class (D1). Example: vendor publication (`vendor_platform`) and its linked NVD copy (`cna`). If the vendor publication is withdrawn, step 4 runs again, finds `cna`, and the NVD copy is selectable there.
2. **Same assessor, several identities:**
   - different asserted contexts that all apply: the most specific asserted context (package > ecosystem/family > unstated) wins, **when the contexts are comparable** (below). The less specific ones are `not_selected`, reason `less_specific_same_assessor`. This is specificity of one assessor's own statements, not authority. If two applicable contexts of one assessor are **incomparable**, there is no ranking. Two cases:
     - **different vectors:** `assessor_self_inconsistency`, outcome `contested` (SETTLED 2026-11-19, D21 follow-on).
     - **identical vectors (D23, SETTLED 2026-11-19 as the owner recommended):** no score disagreement, so the context difference alone is **not** `assessor_self_inconsistency`. Both identities are kept, with their publications; they are never merged because the vectors match (D18). This is **not** independent-assessor agreement (one assessor). Identity roles: **both** are `concurring` (4.1b), and both are contributors. Neither is `selected`, because the contexts are not ranked. The score uses the common vector. One of them carries the technical **representative** flag, chosen by the representative rule (D24, 4.1b). That rule implies no authority, no context precedence and no scoring preference, and it never changes the score. The revision carries the diagnostic flag `context_ambiguity` (identifier SETTLED 2026-11-19). It is not a condition, so the score is `final` if nothing else applies. It is shown for visibility and for future policy refinement.
   - **Specificity and unresolved candidates (SETTLED D14 principle; "could affect" definition SETTLED 2026-11-19).** Specificity compares **applicable** candidates only. It never removes an unresolved candidate silently. An unresolved candidate U in the deciding class **could affect** the result, and so sets `same_class_unresolved` (score provisional, 4.1a rule 4), **unless** one of these holds:
     a. U has the same vector as the selected assessment (if it applied, it would agree; D3), or belongs to the selected identity. This removes **scoring uncertainty only** (SETTLED D18): U keeps its own identity, assessor and publication provenance. If U is the same identity it is duplicate publication evidence (never counted twice); if U is another assessor it is recorded as potential agreement; if U is the same assessor with another asserted context, specificity (above) still decides which applies once U is resolved;
     b. (SETTLED D21) **all four** hold:
        1. U and the selected candidate belong to the **same assessor**;
        2. **both** candidates have **asserted** contexts: neither the selected candidate's nor U's context is inherited or unstated (fixed in v4.9.2: an inherited context on U proves nothing about specificity);
        3. the selected candidate's asserted context is **strictly more specific** than U's asserted context;
        4. the policy's context order gives an **unambiguous** ordering of the two (they are **comparable**, below).
        If any of these fails, b does not apply. U then keeps `same_class_unresolved` and the score is provisional, unless a applies. Specificity is never assumed from an inherited or unstated context (on either side) or from an uncertain mapping.
     **Comparable contexts (wording SETTLED 2026-11-19, D21).** Two normalised contexts are comparable only when one **contains** the other under the policy-versioned context order: package P (in ecosystem / family E) is more specific than E; E is more specific than unstated. Anything else is **incomparable**. That covers two different packages, a CPE product against a package with no policy mapping, two families the policy does not relate, and any mapping the policy marks ambiguous. Incomparable contexts are never ranked.
     An unresolved candidate that cannot affect the result is still recorded: disposition `unresolved`, reason `cannot_affect` with which of a / b applied. Example: assessor X asserts package P (applies, 6.5) and the ecosystem of P (unresolved, 9.1). All four conditions of b hold, so 6.5 is `final`. If X's package-level rating applies only through an **inherited** context, b fails, so the score is provisional 9.1. If X's unresolved one were also package-level, or more specific, it **could** affect: provisional 9.1. If the unresolved one is from a **different** assessor, specificity never applies across assessors: D10 as before.
   - same asserted context, different vectors: `self_inconsistent`; treated as contested (4.1a).
   - **Comparability vs disagreement (SETTLED D25 principle).** Context comparability only decides whether **specificity** can resolve one assessor's identities. It says nothing about disagreement. Disagreement means two or more scoring candidates with different calculable vectors that specificity does not resolve. One assessor is in conflict with itself when its contexts are the same **or incomparable** and the vectors differ, and that gives `contested` with `assessor_self_inconsistency`. When the contexts are comparable, the most specific one wins and there is no conflict.
3. **Different assessors, different vectors:** selection status = `contested` (4.1a), whatever the contexts are: specificity never applies across assessors. Recency is **never** used to choose between independent assessors. Resolved only by an explicit **assessor-pair precedence** entry in the class policy table (versioned) or a person's source selection override (R-O9).
4. **Different assessors, same vector (SETTLED D3, wording D16):** different assessors with the same vector are in **agreement**, not conflict. Selection outcome is `selected`, and **all agreeing assessors are contributors**, recorded with their identities and publications. The score is `final` **only when no other condition** (e.g. `same_class_unresolved`, `unscorable_peer_assessment`) makes it provisional (4.1a rule 6). Agreement never merges the agreeing identities into one (D18). The shared vector is the agreed result; the score is the same whichever publication is referenced. Every agreeing identity has role `agreeing` (symmetric, D24); none is `selected`. Where one reference is technically needed (e.g. one link in an export), the **representative** identity is picked by the representative rule (4.1b), and its reference publication is the representative publication. The representative is **not** the authoritative assessor and never changes the score, the class or the selection.

**Step 7. Reference publication inside each contributing identity (D19, D24).** This runs once **per contributing identity** (`selected`, `agreeing` or `concurring`) and picks that identity's technical reference only. Its other publications become `supporting` (`same_identity`). Order: asserted context over inherited; then the assessor's own publication over a copy; then newest source updated at; then the publication's canonical key, so the result never depends on arrival order.
   **Timestamp rule (wording SETTLED 2026-11-19, owner v4.9.3 review):**
   1. Comparison uses the **normalised UTC instant** stored at ingestion (3.1). A zone-less value is read as UTC only under the ingestion contract and is marked `zone_assumed_utc`; the original value is kept beside it. `unparseable` counts as missing. The comparison is reproducible from the stored values and never re-parses the original.
   2. A publication with a known time sorts ahead of one with no time.
   3. If the times are equal, or both are missing, the **canonical publication key** decides: source, then document reference, then source revision (or the content fingerprint when there is no revision, 3.1), compared as byte strings.
   4. None of these steps reads arrival time, fetch time or a stored id. "Own publication" = the publisher's org id equals the assessor's org id. Org ids come from the same places as in the relationship table (CVE.org org id, NVD `source`, the vendor map). A publisher with no org id (an aggregator or feed) is never "own".

**Step 8. No candidate at all.** If no class has an applicable or unresolved candidate -> unscored `no_applicable_rating` (or `no_vector` if no candidate had a vector).

**Step 9. Record:** outcome, condition sets, score status, contributing identities with their roles, competing identities, contributor relations, each contributing identity's reference publication, the representative identity and publication (if any), every identity role and every candidate publication's disposition and reason (4.1b), identity grouping version, class and class basis, assessor, publisher, feed, revision, class-policy version, selection-policy version.

Example (3.4 item 2a): a vendor that is also the CNA asserts a package context in its own document, so for an RPM of its platform the rating is `vendor_platform`. The NVD Secondary copy (linked, same identity, inherited context) is `cna` for that component. When the vendor's own publication is withdrawn, step 1 rejects it (`rejected`, `inactive`); step 4 finds `cna`; the NVD publication is selected.

### 4.1a Selection outcome, conditions and score status (SETTLED by the owner 2026-11-18: 16:53 decision, D8-D10)

Every ComponentAssessment revision carries:

| Field | Values | Cardinality |
| --- | --- | --- |
| Selection outcome | `selected` · `contested` · `unresolved` | exactly one when the deciding class has a scoring or unresolved candidate; otherwise none ("no outcome", below) |
| Contributing identities | every identity whose vector is the score: role `selected` (only one), or all `agreeing`, or all `concurring` (D24) | set, may be empty (D19, D24) |
| Competing identities | **every** identity taking part in an unresolved scoring conflict in the deciding class (D25), i.e. at least one of its publications there is a participating publication (D26). This does not imply that their contexts are comparable | set; non-empty exactly when outcome is `contested`; then contributing identities, reference publications and representative are all empty |
| Contributor relations | for several contributing identities: each pair, marked `independent_agreement` (different assessors) or `same_assessor_incomparable_context` (D23) | list, may be empty (values SETTLED 2026-11-19) |
| Reference publications | one per contributing identity (step 7) | one per contributing identity |
| Representative | one contributing identity, and its reference publication, for API / export convenience only (D24) | zero or one |
| Conflict conditions | `independent_assessor_disagreement` · `assessor_self_inconsistency` · `unscorable_peer_assessment` | set, may be empty |
| Applicability conditions | `higher_class_unresolved` · `same_class_unresolved` | set, may be empty |
| Score status | `final` · `provisional` · `unavailable` | exactly one, derived |
| Score | Base / Temporal / Environmental, or none | |

No combined status values. Conditions explain; the outcome says what was picked; the score status says how settled the number is.

**No outcome (SETTLED by the owner, v4.8 review):** when there is no candidate at all (step 8), or the deciding class holds only unsupported or invalid candidates (step 5a last row), there is nothing to select or contest. The revision then has **no** outcome, empty condition sets, score status `unavailable`, and its unscored reason. This is the only exception to D8's "exactly one". An outcome is never invented.

API and GUI keep "no outcome" and `unresolved` visibly apart:

| Situation | Outcome | Score status | Unscored reason |
| --- | --- | --- | --- |
| no applicable or unresolved rating | none | `unavailable` | `no_applicable_rating` / `no_vector` |
| only unsupported ratings in the deciding class | none | `unavailable` | `unsupported_cvss_version` |
| only invalid vectors in the deciding class | none | `unavailable` | `invalid_vector` |
| only unsupported and invalid, mixed | none | `unavailable` | `no_calculable_rating` (SETTLED), each candidate keeps its own `unsupported_*` / `invalid_*` disposition reason |
| higher-class applicability unresolved | `unresolved` | `provisional`, or `unavailable` (D4) | `rating_applicability_unresolved` when unavailable |

The last row stays `unresolved` even when nothing can be calculated: uncertainty about applicability is not the same as having no usable rating. The GUI words them differently ("No usable rating" vs "Vendor rating may apply; not yet decided").

**Outcome (exactly one), decided in this order:**
1. `unresolved`: after capability filtering, the deciding class has **no scoring candidate** and at least one unresolved candidate (step 5a, D13). Condition `higher_class_unresolved` is set.
2. `contested`: in the deciding class, independent assessors (or one assessor) give different **calculable** vectors (supported version, valid vector), and neither specificity (one assessor, comparable contexts) nor a precedence entry nor an override resolves them. Whether the contexts are comparable does not matter here (D25). Condition `independent_assessor_disagreement` and/or `assessor_self_inconsistency` is set.
3. `selected`: one assessment (or one agreed vector, D3) was picked.

Conditions found in a lower class than the deciding one are kept in provenance but do not set the outcome; e.g. outcome `unresolved` from a vendor class while two lower-class assessors disagree: outcome `unresolved`, and the lower-class disagreement is recorded on those candidates.

**Conditions that do not change the outcome:**
- `unscorable_peer_assessment` (SETTLED D9, closes O12; scope fixed by D20): the chosen class holds an independent assessor whose only rating is an **unsupported version**. A capability limit only. The supported assessment stays `selected`; the unsupported one is kept "available, not compared". It is **not** `contested`: `contested` means calculable vectors disagree (D25).
- `same_class_unresolved` (SETTLED D10): the chosen class holds an unresolved candidate besides the applicable one(s).

**Invalid independent peer (SETTLED D20, the owner's recommendation adopted).** An independent assessor whose only rating in the deciding class has an **invalid vector** sets **no** condition. A valid selected assessment stays `final` if nothing else applies. The reason is that an invalid vector is a validation failure in source data, not a missing Themis capability. The invalid peer is kept as `available_not_compared`, reason `invalid_peer`, with the RatingValidation's parser reason. The revision carries the **diagnostic flag** `peer_rating_invalid` (behaviour SETTLED, identifier SETTLED 2026-11-19), which is shown in the GUI ("another assessor's rating could not be validated") and in feed-health. A diagnostic flag is not a condition and never changes the outcome, score or score status. If invalid peers should ever affect finality, that needs its own new condition and the owner's decision; `unscorable_peer_assessment` is never widened silently.

**Diagnostic flags (behaviour SETTLED; identifiers SETTLED 2026-11-19).** `peer_rating_invalid` (D20) and `context_ambiguity` (D23) are stored on the revision and shown in the GUI and API. They are **never** conditions. They never change the outcome, score or score status, and an implementation must not use them as score inputs.

**Calculable** (SETTLED D17) = supported CVSS version **and** a valid vector (RatingValidation `valid`). Only calculable candidates ever give a value to any maximum below (rules 2-4); an unsupported or invalid candidate's contribution is always none.

**Score status and score (rules):**
1. Outcome `selected`, no conditions -> `final` (if calculable), else `unavailable` with its unscored reason.
2. Outcome `contested` -> select none; **provisional** = highest Environmental among the competing calculable assessments **and** any calculable unresolved candidate of the deciding class whose vector differs from every competing vector (D28 row c); record which gave it.
3. Outcome `unresolved` -> keep the unresolved higher-class candidate(s) and the **lower-class contribution** (SETTLED D17): the highest Environmental score among **applicable, calculable** candidates in **all** lower classes, not only the next class ("available, not selected"). Unsupported and invalid candidates never contribute. **Provisional** = highest Environmental among the calculable unresolved candidates and that lower-class contribution, provided at least one **unresolved** candidate is calculable. If none is calculable: `unavailable`, reason `rating_applicability_unresolved`; the lower-class rating is **not** used provisionally (SETTLED D4, O11 closed). The component stays in the scoring-coverage denominator.
4. Outcome `selected` with `same_class_unresolved` -> **provisional** = highest Environmental among the selected assessment and every **calculable** unresolved candidate of that class. If no unresolved candidate is calculable, the selected score is used, still **provisional** (the unresolved one cannot be compared). Unlike rule 3, this is not a lower-class fallback: the applicable candidate is in the same highest class.
5. Outcome `selected` with `unscorable_peer_assessment` -> the selected score, **provisional**.
6. Any combination: the score is the highest calculable value the applicable rules allow, and the status is `provisional` if **any** condition is set. The condition sets hold **only** conditions found in the deciding class (plus `higher_class_unresolved`). A disagreement, unresolved candidate or unsupported rating in a lower class is a candidate disposition and reason, never a condition, so it can never make a score provisional. Rule 3's `unavailable` wins over provisional only when the outcome is `unresolved` and nothing unresolved is calculable.
7. **Provisional is labelled everywhere** it appears: component, roll-up, GUI, API, exports, notifications. The GUI states **which conditions** made it provisional, in words.
8. Resolution (assessor-pair precedence, a person's source selection override, an applicability decision becoming available, a calculator for the unsupported version) creates a **new** ComponentAssessment revision. It never rewrites the earlier revision or its provisional score.

### 4.1b Candidate disposition (SETTLED D15: one enum + separate reasons; D19 two levels; identity roles and `reference` / `supporting` SETTLED; other exact values SETTLED 2026-11-19 until the owner confirms D20)

Two levels are recorded, so selecting an assessment never reads as rejecting its other publications (SETTLED D19):

**Identity level.** Each assessment identity that has a candidate publication in the deciding class gets one **identity role**:

| Identity role | Meaning |
| --- | --- |
| `selected` | the **only** contributing identity |
| `agreeing` | one of several contributing identities with the same vector, when they come from **two or more** assessors (D3). Every one of them gets this role (symmetric) |
| `concurring` | one of several contributing identities with the same vector, all from **one** assessor, with incomparable asserted contexts (D23, SETTLED 2026-11-19). Every one of them gets this role (symmetric); not independent agreement |
| `competing` | an identity taking part in an unresolved scoring conflict (`contested` outcome). Its context may be comparable or incomparable to the others (D25) |
| `not_selected` | set aside inside the class (`less_specific_same_assessor`, or `lower_supported_version`, D27) |
| `not_compared` | unsupported version or invalid vector |
| `unresolved` | its publications in the class are unresolved |

Identities in other classes take no role here; their publications carry the disposition (below).

**Scope of `competing` (SETTLED D26 principle, the owner's five rules adopted):**
1. The identity role `competing` applies to an identity that takes part in the deciding-class conflict.
2. The publication disposition `competing` applies only to that identity's **participating** publications: active, applicable, calculable and in the deciding class.
3. Its other publications keep their own dispositions: `unresolved`, `available_not_compared` (unsupported or invalid), `rejected` (inactive or does not apply), or a disposition in another class (rule 1 below).
4. The identity-level conflict stays visible through the role and the competing-identities set, even when its publications have different dispositions.
5. No publication becomes `competing` only because another publication of its identity takes part in the conflict.
6. (D26 rule 6; reason name SETTLED 2026-11-19) In a `contested` outcome there is no selected assessment, so D14 exception (a) does not apply. Instead, an unresolved publication of a **competing** identity carries that identity's own vector, so it cannot introduce a new scoring value. It keeps disposition `unresolved`, reason `same_vector_as_competing_identity`. It contributes nothing to the provisional maximum and sets no `same_class_unresolved`. An unresolved candidate with a **different** vector is covered by rule 7, not by D10 / D14.
7. **(D28: unresolved candidates in a contested outcome; principle as the owner recommended, reason names SETTLED 2026-11-19.)** D14's exceptions are defined against a selected assessment, so they never apply in a `contested` outcome. Instead, each unresolved candidate U in the deciding class is classified once, in this order:

| U in a `contested` outcome | Disposition / reason | Condition | Contribution to the provisional maximum |
| --- | --- | --- | --- |
| a. publication of a competing identity (same vector as it) | `unresolved` / `same_vector_as_competing_identity` (rule 6) | none | none |
| b. another identity whose vector **equals** some competing identity's vector | `unresolved` / `same_vector_as_competing_identity` | none: it cannot introduce a new value. Its own identity and assessor stay in provenance (D18) | none |
| c. calculable, vector **differs** from every competing identity's vector | `unresolved` / `differs_from_competing_vectors` | `same_class_unresolved` added | its Environmental score |
| d. no calculable vector (no vector at all) | `unresolved` / `same_class` | `same_class_unresolved` added (as D10: it cannot be compared) | none |

   - In every row the outcome stays `contested`, and the conflict conditions (`independent_assessor_disagreement` / `assessor_self_inconsistency`) stay as they were.
   - U never enters the competing-identities set: it is uncertain applicability, not a scoring disagreement (D25).
   - U never becomes a contributing identity, a reference or a representative; a contested outcome has none.
   - Rows b-d apply whether or not U's assessor is one of the competing assessors.
   - An unresolved candidate that is invalid or unsupported keeps the treatment it has in any outcome (D20 / D9): `available_not_compared`, no contribution.

Distinct identities with the same vector stay distinct: each keeps its own role, assessor and publications (D18).

Mixed group (one assessor with two incomparable identities, plus another assessor with the same vector): all three are `agreeing`. The same-assessor pair is still visible as a `same_assessor_incomparable_context` relation, and the flag `context_ambiguity` is set.

**Representative (D24; rule SETTLED 2026-11-19).** Representative is a **flag** on exactly one contributing identity when there is at least one. It is not a role, and it means "technical anchor for one link in an API response or export", nothing more. It never implies authority, context precedence or scoring preference.
- Rule (versioned with the selection policy): take the smallest **canonical identity key**, compared in this order: assessor org id, CVSS version, normalised vector, normalised asserted-context string.
- The last two fields are compared as **plain byte strings**, as a deterministic technical tie-breaker only. The comparison has **no semantic specificity, no applicability precedence, no assessor authority, and no effect** on scoring, roles, contributors or identity grouping. A context string that sorts first is not "more specific" or "better"; specificity exists only in step 6.2, under the policy context order.
- In a `contested` outcome there is **no** representative (D25).
- The key is derived from content only, so the result is the same whatever order publications arrive in. A stored identity id is never used unless it is itself derived from that content.
- Changing the rule is a `selection_policy_changed` trigger. It changes only the representative, never the score, roles or contributors.

**Publication level.** Every candidate publication in a revision has **exactly one** disposition. A reason is required where the table says so, from the closed list. The same names are used in 4.1, 4.1a, 8.1, the API and the GUI.

| Disposition | Meaning | Reason (closed list) |
| --- | --- | --- |
| `reference` | the technical reference publication of **one** contributing identity (step 7). There is one per contributing identity. The representative identity's reference is also the overall representative publication. Carries no authority | none |
| `supporting` | another active, applicable publication of the **same** identity as a `reference` in the deciding class. Provenance kept; never rejected, never counted twice. Never used for a publication of a different identity (D24) | `same_identity` |
| `competing` | a **participating** publication of a `competing` identity: active, applicable, calculable and in the deciding class (D26). In a `contested` outcome no publication is `reference` or `supporting` | `independent_assessor_disagreement` or `assessor_self_inconsistency` |
| `unresolved` | applicability could not be decided | `higher_class` (decides an `unresolved` outcome), `same_class` (sets `same_class_unresolved`), `differs_from_competing_vectors` (D28, contested only; sets `same_class_unresolved`, contributes), `cannot_affect` (D14, with a or b; only when an assessment is selected), `same_vector_as_competing_identity` (D26 rule 6, contested only), `lower_supported_version_unresolved` (D27), `lower_class` (recorded only) |
| `available_not_selected` | applicable, supported and valid, but not in the deciding class | `lower_class` |
| `available_not_compared` | applicable but not calculable, so cannot take part in score competition or any maximum | capability: `unsupported_peer` (sets `unscorable_peer_assessment`), `unsupported_same_assessor` (step 5), `unsupported_only` (step 5a last row), `unsupported_lower_class`. Validation: `invalid_peer` (sets **no** condition; diagnostic flag `peer_rating_invalid`, D20), `invalid_vector`, `invalid_lower_class` |
| `not_selected` | applicable, calculable, in the deciding class, but set aside inside it | `less_specific_same_assessor` (step 6.2), `lower_supported_version` (step 5, D27) |
| `rejected` | out of the evaluation | `inactive`, `does_not_apply` |

Rules:
1. A linked publication in another class gets its disposition in **its own** class (D1), never a second one. Example: the vendor publication is `reference` in `vendor_platform`; its linked NVD copy in `cna` is `available_not_selected` (`lower_class`). Neither is rejected; the identity's role covers both.
2. Each candidate also records its **contribution**: the value it put into a provisional maximum (rules 2-4 of 4.1a), or none. A disposition says *why*; the contribution says *how much*.
3. `invalid_vector` (SETTLED by the owner, v4.8 review): an applicable rating whose vector the calculator refuses (R-C3) keeps its publication, keeps its class, is excluded from scoring competition and from every maximum, never causes a fallback to a lower class, and gives `unavailable` when no calculable candidate remains. An unsupported version is a **capability limit**; an invalid vector is a **validation failure**. They are never one generic error: their reasons differ (rule above), and diagnostics point to the RatingValidation result (`unsupported_cvss_version` vs `invalid_vector` with its parser reason, 3.5).
4. Mapping from v4.9.2 (D24): in an agreement, the identity that was `selected` is now `agreeing` like the others, and it may carry the representative flag. Under D23 the old `selected` + `concurring` pair is now `concurring` + `concurring`. A publication of an agreeing or concurring identity that was `supporting` is now that identity's own `reference`.
5. Mapping from v4.8 names: publication `selected` -> `reference`; `agreeing` publication -> identity role `agreeing` + its publications `reference`/`supporting`; `not_selected` / `other_publication_of_selected_identity` -> `supporting` / `same_identity`.

### 4.2 Calculator (SETTLED R-C1..R-C6)

1. Parse every CVSS 3.0 / 3.1 metric; keep X (not defined).
2. Full Base, Temporal, Environmental equations with the spec's Roundup (3.0 and 3.1 differ).
3. Malformed vector refused with a reason; never 0.
4. CVSS 4.0 and 2.0 stored and shown, not scored. A v4 calculator is its own item and never reuses 3.1 logic.
5. Deterministic; AI never sets a score.
6. Every result records calculator version and spec version.

### 4.3 Temporal metrics

**SETTLED (R-T2, R-T3, R-T4, R-T5): the state model.** States per metric: **not defined**, **proposed** (does not count; metric stays X), **accepted by policy**, **accepted by user**. Evidence found, evidence accepted, and value used are separate fields.

**The evidence-to-metric mapping.** The KEV row (R-T6, KEV without autonomous evidence -> E:F) is **SETTLED**. Every other row is **OPEN for EDR-SCORING-01** (R-T1).

**Mapping is not acceptance (SETTLED D22).** These are two separate decisions:

| Decision | Question | Status |
| --- | --- | --- |
| Mapping | which metric value a piece of evidence **proposes** | KEV -> E:F SETTLED; other rows OPEN for EDR-SCORING-01 |
| Policy acceptance | whether the temporal policy **accepts** that proposal automatically, so it counts in the score | per row, per temporal-policy version; day-one policy is O2 |

A mapping, settled or not, only ever produces a metric in state **proposed**, which does not count (the metric stays X). It moves to **accepted by policy** only when the active temporal policy names that row, or to **accepted by user** when a person accepts it. So "KEV -> E:F is settled" never means "every KEV listing changes the score".

| Evidence | Proposed |
| --- | --- |
| Exploit known to run autonomously | E:H |
| KEV listing (no autonomous evidence) | **E:F** (R-T6) |
| Public functional exploit | E:F |
| PoC only | E:P |
| No exploit evidence | E:X |
| Vendor fix published **and applicable to this component** | RL:O |
| Temporary fix | RL:T |
| Workaround stated | RL:W |
| Source says no remediation exists | RL:U |
| No reliable evidence | RL:X |
| No confidence stated | RC:X |

Temporal values never change a source vector; they live only on the assessment.

### 4.4 Environmental requirements (SETTLED R-E1..R-E7)

1. CR, IR, AR each resolve on their own: component exception, then Release, then Project, then Product, then X.
2. A component exception needs the permission and a reason.
3. Modified metrics per component assessment, default X.
4. Each value records the level it came from.
5. A change at any level: list affected releases and Findings, recalculate as new revisions, keep the old ones, record the reason, report SLA/priority impact. Never silent.
6. Deployment-level requirements out of scope.

---

## 5. Component assessment and eligibility (SETTLED Part A, B4)

1. Every matched component gets a full ComponentAssessment, keyed by PURL (F2).
2. **Eligibility** from claim class (F5): `carrier` and unknown are eligible. `scope` is **always** `excluded_from_rollup`, whatever the other components are. The assessment is still calculated and shown (greyed), with reason and evidence.
3. **Applicability** from the occurrence verdict (F6): `open` (including empty) stays in the roll-up; `cleared_vendor_fix` stays visible but leaves the current roll-up, with the verdict's reason. No parallel `not_applicable` state. Inferred clearances follow EDR-VERDICT-01 (including its D4 switch); no CVSS-specific switch.
4. No per-component human `not_affected`. That stays a Finding-level Position.
5. Coverage counts eligible, open components only (section 6). Scope or cleared components never make coverage Partial.
6. Unscored reasons (closed set, SETTLED by the owner in the v4.9 review; shown per component; produced by selection (4.1, 4.1a) or the calculator): `unsupported_cvss_version`, `invalid_vector`, `no_calculable_rating` (mixed unsupported and invalid), `no_vector`, `no_applicable_rating`, `rating_applicability_unresolved` (cannot tell whether a source rating applies to this component; not the occurrence verdict).
   - **Extensibility rule:** each reason is a machine-readable code. Explanatory text is separate and never parsed. A new reason needs a policy-version change and a test.
   - `awaiting_review` (listed until v4.9.1) is **removed** from the initial set. No lifecycle event produced it, and a proposed metric waiting for acceptance leaves that metric at X (4.3); it never makes a score unavailable. If a review state is needed later, it is added under the extensibility rule.

---

## 6. Roll-up (SETTLED: states, state order, max rule, coverage denominator (v4.1 review) and coverage formulas (v4.9 review))

Contributors = currently matched, eligible (not scope), open (not cleared) components with a valid assessment.

States are checked in this order; the first that matches is the state:

| # | State | Meaning | Score |
| --- | --- | --- | --- |
| 1 | `no_components` | Evidence reports no current matched component | none |
| 2 | `no_carrier` | components exist, all are scope (none passes eligibility) | none |
| 3 | `no_open_occurrences` | some components pass eligibility, but every eligible one is `cleared_vendor_fix` (scope + cleared mixes land here too) | none |
| 4 | `unavailable` | eligible open components exist, none has a usable assessment | none |
| 5 | `scored` | at least one contributor | highest **Environmental** score among contributors, with its band |

Rules for every state:

1. States 1 to 4 never produce 0, and never mean "fixed" at Finding level. `no_open_occurrences` is not a decision: the Finding stays as governance left it (8.6).
2. For states 1 to 4, priority keeps today's path (F16); none of them can lower priority. Each is shown in the GUI by its own name.
3. Ties keep all contributors. Never mix one component's Base with another's Environmental.
4. The unassessed list names each eligible open component without a usable assessment and its unscored reason (section 5, item 6).
5. A component with a provisional score (contested or unresolved) **is** a contributor: it counts as scored.
5a. **Finding score status (SETTLED D5):** `provisional` if **any** contributor tied at the maximum is provisional; otherwise `final`. A provisional component **below** the maximum does not make the Finding provisional; the Finding's status describes the provenance of the actual maximum. Example: A 8.2 provisional + B 8.2 final -> 8.2 provisional, both contributors. A 7.5 provisional + B 8.2 final -> 8.2 final.
6. A component with score status `unavailable` (including `rating_applicability_unresolved` with nothing calculable) counts in the denominator, not the numerator.

**Coverage:**

Two indicators (SETTLED by the owner: two indicators; formulas accepted in the v4.9 review):

```
scoring coverage     = eligible open components with a score (final or provisional)
                       -------------------------------------------------------------
                                     eligible open components

assessment finality  = scored components whose score status is final
                        ----------------------------------------------
                         eligible open components with a score
```

| Value | When |
| --- | --- |
| Complete | ratio = 1 |
| Partial | 0 < ratio < 1 |
| None | ratio = 0 with a non-zero denominator (that is state `unavailable`) |
| Not applicable | denominator = 0 (states `no_components`, `no_carrier`, `no_open_occurrences`); never shown as 100%, 0%, Complete or Partial |

The table applies to scoring coverage. **Assessment finality** (SETTLED D7) measures source-selection status only: the share of scored components whose selection is settled. It is not a probability and says nothing about source or evidence quality. It is shown as a ratio (e.g. "3 of 4 final") and is Not applicable when no component is scored.

---

## 7. Governed changes (R-O1..R-O11 SETTLED; scope semantics in item 2 and R-O12 detail in item 3 OPEN for EDR-SCORING-01)

Three kinds, each with its own audit record:

| Kind | Changes | Stays |
| --- | --- | --- |
| Source selection override | which applicable rating is used | all source records |
| Vector override | the assessment vector and scores (user edits metrics; Themis computes the number) | source records, the originally selected vector |
| Environmental exception | CR/IR/AR or M* for one component | product / project / release defaults |

Every record: id, kind, previous effective assessment, new values, computed scores, reason (required), actor, time, scope, review date (optional), status (active / superseded / removed).

1. Removing a change restores the layer below; history stays.
2. Scope = finding / release / project / product, always for **one CVE** plus explicit component criteria (ecosystem, package). Never "every vulnerability in the product".
3. Before propagating, evaluate each target: same CVE, component matches criteria, CVSS version compatible, no local change already, no independent governed assessment. Only compatible targets get it (R-O12).
4. A wider scope proposes to each target and never replaces a local change (R-O5, same rule as EDR-SYNC-01).
5. Record where the change was made, which assessments applied it, which declined or kept a local change.
6. Impact shown before saving a wider scope.
7. When its premise changes (source corrected or withdrawn, new vendor rating), a governed change is flagged for review, never altered.
8. Permission `security.score.override`, checked by the Governance API on every create and remove; the GUI is not the boundary; actor on every record (R-O10).
9. Two-person approval: later.

### 7.1 Owner-set severity (owner, 2026-11-25, PROPOSED; first part of step S6)

The owner's ask: "even if Themis identifies Critical for the original score, it is the product
owner who decides what should be the correct severity, identifying the impact on the product.
This should be configurable." This section says how the "Vector override" row above is built,
and adds a second, simpler way to do it. Nothing in items 1-9 above is removed; where this
section is narrower or different, it says so.

**The owner's answers (2026-11-25):**

| # | Question | Answer |
| --- | --- | --- |
| V1 | What does the owner set? | Either a severity level, or changed CVSS metric values. In both cases Themis computes the score |
| V2 | Where does it apply? | Any release listed under the product, picked from a list |
| V3 | Who may set it? | The admin now; the product security lead (PSL) later |
| V4 | Does it copy with a decision? | Yes, it copies along (EDR-SYNC-01 D12) |
| V5 | The world score changes later | Flag it for review |

**OS1. Two ways in, one result.** An owner-set severity is one governed change on one Finding
(one CVE in one release). The person gives a reason (required) and one of:

1. **Changed metrics.** The person changes CVSS metric values on the vector Themis selected
   (for example privileges required to Low, availability to None). The kernel calculator of
   section 4.2 computes the score from the changed vector. The record keeps the changed vector.
2. **A level.** The person picks None, Low, Medium, High or Critical. Themis computes the score
   as **the original score moved into the picked band by the shortest way**: a score above the
   band becomes the top of the band, a score below it becomes the bottom, a score already inside
   stays. The bands are the CVSS ones (Low 0.1-3.9, Medium 4.0-6.9, High 7.0-8.9, Critical
   9.0-10.0; None is 0.0). The record keeps the picked level and no vector, and says so: a
   level-only score is never shown with a vector it was not computed from.

Either way the Finding then shows two numbers side by side: the **original** score with its
source, unchanged, and the **owner-set** score with the level, the person, the time and the
reason. The original is never hidden or rewritten (same rule as the table above: source
records stay).

**OS2. It counts.** The owner-set score is the Finding's severity for priority, the remediation
deadline and the lists, from the moment it is saved. This does not wait for the shadow exit of
9.1: shadow covers what Themis calculates on its own, and this is a person's decision with a
name on it. Removing the owner-set severity brings the original back (item 1); history stays.

**OS3. Where: a pick list, same as the copy.** The form lists every release under the same
product that has the same CVE (the list of EDR-SYNC-01 D10), with "Select all projects" and
"Select all in product". Never another product. A picked release that already has an owner-set
severity is marked "will be replaced" and the count is shown before saving. This is narrower
than item 4 above for this one kind: an explicit pick by the person may replace, a wider scope
that the person did not pick release by release still may not. The compatibility checks of item
3 stay for changed metrics (same CVE, CVSS version the calculator supports); a level needs only
the same CVE.

**OS4. Who.** Admin only for now, checked by the Governance API (item 8) and by the dashboard
gate, because a node only sees the dashboard's own key (the rule already used for the bulletin
register). The product security lead role comes with GUI users and roles and
product-scoped rights; the permission name stays `security.score.override`.

**OS5. It travels with the decision.** When a decision is copied (EDR-SYNC-01 D11), the
owner-set severity of the source goes to each target with the same reason and person (D12
there). A later upload is handled as today: roll-forward proposes the decision; the owner-set
severity is offered with it and is not applied on its own.

**OS6. Flag, never change.** When the original changes after the owner set a severity (a new
or corrected source rating, a withdrawn one, a different selected source), the Finding is
flagged "severity to review" with what changed. The owner-set severity stays in force until a
person keeps it, changes it or removes it (item 7).

**Steps (each on the owner's go):**

- **V0** this section (docs only).
- **V1** Governance: the record, the two inputs and the level rule, the API (set, remove,
  history), admin check, the effect on priority and deadline, a migration, tests.
- **V2** GUI: "Set severity" on the decision page with the two ways, a preview of the computed
  score before saving, the pick list, both numbers on the Finding.
- **V3** The review flag (OS6) and the copy with a decision (EDR-SYNC-01 C4).
- **V4** VM check.

**Settled by the owner (2026-11-25):** the level rule of OS1 item 2 is the one written there:
the original score moved into the picked band by the shortest way. One fixed number per level
was the other choice and was not taken.

**Realization note, V1 and V2 (2026-11-25, on the owner's "go but build both v1 and v2").**

- **The record.** Governance migration 000027 adds `finding_owner_severities` (kind level or
  vector, level, vector, score, the original score at that time, reason, person, time, the
  Finding whose form it was set on). A row is never deleted or rewritten: a new severity or a
  removal ENDS the row in force (when, who, `replaced` or `removed`). At most one row per
  Finding is in force.
- **The score (OS1).** `domain.ComputeOwnerScore` takes exactly one of a level or a CVSS 3.0 /
  3.1 vector. A level gives the original moved into its band (`ScoreForLevel`); with no
  original score there is nothing to move and the result is the bottom of the band. A vector
  goes through the kernel calculator and the result is its Environmental score, which is the
  Base score when the vector carries no temporal or environmental metrics.
- **"Original" here** is the Original column of the lists: the highest source Base score over
  the open carrier components, else over every current component. The vector the form starts
  from is the assessment vector of the component that gave it.
- **It counts (OS2).** Two read columns on `findings`: `owner_base_score` (the owner score
  times ten, on the 0-100 scale) and `owner_sla_bucket`. The posture list (so both
  priorities), the remediation deadline, the remediation metrics and the severity counts of
  `release_evaluated` read them before `base_score` / `sla_bucket`, which are never touched.
  The floors of the 0-100 scale (90 / 70 / 40) are the CVSS bands times ten, so the level the
  person sees is the deadline bucket. Removal sets the columns back to empty and the original
  counts again.
- **Three things to know.** (1) While an owner-set severity stands, the deadline uses ITS
  bucket, not the bucket frozen at first score (EDR-REMEDIATION-01 Q1); the period start does
  not move. (2) The owner score replaces the whole 0-100 base score, including the lift
  Knowledge gives for KEV and EPSS; the exploit band and a CISA due date still show and still
  apply. (3) Level None gives score 0: no deadline bucket, and counted in no severity bucket.
- **The API.** `GET /findings/{id}/severity` (original, in force, history),
  `PUT /findings/{id}/severity` (reason plus `level` or `vector`, optional `apply_to`),
  `POST /findings/{id}/severity/remove`, `POST /findings/{id}/severity/preview` (computes,
  records nothing), `GET /findings/{id}/severity/targets` (the pick list). The posture row
  carries `owner_severity`.
- **The pick list (OS3)** is the list of EDR-SYNC-01 D10 (same CVE, same product), without
  the same-component rule: a severity is about the CVE in the product, not about one package.
  Every pick is checked before anything is saved, and all picks are saved in one transaction.
  For a level, each picked Finding gets its own score from its own original. Without the
  Registry seam a severity can still be set on the one Finding; the pick list answers 503.
- **Who (OS4).** Set and remove are admin only in the Governance API (no principal means auth
  is off) and at the dashboard gate (`isOwnerSeverityWrite`). Reading and the preview need the
  read scope. The record names the authenticated key, like every decision.
- **The GUI (V2).** A "Severity" card on the decision page, above "Your decision": the
  original with its vector, the owner-set one with who, when and why, and for an admin "Set
  severity" with the two ways (a level, or the eight base metrics as lists starting from the
  original vector), the score Themis would compute shown before saving, the required reason,
  the pick list ("Select all in product", "will be replaced"), a question before any existing
  owner-set severity is replaced, "Remove owner-set severity", and the history. In the lists
  the Expert severity cell shows the owner-set score with the words "owner-set", and the
  release's severity donut counts it.
- **Not built yet:** V3 (the "severity to review" flag of OS6, and the severity travelling
  with a copied decision, OS5 / EDR-SYNC-01 C4), no event is published when a severity is set,
  and V4 (VM check).

---

## 8. Lifecycle summary (B5, SETTLED)

### 8.1 Assessment revisions

A ComponentAssessment revision is immutable and holds the full input snapshot: selected source and rating with revision, every metric with state and origin, CR/IR/AR with level, eligibility (claim class), applicability (verdict), calculator / spec / selection-policy / temporal-policy versions, the contributing and competing **identities** with roles, contributor relations, each contributing identity's **reference publication**, and the representative (D19, D24), the **RatingValidation** used, the Evidence **membership event** that put the component in the Finding, the three scores, time, cause, and the triggering event reference. The snapshot also holds the **complete candidate evaluation** (SETTLED with D8-D11): for **every** candidate publication, its publication and identity references, the identity-grouping version, applicability result, selection class and class basis, RatingValidation reference (where one exists), version eligibility (supported / set aside), identity role, disposition and reason from the canonical lists in 4.1b (SETTLED D15, D19), and its contribution to the score (the value used for the maximum, or none). Outcome, conditions and score status are stored with it.

The **current** assessment is the newest revision; older ones are history. An old revision's result is explained **from its own snapshot**: re-running today's algorithm on today's source data is never needed to say why it produced its score (R-X5).

### 8.2 Triggers (each names its cause)

| Cause | From | Rule |
| --- | --- | --- |
| `component_added` | Governance `AbsorbComponent` (F3) | B1: first revision from current Knowledge state and policy; existing components not recalculated; pending wider-scope changes for the CVE are evaluated and applied/proposed |
| `component_reappeared` | Evidence membership | B2: new membership event; history kept; new revision per B1 |
| `eligibility_changed` | claim class re-delivery (F5) | Part A: scope <-> carrier/unknown moves the component in or out of roll-up |
| `applicability_changed` | verdict re-delivery (F6) | B4: open <-> cleared moves it in or out of roll-up |
| `classification_changed` | Knowledge: CNA of a CVE learned or changed; an assessor's org identity corrected. Policy: vendor map or class table changed (also counts as `selection_policy_changed`) | recompute classes, re-run selection |
| `identity_relinked` | Knowledge AssessmentLink event (3.2a) | re-run selection with the new grouping |
| `contest_resolved` | assessor-pair precedence added, or a source selection override | new revision; earlier provisional revision kept (4.1a rule 6) |
| `source_added` / `source_corrected` / `source_withdrawn` | Knowledge (new SourceRating or SourceRatingEvent; never a SeenEvent alone) | B3: re-select; if nothing usable remains -> `unavailable` |
| `requirement_changed` | Registry | R-E7: impact list, versioned recalculation |
| `temporal_accepted` / `temporal_policy_changed` | Governance | R-T2 |
| `governed_change` / `governed_change_removed` | person | section 7 |
| `calculator_changed` / `selection_policy_changed` | release of Themis | new RatingValidations and assessment revisions; old results kept. The bulk mechanism (affected list, impact, regression report) stays **OPEN for EDR-SCORING-01** and is not approved by this document |

**Not an assessment trigger:** `component_removed`. It is an Evidence membership event (8.4). The component's last assessment revision is kept unchanged; only the Finding **roll-up** gets a new revision (cause `component_removed`), because its contributor set changed.

### 8.3 Integrity rules (R-H1 SETTLED via B3; R-H2 OPEN for EDR-SCORING-01)

1. Staleness invariant (SETTLED in B1): every input change is its own trigger, so existing assessments are current. A stale one is a missed trigger (a defect), not a reason to recalculate everything at B1.
2. Idempotent (OPEN for EDR-SCORING-01, R-H2): the same event delivered twice creates no second revision and no second notification. Equivalent recalculation requests are de-duplicated. Every revision names its cause and source event. Even while the exact rule is open, duplicate event handling is an **implementation concern** the EDR must address: the bus is at-least-once.
3. Same inputs always give the same result.

### 8.4 Membership (DEPENDS EV-CURRENT-SBOM-1)

1. Evidence owns the effective SBOM and membership events. Governance never decides which SBOM is current.
2. Until EV-CURRENT-SBOM-1 exists: membership only grows (F4) and the roll-up uses every component. Removal is not simulated.
3. Removal: Evidence emits an immutable `component_removed` membership event. Governance updates its current-membership view. The component's assessment revisions are not touched. The roll-up gets a new revision. Absence alone never means `not_affected`.
4. Version upgrade (new PURL) = removal + addition. `replaced_by` is shown only when Evidence links them; never inferred from version similarity.
5. Scanner-report membership (KN-SCAN) stays with Evidence, outside this EDR.

### 8.5 Roll-up revisions

A roll-up revision is created whenever its state, score, contributors or coverage change, with its cause: a component-level revision (e.g. `component_added`, `applicability_changed`) or a membership event (`component_removed`).

### 8.6 Governance invariant

No assessment change, roll-up change, membership change, eligibility change, verdict change or source change ever changes a Finding's stage or Position by itself (A12). Whether a large roll-up rise on a suppressed Finding should raise a premise-drift signal is OPEN (section 10, O8).

---

## 9. Priority, exports, GUI

### 9.1 Priority (R-P1..R-P3 SETTLED; R-P4 OPEN for EDR-SCORING-01)

1. CVSS Base / Temporal / Environmental and Themis priority are different things.
2. The roll-up is an input to priority, never the priority.
3. First release runs in **shadow**: computed and shown, not used by priority or SLA.
4. (OPEN for EDR-SCORING-01, R-P4) Shadow exit needs measured results reviewed and approved: coverage %, old vs new distribution, Findings whose priority would change, Findings whose SLA bucket would change, material source disagreements, incomplete coverage, unexpected score changes. Duration alone is not enough.
5. (OPEN for EDR-SCORING-01, R-P4) Rollback: switching priority back must not delete assessment data.

### 9.2 Exports (R-X4 SETTLED; R-X6 OPEN for EDR-SCORING-01)

Kept as separate ratings, never collapsed: original source rating, Themis calculated rating, Themis governed rating, Finding roll-up, coverage. How each maps to CSAF and CycloneDX-VEX is its own design step: check each format's schema first; never present a Themis assessment as a vendor's.

### 9.3 GUI (SETTLED R-X1..R-X3)

Per Finding: roll-up state, score with its score status, contributors, scoring coverage, assessment finality and the unassessed list. Per component: eligibility and verdict (greyed when excluded or cleared), sources (linked duplicates as one row), selection status (selected / contested / unresolved) with all competing or unresolved candidates side by side, score status (final / provisional / unavailable) with "provisional" shown as a label on every number it applies to, selected source and rating with reason, each metric with its state in words (not defined / proposed / accepted by policy / accepted by user; proposed on its own line with accept / reject), CR/IR/AR with level, governed changes, final vector, three scores, "Calculation details" (inputs, versions, breakdown), history. Buttons only with the permission; the API checks again.

Every number in a GUI example or doc comes from the calculator or oracle, never by hand.

---

## 10. Dependencies and open questions

### 10.1 Dependencies (DEPENDS)

| Item | What this model needs from it | Status today |
| --- | --- | --- |
| **EV-CURRENT-SBOM-1** | effective SBOM; membership events (removed, reappeared, replaced_by) | design-gated backlog item; not built |
| **EDR-CORRELATION-01** | claim class semantics and re-delivery (F5) | built; used as is |
| **EDR-VERDICT-01** | occurrence verdict and its D4 switch (F6) | built; used as is |
| **GUI users and roles** (S2 on the 2026-11-10 list) | `security.score.override` and requirement-edit permissions | not built; blocks section 7 |
| **EDR-SYNC-01** | scope semantics for wider changes | S1/S2 built; S3 waits for the owner |
| **EDR-GOVERNANCE-01 D14** (disposition watcher) | only if O8 is answered yes | built |
| **EDR-KNOWLEDGE-01** | Proposals and precedence; to be amended for observations/ratings | built; needs amendment |
| **Incident step C** (rescan reminder) | possible resolution path for `no_components` | waits for the owner |
| **Knowledge card lifecycle** | CVE REJECTED -> `Superseded` (3.4 item 6) | `Superseded` stage exists; that REJECTED maps to it is **not verified**; stays a dependency until checked |
| **CVSS 4.0 calculator** | scoring v4-only components | separate future item |

### 10.2 Open questions (OPEN)

O1-O7 were CLOSED by the owner's decision on 2026-11-19, with the recommendations below.

| # | Question | Recommendation |
| --- | --- | --- |
| O1 | A vendor observation with a severity word but no vector (e.g. a Rocky word via OSV). Is it a selectable "source with no rating" (component unscored, like 4.0-only) or not selectable at all? | Not selectable as a CVSS rating; the word is kept and shown as source metadata. **owner v4.9: same.** **CLOSED 2026-11-19 by the owner decision, as recommended.** |
| O2 | Default temporal policy on day one: which evidence is "accepted by policy"? | Day-one policy accepts only an applicable vendor fix -> RL:O. The KEV **mapping** is settled, but its automatic **acceptance** waits for the shadow review (D22). **owner v4.9: same.** **CLOSED 2026-11-19 by the owner decision, as recommended.** |
| O3 | Existing releases before any CR/IR/AR is set get X (Environmental = Temporal). | Yes; no back-filled guesses. **owner v4.9: same.** **CLOSED 2026-11-19 by the owner decision, as recommended.** |
| O4 | Exact tie rule between two applicable vendor ratings. | **owner v4.9 (adopted):** no separate vendor tie-break. Reuse the existing model: different assessors -> `contested`, same assessor -> `assessor_self_inconsistency`, same vector -> agreement. Never recency. Add a mechanism only if real estate examples show a case these rules cannot represent. **CLOSED 2026-11-19 by the owner decision, as recommended.** |
| O5 | Shadow exit thresholds (9.1 item 4): numbers, not only metrics. | Set after the first measurement run; exit needs measured evidence and approval. **owner v4.9: same.** **CLOSED 2026-11-19 by the owner decision, as recommended.** |
| O6 | Export mapping per format (9.2). | Separate design exercise for CSAF and CycloneDX-VEX. **owner v4.9: same.** **CLOSED 2026-11-19 by the owner decision, as recommended.** |
| O7 | Should a NVD Primary rating that disagrees with the CNA be shown as "NVD disagrees" in the GUI? | Visible disagreement indicator; no change to selection authority. **owner v4.9: same.** **CLOSED 2026-11-19 by the owner decision, as recommended.** |
| O8 | Parked: does a large roll-up rise on a `not_affected` / `accepted_risk` Finding raise premise drift? | Decide with priority/SLA, not in the CVSS model. |
| O9 | Parked: per-component human `not_affected`. | Out of scope; would be a new governance concept. |
| O10 | Owner of RatingValidation (3.5). | **SETTLED by the owner 2026-11-18: Knowledge.** |
| O11 | Unresolved higher-class candidate with no calculable vector. | **CLOSED (D4): `unavailable`; lower-class rating not used provisionally.** |
| O12 | Unsupported independent peer. | **CLOSED (D9): supported assessment `selected`, condition `unscorable_peer_assessment`, provisional.** |
| O13 | Rule 3 lower-class maximum vs the owner's "based on B". | **CLOSED (D17): lower-class maximum preserved; only applicable, calculable candidates contribute.** "All lower classes" is SETTLED 2026-11-19 (section 13). |

---

### 10.3 Open items carried into EDR-SCORING-01 (group C, the owner decision 2026-11-19)

| Item | Where | Note |
| --- | --- | --- |
| R-H2 idempotent recalculation and duplicate event handling | 8.3 | the bus is at-least-once; the EDR must define it |
| R-O12 detailed target checks, scope semantics of wider governed changes | 7 items 2-3 | ties to EDR-SYNC-01 |
| Calculator / selection-policy change bulk mechanism | 8.2 last row | affected list, impact, regression report |
| R-P4 shadow exit criteria and rollback | 9.1 items 4-5 | thresholds after the first measurement run (O5) |
| R-X6 export rating kinds | 9.2 | with the CSAF / CycloneDX-VEX design (O6) |
| Temporal mapping rows other than KEV | 4.3 | day-one policy per O2 |

## 11. Test plan

Oracle: CVSS 3.1 specification examples and the FIRST reference calculator. Themis is never validated only against itself.

Categories: official examples, base-only, temporal, environmental (every M*, scope U and C), X handling, invalid vectors, 3.0 vs 3.1 Roundup, stated vs computed mismatch, reproducibility from snapshot, recalculation creates a revision, idempotent re-delivery, override removal, permission refused at the API, wider scope never overwrites local, roll-up (five states, ties, never zero), eligibility (scope always excluded), applicability (cleared excluded, empty = open), applicability filter (vendor never picked for a non-matching component), no capability fallback across sources, withdrawal (complete revision withdraws, fetch failure does not; one publication withdrawn leaves a linked publication active), linked duplicates counted once, rating immutability (status only via events), fingerprint canonicalisation (reformatted document = same revision), roll-up state order (all five), coverage not applicable on zero denominator, removal creates a roll-up revision and no assessment revision, unchanged fetch creates only a SeenEvent, failed fetch changes no rating state, one terminal event per publication (the owner's A -> B -> absent sequence gives exactly one `superseded`), republished identical content = new publication, RatingValidation reproducible from rating + calculator version, selection class follows assessor + context and never the publisher or feed (a CNA rating via NVD is `cna`; a CNA vector inside an OSV record is `cna`; a scanner vector with no stated assessor is `unattributed`), publication-level context prevents reusing a rating across packages in one document, identity linking (both asserted equal / different, one unstated with one or several candidates -> `ambiguous_link`, both unstated), capability fallback only within same assessor and class, unresolved candidate gives `rating_applicability_unresolved` and Partial/None coverage, unknown CNA gives `other_assessor` then `classification_changed` when learned, competing identities in one class ordered and flagged.

Selection-status cases (v4.5-v4.7):

| Candidates | Expected |
| --- | --- |
| other_assessor A 6.5, other_assessor B 8.2 (different vectors) | `contested`, provisional 8.2, neither selected; B's later date irrelevant |
| A and B same vector | `selected`, final, agreement shown |
| vendor_platform unresolved 9.1, cna applies 7.2 | `unresolved`, provisional 9.1, CNA "available, not selected" |
| vendor_platform unresolved 5.0, cna applies 7.2 | `unresolved`, provisional 7.2 (highest of the set) |
| vendor_platform unresolved, no vector; cna applies 7.2 | `unresolved`, score `unavailable`, reason `rating_applicability_unresolved`, CNA shown (O11) |
| cna 3.1 (10 Nov) and cna 4.0 (15 Nov), same assessor | step 5 sets 4.0 aside; `selected` 3.1, final |
| cna 4.0 only; nvd_analyst 3.1 | unscored `unsupported_cvss_version`; NVD "available, not used" |
| contested in `cna` and unresolved `vendor_platform` 9.1 | `unresolved` + contested candidates kept, provisional = highest calculable |
| contested, then an assessor-pair precedence entry is added | new revision `selected`, final; old provisional revision unchanged |
| linking order A vs order B (3.2a) | identical grouping |
| ambiguous link, one candidate identity withdrawn | `ambiguity_resolved` + `linked`, trigger `identity_relinked` |
| roll-up max from a provisional component | Finding score status `provisional` |
| 3 final + 1 provisional scored, 1 unavailable | scoring coverage 4/5 Partial; finality 3 of 4 |
| vendor publication (`vendor_platform`) linked to NVD copy (`cna`); then the vendor publication is withdrawn | before: vendor selected; after: NVD copy selected in `cna`; one identity throughout; never counted as two assessors (D1) |
| `cna`: A 4.0 only (8.5), B 3.1 (7.2) | A set aside "unsupported version"; B scored 7.2, provisional per D9; no lower-class fallback (D2) |
| `cna`: A 4.0 only, B 4.0 only; `nvd_analyst` 3.1 exists | `unavailable`, `unsupported_cvss_version`; NVD "available, not used" (D2) |
| A and B same vector, reversed org-id order | same score, class, roles and contributors; only the representative flag moves (D3, D24) |
| A 8.2 provisional, B 8.2 final | Finding 8.2 `provisional`, both contributors (D5) |
| A 7.5 provisional, B 8.2 final | Finding 8.2 `final` (D5) |
| linking-policy version changes, no new publication | every affected set recomputed; one AssessmentLink event per set with the complete grouping (D6) |
| independent disagreement vs same-assessor contradiction | both `contested`; conflict condition `independent_assessor_disagreement` vs `assessor_self_inconsistency` |
| `vendor_platform`: A applies 6.5, B unresolved 9.1 | outcome `selected` (A), condition `same_class_unresolved`, provisional 9.1 (D10) |
| `vendor_platform`: A applies 6.5, B unresolved 5.0 | `selected` (A), `same_class_unresolved`, provisional 6.5 (D10) |
| `vendor_platform`: A applies 6.5, B unresolved, no vector | `selected` (A), `same_class_unresolved`, provisional 6.5 (D10) |
| `cna`: A 4.0 only, B 3.1 7.2 | `selected` (B), condition `unscorable_peer_assessment`, provisional 7.2; A "available, not compared"; not `contested` (D9) |
| vendor class only unresolved (9.1) + lower `cna` A 6.5 vs B 8.2 disagree | outcome `unresolved`, conditions `higher_class_unresolved`; lower-class disagreement recorded on candidates; provisional 9.1 (D8) |
| `cna` contested + `unscorable_peer_assessment` in same class | outcome `contested`, both conflict conditions in the set, provisional = highest calculable (D8) |
| ambiguous NVD copy between A (A1, A2) and B (B1); A1 withdrawn | stays ambiguous; after A2 also terminal -> links to B (D11). Each step's AssessmentLink event is checked for the **complete** grouping (A1, A2, B1, NVD copy and their identities), not only the last link |
| linking-policy change makes identity A non-viable | viability and grouping both recomputed; AssessmentLink with complete grouping (D6, D11) |
| publication with no asserted context; observation applicability names family rhel; RPM component of rhel | inherited context -> effective context applies; class from effective context (D12) |
| publication asserts package P; observation applicability covers P and Q; component Q | `does_not_apply`; observation applicability never widens an asserted context (D12) |
| `vendor_platform` A applies 4.0; `vendor_platform` B unresolved 3.1 (9.1); `cna` C applies 7.2 | outcome `unresolved`, `higher_class_unresolved`, provisional 9.1; A `available_not_compared` (`unsupported_only`), no `unscorable_peer_assessment`; C `available_not_selected` (D13) |
| same, B unresolved 5.0 | `unresolved`, provisional 7.2 from C (rule 3 maximum; O13) |
| same, B unresolved with no vector | `unresolved`, `unavailable`, `rating_applicability_unresolved`; C not used (D4 + D13) |
| `vendor_platform` A applies 4.0 only, nothing else in class; `cna` C 7.2 | no outcome, `unavailable`, `unsupported_cvss_version`; C `available_not_selected`; no fallback (D2 + D13) |
| `cna` class: assessor X has A 3.1 (6.5) and A' 4.0, both apply; independent assessor Y in the same class has only 4.0 | `selected` A, provisional 6.5 because of Y (`unsupported_peer`, sets `unscorable_peer_assessment`); A' is `unsupported_same_assessor` and sets nothing (D9 + D13) |
| assessor X: package P applies 6.5, ecosystem unresolved 9.1 | `selected` 6.5, **final**; unresolved one `cannot_affect` (b) (D14) |
| assessor X: package P applies 6.5, another package-level statement unresolved 9.1 | `selected`, `same_class_unresolved`, provisional 9.1 (D14) |
| assessor X: ecosystem applies 6.5, package unresolved 9.1 | `selected`, `same_class_unresolved`, provisional 9.1 (more specific could win; D14) |
| assessor X: package applies 6.5, unresolved candidate with the same vector | `selected`, final; unresolved one `cannot_affect` (a) (D14) |
| assessor X package applies 6.5; assessor Y ecosystem unresolved 9.1 (same class) | `same_class_unresolved`, provisional 9.1; specificity never compares two assessors (D10, D14) |
| any revision | every candidate has exactly one disposition; reason present and from the closed list where 4.1b requires one (D15) |
| deciding class `selected` final; lower class has a disagreement and an unresolved candidate | score stays **final**; lower-class items appear only as dispositions/reasons, never in the condition sets (4.1a rule 6) |
| applicable vendor rating with an invalid vector, `cna` 7.2 present | no outcome, `unavailable`, `invalid_vector`; no fallback; diagnostics show the parser reason (4.1b rule 3) |
| A (vendor org) and B (CNA org) both `cna` class, apply, same vector X; C another assessor, same class, unresolved, vector Y | `selected`, contributing identities A + B (both `agreeing`), condition `same_class_unresolved`, **provisional** (D16, D24) |
| A and B agree on X; independent assessor D in same class has only 4.0 | `selected`, provisional, `unscorable_peer_assessment`; D `available_not_compared` (`unsupported_peer`) (D16) |
| `vendor_platform` A unresolved 3.1 (6.5); `cna` B applies 3.1 (7.2); `nvd_analyst` C applies 4.0 (9.8) | `unresolved`, provisional **7.2** from B; C `available_not_compared` (`unsupported_lower_class`), contribution none; A `unresolved` (`higher_class`) (D17) |
| `vendor_platform` A unresolved 6.5; `cna` B 7.2; `nvd_analyst` C 8.1; `other_assessor` D 5.0, all calculable and applicable | `unresolved`, provisional **8.1** from C (highest across **all** lower classes) (D17) |
| `vendor_platform` A unresolved 6.5; `cna` B applies with an invalid vector | `unresolved`, provisional 6.5; B `available_not_compared` (`invalid_lower_class`), contribution none (D17) |
| A and B different assessors, same vector X, both `agreeing` | two identities kept, each with its assessor and publications; GUI shows "2 assessors agree", never one merged row (D18) |
| assessor X: package P applies (vector X) and ecosystem unresolved (same vector X) | final; the unresolved one keeps its own identity and provenance, reason `cannot_affect` (a) (D18) |
| identity A has publications A1 (vendor site) and A2 (NVD Secondary), both in the deciding class; A selected | identity role `selected`; A1 `reference`, A2 `supporting` (`same_identity`); neither rejected; score counted once (D19) |
| identity A selected in `vendor_platform`; its linked NVD copy is in `cna` | NVD copy `available_not_selected` (`lower_class`), not rejected (D19, 4.1b rule 1) |
| no candidate at all | no outcome, `unavailable`, `no_applicable_rating` (or `no_vector`) |
| deciding class has only invalid vectors | no outcome, `unavailable`, `invalid_vector` |
| deciding class has one unsupported and one invalid candidate | no outcome, `unavailable`, `no_calculable_rating`; each candidate keeps its own reason |
| `cna`: assessor X 3.1 applies (7.2, valid); independent assessor Y applies, invalid vector | `selected` X, **final** 7.2; Y `available_not_compared` (`invalid_peer`), diagnostic flag `peer_rating_invalid`, no condition (D20) |
| `cna`: X 7.2 valid; Y 4.0 only; Z invalid | `selected` X, provisional 7.2 (from Y: `unscorable_peer_assessment`); Z `invalid_peer` + flag `peer_rating_invalid`; Y and Z keep distinct reasons and diagnostics (D9 + D20) |
| `cna`: X and Y contested; Z invalid | `contested`; Z adds no condition; flag `peer_rating_invalid` (D20) |
| X1: package P **asserted**, applies 6.5; X2 (same assessor): ecosystem E **inherited** from the observation, unresolved 9.1; P is in E | b fails (condition 2, U not asserted): `same_class_unresolved`, provisional 9.1 (D21 fix) |
| X1: package P asserted, applies 6.5; X2: context unstated (no inherited either), unresolved 9.1 | b fails (condition 2): provisional 9.1 (D21 fix) |
| X: package P asserted applies V1 (6.5); X: different CPE product asserted applies V1, incomparable | both `concurring`, both contributors, score 6.5 **final**, no `assessor_self_inconsistency`, flag `context_ambiguity`; two identities kept; representative by canonical key, not by context (D23, D24) |
| same as above, order of arrival reversed | identical **complete** identity grouping (every publication and its identity), same roles, same reference per identity, same representative identity and publication (D23, D24) |
| X: three incomparable asserted contexts, all identical vector V1 | three identities, all `concurring`; three `same_assessor_incomparable_context` relations; one representative; score final (D24) |
| A (assessor X) and B (assessor Y) agree on V1; A has publications A1, A2; B has B1 | A, B `agreeing`; A1 or A2 `reference` for A (step 7), the other `supporting` (`same_identity`); B1 `reference` for B, never `supporting` of A (D24) |
| X1, X2 (assessor X, incomparable) and Y1 (assessor Y), all V1 | all three `agreeing`; relations X1-X2 `same_assessor_incomparable_context`, X1-Y1 and X2-Y1 `independent_agreement`; flag `context_ambiguity` (D24) |
| representative-rule version changes | new revision, cause `selection_policy_changed`; only the representative changes; score, roles and contributors identical (D24) |
| any revision with several contributing identities | every contributing identity has exactly one `reference`; no `supporting` publication belongs to a different identity than its `reference` (D24) |
| `contested`: A 6.5 vs B 8.2 | contributing identities empty, competing identities A and B, no representative (D24) |
| component missing only an accepted temporal value (proposal pending) | scored with that metric at X; no `awaiting_review` reason (section 5 item 6) |
| X: package P **asserted**, applies 6.5; X: ecosystem of P asserted, unresolved 9.1 | final 6.5; U `cannot_affect` (b), all four conditions met (D21) |
| X: package-level rating applies only through **inherited** context 6.5; X: ecosystem asserted, unresolved 9.1 | b fails (condition 2): `same_class_unresolved`, provisional 9.1 (D21) |
| X: asserted package P applies 6.5; X: unresolved CPE product with no policy mapping to P, 9.1 | incomparable (condition 4): `same_class_unresolved`, provisional 9.1 (D21) |
| X: two applicable asserted contexts, incomparable, different vectors (X1 6.5, X2 8.2) | outcome `contested`; conflict condition `assessor_self_inconsistency`; competing identities {X1, X2}, both role `competing`; every **participating** publication of X1 and X2 (active, applicable, calculable, in the deciding class) disposition `competing`; any other publication of X1 or X2 keeps its own disposition per D26 (e.g. `unresolved`, `rejected`, other class); contributing identities empty; no `reference`, no `supporting`; no representative identity or publication; score provisional 8.2 with contribution recorded on X2 (D25; identical-vector case is D23) |
| A (assessor X) V1 6.5, B (assessor Y) V1 6.5, C (assessor Z) V2 8.2, all applicable, same class | `contested`, `independent_assessor_disagreement`; competing identities {A, B, C}; all publications `competing`; no representative; provisional 8.2 (D25) |
| X: asserted package P V1 and asserted ecosystem of P V2, both apply (comparable) | no conflict: package wins by specificity; `selected` P, ecosystem `not_selected` (`less_specific_same_assessor`); final (D25: comparability resolves, so no disagreement) |
| two contributing identities whose context strings sort in reverse order to their specificity | representative follows byte order only; score, roles and contributors unchanged; GUI never labels the representative as more specific (D24 note) |
| reference choice: P1 time 2026-11-10T10:00+05:30, P2 2026-11-10T04:30Z (same instant) | equal after UTC normalisation -> canonical publication key decides; same result in both arrival orders (step 7) |
| reference choice: P1 has a time, P2 none | P1 (known before missing); both missing -> canonical key (step 7) |
| **Test A (D26):** identity I (assessor X) has P1 (package context, applies, calculable, V1 6.5) and P2 (broad context, unresolved) in the deciding class; independent assessor Y has Q1 applies, V2 8.2 | `contested`, `independent_assessor_disagreement`; competing identities {I, Y's identity}, both role `competing`; P1 `competing`, P2 `unresolved` (`same_vector_as_competing_identity`, D26 rule 6), Q1 `competing`; no contributing identities, no `reference`, no representative; provisional 8.2 = highest among competing calculable assessments |
| identity I competing in `cna`; its linked NVD copy is in `nvd_analyst`; another publication of I is withdrawn | NVD copy `available_not_selected` (`lower_class`); withdrawn one `rejected` (`inactive`); neither `competing` (D26 rule 3) |
| **Test B (D27):** assessor X has applicable 3.1 V1 (6.5) and applicable 3.0 V3 (8.8) in the deciding class | 3.1 `selected`, final 6.5; 3.0 identity role `not_selected`, its publications `not_selected` (`lower_supported_version`), contribution none; not contested, not provisional; every publication exactly one disposition with its reason |
| assessor X 3.0 only (6.5), assessor Y 3.1 (8.2), different vectors, same class | `contested` (version preference applies only inside one assessor, D27) |
| assessor X: P1 3.1 applies, valid; identity J (3.0) with P2 applies, valid and P3 unresolved, valid | 3.1 `selected`, final; J role `not_selected`; P2 `not_selected` (`lower_supported_version`); P3 `unresolved` (`lower_supported_version_unresolved`), no condition, contribution none (D27) |
| assessor X: 3.1 applies, valid; 3.0 applies, **invalid** vector | 3.1 `selected`, final; 3.0 publication `available_not_compared` (`invalid_vector`), not `not_selected`; never made valid (D27 boundary) |
| **D28 (the owner's case):** A (X) applies V1 6.5; B (Y) applies V2 8.2; C (Z) unresolved V3 9.1; same class, all calculable | outcome `contested`; `independent_assessor_disagreement` + `same_class_unresolved`; competing identities {A, B}; C `unresolved` (`differs_from_competing_vectors`), not competing; provisional **9.1** with contribution on C; no contributors, references or representative |
| same, C unresolved V3 5.0 | `contested`, both conditions; provisional 8.2 (from B); C still recorded with contribution 5.0 |
| A (X) V1 6.5, B (Y) V2 8.2 contested; C (Z) unresolved with **V2** | C `unresolved` (`same_vector_as_competing_identity`), no condition, no contribution; C's own identity and assessor kept; provisional 8.2 (D28 row b) |
| A, B contested; C unresolved, no vector | `contested`, `same_class_unresolved`; C `unresolved` (`same_class`), contribution none; provisional 8.2 (D28 row d) |
| assessor X: 3.1 **unresolved** only; 3.0 applies, valid | D27 does nothing: 3.0 takes part in step 6 and is `selected`; the 3.1 one keeps `same_class_unresolved` unless D14 b holds; provisional if it could affect (D27 boundary) |
| source time `2026-11-10 10:00` with no zone | stored original `2026-11-10 10:00`, normalised `2026-11-10T10:00Z`, interpretation `zone_assumed_utc`; GUI shows the original and says the zone was assumed (3.1) |
| KEV listing for the CVE, day-one temporal policy (no KEV row) | E proposed E:F, metric used = X; score unchanged. After the policy adds the KEV row: new revision, cause `temporal_policy_changed`, E:F accepted by policy (D22) |
| `vendor_platform` applicable rating with an invalid vector; `cna` 7.2 valid | no outcome, `unavailable`, `invalid_vector`; `cna` `available_not_selected`; no fallback (4.1b rule 3) |
| old revision explained after source data changed | explanation comes from the stored candidate snapshot; no re-run needed |

Lifecycle cases:

| Revision | Source content | Expected |
| --- | --- | --- |
| R1 | rating A | A active |
| R2 | rating B in A's lineage, A absent | A `superseded` (by B); B active |
| R3 | rating C in B's lineage, B absent | B `superseded` (by C); C active; A unchanged (still one event) |
| R4 | rating C still present | no new event on A, B or C |
| R5 | C absent, no same-lineage rating | C `withdrawn` |
| R6 | content identical to C republished | new publication C' active, linked to C's assessment identity; C stays `withdrawn` |

Roll-up mixed-state cases (state order of section 6):

| Components (claim class / verdict / usable assessment) | Expected state | Coverage |
| --- | --- | --- |
| none current | `no_components` | not applicable |
| scope/open, scope/open | `no_carrier` | not applicable |
| scope/cleared, scope/open | `no_carrier` (no component passes eligibility) | not applicable |
| carrier/cleared, carrier/cleared | `no_open_occurrences` | not applicable |
| scope/open, carrier/cleared | `no_open_occurrences` | not applicable |
| scope/open, unknown/cleared | `no_open_occurrences` | not applicable |
| carrier/open/no usable, scope/open/usable | `unavailable` (the scope one never counts) | None |
| carrier/open/usable 6.5, carrier/open/no usable | `scored` 6.5 | Partial (1/2) |
| carrier/open/usable 6.5, unknown/open/usable 7.2, scope/open/usable 9.8 | `scored` 7.2 (scope 9.8 never counts) | Complete (2/2) |
| carrier/open/usable 7.2, carrier/open/usable 7.2 | `scored` 7.2, both contributors | Complete (2/2) |
| carrier/cleared/usable 9.8, carrier/open/usable 5.9 | `scored` 5.9 (cleared never counts) | Complete (1/1) |

**Candidate** cases, computed here with the 3.1 equations. They are **not** regression tests until each is independently confirmed with the FIRST reference calculator:

| Vector | Base | Temporal | Environmental |
| --- | --- | --- | --- |
| `CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:N/A:H/E:U/RL:O/RC:C` | 6.8 | 5.9 | 5.9 |
| same + `/CR:H/IR:M/AR:H` | 6.8 | 5.9 | 6.5 |
| same + `/CR:L/IR:L/AR:L` | 6.8 | 5.9 | 4.2 |
| `CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:N/A:H/RL:O/CR:H/IR:M/AR:H` | 6.8 | 6.5 | 7.2 |

---

## 12. Order of work (proposed; each step on the owner's go, one PR each)

| Step | What | Contexts | Visible change |
| --- | --- | --- | --- |
| S1 | Kernel CVSS 3.0 / 3.1 calculator: every metric with X kept, Base / Temporal / Environmental with Roundup, refusal with reason (R-C1..R-C6). Candidate vectors of section 11 checked against the FIRST reference calculator before they become regression tests | kernel `value` | none |
| S2 | Knowledge source truth: SourceObservation + SeenEvent, SourceRating per publication + SourceRatingEvent, RatingValidation, AssessmentIdentity + AssessmentLink; keep NVD Secondary and read its `source` (F10); fix the dropped Red Hat score (F11); read API. CVE.org feed (CNA + ADP) opt-in like the other feeds | knowledge | read API only |
| S3 | Registry requirements: CR / IR / AR on Product, Project, Release with reason, resolved per metric (4.4) | registry | registry API |
| S4 | Governance ComponentAssessment revisions inside the Finding, selection (4.1-4.1b), roll-up (6), lifecycle triggers (8), provenance API; **shadow**: priority and SLA unchanged | governance | provenance API |
| S5 | GUI, read only: "How Themis got this score" panel on the Finding (per component: candidates, outcome, conditions, score status, metrics with state, CR/IR/AR with level, history) and source ratings on the CVE page (9.3) | dashboard | yes |
| S6 | GUI users and roles (dependency), then governed changes: vector override, source selection override, environmental exception, change-vector form with preview (7) | dashboard, governance | yes |
| S7 | Shadow review with measured results, then the priority input switch (R-P4, 10.3) | governance | priority |
| S8 | Exports (R-X6, O6), CVSS 4.0 calculator (separate item) | communication, kernel | exports |

S1 to S5 are self-contained and keep today's priority, SLA, Jira and notifications unchanged.

**Release scope (owner decision 2026-11-20):** Themis 0.5.x carries S1-S5 (read-only GUI, shadow). S6-S8 follow in a later release.

### 12.1 S2 realization notes (2026-11-21)

How S2 maps the model onto the code. None of these change a rule of sections 3.1-3.5; each is a
choice the model left to the build, or a gap still open.

1. **One door.** Every feed path already folds through `FaultlineService.FoldProposal`. A feed attaches
   the source revision it parsed to a Proposal (`Proposal.WithObservation`, transport only: never
   persisted with the Proposal, never part of restatement detection), and the fold records it in the
   rating store first. CVE.org raises no Proposal, so its sweep records directly. The headline
   (`EnterpriseView.CVSS`, F8) and `BaseScoreFromVector` are unchanged; nothing reads the new tables
   yet except `GET /faultlines/{id}/ratings`.
2. **Unchanged means "equal to the latest revision"** of the same document. A document that changes
   back to an earlier content is a new revision (it can withdraw or supersede again), so the
   fingerprint is not unique per document.
3. **A publication carried unchanged** by a later revision of the same document keeps its first
   SourceRating; no copy is recorded per revision. A rating identical to a terminal one is a new
   publication (3.4 item 5a).
4. **Seen events** are recorded for successful fetches (`success_new_revision`,
   `success_unchanged`). Failed fetches stay on the existing `feed_health` rows (3.4 item 3: they
   change no rating state); per-document failure events are a follow-up.
5. **Assessor names** differ by publisher (NVD gives a contact address or UUID, CVE.org a short
   name). Linking policy `link-1` folds a short alias table (NVD, Red Hat, CISA ADP, GitHub, MITRE);
   an assessor not listed keeps its own name, so nothing is merged by guess.
6. **Feeds covered:** NVD (every metric of every version, Primary and Secondary, with `source`: F10),
   Red Hat (the document rides its first Proposal even without `cvss3`, so a complete revision without
   it withdraws the old rating: F11), Rocky (advisory severity word as observation metadata, O1),
   CVE.org (CNA + every ADP, opt-in `THEMIS_CVEORG_ENABLED`, F13). Alpine secdb states no severity
   word, so it records nothing. OSV ratings are not recorded yet.
7. **Residual gaps:** a Red Hat document that yields no Proposal at all, and an NVD record with no
   metric left, record no revision, so a rating they dropped stays active until a later revision of
   that document is seen.

### 12.2 S3 realization notes (2026-11-21)

1. **Records.** `registry_security_requirements` (migration 000005) is append-only: each change at a
   Product, Project or Release is a new row with CR, IR, AR (H / M / L / X), a required reason and
   actor, and the API key name when auth is on. The current value of a level is its latest row.
2. **Resolution** is per metric in the domain (`ResolveRequirements`): Release, then Project, then
   Product, then X with level `default`. X at a level states nothing, so the metric falls through.
3. **API.** `GET` / `POST /products|projects|releases/{id}/requirements` (history newest first;
   writing is a product write, like tags) and `GET /releases/{id}/requirements/resolved` (each
   metric with the level it came from).
4. **Not in S3.** The component exception (4.4 item 2) needs the S6 permission. R-E5 (list the
   affected Findings and recalculate as new revisions) is Governance's: Registry has no event
   outbox, so S4 reads the resolved requirements over the read seam, records the records it used,
   and a different current record is its `requirement_changed` trigger.

### 12.3 S4 realization notes (2026-11-21)

1. **Where it lives.** The selection (4.1-4.1b), the roll-up (6) and the cause rule are pure
   Governance domain code (`cvss_select.go`, `cvss_context.go`, `cvss_rollup.go`,
   `cvss_cause.go`), tested with the cases of section 11 at 100% coverage. The app ring
   (`ScoreService`) reads Knowledge's `GET /faultlines/{id}/ratings`, the card (KEV, fixes) and
   Registry's resolved requirements over the existing read seams; no cross-context import.
2. **Policy versions** recorded on every revision: `select-1`, `class-1`, `applicability-1`,
   `temporal-1`, calculator `kernel-cvss3-1`.
3. **Applicability policy `applicability-1`.** An effective context is a list of items. A CPE
   whose product scope can be placed is compared with the component's own scope (the kernel
   `ProductScope` used by EDR-VEX-02): same family and major applies, a known different one does
   not apply, an unplaceable component leaves it unresolved. Any other item applies only when one
   of its parts equals the component's name, source package or purl name. An inherited product
   list that does not name the component is `unresolved`, never `does_not_apply`. A single
   **asserted** package naming another package, or another ecosystem, does not apply; a bare
   asserted ecosystem is too broad (`unresolved`). An empty context is `unresolved`.
4. **Class policy `class-1`.** Vendor map: family enterprise-linux (RHEL, Rocky, Alma) -> the
   Red Hat assessor; no other family has a vendor yet. `vendor_platform` needs the context to
   name the platform (a platform CPE of the component's family) or to **assert** the package: an
   inherited product list in an NVD copy is not the vendor's platform statement, which keeps the
   step 6 example (the NVD copy is `cna`). The CNA of a CVE is the assessor of its CVE.org CNA
   container publications (publisher `cve.org/cna`); `adp` = `cisa-adp`; `nvd_analyst` = `nvd`.
   Knowledge now exposes the alias-normalised `assessor_key` so Governance compares assessors by
   one key. The assessor-pair precedence table is empty in this version.
5. **Context order.** unstated < ecosystem / family < package in that ecosystem. A CPE product, a
   product name without an ecosystem, a platform CPE against an ecosystem, and any list are
   incomparable (never ranked).
6. **Unresolved and not calculable.** An unresolved candidate whose vector is unsupported or
   invalid is treated like one with no vector: disposition `unresolved`, contribution none, and
   it sets `same_class_unresolved` where D10 / D28 row d would. This is the conservative reading:
   the uncertainty stays visible and never drops a condition.
7. **Temporal policy `temporal-1`** (O2): RL:O is accepted by policy when a published fix is
   attributable to this open component (the same rule as the Finding's fix list); KEV proposes
   E:F, which stays X. The assessment vector is the source vector's Base metrics plus the
   assessment's own temporal and environmental values; a source vector's temporal metrics are
   never used (4.3).
8. **Triggers and idempotency (8.2, 8.3, R-H2).** In shadow, one re-assessment sweep re-reads
   every Finding's inputs (at startup, then every `THEMIS_SCORE_SWEEP_INTERVAL`, default 6h; one
   read per card and per release per run). A revision is written only when the snapshot's content
   fingerprint differs from the current one, so a re-delivered or repeated trigger writes nothing.
   The cause is derived from the difference, in a fixed order: `component_added`,
   `calculator_changed`, `selection_policy_changed`, `temporal_policy_changed`,
   `eligibility_changed`, `applicability_changed`, `requirement_changed`, `source_added`,
   `source_withdrawn`, `identity_relinked`, `classification_changed`, `temporal_accepted`, else
   `source_corrected`. Event-driven triggers (shorter delay) are a follow-up before S7; the
   priority switch needs them.
9. **Membership.** A retired component gets no new assessment revision; the roll-up gets one with
   cause `component_removed`.
10. **Store and API.** Migration 000025: `component_score_revisions` and
    `finding_score_revisions`, append-only, JSONB snapshot (the complete candidate evaluation of
    8.1), numbered per component and per Finding under an advisory lock. `GET
    /findings/{id}/score` serves the current roll-up, the current revision per current component
    and the history. 200 without a roll-up means "not yet assessed".
11. **Failures.** A failed read (Knowledge, Registry, the store) writes nothing for that Finding:
    an assessment is never built from partial inputs. Without a Registry seam every requirement
    is X at level `default`.
12. **Known gaps.** A component whose platform cannot be placed (no `.elN` marker and no `distro=`
    qualifier) gets no `vendor_platform` rating. An RPM sub-package matches a product list only
    through its source package. Both read as `unresolved` (provisional), never as a hidden score.

---

### 12.4 VM check (task 5.3, 2026-11-23): PASS

On the test VM (Rocky and Alpine components, 1,058 Findings), after S1 to S5 were merged:

1. First sweep after a restart of all nodes: 16 of 1,058 failed with "connection refused" on
   Knowledge, because Knowledge was still starting. A failed read wrote nothing; the next run
   assessed them. Follow-up (not needed for shadow): let the first sweep wait until Knowledge
   answers.
2. Knowledge recorded source ratings for the first time over several minutes after its restart, so
   the second and third sweeps wrote revisions with cause `source_added` (and `component_added`).
   Once no new rating arrived, the fourth sweep reported `changed 0`: a revision is written only
   when an input changes (R-H2).
3. Current state: 660 Findings scored, 360 `no_carrier`, 38 `no_open_occurrences`. Components:
   5,004 RPM final; PyPI 71 final and 62 provisional; Maven 24 and Alpine 2 provisional.
4. RPM sample (CVE-2023-47038, perl on Rocky 8.10): Base 7.0 from
   `AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H`, RL:O from the applicable fix, 6.7 temporal and
   environmental, final; coverage 6 of 6 carriers, 31 scope packages shown as "scope, not counted".
5. Alpine sample (musl 1.2.5-r3, Alpine 3.20): Base 8.1, RL:O gives 7.7, provisional with
   `higher_class_unresolved`.
6. GUI: the Finding drawer shows "How Themis got this score" with the shadow chip, coverage,
   finality and per-component rows; priority and SLA unchanged.

## 13. Label audit (what the owner explicitly confirmed)

"Accepted" below means the owner wrote accept, preserve, retain, or verified the item as addressed in a review.

| Item | Label now | Where confirmed |
| --- | --- | --- |
| Three truths, Finding identity, component assessment by PURL, roll-up = max Environmental, A1-A16 | SETTLED | Option C approval (2026-11-17) |
| R-S5, R-C6, R-L3, R-L4, R-T3, R-E6, R-E7, R-O9, R-O10, R-P3, R-X5 | SETTLED | "I agree to all eleven additions" (v3 review) |
| SourceObservation + SourceRating[], polling dedup (R-S7, R-S8) | SETTLED | Q1 |
| Assessor / publisher / feed, linking (R-S6) | SETTLED | Q2 |
| Source then rating selection, no capability fallback (R-L6) | SETTLED | Q3 |
| KEV -> E:F (R-T6) | SETTLED | Q1-Q3 round |
| Eligibility, scope always excluded, `no_carrier`, `unavailable` (R-A2) | SETTLED | Part A |
| B1 incl. wider-scope at birth | SETTLED | B1 |
| Membership owned by Evidence, `no_components`, replaced_by (R-A3) | SETTLED | B2 |
| Withdrawal / correction lifecycle (R-H1) | SETTLED | B3 |
| Applicability = occurrence verdict | SETTLED | B4 |
| `no_open_occurrences`, state order, coverage denominator and Not applicable, SourceRatingEvent, per-publication withdrawal, removal = membership event | SETTLED | verified as addressed, v4.1 review |
| Fingerprint canonicalisation, rating identity incl. context | SETTLED | verified as addressed, v4.1 review |
| RatingValidation split (R-S13), SeenEvent (R-S11), terminal lifecycle rules (R-S12), `rating_applicability_unresolved` | SETTLED | verified as addressed, v4.2 review; "preserve" list, v4.3 review |
| RatingValidation owner = Knowledge (O10) | SETTLED | the owner, v4.2 review |
| Observation model, publication lifecycle, domain ownership | SETTLED | "Accept", v4.4 review |
| Three contexts, identity separate from publication, assessor/publisher/feed, selection classes with policy provenance, capability fallback inside same assessor + class, explicit unsupported / unresolved handling | SETTLED | "preserve" list, v4.4 review |
| Contested / unresolved with provisional conservative score; three status dimensions; provisional labelled everywhere; resolution = new revision; two coverage indicators | SETTLED | the owner decision 16:53 |
| D1-D7 | SETTLED | owner v4.5 review, section 5 |
| D8-D11 (outcome + condition sets, unscorable peer, same-class unresolved, viability rule for ambiguous links) | SETTLED | owner v4.6 review, section 7 |
| Complete candidate-evaluation snapshot (8.1) | SETTLED | owner v4.6 review P1-5 (recommendation adopted as written) |
| D12 observation applicability only via inherited publication context | SETTLED | owner v4.7 review, section 8 (recommendation adopted as written) |
| D13 outcome decided after capability filtering; class fixed before it | SETTLED | owner v4.7 review, section 8 |
| D14 principle: unresolved evidence that could affect the result keeps it provisional | SETTLED | owner v4.7 review, section 8 |
| D14 exception a (same vector / same identity), with D18 wording | SETTLED | owner v4.8 review, section 4 ("retain the exception") |
| D14 exception b, with D21's four conditions (condition 2 = **both** asserted) | SETTLED | owner v4.9 review; corrected per v4.9.1 review; "Accept", v4.9.2 review |
| D23 principle: identical vectors from one assessor across incomparable contexts are no disagreement, identities preserved, `context_ambiguity` diagnostic | SETTLED | owner v4.9.2 review, section 5 ("Accept") |
| D24 split of contribution / provenance / representation; contributing identities include `concurring`; `same_identity` only for the same identity | SETTLED as principle | owner v4.9.2 review, sections 2-4 |
| D24 symmetric roles, representative flag, canonical-key rule, per-identity reference, contributor-relation values | SETTLED (the owner decision 2026-11-19 13:06 (group A/B)) | the approach is mine (the owner offered two options; I took per-identity reference + one overall representative) |
| `concurring` role name, `context_ambiguity` flag name | SETTLED (the owner decision 2026-11-19 13:06 (group A/B)) | names are mine |
| `awaiting_review` removed from initial unscored set | SETTLED | owner v4.9.2 review, section 5 ("Accept") |
| Comparable-contexts wording, incomparable applicable contexts -> self-inconsistency | SETTLED (the owner decision 2026-11-19 13:06 (group A/B)) | wording is mine |
| D25 principle: context comparability is separate from assessment disagreement; contested needs different calculable vectors only | SETTLED (principle and outcome model) | owner v4.9.3 review P0; "Accept the D25 principle and its outcome model", v4.9.4 review |
| D25 detail: all conflict identities competing, all their publications `competing`, no reference / representative in contested | SUPERSEDED by D26 | publication-level `competing` covers participating publications only |
| Representative byte-order tie-breaker has no semantic meaning | SETTLED (principle and rule) | owner v4.9.3 review P1; "Accept the representative principle and rule", v4.9.4 review |
| D26 identity-level vs publication-level `competing` scope (five rules) | SETTLED as principle | owner v4.9.4 review P0 (rules adopted as written) |
| D27 lower supported version: 3.1 over 3.0 inside one assessor, 3.0 kept but out of competition | SETTLED as principle | owner v4.9.4 review P1 |
| `lower_supported_version` reason name | SETTLED (the owner decision 2026-11-19 13:06 (group A/B)) | the owner's suggested name; not yet confirmed |
| D26 and D27 main rules | SETTLED | owner v4.9.5 review, section 4 ("Accepted") |
| D27 publication-level dispositions and competition-only boundary | SETTLED as principle | owner v4.9.5 review P1, P2 (rules adopted as written) |
| D26 rule 6 (unresolved publication of a competing identity) and reasons `same_vector_as_competing_identity`, `lower_supported_version_unresolved` | SETTLED (the owner decision 2026-11-19 13:06 (group A/B)) | behaviour from the owner's v4.9.5 review; names are mine |
| D26 rule 6 and D27 fixes | SETTLED (behaviour) | owner v4.9.6 review, section 1 ("Resolved") |
| D28 principle: contested + differing unresolved -> stays contested, adds `same_class_unresolved`, contributes if calculable, never competing / contributor / representative | SETTLED as principle | owner v4.9.6 review, section 2 (suggested treatment adopted) |
| D28 rows b and d, and reason `differs_from_competing_vectors` | SETTLED (the owner decision 2026-11-19 13:06 (group A/B)) | row b (another identity with an equal vector) and row d (no vector) are mine |
| Timestamp evidence model (three values) | SETTLED in principle; value names and "no zone = UTC" SETTLED (the owner decision 2026-11-19 13:06 (group A/B)) | owner v4.9.5 review |
| Three-value source time (original, UTC instant, interpretation) and its values | SETTLED (the owner decision 2026-11-19 13:06 (group A/B)) | owner v4.9.4 review P2 recommended; value names are mine |
| Step 7 timestamp ordering (UTC, known before missing, canonical key) | SETTLED (ordering) | owner v4.9.4 review ("deterministic ordering is acceptable") |
| "No zone = UTC" | SETTLED (the owner decision 2026-11-19 13:06 (group A/B)), only as an explicit, recorded ingestion-contract assumption | owner v4.9.4 review 1.3 |
| D20 invalid peer sets no condition; diagnostic flag `peer_rating_invalid` | SETTLED ("Accept", v4.9.1 review); flag identifier SETTLED (the owner decision 2026-11-19 13:06 (group A/B)) | owner v4.9 and v4.9.1 reviews |
| Diagnostic flags are never conditions or score inputs | SETTLED | owner v4.9.1 review, D20 note |
| D22 mapping vs policy acceptance | SETTLED | owner v4.9 review P1; "retain D22 as written", v4.9.1 review |
| D15 one disposition enum + separate closed reasons | SETTLED | owner v4.7 review, section 8; "accept D12-D15 principles", v4.8 review |
| Exact disposition and reason values (4.1b) | SETTLED (the owner decision 2026-11-19 13:06 (group A/B)) | owner v4.9: "accept after invalid-peer resolution"; D20 now resolves it |
| "No outcome" when nothing is scorable before selection, and its separation from `unresolved` (4.1a) | SETTLED | owner v4.8 review, sections 6 and 9 |
| `invalid_vector` handling, with reasons separate from unsupported (4.1b rule 3) | SETTLED | owner v4.8 review, sections 7 and 9 |
| D16 agreement does not override provisional conditions | SETTLED | owner v4.8 review, section 2 (wording adopted) |
| D17 only applicable, calculable candidates contribute to a maximum | SETTLED | owner v4.8 review, section 3 |
| D17 lower-class contribution taken across **all** lower classes | SETTLED | owner v4.9 review, section 3 ("Accept") |
| D18 matching vectors do not collapse identities | SETTLED | owner v4.8 review, section 4 |
| D19 identity-level selection vs publication-level reference | SETTLED | owner v4.8 review, section 5 |
| Identity role values, `reference` / `supporting` names, `no_calculable_rating` | SETTLED | owner v4.9 review, section 3 ("Accept") |
| Context normalisation: policy-versioned, examples not universal (3.2) | SETTLED as a principle; the example rules stay SETTLED (the owner decision 2026-11-19 13:06 (group A/B)) | owner v4.9 review, section 3 |
| Outcome decision order and score rules 4-6 exact wording (4.1a) | SETTLED (the owner decision 2026-11-19 13:06 (group A/B)) | owner v4.9: "accept after the clarifications above"; D20-D22 are those clarifications |
| Class table rows (`vendor_platform` ... `unattributed`) | SETTLED as classes (v4.4 preserve list); exact row wording SETTLED (the owner decision 2026-11-19 13:06 (group A/B)) | |
| CNA source = CVE.org assigner; vendor map table; unknown behaviour; `classification_changed` causes | SETTLED (the owner decision 2026-11-19 13:06 (group A/B)) | not explicitly confirmed |
| Step order (version before identity), same-assessor specificity, step 7 org-id rule | SETTLED (the owner decision 2026-11-19 13:06 (group A/B)) | the owner recommended the order (v4.4 review); the exact rules are mine |
| Conflict-condition values | SETTLED | named by the owner (v4.5, v4.6 reviews) |
| R-H2 idempotent recalculation | OPEN for EDR-SCORING-01 (10.3) | never confirmed |
| R-O12 detailed target checks, scope semantics table (7 items 2-3) | OPEN for EDR-SCORING-01 (10.3) | never confirmed |
| Calculator-change bulk rules (8.2 last row) | OPEN for EDR-SCORING-01 (10.3) | never confirmed |
| R-P4 shadow exit criteria and rollback | OPEN for EDR-SCORING-01 (10.3) | never confirmed |
| R-X6 export rating kinds | OPEN for EDR-SCORING-01 (10.3) | never confirmed |
| Coverage / finality formulas as written | SETTLED | owner v4.9 review, section 3 ("Accept") |
| Unscored reason list | SETTLED, with extensibility discipline: each reason is a machine-readable code; explanatory text is separate; a new reason needs a policy-version change and a test | owner v4.9 review, section 3 |
| Temporal mapping rows other than KEV | OPEN for EDR-SCORING-01 (10.3) (proposals only; never count without policy or a person, D22) | default policy is O2 |
| R-L5 tie rule | CLOSED (O4: no separate tie-break; reuse contested / self-inconsistency / agreement) | the owner decision 2026-11-19 (group D) |
| O12 | CLOSED by D9 | |
| O13 | CLOSED by D17 | |

No PROPOSED rows remain. Group C rows are OPEN for EDR-SCORING-01 (10.3).
