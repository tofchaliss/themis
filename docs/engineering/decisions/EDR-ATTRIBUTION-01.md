# EDR-ATTRIBUTION-01 — The carrier attribution gap (the backlog's "EDR-3")

Status: **Accepted — specification 2026-09-17.** The design this replaces was agreed in principle on
2026-09-16 and **invalidated by measurement on 2026-09-17**, before any code was written. That sequence is
the point: the premise was checked against the estate and did not survive.
Date: 2026-09-17
Author: the httpd/claim-class arc → the EDR-3 measurement session

## Purpose

Engineering Decision Record for what it MEANS when a Faultline's carrier products match none of the
components recorded against it.

The governing sentence, and everything below follows from it:

> **Zero match is an OBSERVATION, not an identity conclusion.**

## What the measurement decided (and what it killed)

The agreed design was: *when carriers are known but none relates to any component on the card, classify
`unknown` rather than `scope`* — "the UNKNOWN rule". It rested on a recorded claim that the python
module-stream cluster was protected, because `python3` on those same cards would match and make them
partial rather than whole-card misses.

**That claim is false.** Measured 2026-09-17 on MRF, post-retirement — the all-scope findings are:

| component | rows | correct class |
| --- | --- | --- |
| `python3-pyyaml` | 116 | **`scope` — correct** |
| `httpd` | 87 | `scope` — **wrong**, it is the carrier under another name |
| `python3-ply` | 66 | **`scope` — correct** |
| a ~6-each `perl-*` cluster, `javapackages-filesystem` | ~90 | mixed |

**The decisive case.** Finding `a3c6e965`, card `a8676695`, **CVE-2023-32681 — the `requests`
proxy-authorization leak.** Its only components are `python3-ply` and `python3-pyyaml`, both `scope`. There
is **no `python3-requests`** on the release: the estate has the rebuilt stream members installed and not
the package that carries the flaw. So every component on that card is a **legitimate bystander**, and
`scope` is right for both.

**Two situations, one observable condition, opposite correct outcomes:**

| | carriers | matches | correct outcome |
| --- | --- | --- | --- |
| `http_server` vs `httpd` | known | zero | the carrier IS installed, under another name |
| `requests` vs `pyyaml`/`ply` | known | zero | the carrier is genuinely NOT installed |

The UNKNOWN rule cannot tell them apart, because telling them apart IS the synonym question. It would
have broken **182 correct suppressions to fix 87 wrong ones** — re-opening precisely the module-stream
false positives EDR-CORRELATION-01 exists to prevent. **REJECTED on evidence.**

## Realizes (ADR/EDR traceability)

- **EDR-CORRELATION-01 D3** — the `carrier`/`scope`/unknown vocabulary is **unchanged**. This EDR adds an
  observation ABOUT a card's attribution, not a fourth class.
- **EDR-IDENTITY-01 D9** — that EDR owns whether an identity can be ESTABLISHED and hands the
  *meaning of failure* here. This is that answer: failure means a gap, not a verdict.
- **EDR-VERDICT-01 D2** — "checked and fine" must be distinguishable from "never looked". The same
  principle, one level up: *"attributed and unmatched"* must be distinguishable from *"we cannot attribute
  at all"*.
- **Domain Invariant 3 ("Gathering Is Not Knowing")** — a gap is gathered information about the limits of
  what was gathered. It asserts nothing about the world.

## Decisions

### D1 — The Attribution Gap is a state, and it is NOT a verdict

    carrier attribution gap  =  carriers exist  +  zero deterministic component matches

It says exactly one thing: **"Themis has insufficient identity evidence to attribute this carrier to an
installed component."**

It says **nothing** about whether any component is affected. It is not a severity, not a stance, not a
claim class, and nothing may treat it as one. The `requests` case proves why: zero correlation cannot by
itself mean affected, unaffected, or bystander.

### D2 — The gap must NOT be expressed as `unknown`

`unknown` already means something precise and different: *this component is treated as affected, its
attribution evidence is missing, and it therefore acts as a carrier* (EDR-CORRELATION-01 D3). Overloading
it with *"we cannot attribute this carrier to anything installed"* would give one value two meanings, and
every consumer would then have to guess which one it holds. **Two different statements, two different
places to record them.**

### D3 — The gap is DERIVED, not stored

`ClassifyClaim` returns `scope` **only** when the carrier set is non-empty and the component matched none
of it. Therefore, for a Finding whose components were classified against one carrier set:

    every active component is `scope`   ⟺   carriers exist + zero matches

So the gap needs **no column, no event, no migration** — it is a read-model derivation over data both
contexts already hold. Governance can compute it without knowing the carrier set at all.

**Its one precondition is classification currency**, which the re-classification sweep (KN-CLAIM-1,
shipped 2026-09-17) now provides: before that sweep, two components of one Finding could carry classes
stamped against different carrier sets, and the equivalence would not hold.

### D4 — The 182 module-stream bystanders keep `scope`

Their current classification is **supported by the evidence measured**. They are not reclassified to make
the system look conservative; conservatism that contradicts measured evidence is not caution, it is noise
that costs an operator 182 re-opened findings.

### D5 — The 87 httpd cases stay UNCHANGED until identity evidence exists

They are wrong today: `http_server` and `httpd` are the same software, and `scope` understates them. But
the fix requires evidence Themis does not currently hold, and **no rule available now can separate them
from D4's cases.** They are surfaced (D6), not reclassified.

### D6 — Surfacing is the deliverable, and it is what recovers the measured cost

The gap SHALL be exposed as a countable, visible state. The specific measured cost it recovers: of the 87
httpd components, **74 are `cleared_vendor_fix`** — verified clearances invisible to the GUI's cleared
tile, because that tile requires `carriers.length > 0`. Surfacing the gap lets the tile present them
**without asserting that any component carries the flaw**.

Honest in both directions, which is the whole point: the operator sees "74 verified clearances on cards
whose carrier we could not attribute", not "74 carriers".

### D7 — CPE is an evidence-ACQUISITION experiment, not the solution

The measured absence of CPE in the estate's SBOM is a property of **how that artifact was generated**, not
proof that CPE cannot exist. Syft can emit `cpe23Type` external refs. If it does, then
`cpe:2.3:a:apache:http_server` beside `pkg:rpm/rocky/httpd` makes the synonym **deterministic** — no
Themis-maintained synonym dictionary, which is the line every reviewer of this arc has refused to cross.

**It is not accepted as the answer.** Six preconditions must ALL hold before CPE becomes an
identity mechanism in Themis:

1. Syft emits the expected CPE for `httpd`.
2. The CPE survives the SBOM parser.
3. Themis retains it through the identity path.
4. NVD's CPE representation normalizes to the same identity.
5. The relationship holds for more than httpd.
6. A missing or wrong CPE fails SAFE rather than creating a false match.

### D7a — ATTR-CPE-1 RESULT (measured 2026-09-17): CPE is present, and insufficient

Phase B ran **without regenerating anything** — the evidence was already in the database.

| precondition | result |
| --- | --- |
| 1 · Syft emits the expected CPE for httpd | **NO.** It emits CPEs (6384 `cpe23Type` refs vs 548 purls, Syft 1.42.1), but httpd gets `cpe:2.3:a:httpd:httpd:…` and `cpe:2.3:a:rocky:httpd:…` — **never `apache:http_server`** |
| 4 · NVD's CPE normalizes to the same identity | **NO.** NVD's carrier is `apache:http_server`; the SBOM's are product `httpd`, vendors `httpd` and `rocky`. Comparing them needs precisely the `httpd` ↔ `http_server` mapping CPE was supposed to supply |
| 2, 3, 5, 6 | not reached — 1 and 4 settle it |

**Why, and this is the durable part: a GENERATED CPE carries no more identity information than the name
it was generated from.** Syft derives these heuristically from the package name, so they sit on the SAME
side of the vocabulary gap as the name. `httpd:httpd` cannot bridge `httpd` → `http_server` because it
*is* `httpd`, re-encoded. CPE here **moves** the synonym problem rather than solving it.

**And the generalization matters more than the measurement.** Any CPE that *could* bridge would have to
come from an authoritative source not derived from the package name — NVD's CPE dictionary, or a
vendor-authored SBOM. That is the alias table with extra steps, which this arc has rejected three times on
the same grounds each time.

**Conclusion: the Attribution Gap is not merely the current terminal state — it is the PRINCIPLED one**,
absent an upstream authoritative identity source. It stands, and it prompts no invented synonym mechanism.

**Scope of this finding, stated so it is not over-read:** it tests *Syft-generated* CPEs, which is what
this estate has. It does not prove no CPE could ever bridge — only that a CPE derived from the package
name cannot, which is a property of the derivation and not of this estate.

### D8 — Do not declare an identity hierarchy yet

`PURL → CPE → metadata → name` is **not** written as a normative hierarchy by this EDR. It is a
hypothesis until D7's six preconditions are measured. Declaring it now would repeat the mistake
this EDR exists to correct: encoding an invariant ahead of its evidence.

### D9 — The Attribution Gap is a TERMINAL state, not a provisional one

Settled after ATTR-CPE-1 (D7a). The gap is **not** an implementation placeholder waiting for a smarter
matcher. It is the **correct terminal state** when the available evidence cannot establish identity:

    Carrier
      ├── deterministic identity evidence exists  → correlate
      └── no deterministic identity evidence      → Attribution Gap

**Therefore the following are prohibited as "improvements" to it.** Each has been proposed and rejected
during this arc, some more than once, and each would convert an honest observation into a manufactured
conclusion:

1. **A synonym or alias table.** Rejected three times on the same grounds: it grows forever and covers
   only what someone remembered. `roleSuffixes` is a small closed packaging vocabulary; `http_server →
   httpd` is unbounded data.
2. **Guessing from name similarity.** Fuzzy matching over identity widens rather than narrows, and the one
   error identity comparison must never make is merging two different builds.
3. **Treating a CPE generated from the same name as independent evidence.** Measured false (D7a): a
   derived value carries no information about the thing it was derived from.
4. **Promoting NVD's CPE product names into package identities.** That is (1) entered through a feed
   instead of a table.
5. **Converting zero correlation into `unknown`.** The rejected rule. It breaks 182 correct suppressions
   to fix 87 wrong ones, because zero correlation collapses "installed under another name" and "not
   installed at all" (D1, and the CVE-2023-32681 case).

**What WOULD reopen this:** an authoritative identity source not derived from the package name — a
vendor-authored SBOM carrying real CPEs, or an upstream mapping Themis consumes rather than maintains.
Absent that, the gap stands, and surfacing it (D6) is the whole of the work.

## PROPOSED D10–D15 — explaining and gating the gap (ATTR-GAP-2, for review 2026-09-22)

**Status: PROPOSED, NOT ACCEPTED.** Raised by the user 2026-09-21 after a live walkthrough of
`CVE-2026-33006` — carrier `http_server`, installed `httpd`, both components `scope`, zero
proposals, and an AI "no answer". A textbook instance of the D5/D9 httpd cluster, and one of the
227 gaps the ATTR-GAP-1 tile already counts.

**The governing principle the user stated, and it is the reason these five are in this order:**

> *Improve the system's ability to EXPLAIN and RESOLVE uncertainty before improving its
> willingness to ELIMINATE uncertainty.*

That is the sibling of CONVENTIONS R4/R4c and it is what D9 already embodies. Recommended for
promotion to a convention in its own right. **The explicit non-goal: none of this makes the AI more
aggressive.**

Proposed order of work, which deliberately puts identity evidence LAST:

    1. the gap is explicit          → D10
    2. say WHY it is unresolved     → D11
    3. AI ineligible before invoke  → D12
    4. measure the gap's classes    → D13
    5. only then, evidence bridges  → D14

### PROPOSED D10 — The gap states its two sides, and `carrier_products` must cross the seam

A Finding must say *"vulnerability carrier: `http_server` · installed component: `httpd` · no
deterministic identity relationship established"*, rather than leaving a reviewer to infer it from
a `scope` label.

**The blocking finding, measured in code 2026-09-21: `carrier_products` does not reach Governance
at all** — absent from the Knowledge read API, from Governance's Knowledge client, and from the
assessment projection. `isAttributionGap` works today only because it needs nothing but the
components' claim classes (D3's equivalence). The dashboard therefore **cannot name the carrier**.

So D10 is not a rendering change: it is an additive field through Knowledge read API → client DTO →
`FaultlineKnowledge` → assessment schema → drawer. Two API contracts. **This is the first thing to
approve.**

### PROPOSED D11 — "Why unresolved" is DATA; "evidence required" is DOCUMENTATION

Split, because only one half is per-Finding:

    Why unresolved            → varies per card → a field
      • NVD supplied carrier: http_server
      • installed identity: httpd
      • no independent CPE identity (D7a)
      • no vendor identity mapping configured

    Evidence required         → IDENTICAL on all 227 → a link
      • vendor/package identity mapping
      • authoritative CPE mapping
      • other independent product identity evidence

A field whose value never varies carries no information, and persisting invariant prose into a
projection turns it into a CMS. The second block becomes one link to this EDR. **If D13 shows the
reasons diverge by class, the second block becomes data at that point** — not before.

### PROPOSED D12 — Promote the existing thinness predicate from a LABEL to a GATE

The predicate is **already written and already measured**. `domain.GroundingThinness` returns
*"N component(s), all scope-class (zero carriers) — no evidence any component carries the flaw"*,
and its comment cites a prior instance (CVE-2026-42496, 37 components from a module rebuild set).
It is computed **before any model runs**, and AI-204-2 deliberately applies it *only on the
insufficient exits* — as an explanation, never as a refusal.

So D12 is small: promote it to a gate. Measured cost of not doing so on `CVE-2026-33006` — two
invocations, 72s and 35s, output discarded both times by Grounding Verification.

**Gate on the ZERO-CARRIERS reason only**, not all three thinness reasons:

| thinness reason | gate | why |
| --- | --- | --- |
| all components scope-class ⇒ zero carriers | **yes** | there is no security subject at all |
| every carrier cleared by a vendor fix | no | there IS a subject, with a known disposition |
| no ranges and no fix versions | no | the model may still reason from the summary |

**A distinct outcome reason is justified** — *"not invoked, no grounded subject"* is a different
operator fact from *"invoked, model declined"*, which is precisely the argument the repo already
accepted for `budget_exhausted` (*"a distinct reason because the operator response is unlike every
other no-proposal"*). **Hard sequencing constraint: it must ship with or after
`DEF_GUI_AI_REASON_MAP_INCOMPLETE` (#116)**, or it renders as *"the Gateway stated no reason"* —
the exact defect diagnosed the same evening.

### PROPOSED D13 — Measure the gap's classes BEFORE inventing a taxonomy for them

The user's own instruction, and R4 verbatim: *"I wouldn't create this taxonomy yet. First measure
the attribution-gap population and see whether multiple stable failure modes actually exist."*

A `claim_reason` beside `claim_class` (`carrier_component_unresolved`, `carrier_missing`,
`component_identity_unresolved`, `ambiguous_carrier_match`) is **deferred** until the population
shows the classes are real. The discriminating measurement is cheap: carriers named but unmatched
versus **no carriers at all**. `vm-verify` reports the 227 as *"carrier named, none matched"*, so
`carrier_missing` may be a separate and currently uncounted population.

### PROPOSED D14 — Attribution is a PROJECTION. D3 already decided this.

The user proposed Attribution as a first-class structure on the Finding. The shape is right; the
location is not, and **D3 already settles it** — *"no column, no event, no migration … a read-model
derivation over data both contexts already hold."*

    Finding (aggregate)     ← stores NOTHING new
          └── FindingAssessment.Attribution     ← computed at read time
                   ├── carrier(s)      from the card (needs D10)
                   ├── component(s)    from the Finding
                   ├── status          derived via D3's equivalence
                   └── unresolved_because  derived (D11)

Two reasons beyond D3. Every field would copy a fact that already exists elsewhere, and copying
derived state into an aggregate is the generation-stamp trap hit twice in September — it is why
`DEF_GOV_RELEASE_SCOPE_FROM_FINDING` rejected stamping the scope onto the Finding at open. And the
shape has precedent: `FindingAssessment.VendorStatements` is exactly this — one read-time structure
the drawer, the queue and the AI all consume, owning no state.

This still delivers the user's goal of **one structured fact with three consumers**. It just does
not create a fourth place for it to go stale.

### PROPOSED D15 — Independent identity evidence: one candidate is ALREADY ingested, and must be measured before it is believed

The user's boundary is exact and unchanged from D7a: *"`httpd` → generate CPE → `httpd` → compare
CPE"* does not qualify, because the evidence was generated from the component name itself.

**The candidate: Red Hat's per-CVE `package_state`,** which names `httpd` directly. That is Red Hat
tracking *this CVE* against *that package name* — not derived from the customer's SBOM, so it is
independent in the required sense, and **it already flows into Themis** (this card's
`severity_source` is `redhat`).

**The trap, and it is this arc's founding observation.** A module-stream advisory rebuilds every RPM
in the stream and publishes a fixed version for each, so *"Red Hat shipped a fix for httpd"* is
**not** evidence that httpd carries the flaw. `CVE-2026-33006` is a module build
(`2.4.37-65.module+el8.10.0+40257+286895ef.9`).

So the question is narrow and empirical: does `package_state`'s **flaw-specific state**
(`Affected` / `Not affected` / `Fix deferred`) discriminate carriers from rebuild members, or does
it enumerate the whole stream as well? If it discriminates, there is an authoritative bridge already
in the data. If it enumerates, it is the same rebuild artifact in different clothing.
**This measurement belongs in D13's step, not D15's** — nothing is designed until it answers.

## Validation criterion

1. The gap is countable and visible, and equals the all-scope Finding population (227 measured).
2. The 74 cleared httpd components become visible WITHOUT any component's class changing.
3. `python3-pyyaml` (116) and `python3-ply` (66) keep `scope` — the guard this EDR exists to protect.
4. No component anywhere is classified `unknown` by a gap.

## Phases

- **A — specify the Attribution Gap** (this document).
- **B — the CPE experiment: DONE 2026-09-17, negative.** No regeneration was needed; the evidence was
  already stored. See D7a.
- **C — trace CPE end to end** — **not reached.** B failed at preconditions 1 and 4.
- **D — decide whether CPE belongs in the canonical identity model** — **decided: NO**, for
  name-derived CPE. Reopening requires an authoritative identity source, not a re-run.

## Methodology, recorded as a standing rule

The lesson generalizes beyond this EDR and is therefore **CONVENTIONS R4**, not a story told here: *a
design can be logically sound, feel conservative, and still be wrong when its TRIGGERING PREDICATE
collapses distinct real-world cases that require opposite outcomes.* Measure what fires a rule against the
estate before encoding it — including the population you expect it to exclude.

The `scope` ⟺ whole-card-miss equivalence is what exposed it here: the same predicate that makes the gap
cheap to derive (D3) is the predicate that made the rejected rule unsound.

## Honest limits

- **The 87 httpd cases remain misclassified** for as long as this EDR stands alone. That is a stated cost,
  not an oversight: the alternative breaks 182 correct answers.
- **The gap derivation depends on classification currency.** If the re-classification sweep stops running,
  the equivalence in D3 silently weakens. That coupling is real and belongs in whatever surfaces the gap.
- **`perl-*` and `javapackages-filesystem` in the all-scope population are a MIXED set** — some genuine
  bystanders, some vocabulary failures — and this EDR does not separate them either. Same reason.
