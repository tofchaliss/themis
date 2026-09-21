# EDR-VEX-02 — Vendor statement scope, and Themis's applicability determination (VEX-SCOPE-1)

Status: **Accepted — decided with the user 2026-09-17/18, every decision grounded in measurement
taken before it was made.**
Date: 2026-09-18
Author: the VEX-SCOPE-1 investigation (found by a reviewer reading one drawer line)

## Purpose

Engineering Decision Record for **what a vendor's `not_affected` statement covers, and who decides
whether it applies here.**

It exists because Themis had no answer to the second half. A vendor statement carried no product scope
at all, so a statement about one product could be presented against a release running another.

## The measured defect

A **Rocky Linux 8.10** release showed this vendor proposal on an httpd Finding:

> *vendor VEX: not_affected for httpd (Red Hat: not affected in Red Hat Enterprise Linux 7)*

RHEL 7 is not what the estate runs, and nothing said so.

**Mechanism, read from the code.** `domain.Applicability` is `{Package, Status, Justification}` — no
product field. Red Hat's Hydra document lists `package_state` per product, and `redhat_client.go`
dedups with a map keyed on **the package name alone**, so exactly one entry survives per (CVE, package)
and **which one is decided by its position in the array**. The product survived only as display prose,
via `productSuffix` → `" in Red Hat Enterprise Linux 7"`. Then `coveringStatement` takes the **first**
statement whose package the Finding covers — first-match on top of arbitrary survival.

**Measured distribution of surviving statements (≈907):**

| product | statements | applies to a Rocky 8.10 estate |
| --- | --- | --- |
| RHEL 6 | 207 | no — EOL |
| RHEL 7 | 193 | no — EOL |
| RHEL 10 | 130 | no |
| **RHEL 8** | **90** | **yes** |
| RHEL 9 | 87 | no |
| Hardened Images · Software Collections · JBoss Core Services · Ansible · OpenShift · Satellite · RHV · OpenJDK | ~170 | no |
| RHEL 5 | 30 | no — EOL |

**≈90% of surviving statements are scoped to products the estate does not run.**

**Impact measured before severity was claimed (CONVENTIONS R4):** 26 accepted `not_affected`
proposals, **zero** of them EOL-scoped; 60 of 171 pending ones EOL-scoped. The accepted rationales
confirm none came from the vendor path — 23 are the version-range path, 1 a supersession, 2 test/human.
**The guard is real and named:** the wired policy requires `TrustObserved`, vendor VEX is hard-coded
`TrustAsserted`, and `MaxTrust(Asserted, Observed) = Asserted`, so the floor is never met. The
composition root announces it at startup.

**So this is a HUMAN-DECEPTION risk, not an automation one.** Nothing auto-suppresses. The exposure is
a reviewer accepting a statement about another product — vendor statements being exactly the evidence a
reviewer trusts — or one policy change admitting Asserted evidence and suppressing all 60 at once.

## Decisions

### D1 — Three concepts, kept separate

    Statement
       ├── what the vendor ASSERTED       (evidence — immutable, theirs)
       ├── product SCOPE                  (what the vendor said it covers)
       └── APPLICABILITY to this release  (Themis's determination)

**Applicability SHALL NOT be encoded by modifying or interpreting the vendor's statement.** These two
sentences must stay distinguishable forever:

- *"Red Hat said httpd is not affected in Red Hat Enterprise Linux 7."*
- *"Themis determined that statement does not apply to this Rocky 8.10 release."*

Concretely forbidden: appending "(does not apply here)" to the justification; discarding the statement
so only Themis's conclusion survives; reusing the vendor's `Status` field to carry Themis's
determination; recovering the scope by parsing the justification prose.

This is Domain Invariant 3 ("Gathering Is Not Knowing") and EDR-VEX-01's *gathered, not obeyed*, applied
one level down — to the statement's SCOPE rather than its content. **External evidence stays evidence;
Themis determines its applicability rather than rewriting it.**

### D2 — Show and block; a mismatched statement is NOT "ignored"

The statement is displayed, marked, and unusable for disposition:

    Vendor said:        not_affected on Red Hat Enterprise Linux 7
    Themis determined:  does not apply to this release (Rocky Linux 8.10)
    Finding:            unaffected status NOT established

The applicability state is **visually and semantically explicit** — it must not render like an active,
applicable statement. The correct description is *a valid vendor assertion with `not_applicable`
scope*, never "ignored", which keeps **"no vendor statement exists"** distinguishable from **"a
statement exists and Themis determined its scope does not apply"**.

Hiding it was rejected: it would recreate the invisibility this arc has spent itself removing, and it
destroys the audit trail for exactly the situation that prompted the investigation.

### D3 — Three applicability states, keyed on the EVIDENCE, not on the outcome

| scope evidence | Themis determination |
| --- | --- |
| structured scope positively **matches** the release | `applicable` |
| structured scope is positively **known and does not match** | `not_applicable` |
| scope **cannot be reliably determined** | `unknown` |

### D4 — `unknown` is epistemic uncertainty, NOT product mismatch

The load-bearing distinction: **"I know this does not apply" ≠ "I cannot determine whether this
applies."** So `unknown` is reserved for a malformed, absent or unclassifiable scope — never used as a
catch-all for "not the product we run".

    RHEL 8               → enterprise-linux / 8      → applicable
    RHEL 7               → enterprise-linux / 7      → not_applicable
    OpenShift Pipelines  → redhat / openshift_pipelines → not_applicable
    malformed / absent   → cannot establish scope    → unknown

### D5 — Classify the product FIRST, then compare; never extract a version from a string

The CPE must not be treated as a string to pull a major number out of. The resolver **establishes the
CPE's product identity, then compares it against the release's structured identity.**

The measured reason: `cpe:/a:redhat:openshift_pipelines:1` has a perfectly valid version — `1` — that
has nothing to do with an OS major version. A resolver that extracted "the version" before establishing
"which product" would read that as major 1 and compare it against an OS release. That is the same
mistake class as deriving identity from a name.

    Vendor package_state
        └── structured CPE
              └── classify product scope
                    ├── enterprise-linux / N  → compare with the release
                    ├── known different product → not_applicable
                    └── unclassifiable         → unknown

### D6 — Equivalence at distribution FAMILY + MAJOR, not product-string equality

`Red Hat Enterprise Linux 8` and `Rocky Linux 8.10` both reduce to *(enterprise-linux, 8)* and match;
RHEL 7 and RHEL 9 do not. Explicitly **not** `contains("RHEL") && contains("8")`.

Themis already relies on this equivalence twice: the rocky feed skips RLSA as a 1:1 RHSA clone
(EDR-VEX-01 D11), and `RPMReleaseMajor` reduces `el8.10.0` to major `8` — which is the same pair the
release side yields, so both sides of the comparison come from structured data.

### D7 — Keep one statement per (package, PRODUCT); stop collapsing to one per package

The dedup key gains the product. `coveringStatement` must then select among the statements covering a
Finding's package by APPLICABILITY, not by array position.

### D8 — The vendor's statement is immutable and is never discarded

`Status` and `Justification` are the vendor's. An inapplicable statement is retained in full: it is
evidence about the world, and its inapplicability is a separate fact Themis owns.

## The structured scope exists and is simply unread

`package_state` entries **do** carry a CPE — measured 2026-09-18:

    {"product_name": "OpenShift Pipelines", "fix_state": "Affected",
     "package_name": "httpd", "cpe": "cpe:/a:redhat:openshift_pipelines:1"}

The DTO reads `product_name`, `fix_state`, `package_name` and drops the `cpe`. So D5/D6 need **no prose
parsing** — the DTO gains one field.

`redhatIsMainStream` already parses this exact CPE form (2.2 URI) on `AffectedRelease` to exclude
EUS/AUS/E4S/TUS. **It is implementation evidence that the parsing is feasible — not business semantics
to borrow wholesale.** The applicability decision is its own domain operation; that function answers a
different question (is this advisory a main-stream fix line?) and must not be repurposed to answer this
one.

### D9 — NON-GOAL: this EDR does not change the auto-accept trust policy

It determines whether a vendor statement **applies to the release**. It does **not** elevate the vendor
assertion from `Asserted` to `Observed`, and it does not alter any policy rule.

Stated as a decision because the two are easy to conflate, and conflating them would undo the guard this
investigation confirmed twice:

    not_applicable
        └── visible vendor evidence, cannot clear the Finding

    applicable + not_affected
        └── enters the EXISTING governance path
              └── still subject to the TrustObserved floor → still waits for a human

So `applicable` means *"this statement is about your release"*, never *"this statement may be acted on
automatically"*. Two independent barriers remain, and D2's block is aimed at the human path while the
trust floor is aimed at the automated one.

### D11 — Four states, because `unknown` was carrying two facts of different value

Decided 2026-09-21 after measuring the first cleanup run (`DEF_VEX_UNKNOWN_CONFLATES_TWO_UNCERTAINTIES`).
D3's three states were insufficient, and the insufficiency is **D4's own mistake one level down**.

The measured case — three of 138 rejections, and one of them is decisive:

    spring-web → "Red Hat build of Apache Camel 4 for Quarkus 3"   [unknown × 6]

Red Hat's side of that comparison is **perfectly clear**. It is Themis's side that could not be
placed: a Maven artifact carries no `elN` build, and nothing else on the Finding says which
distribution major the release is. That returned the same word as *"Red Hat named no product at
all"*, which is a feed-quality gap from which nothing follows.

    unknown  (before)
      ├── the vendor's statement could not be placed   → nothing follows; a feed gap
      └── the statement WAS placed, the release was not → a reviewer dismisses it instantly

So the state set becomes:

    ScopeMatch
      ├── applicable
      ├── not_applicable    — both placed, and they differ
      ├── unknown           — the VENDOR'S STATEMENT could not be placed
      └── not_comparable    — the statement was placed; the RELEASE was not

**The vendor side is tested first, so each word means exactly one thing.** When both sides fail,
`unknown` wins: evidence that cannot be read is the more fundamental gap, and that keeps `unknown`
from ever leaking the release-side case.

**`not_comparable` is ONE-SIDED, and therefore uniform.** Vendor-known plus release-known always
resolves through family/major, so the only route into it is a release that cannot be placed — a
fact about the Finding, not about any statement. Every statement on such a Finding reports it, and
that repetition is the signal rather than noise. It is also why the name describes the relation
instead of naming a role: a kernel value object should not carry Governance's word for one of its
operands.

**Safety, and why adding a state changed no behaviour.** Every governance check compares against
`ScopeApplicable`, so a fourth state is non-clearing by construction — asserted directly by
`TestScopeNotComparableIsNotApplicable` rather than left as a reading of the code. A new word is
not a new escape hatch.

**The rejected alternative, named because it is the tempting one:** widening `unknown` to cover the
release case, or reporting it as `not_applicable`. The first is what D4 already forbids; the
second would assert a comparison Themis did not make.

**Explicitly NOT solved here.** Themis still cannot place a non-rpm release against a vendor
product scope at all — a PyPI, npm or Maven component has no distribution major, so every Red Hat
statement about it resolves `not_comparable` however clear the vendor was. This decision makes that
gap **legible**; it does not close it. Closing it is a separate product-scope model question and is
tracked on its own.

### D10 — The scope is part of the STATEMENT, so it must round-trip through persistence

Recorded because it was violated within hours of the implementation landing, and the violation was
invisible in every test: the scope reached the read API, the event payload and the dashboard, but the
store codec's two applicability DTOs had no scope field, so it was recomputed on every fold and thrown
away on every save. Measured on the deployment: 1844 stored statements, every one reporting no scope
(`DEF_VEX_SCOPE_CODEC_DROP`).

Two consequences, and the second is the one that makes this a decision rather than a bug note:

1. Applicability degrades to `unknown` everywhere — the fail-safe direction, so nothing was wrongly
   suppressed, but D2/D3 stop being able to say anything at all.
2. **The reconciled view is compared for equality before every fold.** A field that is computed but not
   stored makes the view differ from itself on every reload, so the aggregate reports a view change that
   did not happen and re-announces `FaultlineEnriched` forever.

So the rule, and it generalises past this EDR: **any field added to the reconciled view or to a Proposal
payload must be added to the store codec in the same change, and guarded by a test that asserts a
repeated identical fold produces NO new event** — not merely that the field survives a round trip. The
presence test passes while the system loops; only the convergence test fails.

Stored as two flat fields (`scope_family`, `scope_major`), not a nested object, for the same reason the
read API emits them flat: a half-populated object must not be readable as an established scope. A record
written before the field decodes with an empty scope and therefore reads as `unknown` — which per D4
cannot suppress anything.

## Implementation sequence

Ordered so that each step is verifiable before the next depends on it:

1. **Extend the `PackageState` DTO with the CPE** — one field; the data is already on the wire.
2. **Preserve the vendor assertion unchanged** — `Status` and `Justification` stay exactly as received
   (D1, D8).
3. **Build the structured product scope** — classify the CPE's product identity FIRST (D5).
4. **Resolve applicability** → `applicable` / `not_applicable` / `unknown` (D3, D4, D6).
5. **Prevent an inapplicable statement from clearing a Finding** (D2).
6. **Keep the statement visible and auditable** — including when inapplicable (D2, D8).

## Validation order — and where to STOP

**Check the `unknown` population FIRST, before looking at whether the 60 pending proposals changed.**

> **If `unknown` is unexpectedly large, stop there.** That means the structured-scope resolver is not
> doing what D3/D4 intend. It is **not** permission to loosen the definition of `unknown` — which is
> precisely the temptation, because a looser `unknown` would make the numbers look reasonable while
> hiding a broken resolver.

Then the concrete matrix, on a Rocky 8.10 release:

| vendor scope | relation | expected |
| --- | --- | --- |
| `Red Hat Enterprise Linux 8` | same family + major | **`applicable`** |
| `Red Hat Enterprise Linux 7` | different major | **`not_applicable`** |
| `OpenShift Pipelines` | different product | **`not_applicable`** |
| missing / malformed CPE | insufficient evidence | **`unknown`** |

Then the governance consequence, which is what the whole change is for:

- `not_applicable` → the statement is visible and **cannot clear the Finding**.
- `applicable` + `not_affected` → enters the existing path and is **still held by the TrustObserved
  floor** (D9).

## Validation criteria

On the measured estate, after this ships:

1. The ~90 `Red Hat Enterprise Linux 8` statements read **`applicable`**.
2. RHEL 5/6/7/9/10 statements read **`not_applicable`** — visible, and blocked from disposition.
3. The ~170 non-OS product statements (OpenShift, JBoss, Software Collections, …) read
   **`not_applicable`** — a definite answer, not an open question.
4. **`unknown` is rare or zero.** A large `unknown` population means the CPE reading is failing, not
   that the estate is ambiguous — which makes this the criterion that falsifies the design.
5. No vendor `Status` or `Justification` is mutated; no statement is discarded.
6. The 60 pending EOL-scoped proposals become visibly `not_applicable` rather than silently pending.

## Honest limits

- **Why a particular product won the old dedup is unexplained, and must stay that way.** An earlier
  note inferred "Hydra lists oldest-first" from RHEL 6 winning 207 times; a sampled document's first
  entry is `OpenShift Pipelines`, so that inference is unsupported. The cause of record is
  **first-match/dedup behaviour**, not array ordering.
- **This does not change the auto-accept guard**, and does not need to: the Observed floor already
  keeps vendor VEX from auto-accepting, confirmed in code and in data. D2's block is a second,
  independent barrier aimed at the human path.
- **Non-Red Hat VEX sources are untouched here.** The generic CSAF path (`csafvex_client.go`) and
  uploaded VEX build the same `Applicability`; whether their scope is structured is not measured, so
  they inherit `unknown` until it is. That is the fail-safe direction under D4.
