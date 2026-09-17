# EDR-IDENTITY-01 — Component identity at intake (KN-SCAN-3b; the backlog's "EDR-1")

Status: **Accepted — spec grilled and agreed 2026-09-16, recorded here 2026-09-17** (the seven normative
rules below were settled with the user before any code; this EDR records them and draws the boundary
with EDR-3, which the backlog left ambiguous)
Date: 2026-09-17
Author: the httpd/claim-class trace (2026-09-16) → KN-CLAIM-1 / KN-SCAN-3b spec session

## Purpose

Engineering Decision Record for **component identity at the intake seam**: what Themis may treat as the
identity of an observed component, and what it must do when the evidence does not establish one.

The arc began as "why is this httpd finding not marked vendor-fixed?" and split into two problems that
were being treated as one. This EDR owns the first and hands the second an explicit boundary:

1. **Can an identity be established from the evidence?** — an observation with a name and no usable
   PURL. This EDR.
2. **What does it mean when a vendor's product name and a package name cannot be related?** —
   `http_server` (NVD's CPE product) vs `httpd` (the package). **EDR-3**, not this EDR. See D9.

It exists as its own horizontal because the 2026-07-31 parity audit's root-cause finding was that
per-context EDRs leave exactly this kind of concern ownerless: the identity decision is made in Evidence's
parsers, consumed in Knowledge's correlation, and enforced as an invariant in Governance's domain.

**Evidence base (measured on one real document, not read from code).** MRF/cdmrf-oamp, 2026-09-16:

- One SPDX document contains the SAME package **twice** — once `primaryPackagePurpose: LIBRARY` with a
  proper `pkg:rpm/rocky/httpd@…` external ref, once `APPLICATION` with `supplier: NOASSERTION` and **no
  `externalRefs` at all**. Same name, same `versionInfo`. **The duplicate originates upstream; Themis did
  not invent it.**
- **Two doors, one input, opposite answers:** the SPDX parser dropped the purl-less twin
  (`canonical_inventory` = 489 components, **exactly 1** httpd); the scanner path admitted its analogue,
  which then became a security subject on **60+ cards**.
- **The document carries NO CPE** — no `SECURITY`/`cpe23Type` ref on either twin — so a CPE-based identity
  bridge is **unavailable on this estate**. Two identity signals *are* present and discarded by the
  parser: `primaryPackagePurpose` and `supplier`.
- Those 60 rows are the same ones GOV-MIRROR-1 found diverged: the `app:` occurrences an out-of-band
  repair healed in Knowledge without emitting.

## What the grounding decided (before intuition)

- **An unknown ECOSYSTEM is a valid state of incomplete knowledge; an empty PURL is not an identity.**
  The two are routinely conflated and are not the same defect. `FixesFor` already models the first
  correctly — an unknown ecosystem filters nothing, so the drawer shows every fix with the
  confirm-install-method caveat, while `StrictFixesFor` stays fail-CLOSED so no verdict fires. Only the
  empty purl is broken. **Manufacture neither.**
- **Names are attributes of identity, not identity itself.** Every mechanism here compares names because
  names are what the evidence supplies; none of them may be read as having established identity.
- **The fail-safe direction is unchanged.** Every fail-safe that produced the observed defects exists to
  prevent false negatives. Nothing below weakens that: an unresolved observation stays unresolved and
  visible, never quietly reclassified as a bystander.
- **An empty PURL is already an availability hazard, not only a correctness one** (found 2026-09-16 while
  speccing this; not yet fired on any estate). `scanner_source.go` skips a finding only when **both**
  purl and name are empty, so a named component with no purl is accepted and recorded with
  `component_purl = ''`. The purl is in the PRIMARY KEY, so every purl-less component on one
  (release, card) **collapses onto a single row — merged by the ABSENCE of identity rather than a shared
  one.** Downstream is worse: `governance/domain/component.go` rejects an empty PURL,
  `AbsorbComponent` returns `errEmptyComponentURL`, and `governance/app/service.go` returns it OUT of the
  ComponentMatched handler — the inbox transaction rolls back and the D8 poison-halt stops the **whole**
  Knowledge→Governance stream. Cortex supplies a non-empty-but-unusable string, which is the only reason
  this has not fired; a scanner that simply OMITS the purl would stop the pipeline.

## Realizes (ADR/EDR traceability)

- **EDR-EVIDENCE-01** — evidence is immutable and content-addressed; this EDR adds no mutation of stored
  bytes. The raw identifier stays recoverable from `evidence.raw_document` (D5).
- **EDR-CORRELATION-01** — claim classes are untouched. An unresolved observation is NOT a bystander;
  conflating the two would be this EDR causing the defect EDR-CORRELATION-01 exists to prevent.
- **EDR-VERDICT-01 D2** — "record every examined occurrence": an unresolved observation is retained and
  countable, never dropped, for the same reason a cleared occurrence is recorded rather than deleted.
- **EDR-KNOWLEDGE-01 D5** — no new feeds; every input is already in hand.
- **Domain Invariant 3 ("Gathering Is Not Knowing")** — a scanner's identifier is *gathered information*.
  Resolving it to a canonical component is a deterministic computation over evidence already present;
  where that computation abstains, nothing is asserted.

## Decisions

### D1 — The design principle

*An unknown ecosystem is a valid state of incomplete knowledge; an empty PURL is not an identity.
Manufacture neither.* Every decision below follows from this sentence.

### D2 — Resolve a purl-less observation onto its twin, and ONLY when the twin is unambiguous

- **Exactly one** valid candidate on the same release matching by name+version → resolve the observation
  to that component's canonical PURL and proceed normally.
- **More than one** candidate → **ABSTAIN**; retain as unresolved.
- **Zero** candidates → **ABSTAIN**; retain as unresolved.

On the measured case the resolution is exact — same name, same version, the usable twin one entry away in
the same file. Abstention on ambiguity is the same shape as the D9 apk multi-bound abstention, and it is
why this is a convergence rather than a guess.

**Dedup is structural, not new machinery.** Resolved observations land on the twin's purl and collapse
under the existing primary key; the KN-SCAN-4a overlay already treats a repeat as a new observation of
the same occurrence.

### D3 — Never synthesize a PURL to satisfy the identity invariant

`pkg:generic/<name>@<version>` was considered and **REJECTED on measured evidence.** It is a structurally
valid purl (`NewPURL` accepts it; `CanonicalEcosystem` yields `generic`) — but **a purl TYPE is an
ecosystem claim.** `FixesFor` skips a fix whose ecosystem is known and different from the component's, so
a `generic` component would filter out every rpm-stamped fix, **stripping the operator of the fix advice
an EMPTY ecosystem currently shows them.** Synthesizing turns "we do not know the world" into "the world
is generic", which is strictly worse than the blank.

### D4 — Skipping the observation is also rejected

Skipping (what the SPDX parser does today) would hide real findings on a scanner-ONLY release, where
fail-open is the right direction. It is only safe when a twin exists — which is precisely the case D2
already handles. The asymmetry between the two doors is the defect, and closing it means one rule, not
one door adopting the other's behaviour.

### D5 — Never discard the underlying scanner evidence, and do not duplicate it

The report's bytes stay in `evidence.raw_document` (scanner reports retain bytes even though they produce
no inventory), so the raw identifier is **always** recoverable. `faultline_matches` has no column for an
observed identifier — the purl column IS the identity — so resolving it drops the raw string from that
row. **Read it back from Evidence on demand rather than adding a column:** the alternative duplicates
evidence Knowledge does not own, and the ownership boundary is worth more than the convenience.

### D6 — An unresolved observation SHALL be discoverable and countable, and surfacing ships WITH this change

It SHALL NOT be silently discarded, nor treated as a bystander. **Surfacing is part of this change, not a
follow-up** (KN-SCAN-OBS-1 / OBS-2). The lesson of the 2026-09-16 session, stated as a rule because it
cost a week: *a correct answer nobody can see is indistinguishable from a wrong one.*

### D7 — This is an availability fix as well as a correctness one

D2 removes the empty-purl population that can halt the Knowledge→Governance stream (see the grounding
above). It does **not** make the consumer resilient to a poison message — that is **PARITY-GAP F7** and
stays separate. Two independent defects; fixing the producer does not excuse the consumer.

### D8 — Accepted cost, stated so nobody re-litigates it

On a scanner-ONLY release (no SBOM, therefore never a twin) an unresolved observation does **not** reach
the Governance posture. That is materially different from losing it — the evidence is immutable and the
unresolved population is exposed by count — but it **is** a gap, and it is the price of not making an
ecosystem claim Themis cannot substantiate. The alternative (let Governance accept a marked unresolved
identity) preserves visibility but weakens the canonical-component invariant, which is a larger domain
change than this item should carry.

### D9 — The carrier-name synonym class is EDR-3's, not this EDR's — and the boundary is explicit

`http_server` (NVD's CPE product) and `httpd` (the package) share no substring and no token. This is a
**synonym**, not a name variation, and no string comparison can bridge it. The backlog carried two
readings of who owns it; this decision resolves them:

- **EDR-IDENTITY-01 (this EDR) owns whether an identity can be ESTABLISHED** from evidence in hand. For
  the synonym class it establishes nothing, because the measured document carries **no CPE** — the one
  signal that could have related the two vocabularies deterministically.
- **EDR-3 owns what a failure to establish identity MEANS** — the UNKNOWN rule: when carriers are known
  but none relates to any component on the card, the class is `unknown` (which acts as carrier) rather
  than `scope`. Validated 2026-09-16 against all four measured cards: the python card keeps `pyyaml` as
  scope because `python3` on that same card DOES match, so it is not a whole-card miss; the httpd, spring
  and perl cards have no matching carrier at all and would flip wholesale.
- **An alias table belongs to NEITHER.** `roleSuffixes` is vocabulary — a small closed set of packaging
  roles; `http_server → httpd` is data that grows forever and covers only what someone remembered. That
  is the line both reviewers rejected, and it must not be re-entered through an identity door.

**Measured cost of leaving it to EDR-3** — **CORRECTED 2026-09-17 after measuring the basis.** The
first figure written here was "174 `httpd` component rows, 148 cleared", taken from a row count. It is
**87 distinct httpd components, 74 of them `cleared_vendor_fix`** — so 74 verified clearances are
invisible to the GUI's cleared tile, which requires `carriers.length > 0`.

The doubling was not noise: every affected Finding carries httpd **twice**, once under
`pkg:rpm/rocky/httpd@…` and once under the raw scanner identifier `app:httpd@…`, and the two halves are
verdict-identical (74 cleared / 13 open on each side). **So half of what was attributed to the synonym
class is really the identity defect** — KN-SCAN-4(b), not EDR-3. Deduplicating those rows shrinks this
problem before EDR-3 touches it, which is why (b) comes first.

The lesson is about method rather than arithmetic: a row count is not a component count when identity is
the very thing in question, and this EDR is *about* identity. Count the subjects, not the rows.

## Validation criterion (binding on every phase)

On the measured MRF document, after this EDR ships:

1. The purl-less httpd twin resolves onto `pkg:rpm/rocky/httpd@…` — **one** component, not two subjects.
2. No component is recorded with `component_purl = ''` on any path.
3. An ambiguous or twin-less purl-less observation is retained, counted as unresolved, and visible.
4. `pkg:generic/` appears nowhere.
5. The SPDX and scanner doors agree on the same input.

## Phases (each independently shippable; `make check-ci` + vet-tags gate each)

- **Phase 1 — the rule.** Twin resolution at the scanner ACL seam (D2), abstention on ambiguity, no
  synthesis (D3). Domain/app tier at 100%.
- **Phase 2 — surfacing (D6).** The unresolved count exposed where an operator already looks; ships with
  Phase 1, not after it.
- **Phase 3 — the SPDX door (D4).** Bring the parser's behaviour under the same rule, so the asymmetry
  closes from both sides.

## Honest limits

- **Existing rows are NOT repaired by this.** Converging the current `app:` rows means changing a value
  that is part of the primary key — that is **KN-SCAN-4(b)**. The two are one piece of work from opposite
  ends; shipping this alone leaves current rows as they are.
- **No CPE on the measured estate**, so the identity hierarchy's strongest deterministic signal below
  PURL is untestable here. Any decision resting on CPE would be unverifiable and is therefore not taken.
- **No `CanonicalComponent` entity is created.** It was explicitly deferred: the measured problems are
  resolvable at the intake seam, and a new database entity is a larger commitment than the evidence
  currently justifies.
- **The producer-side note:** in the observed case the `app:` strings came from an external CSV→JSON
  converter that passed them through unchanged; that converter now rewrites rpm-shaped rows and reports
  the rest. The Themis-side asymmetry is filed and fixed on its own merits, independent of that.
