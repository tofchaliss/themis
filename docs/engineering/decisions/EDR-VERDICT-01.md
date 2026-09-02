# EDR-VERDICT-01 — Per-occurrence verdicts and the ownership bridge (KN-VERDICT-1)

Status: **Accepted — grilled and confirmed 2026-09-02** (all eight decisions taken with the user in one
session; evidence measured live before any decision)
Date: 2026-09-02
Author: KN-VERDICT-1 case session (CVE-2025-47273 / MRF investigation → grill)

## Purpose

Engineering Decision Record for the **KN-VERDICT-1 fix arc**: a vendor-backported fix that Themis had
fully ingested could not clear a live finding, and the finding's single all-or-nothing Position could not
be honest about a release carrying two copies of the same package with opposite truth values. This EDR
decides the occurrence-level verdict model, the RPM→language-package ownership bridge, re-verdict timing,
queue semantics, remediation selection, and the GUI shape — as one cross-cutting arc with a single owner,
because the 2026-07-31 parity audit's root-cause finding was that per-context EDRs leave exactly this kind
of horizontal concern ownerless.

**Evidence base (measured, not read from code):** CVE-2025-47273 on MRF/cdmrf-oamp/R20.1.0.0-118,
verified live 2026-09-02 — the card held the exact bound `python-setuptools 0:39.2.0-9.el8_10 (rpm)`,
the `redhat` proposal had folded, feed health was honestly green, the image carried the patched
`platform-python-setuptools-39.2.0-9.el8_10` (changelog names the CVE) — and the finding stayed open
because its component is `setuptools@39.2.0 (pypi, source empty)`. Full case file:
`docs/BACKLOG.md` → KN-VERDICT-1, and the published report
(claude.ai/code/artifact/b57b9622-c500-4a8e-9e10-6503bdb91210).

## What the grounding decided (before intuition)

- **The feeds are not the defect.** Red Hat's Hydra data was fetched, folded, reconciled; Rocky's
  RLSA-2025:11044 is a 1:1 clone the `rocky` feed rightly skips (EDR-VEX-01 D11). Red Hat's record says
  RHEL 8 is *affected → fixed via RHSA-2025:11044*, NOT `not_affected` — so the Phase-2 suppression
  overlay correctly never fires and the only path that can clear the finding is the Phase-3 rpm
  fixed-verdict.
- **A name map cannot fix it (measured).** The language-package row carries bare `39.2.0` — no build
  release — so an rpm compare against `0:39.2.0-9.el8_10` is undecidable from that row alone. The bridge
  is two hops (file → binary RPM → source package); hop two already exists (`componentPackage`'s
  source-wins rule); hop one is ownership evidence only the inventory can supply.
- **The fail-safe direction is preserved.** Every fail-safe that produced this false positive exists to
  prevent false negatives. Nothing below weakens that: clearing requires affirmative evidence, and every
  undecidable input keeps the occurrence open.
- **"Overlays, never deletes" governs the whole arc.** A clearance is recorded state with a stated
  premise — never a silent row deletion. Match rows are never removed, only stateful.

## Realizes (ADR/EDR traceability)

- **EDR-GOVERNANCE-01 D1** — the (Release, Faultline) Finding business key is **upheld** (D1 below).
- **EDR-VEX-01 Phase 3** — `RPMFixedByStream` / EL-stream scoping is **reused unchanged** as the
  comparator; this EDR changes where its verdict lands, not how it is computed.
- **EDR-CORRELATION-01** — claim classes (`carrier`/`scope`/unknown-as-carrier) are untouched; only
  carrier occurrences drive queue state (D7).
- **EDR-TRUST-01** — the bridge's two evidence grades are expressed as the existing trust classes
  (Observed / Inferred), not a new vocabulary (D3).
- **EDR-KNOWLEDGE-01 D5** — no new feeds; every input to the verdict already lives on the card or in the
  inventory.
- **Domain Invariant 3 ("Gathering Is Not Knowing")** — a clearance is a deterministic computation over
  gathered evidence, honestly labeled with its evidence grade; the Inferred grade exists precisely so a
  guess is never presented as knowledge.

## Decisions

### D1 — The decision unit stays (Release, CVE); verdict state moves to the occurrence

One Finding per (release, CVE) remains the unit of human decision. Each component row (an **occurrence**)
under a Finding gains its own verdict state. A Finding leaves the triage queue only when every *carrier*
occurrence is cleared or covered by the Position. **Rejected:** splitting Findings per component (count
explosion ~3×, repeated decisions on the same CVE, breaks EDR-GOVERNANCE-01 D1, every projection, the
disposition watcher, and the AI's one-Finding grounding); status quo (a single Position over occurrences
with opposite truth values is dishonest in one direction or the other — measured: marking the Finding
`not_affected` for the patched RPM copy would silently suppress the genuinely-vulnerable pip copy).

### D2 — Record every examined occurrence, with its state; one recording path

Discovery and scanner-report intake unify into a single record-then-judge path: every examined occurrence
is recorded, and the verdict sets its state instead of silently dropping the match. States (initial
vocabulary; design.md owns the enum): `open` · `cleared_vendor_fix` (with evidence grade + reason).
"Checked and fine" becomes a visible row, so silence never has two meanings ("checked, fine" vs "never
looked" were indistinguishable in the live investigation — the missing rpm-setuptools row could not be
explained from the data). This also closes **link (b)** (scanner matches took no verdict) by unification
rather than by a parallel gate. **Rejected:** silent drops (the measured ambiguity), scanner-only gating
(two code paths for one meaning).

### D3 — The ownership bridge: two evidence grades through the existing trust classes

A language-package occurrence may be cleared by an rpm fix only via an **owning-RPM** connection:

- **Observed grade** — the SBOM carries an explicit ownership relationship (e.g. Syft's rpm→python
  edges): file → binary RPM → source package, then the existing source-wins rule meets the fix
  attribution. Pure evidence.
- **Inferred grade** — no ownership edge, but the SAME inventory holds an rpm component whose **source
  package equals the fix's attributed package** AND whose **upstream version segment equals the language
  row's version** (39.2.0 == 39.2.0), same release. A careful, labeled guess.

Both grades clear (subject to the unchanged EL-stream rpm comparator on the owning RPM's full EVR); the
grade is stored on the occurrence and always shown. A configuration switch (design.md names it) disables
the Inferred grade entirely for strict estates. **Clearing requires all of:** owning rpm present in the
inventory with full EVR · same EL stream · fix attributed to its source package. Anything less keeps the
occurrence open. **Rejected:** name-map table (version evidence missing — see grounding); Observed-only
(zero coverage on the motivating estate, and the pressure to weaken it later would arrive without design
scrutiny).

### D4 — An Inferred clearance removes the occurrence from the queue by default, clearly labeled

The label states plainly that Themis matched it itself ("matched to vendor package X at the distro
version — inferred"), distinct from the Observed label ("the scan document confirms this belongs to X").
Rationale: a Red Hat estate produces hundreds of these; leaving them half-on-the-list rebuilds the noise
the arc exists to remove. Strict mode (D3 switch) is the escape hatch. **Rejected:** downweight-until-
human-confirms as the default (someone must click through hundreds once, for a guess whose failure mode —
a pip install of the exact distro version — is rare and visible in the drawer).

### D5 — Knowledge owns the verdict; Governance mirrors it; humans stay Governance's alone

The occurrence verdict is a fact about software ("these files carry the fix") — Knowledge computes it
(all inputs live there: card fixes, inventory, comparators; it is the same comparison correlation already
performs once today) and stores it on the match record. Governance receives it over the existing event
seam (additive fields / a state-change event beside `ComponentMatched`), mirrors it on
`finding_components`, and re-derives queue state. Human decisions (accept risk, not affected) remain
exclusively Governance's book; the drawer shows which kind of "handled" each label is. **Rejected:**
Governance computes (would duplicate the comparator and need new read seams for the card's fixes and the
inventory).

### D6 — Re-verdict: immediate on real card news, plus a self-targeting catch-up sweep

- **Immediate:** when a fold actually changes a card's fix set (the KN-PROPOSAL-BLOAT-1 rule already
  makes "changed" mean real news, not a feed restating itself), Knowledge re-verdicts the occurrences
  matched to that card — a direct index lookup, nothing else touched.
- **Catch-up:** every match record carries a stamp, "verdict checked against card version N", written at
  record time. A bounded, interval-configured sweep (the KN-RECOR-1 / KN-FIX-2 pattern) picks records
  whose stamp is missing (all pre-existing rows — the MRF finding IS history) or behind their card,
  re-verdicts, stamps. Idempotent; a completed sweep writes nothing; downtime self-heals because stamps
  lag. **Rejected:** trigger-only (never heals history — the motivating finding would stay flagged
  forever); sweep-only (hours of latency for news whose arrival moment is precisely known).

### D7 — Full urgency while any carrier occurrence is open

Priority (effective and residual) is computed from open carrier occurrences ONLY, at full value; cleared
occurrences contribute zero; there is no proportional discount. A finding whose every carrier occurrence
is cleared or decided leaves the queue — that is where the noise reduction comes from. **Rejected:**
proportional scoring (nine cleared copies would drag one live path-traversal to a tenth of its urgency —
a live copy is not diluted by dead neighbours).

### D8 — Per-occurrence remediation, selected by the occurrence's own ecosystem

Each open occurrence gets the fix that matches its world: rpm-owned → the rpm bound; language-package →
the upstream ecosystem's fix already on the card ("upgrade to 78.1.1+"). Cleared occurrences get nothing.
`plan_remediation`'s deterministic pre-prompt grouping becomes (package, world) so "update the RPM" and
"upgrade the pip install" emerge as distinct work items. Unknown world → show the upstream fix with an
explicit "confirm how this copy was installed" caveat, never a guess. Module-stream bounds keep their
KN-MODULE-1 labeling and non-preference.

### D9 — GUI: the card is the headline; the drawer tells the per-occurrence story

The Faultline/Finding card stays the list row. The drawer lists occurrences with state, evidence-grade
label, plain-language reason, and per-occurrence fix advice — the measured case renders as: `setuptools
39.2.0 · cleared — vendor backport (owned by platform-python-setuptools-39.2.0-9.el8_10)` above
`setuptools 70.3.0 · open — below upstream fix 78.1.1, pip-installed`. Cleared rows sit in a quiet
section below open ones.

## Validation criterion (from the measured case — binding on every phase)

The fix is validated on CVE-2025-47273 / MRF only when: the 39.2.0 occurrence is **cleared with its
stated reason and grade**, the 70.3.0 occurrence is **still open** with the upstream-fix advice, and the
Finding is **still in the queue** at full urgency. A validation that celebrates "the CVE went away" has
validated the wrong outcome.

## Phases (each independently shippable; `make check` + vet-tags gate each)

1. **The record book** — occurrence state + grade + reason + checked-version stamp on match records;
   unified record-then-judge intake; additive event fields; Governance mirror + queue derivation (D1, D2,
   D5, D7).
2. **The bridge** — both grades + the strict-mode switch, applied at record time; per-occurrence fix
   selection on the read path (D3, D4, D8 read side).
3. **The re-verdict** — fold-change trigger + catch-up sweep with stamps. *This phase clears the MRF
   finding's historical rows* (D6).
4. **The face** — drawer per-occurrence view + labels; plan grouping by (package, world) (D8 plan side,
   D9).

## Honest limits

- The Inferred grade can be wrong exactly one way: a hand-installed copy of the exact distro version
  beside the patched RPM would be cleared. Rare, labeled, and switchable off; the drawer keeps it
  auditable.
- Observed-grade coverage depends on SBOM tooling: Syft emits ownership edges; Trivy's analyzers do not.
  Estates on Trivy-only documents run on the Inferred grade until their tooling changes — the labels make
  that visible rather than hidden.
- The bridge covers RPM ↔ language-package ownership. The same shape exists for deb and apk worlds; this
  EDR deliberately ships rpm-first (the measured case) and leaves deb/apk as recorded follow-ups, not
  silent scope creep.
- Priority projections and the compare read gain a new input (occurrence state); their consumers must
  treat missing state as `open` (fail-safe direction), so mixed-version fleets stay correct during
  rollout.
