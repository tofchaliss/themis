# Proposal — phase3-component-identity (KN-SCAN-3b: component identity at intake)

## Why

One SPDX document contains the same `httpd` package **twice** — once `primaryPackagePurpose: LIBRARY`
with a proper `pkg:rpm/rocky/httpd@…` external ref, once `APPLICATION` with `supplier: NOASSERTION` and
**no `externalRefs` at all**. Same name, same `versionInfo`. The duplicate originates upstream; Themis did
not invent it.

**Two intake doors gave opposite answers on that one input** (measured live on MRF/cdmrf-oamp,
2026-09-16): the SPDX parser dropped the purl-less twin (`canonical_inventory` = 489 components, exactly
**1** httpd), while the scanner path admitted its analogue — which then became a security subject on
**60+ cards**. Those are the same rows GOV-MIRROR-1 found diverged.

It is also an **availability** defect, not only a correctness one. `scanner_source.go` skips a finding
only when **both** purl and name are empty, so a named component with no usable purl is accepted and
recorded with `component_purl = ''`. The purl is in the PRIMARY KEY, so every purl-less component on one
(release, card) **collapses onto a single row — merged by the ABSENCE of identity rather than a shared
one.** Worse, Governance's domain rejects an empty PURL, `AbsorbComponent` returns `errEmptyComponentURL`,
and the app returns it OUT of the ComponentMatched handler — the inbox transaction rolls back and the D8
poison-halt stops the **whole** Knowledge→Governance stream. Cortex supplies a non-empty-but-unusable
string, which is the only reason this has not fired; **a scanner that simply OMITS the purl would stop
the pipeline.**

Grounded in **`docs/engineering/decisions/EDR-IDENTITY-01.md`** (D1–D9, spec agreed with the user
2026-09-16, recorded 2026-09-17), which is the source of truth for every decision, rejected alternative,
and honest limit. Tracked as **KN-SCAN-3b** in `docs/BACKLOG.md` (with KN-CLAIM-1 for the carrier half).

## What changes

- **Twin resolution at scanner intake (D2)** — an observation whose purl is absent or unusable resolves
  onto the canonical PURL of the release's own component when **exactly one** matches by name+version.
  More than one, or none, **ABSTAINS**: the observation is retained as *unresolved*, never guessed at.
- **Knowledge begins validating the purl (D1)** — via the existing kernel value object, not a new parser.
  It must be able to tell an identity (`pkg:rpm/rocky/httpd@2.4.57`) from a string (`app:httpd`), and it
  currently cannot: `value.NewPURL` is called only in Evidence today.
- **No synthesis, no skipping (D3/D4)** — `pkg:generic/<name>@<version>` is rejected on measured
  evidence (a purl TYPE is an ecosystem claim, and `FixesFor` would then filter out every rpm-stamped
  fix, stripping the operator of advice an empty ecosystem currently shows). Skipping is rejected too:
  it hides real findings on a scanner-only release.
- **Unresolved observations are surfaced (D6), in the same change** — counted and visible, never silently
  discarded and never reclassified as a bystander. This is where **KN-SCAN-OBS-1** lands: the existing
  `Skipped` counter is computed and never logged, so today both populations are invisible.
- **The SPDX door joins the same rule (D4, Phase 2)** — so the asymmetry closes from both sides rather
  than one door adopting the other's behaviour.

## Impact

- **Knowledge**: `ScannerReportService.PlanIngest` gains an identity-resolution step and two new port
  reads (release → correlated evidence id → canonical inventory) — the **same ports
  `ReverdictService.bridgeFor` already uses**, so no new seam. New app-ring resolver + unresolved
  population on `ScannerPlan`. **No migration**: resolution happens before a row is written, and the
  raw identifier stays recoverable from `evidence.raw_document` (D5) rather than being duplicated into
  `faultline_matches`.
- **Evidence**: Phase 2 only — the SPDX parser's purl-less handling comes under the same rule.
- **Governance, Communication, Intelligence**: untouched. The canonical-component invariant is upheld,
  not relaxed.
- **No new feeds, no new services, no new dependencies, no new database entity.** A `CanonicalComponent`
  entity was explicitly deferred: every measured problem is resolvable at the intake seam.
- **Accepted cost (D8), stated so nobody re-litigates it:** on a scanner-ONLY release (no SBOM, therefore
  never a twin) an unresolved observation does not reach the Governance posture. Materially different
  from losing it — the evidence is immutable and the population is counted — but it IS a gap, and it is
  the price of not making an ecosystem claim Themis cannot substantiate.
- `phase3-*` change: proposal/design/tasks + EDR are the source of truth, **no `specs/` deltas**;
  archive with `openspec archive phase3-component-identity --skip-specs -y`.
