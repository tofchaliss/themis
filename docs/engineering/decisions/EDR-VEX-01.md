# EDR-VEX-01 — Vendor VEX applicability: ingest, carry, and govern suppression (parity B3/B4 + VEX-ingest)

Status: **Accepted — design confirmed 2026-07-31** (grounded against the existing EDRs, which decide most of it)
Date: 2026-07-31
Author: parity-closure session (vendor-VEX cluster)

## Purpose

Engineering Decision Record for **vendor VEX / vendor advisory** support — so a vendor statement that a CVE
is `not_affected` (or a vendor's own severity) actually reaches a Finding instead of being ignored. Closes the
VEX-ingestion gap plus parity **B3** (Red Hat CSAF) and **B4** (generic vendor-VEX feed). The Faultline domain
already *carries* applicability (`EnterpriseView.Applicabilities`) but nothing produces it in a wired path, and
by explicit design it never *applies* it. This EDR wires the ingestion and locates the suppression.

Ground rule: **ADR/EDR wins; the PoC is reference only.** This EDR is subordinate to EDR-KNOWLEDGE-01 (D4/D6)
and EDR-EVIDENCE-01 (D2/D4/D6), which already constrain most decisions below.

## What the grounding decided (before intuition)

An initial instinct was "Evidence parses the uploaded VEX." **The existing EDRs override that** — recorded
here so it isn't re-litigated:

- **Evidence is a filing cabinet (EDR-EVIDENCE-01 D2/D4).** It stores raw bytes + a `kind` label and parses
  **SBOM standards only**; it deliberately does not turn VEX into meaning. `register.go` parses only
  `KindSBOM`; a `kind: vex` upload is stored raw and unparsed.
- **Knowledge turns VEX into an `applicability` Proposal (EDR-KNOWLEDGE-01 D6).** "VEX arrives two ways and
  both become an `applicability` Proposal: uploaded evidence (read via Evidence's API) or a Knowledge feed
  worker." The `vexACL` translator already emits exactly these Proposals — it is simply unwired.
- **`not_affected` must NOT suppress on the Faultline — by design.** `reconcile.go` holds applicabilities as
  an inert set ("held, not folded"); `priority.go` never reads them (`priority.go:10-11`: the VEX-state
  modifier is "deliberately NOT applied on the Faultline — a Governance concern"). The Faultline is
  CVE-intrinsic and release-independent, so it *cannot* suppress a release-scoped occurrence.
- **Suppression is a governed acceptance (Domain Invariant 3, "Gathering Is Not Knowing").** A gatherer
  produces *Information*, never truth; Information becomes truth only through an explicit governed step. So a
  vendor `not_affected` becomes a **system Proposal** a human/policy accepts — it never self-suppresses.

## Realizes (ADR/EDR traceability)

- **EDR-KNOWLEDGE-01 D6** — VEX (uploaded or feed) → `applicability` Proposal, held on the card; honoring it is
  Governance's call. **EDR-KNOWLEDGE-01 D4** — Knowledge reads Evidence via its read API, never its tables.
- **EDR-EVIDENCE-01 D2/D4/D6** — Evidence stores raw + kind, parses SBOM standards only, thin event carries
  kind; downstream reads contents via the read API.
- **Domain Invariant 3** ("Gathering Is Not Knowing") + **ADR-CON-0015 / ADR-INT-0066** (human authority) —
  suppression is a governed acceptance, not an automatic overlay.
- **EDR-KNOWLEDGE-01 D5** (relevance-bounded) — feed VEX enriches existing cards, never mirrors a feed.

---

## Decisions

### D1 — Evidence serves the raw VEX document; it does not parse it

Evidence gains a read endpoint returning the stored raw bytes of an evidence document (e.g.
`GET /api/v1/evidence/{id}/document`). This keeps Evidence a filing cabinet (EDR-EVIDENCE-01 D4) while giving
Knowledge the "read via Evidence's API" path EDR-KNOWLEDGE-01 D6 presumes but which does not exist today.

### D2 — Knowledge parses VEX → `applicability` Proposals (the ingestion, two triggers)

A **VEX parser** lives in Knowledge (`adapters/…`), turning a raw VEX document (OpenVEX / CSAF, and the
in-house dialect the current `vexACL` already accepts) into per-statement `applicability` Proposals
(`{Package, Status, Justification}` per CVE) via the existing `NewApplicabilityProposal`. Two triggers, both
funnelling to the existing kind-agnostic `FaultlineService.FoldProposal`:

- **Uploaded VEX** — the `coordinator.go` `EvidenceRegistered` handler gains a `kind == "vex"` branch: read the
  document from Evidence (D1), parse, fold each applicability Proposal onto the card by CVE.
- **Feed VEX** — a scheduled worker (parallel to the NVD watch / signal sweep), **relevance-bounded** (D5):
  Red Hat CSAF (B3) and a generic CSAF/zip crawler (B4). *Note:* the existing `redhatACL` emits **vuln-facts**
  (vendor severity/CVSS), not applicability — that is the *vendor CVE-details* half of B3 and is folded as a
  normal vuln-facts Proposal (precedence already ranks Red Hat authoritative for distro); Red Hat *applicability*
  is a separate statement folded like any other VEX.

### D3 — The card carries applicability; it never suppresses (unchanged domain)

No change to `reconcile.go` / `priority.go`. The reconciled `EnterpriseView.Applicabilities` continues to hold
the vendor statements verbatim. The Faultline stays CVE-intrinsic.

### D4 — Suppression is a Governance overlay via a system Proposal ("Proposal Before Truth")

When a Faultline carries a `not_affected` applicability relevant to a Finding's package, Governance raises a
**system `not_affected` Proposal** on the affected Findings — reusing the existing `ReactToEnrichment` +
system-proposer + policy-auto-accept machinery (the same path `FaultlineSuperseded` already uses). It **never
auto-suppresses**: a human accepts it, or a Governance policy does. Accepting it flips the Finding's Position to
not-affected, and it drops out of the effective posture — fully audited (append-only Proposal + Position).

### D5 — Applicability reaches Governance across the seam

The `FaultlineEnriched` integration event (or a companion) is extended to carry the reconciled applicability
statements (additive/optional, non-breaking per EVENTBUS D9), so Governance's inbound consumer can raise the
D4 Proposal without reading Knowledge's tables. (Alternative considered: Governance reads applicabilities from
Knowledge's read API — rejected as chattier; the event already flows on view change.)

### D6 — Precedence & justification are preserved

Applicability Proposals are append-only and reconciled by source precedence like any Proposal; a later vendor
statement supersedes an earlier one deterministically. The VEX `justification` is carried through to the
Governance rationale so a suppression is explainable (CON-0003 / CON-0016).

### D7 — Alpine secdb: fetch the branch DB, fold only carded CVEs (GUI-2, added 2026-08-12)

Alpine is the one distro in the estate with correlation but **no vendor fix data**: RHEL/Rocky/Alma get
severity + `not_affected` + fixed NEVRAs from D2/Phase 3, Ubuntu/Debian ride OSV, Alpine had nothing. The
authoritative source is the **Alpine secdb** (`https://secdb.alpinelinux.org/<branch>/{main,community}.json`)
— the same DB Trivy/Grype/OSV themselves derive from. *Alternative considered:* rely on OSV's Alpine
ecosystem records (already queried at correlation) — rejected because that path runs per component at
**upload time only**, so a fix published *after* the SBOM landed never reaches the card; the gap GUI-2
measured is precisely the enrichment half.

The secdb is **not per-CVE addressable**, so the D5-compliant reading inverts the Red Hat direction:
fetch the whole (small) per-branch DB, fold **only** the records whose CVE is already carded, and discard
the rest in memory — enrichment of existing cards, never a mirror; nothing about an uncarded CVE is ever
persisted. What it folds: one `alpine` **vuln-facts** Proposal per carded CVE carrying `Fixes`
(package → fixed apk version, per branch) and `SeverityUnknown` — the secdb states no severity/CVSS, and
the reconciled headline skips unknown severities, so the Proposal contributes fix bounds and nothing else.

Classifications (each build-enforced): **trust = Observed** (a public record, reproducible on re-fetch;
unlike Red Hat's feed it contains no judgment statements) · **tier = Tier-2 recommended** (the sole vendor
fix source for apk estates) · precedence unchanged (fixes union across sources; `alpine` never contends
for the severity headline). Branches come from `THEMIS_ALPINE_BRANCHES` (comma-separated) because no
machine-readable branch index exists; a configured branch the server lacks is a normal gap, not an error.

**Split out, exactly as Red Hat split PR2/PR3:** the **apk fixed-verdict** (a matched apk at/above its
branch fix opens no Finding — correlation's gate, the analogue of `value.RPMFixedByStream`) needs an apk
version comparator (`-r` revisions, `_alpha/_beta/_pre/_rc/_p` suffixes) with property tests, and ships
separately (decided in D9). Bounds-first already puts the published fix version on the posture, which is
most of GUI-2's measured value.

### D8 — Fix attribution is ecosystem-scoped, and NEVRA versions normalize once (KN-FIX-3, added 2026-08-13)

D7 created the first estate carrying two ecosystems' fix bounds on shared cards, and it made a latent
defect observable (**measured**: one Rocky EL8 `perl` Finding attributed FOUR fixes — the correct EL8
NEVRA, an Alpine apk version, an EL7 NEVRA, and the same EL8 fix twice under two normalizations).
`FixesFor(pkg)` keyed on the bare package name, `FixedVersion` carried no ecosystem, and Red Hat stored
fixes as full NEVRAs while OSV stored bare EVRs. The selection also populates the AI grounding
(`FaultlineKnowledge.FixedVersions`), so a wrong-ecosystem "published fix" rides into recommendations —
the AI-GROUND-1 class through a new door.

**The decision, in four parts:**

1. **`FixedVersion` gains `Ecosystem`** — the canonical ecosystem key (`rpm`, `apk`, `npm`, `pypi`, …;
   `""` = the source did not say), via a shared kernel canonicalizer so feed names ("Rocky Linux") and
   PURL types ("rpm") meet on one vocabulary. Each feed states what it knows: `redhat` → `rpm`,
   `alpine` → `apk`, OSV → per affected-entry ecosystem. *Alternative considered:* keying fixes on
   `(package, ecosystem)` pairs in a new structure — rejected; the additive field keeps every stored
   card and the v1 wire shape decoding unchanged.
2. **A known ecosystem is a filter; an unknown one is not.** `FixesFor` (and Governance's
   `selectFixesFor`) exclude a fix whose ecosystem is known and different from the asking component's;
   an empty ecosystem still matches everything. Same fail-open direction as `ClaimUnknown → carrier`:
   absence of attribution evidence must never hide a published fix — only *positive* evidence of
   mismatch excludes.
3. **One NEVRA normalization path, at reconcile time.** `Reconcile` normalizes every rpm-class fix
   version through the kernel's EVR extraction (name always stripped) *before* folding into the set, so
   the Red Hat form and the OSV form of the same fix collapse to one entry. Reconcile is where it
   belongs because the view is **recomputed from all Proposals on every fold** — normalizing there
   heals every persisted card with no migration, where a feed-side fix would only help future data.
4. **Decode-time source stamping heals the append-only history.** Proposals are immutable, so the 78
   live Alpine bounds (and every stored Red Hat fix) can never be edited to carry an ecosystem. The
   store codec — which already interprets legacy shapes (the KN-FIX-1 flat-list fallback) — stamps an
   *empty* fix ecosystem from the proposal's **source** for the single-ecosystem feeds
   (`redhat` → `rpm`, `alpine` → `apk`) on decode. Interpretation at the boundary, not mutation of the
   record: the stored bytes are untouched, and the next fold of any card re-derives a clean view.

**Display stream-scoping rides along:** Governance's per-Finding selection additionally excludes an
rpm fix whose `.elN` major is known and differs from the installed component's (the EL7-on-EL8 row),
reusing `value.RPMReleaseMajor`, fail-open when either side lacks a marker. The fixed-*verdict*
(`RPMFixedByStream`) was never at risk — it already refuses cross-stream and non-`.elN` compares — so
this is honesty of display and grounding, not a correctness gate. Excluded fixes join the
`UnattributedFixes` count rather than vanishing: "held but not attributable to yours" stays a
different statement from "no fix published".

### D9 — apk fixed-verdict: max-bound over strictly-stamped apk bounds (GUI-2b, added 2026-08-27)

The verdict half D7 split out. An apk component installed at/above its vendor fix must open no Finding —
the analogue of `value.RPMFixedByStream` — but the rpm verdict's soundness guard does not carry over:
rpm scopes the compare to the same EL stream **read out of the version string itself** (`.el8`), while an
apk version (`1.36.0-r2`) names no branch, and the D7 client deliberately discards the branch when
folding (bounds dedup across branches by `CVE|package|version`; `FixedVersion` carries no branch field).
A card can therefore legitimately hold two bounds for one package — v3.18's `1.35.0-r10` and v3.19's
`1.36.1-r0` — with nothing saying which is whose, and "installed ≥ *any* bound" would declare a v3.19
`busybox@1.36.0-r2` fixed by the v3.18 bound while it is live-vulnerable on its own branch: exactly the
cross-stream false-"fixed" the rpm guard exists to prevent.

**The decision, in three parts:**

1. **The max-bound rule.** `fixed` iff the strict apk bound set for the package is non-empty AND the
   installed version is at/above **every** bound in it (apk segment ordering — the kernel's existing
   `compareAPKVersion`, dispatched by `CompareVersions`; the comparator D7 anticipated already ships).
   If the component's own branch's bound is among the collected set this is provably sound (≥ all ⟹ ≥
   yours); when bounds disagree it errs toward "affected" — the safe direction, costing an operator a
   look, never hiding a live vulnerability. **Residual, stated honestly:** a component whose branch was
   not swept/published AND whose true bound exceeds every collected one can still read false-"fixed";
   Alpine bounds are near-monotone across branches, so the case is rare — and it is the trigger for the
   deferred precise model. *Alternative considered:* `FixedVersion` gains a branch/stream field, the D7
   client stops discarding branches, and the verdict scopes the component's PURL `distro=` qualifier
   (already extractable — the OSV client resolves it today) to the bound's branch — the true rpm mirror.
   Rejected **for now**: a domain-model change with store-codec/decode-healing surface (the D8 class of
   work) bought against a residual nobody has measured. Filed as **GUI-2c**, consciously deferred;
   revisit on a measured hit in either direction.
2. **Strictly-stamped bounds only — fail-open is for display, fail-closed is for verdicts.** The
   verdict's bound set is fixes positively stamped `Ecosystem == "apk"` (a strict domain accessor
   beside `FixesFor`), NOT the D8 fail-open set, which by design includes unknown-ecosystem fixes. On a
   shared card (the measured KN-FIX-3 `perl` estate) the fail-open set can contain an unstamped rpm
   NEVRA; under max-bound it would never prove anything but would silently block the verdict forever.
   The stamps are reliable exactly where it matters: the D7 feed stamps `apk` at the source, D8's
   decode-time healing stamps the persisted alpine history, OSV stamps per affected-entry. This is not
   a contradiction of D8 — it makes the standing asymmetry quotable: **D8's fail-open serves "never
   hide a possible fix" (display/attribution); the verdict's direction is "never decide on weak
   evidence" (fail-closed)** — the rpm verdict already lives by it, silently skipping every bound
   without a resolvable `.elN` marker.
3. **Match-time only, strict rpm parity — no retroactive healing.** The verdict lives in Knowledge's
   correlation (beside the rpm call), applies at upload and at each KN-RECOR-1 re-discovery pass, and
   never retracts an already-recorded match: a bound arriving *after* the match landed shows on the
   card, the drawer and the posture, and a human closes the Finding on that evidence — the governed
   path. Silent retraction would be delete-shaped machinery in an append-only system. Governance and
   Intelligence are untouched: the display twin's stream-scoping is rpm-only and **fail-open**, so apk
   bounds already pass through attribution unfiltered, and the Rule Engine decides off reconciled
   *ranges*, not fix bounds.

**Verified grounding (2026-08-27, read from code):** the package-name seam the verdict inherits already
works for apk — `componentPackage` prefers the component's `Source`, which Evidence's parsers fill from
the SPDX `upstream=` PURL qualifier / CycloneDX source properties, matching the secdb's origin-package
keying. **Live verification waits on an Alpine estate:** the VM estate ships none (the D7 feed was
deliberately switched off 2026-08-12), so the kernel table/property tests and the shared-card domain
tests carry the verdict; the smoke case when an Alpine estate exists is the two-branch `busybox`
scenario above.

## Not in scope (explicit non-goals)

VEX *export* fidelity (a separate serializer concern); cryptographic VEX signature verification (stub in both
trees); auto-accepting vendor VEX without a policy (forbidden by D4); rewriting `redhatACL` from vuln-facts to
applicability (Red Hat applicability is additive, not a replacement).

## Phased implementation (each its own PR, `make check-ci` green)

1. **Phase 1 — uploaded VEX onto the card. ✅ DONE (#73).** D1 (Evidence `…/document` read endpoint) + D2
   uploaded-trigger (Knowledge VEX parser + `kind==vex` coordinator branch + fold). `applicabilities` exposed
   on Knowledge's Faultline read API. *Self-contained; reuses `vexACL` + the domain overlay.*
2. **Phase 2 — Governance suppression overlay (the payoff). ✅ DONE 2026-08-01.** D5 (applicability carried on
   `FaultlineEnriched`, additive/optional so the frozen v1 wire is byte-identical when absent — EVENTBUS D9) +
   D4 (`ReactToEnrichment` raises a **system `not_affected` Proposal** on each Finding whose matched component a
   vendor `not_affected` statement covers, via `Finding.CoversPackage`; policy/human accepts → suppressed;
   never auto-suppresses). Delivers uploaded-VEX suppression end-to-end.
3. **Phase 3 — vendor VEX feeds. ◐ PARTIAL.**
   - **B3 Red Hat fetch client + scheduler — ✅ DONE 2026-08-01 (PR2).** `feed.RedHatClient` does the per-CVE
     relevance-bounded fetch of the public Hydra `securitydata/cve/<id>.json` (the legacy *working* path, not
     the dead CSAF directory crawl) → a vendor-severity **vuln-facts** Proposal (CVSS-gated) + a `not_affected`
     **applicability** Proposal per package Red Hat marks "Not affected". `app.RedHatEnrichmentService` sweeps
     the already-carded CVEs (no watermark needed — it re-reads `KnownCVEs`, so the singleton-`id=1` collision
     never arises). Precedence ranks `redhat` distro-authoritative. Covers RHEL and its 1:1 rebuilds (Rocky,
     Alma). `THEMIS_REDHAT_ENABLED`/`_URL`/`_POLL_INTERVAL`.
   - **RPM NEVRA/epoch fixed-verdict engine — ✅ DONE 2026-08-01 (PR3).** The kernel already had the
     `rpmvercmp`/epoch comparator (`value.compareRPMVersion`); PR3 added `value.RPMReleaseMajor` +
     `value.RPMFixedByStream` (EL-major, same-stream-only compare via `rpmEVR` NEVRA normalization), the Red Hat
     client now surfaces **main-stream** `affected_release` fix NEVRAs (excluding EUS/AUS/E4S/TUS via the CPE)
     into `VulnFacts.FixedVersions`, and correlation's gate drops a match when the installed rpm build is at/above
     its same-EL-stream vendor fix. **Conservative by design** — any parse/stream uncertainty stays *affected*, so
     a false "fixed" (the only unsafe direction) never occurs.
   - **B4 generic vendor CSAF-VEX feed — ✅ DONE 2026-08-01.** Realized **per-CVE** (relevance-bounded, D5),
     NOT as a bulk crawler: `feed.CSAFVexClient` fetches `<base>/<year>/cve-<id>.json` from each configured CSAF
     trusted-provider base (`THEMIS_VEXFEED_URLS`), `feed.parseCSAFVEX` resolves the `product_tree` PURLs to
     package names (the resolution the legacy naive parser skipped), and `app.VexEnrichmentService` sweeps the
     already-carded CVEs — folding `not_affected` applicability into the Phase-1/2 suppression overlay. The bulk
     CSAF-dir/zip crawl the parity line named was **deliberately rejected**: it would transiently mirror the whole
     vendor catalog (violating D5) — the same shape that left the legacy crawler always-empty. A zip/dir crawler
     for providers without a per-CVE endpoint remains a possible future addition.
