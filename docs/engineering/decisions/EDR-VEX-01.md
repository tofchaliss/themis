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

## Not in scope (explicit non-goals)

VEX *export* fidelity (a separate serializer concern); cryptographic VEX signature verification (stub in both
trees); auto-accepting vendor VEX without a policy (forbidden by D4); rewriting `redhatACL` from vuln-facts to
applicability (Red Hat applicability is additive, not a replacement).

## Phased implementation (each its own PR, `make check-ci` green)

1. **Phase 1 — uploaded VEX onto the card.** D1 (Evidence `…/document` read endpoint) + D2 uploaded-trigger
   (Knowledge VEX parser + `kind==vex` coordinator branch + fold). Expose `applicabilities` on Knowledge's
   Faultline read API so the statement is visible. *Self-contained; reuses `vexACL` + the domain overlay.*
2. **Phase 2 — Governance suppression overlay (the payoff).** D5 (carry applicability on the seam) + D4
   (system `not_affected` Proposal on the Findings; policy/human accepts → suppressed). Delivers the
   user-visible behaviour for uploaded VEX end-to-end.
3. **Phase 3 — vendor VEX feeds.** B3 Red Hat CSAF fetch client (applicability + the vendor-severity
   vuln-facts path) + B4 generic CSAF/zip crawler — scheduled, relevance-bounded, feeding the same Phase-1/2
   machinery.
