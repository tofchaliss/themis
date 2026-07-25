# Proposal — phase3-shared-kernel (Shared Kernel, M2)

## Why

The Phase-3 sprint plan builds the **Shared Kernel (M2)** *before* the four bounded contexts — it is the
common foundation every context depends on. It also resolves the forward dependency left open by
`EDR-EVIDENCE-01`: **who owns the Product → Release identity** that Evidence's `SubjectRef` validates.
Grounded in **`docs/engineering/decisions/EDR-KERNEL-01.md`** (D1–D4). Ground rule: **ADR wins; the PoC
(`internal/`) is reference only.**

## What

Two deliverables under the M2 "Shared Kernel" umbrella:

1. **A behavior-free value kernel** (`internal/kernel/`) — the universal ubiquitous-language value
   objects every stage speaks: **CVE-ID** (canonical/normalized), **PURL**, **content fingerprint
   (SHA-256)**, **CVSS** (score + vector), **Severity**; base primitives (typed-ID/UUID helper, clock);
   and the **integration-event envelope** contract. Gated by a strict 4-part admission rule (D3).
2. **The registry supporting context** (`internal/registry/`) — owns the **Product → Project → Release**
   structural identity (names, versions, membership) and exposes register + lookup, including the
   `ReleaseExists` query that backs Evidence's `SubjectRef`. Identity/structure only — **no security
   state**.

## Non-goals (deferred / owned elsewhere)

- **Outbox runner + event bus** — these have behavior; they belong to **Event Infrastructure (M5)**,
  seeded by Evidence's D7. The kernel provides only the event *envelope* contract (D4).
- **Findings, Enterprise Positions, release security posture** — owned by **Governance**, which
  references a Release (Book II §4.4; DOM-0022). Not here.
- **Artifact / image as a business entity, or image storage** — the domain has no Artifact concept; the
  image digest is Evidence provenance only (D2). Themis never stores images.
- **Context-owned aggregate IDs** (EvidenceID, FaultlineID, FindingID) and any business behavior in the
  value kernel.

## Realizes (ADRs / EDR)

CON-0001, CON-0006, CON-0011, CON-0014, DOM-0027, DOM-0028, DOM-0029, DOM-0032, BCK-0046, BCK-0048 — via
**EDR-KERNEL-01**.
