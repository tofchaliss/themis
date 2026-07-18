# EDR-KERNEL-01 — Shared Kernel (M2) Realization

Status: **Grilled — ready for issue breakdown** (4 decisions locked)
Date: 2026-07-14
Author: architecture grilling session

## Purpose

Engineering Decision Record for the **Shared Kernel** — the shared foundation built **before** the four
bounded contexts (Phase-3 sprint M2). Its first job is to resolve the forward dependency left open by
`EDR-EVIDENCE-01` (D5): **who owns the Product → Project → Release → Artifact identity** that Evidence's
`SubjectRef` validates against. Ground rule: **ADR wins; the PoC (`internal/`) is reference only.**

## Realizes (ADR traceability)

- **Constitution:** CON-0001 (single ownership), CON-0011 (bounded contexts = unit of ownership),
  CON-0014 (business capability separation)
- **Domain:** DOM-0027 (stable identity), DOM-0028 (aggregate relationships preserve ownership),
  DOM-0029 (global vs release-scoped state), DOM-0032 (business relationships are explicit);
  Book II Ch.4 (Products/Projects/Releases)

## Grilled against (PoC reference slice)

`internal/domain` (`version.go`, product/project/version model) and the `products` / `projects` /
`versions` / `artifacts` schema.

---

## Decisions (resolved)

### D1 — Split structural identity from governance state; ADRs held on top (K-Q1)

The **shared registry** (Shared Kernel) owns **only the structural identity** of
Product → Project → Release → Artifact — names, versions, membership, image digests — and holds **no
security state**. **Governance retains full ownership of Findings, Enterprise Positions, and release
security posture** (Book II §4.4; Domain Invariant 4; DOM-0022): the Release remains the governance
boundary, and Governance *references* the release identity and hangs its release-scoped state off it.

**ADR consistency (ADR stays on top):** CON-0001 (single owner) — identity and governance-state have
distinct single owners ✓; DOM-0029 (global vs release-scoped) — this split **is** that distinction, so it
*realizes* the ADR rather than bending it ✓; Book II §4.2/§4.3 (Products/Projects don't own
findings/positions) ✓; Domain Invariant 4 (Release = governance boundary) unchanged ✓. Also respects the
one-way flow: the registry sits above all four stages, so upstream Evidence referencing it never depends
on downstream Governance.

*Rejected:* Governance owns the whole hierarchy (identity + state) — forces upstream stages (Evidence) to
depend on a downstream context, violating the directional model.

### D2 — No Artifact entity; Evidence's subject is the Release; image digest is provenance (K-Q2)

The domain model has **no Artifact/image concept**: the ubiquitous language (Book II §2.3) and hierarchy
(§4.1) stop at **Product → Project → Release**, and the Release is the boundary. Per **ADR-wins**: the
registry owns **Product → Project → Release only**; Evidence's `SubjectRef` targets the **Release**; the
**image digest is recorded as provenance on the Evidence record** (Book II §5.7 — "Evidence retains
provenance"), never modeled as a business entity and never stored as the image itself. Users register
Products/Releases (few, deliberate); the digest rides along per upload — **zero per-build burden, zero
image storage**.

*Rejected:* Artifact as a first-class registry entity with Evidence pointing at it (the PoC's `artifacts`
table shape) — the PoC has it, but the domain model does not; ADR wins. Also heavier and drifts toward
per-build identity. This decision **corrects an earlier PoC-influenced lean** — the ADR check overrode it.

**Downstream note:** update `EDR-EVIDENCE-01` D5 — `SubjectRef` validates a **Release**, and the image
digest becomes an Evidence provenance field (not an Artifact reference). *(Applied.)*

### D3 — Minimal Shared Kernel: registry + universal value-nouns + base primitives (K-Q3)

**Admission rule** — a member enters the Shared Kernel only if it is (1) used by every stage, (2) stable,
(3) not owned by any context, and (4) behavior-free. **Residents:** the Product → Project → Release
registry (D1); universal value objects — **CVE-ID** (canonical/normalized), **PURL**, **content
fingerprint (SHA-256)**, **CVSS** (score + vector), **Severity**; base primitives (typed-ID/UUID helper,
clock). **Excluded:** context-owned aggregate IDs (EvidenceID, FaultlineID, FindingID) and any business
behavior — those live in their owning context and are only referenced.

*Rejected:* a fat shared kernel holding context-owned entities or shared business logic — becomes exactly
the "central shared repository" ADR-CON-0001 forbids.

### D4 — Event envelope in the kernel; delivery machinery in M5 (K-Q4)

Split the event plumbing: the **integration-event envelope** (id, type, occurred-at, source context,
subject/aggregate ref, payload schema ref, correlation-id) is a stable, behavior-free contract →
**Shared Kernel** (ADR-BCK-0046). The **outbox runner + relay + event bus** have behavior → **Event
Infrastructure (sprint M5)**, a shared platform, not the kernel (honors D3's behavior-free rule).
**Specific event types** (`EvidenceRegistered`, …) are owned by their publishing context, not the kernel.
The Evidence D7 outbox becomes the reusable M5 component.

*Rejected:* putting the outbox mechanism in the kernel — it has behavior, violating D3 and blurring the
domain-kernel / platform-infrastructure boundary.

---

## Grilling complete

All open questions resolved (D1–D4). One cross-cutting hand-off: the outbox **machinery** belongs to
**Event Infrastructure (M5)**, seeded by Evidence's D7; the kernel provides only the event **envelope**
contract.

## Traceability → issues

Suggested delivery: an OpenSpec change `openspec/changes/phase3-shared-kernel/`.

| # | Issue | Realizes |
| --- | --- | --- |
| KERN-01 | Scaffold `internal/kernel` module + admission-rule doc; arch-test: kernel imports nothing from any context | D3 · CON-0001 |
| KERN-02 | Universal value objects — CVE-ID (canonical/normalized), PURL, ContentFingerprint (SHA-256), CVSS (score + vector), Severity (+ validation + tests) | D3 · CON-0006 |
| KERN-03 | Base primitives — typed-ID/UUID helper, clock | D3 |
| KERN-04 | Registry domain — Product/Project/Release aggregates (identity + structure only, no security state); invariants (project ∈ product, release ∈ project) | D1 · DOM-0028/0029 |
| KERN-05 | Registry persistence + API — products/projects/releases tables; register + lookup use cases; `ReleaseExists` query backing Evidence `SubjectRef` | D1 · BCK-0048 |
| KERN-06 | Integration-event **envelope** contract (value shape + JSON schema) in the kernel | D4 · BCK-0046 |
| M5-seed | Outbox runner + event bus as **Event Infrastructure (M5)** — reusable component seeded by Evidence D7 (tracked for M5, not a kernel issue) | D4 · BCK-0041 |
