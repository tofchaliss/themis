# Proposal — phase3-evidence (Evidence bounded context, greenfield rebuild)

## Why

The architecture book (Books I–III) and the 69 ADRs define a four-context model —
**Evidence → Knowledge → Governance → Communication** — realized by the Phase-3 sprint plan
(`docs/current-changes/themis-phase-3-sprint-plan.md`, M1–M10) as a **greenfield rebuild**. This change
delivers the first context, **Evidence**, which doubles as the **exemplar** every later context copies
(sprint M3) and the first real build (M6).

It is grounded in **`docs/engineering/decisions/EDR-EVIDENCE-01.md`**, which grilled the Evidence ADR
cluster against the existing proof-of-concept (`internal/`). Ground rule: **ADR wins; the PoC is
reference only.**

> Naming note: "Phase 3" here means the **sprint-plan bounded-context rebuild**, not the older
> `openspec/STATUS.md` "Phase 3 — production platform (Docker/UI/RBAC)" label.

## What

Implement the Evidence bounded context — the immutable **Evidence Registry**:

- accepts uploads (CycloneDX / SPDX SBOMs, VEX documents),
- validates + fingerprints (SHA-256) + translates them into one canonical component inventory,
- stores the raw file frozen plus the canonical form, atomically with a **transactional-outbox
  `EvidenceRegistered`** event,
- exposes a **read-only counter** (register / get-facts / get-inventory / list),
- returns a **stable Evidence ID** to the caller on registration.

Full decision list with rationale and rejected alternatives: **EDR-EVIDENCE-01 (D1–D9)**.

## Non-goals (downstream contexts / deferred)

- **Correlation, vulnerability catalog, Faultlines, findings, enrichment, notifications** — these belong
  to downstream contexts (Knowledge / Governance / Communication), triggered by `EvidenceRegistered`. Not
  in this change.
- **Ownership of the Product → Project → Release → Artifact catalog** — deferred to the **Shared Kernel
  (M2)**. Evidence only *references* the subject and validates it via a `SubjectRef` port.
- **The existing `internal/` PoC tree** stays as legacy reference and is **not modified** by this change.
- **Production delete / soft-delete** — none; only a dev/test-gated purge (D8).

## Realizes (ADRs / EDR)

Evidence ADR cluster — CON-0001, CON-0007, CON-0011, CON-0012, CON-0013, CON-0016, DOM-0027, DOM-0031,
DOM-0033, BCK-0037 through BCK-0052 — via **EDR-EVIDENCE-01**.
