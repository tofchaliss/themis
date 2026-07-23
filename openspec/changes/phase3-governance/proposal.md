# Proposal — phase3-governance (Governance: Findings & Enterprise Position)

## Why

**Governance** is the **authority** context (third in the pipeline
Evidence → Knowledge → Governance → Communication). It is the sole capability that establishes
authoritative enterprise decisions (CON-0009): it owns **Findings** (release-scoped concerns) and
**Enterprise Positions** (the committed decision). Grounded in
**`docs/engineering/decisions/EDR-GOVERNANCE-01.md`** (D1–D13). Ground rule: **ADR wins; the `internal/`
PoC is reference only.**

## What

Implement the Governance context — splitting the PoC's single `risk_context.effective_state` into **two
objects**:

- a **Finding** aggregate — one per (Release, Faultline), own identity, referencing the global Faultline,
  carrying matched components and an explicit **investigation lifecycle** (Identified → Under Investigation
  → Position Established → Monitoring → Resolved → Archived; reopenable);
- an **Enterprise Position** — the authoritative decision, held as **append-only immutable versions** with
  an extensible stance set (Affected / Not Affected / Under Investigation / Mitigated / Accepted Risk /
  Deferred);
- a first-class **Governance Proposal** — a proposed decision (from human, AI, policy, or knowledge
  evolution) with a **Proposed → Evaluated → Accepted/Rejected** lifecycle; acceptance establishes a new
  Position version;
- the **inbound seam**: consume Knowledge's `ComponentMatched` (idempotent find-or-create Finding) and
  `FaultlineEnriched` (auto-raise a Governance Proposal + flag for review — never auto-decide);
- the **authority line**: AI proposes only, authorized humans decide, Governance-owned **policy rules**
  may auto-accept;
- thin `PositionEstablished` / `PositionRevised` events (consumed only by Communication) via the shared
  outbox; internal Finding/Proposal events for audit;
- read side — `GetFinding` / `GetPosition` + projections (release posture, Faultline blast-radius).

Full decision list with rationale: **EDR-GOVERNANCE-01 (D1–D13)**.

## Non-goals (other contexts / deferred)

- **Faultlines / enterprise knowledge** — owned by **Knowledge**; Governance references a Faultline by
  immutable id, never redefines it (DOM-0026).
- **Publication + VEX generation** — owned by **Communication**; Governance only establishes Positions
  (DOM-0025). VEX generation **moves out** of triage.
- **AI Proposal generation / ranking** — owned by **Intelligence** (EDR-INTELLIGENCE-01); here AI is just a
  proposer with no authority (CON-0015).
- **RBAC mechanism** — the authorization *rule* is fixed (only an authorized human or policy accepts); the
  concrete roles/keys mechanism is an implementation detail deferred to build.
- **The existing `internal/` PoC tree** stays as legacy reference and is **not modified**.

## Realizes (ADRs / EDR)

CON-0009, CON-0002, CON-0003, CON-0015, DOM-0022, DOM-0023, DOM-0024, DOM-0025, DOM-0026, DOM-0030,
DOM-0031, DOM-0033, BCK-0041, BCK-0042, BCK-0043, BCK-0044, BCK-0045, BCK-0047, BCK-0050 — via
**EDR-GOVERNANCE-01**.
