# Proposal — phase3-trust-model (evidence trust, deterministic inference, capability surface)

## Why

Themis had been conflating three independent things: **how** a conclusion was computed (deterministic vs
AI), **what** evidence it used (reproducible vs declared), and **how much** Governance should trust it
(policy). Because they were conflated, trust was inferred from the **producing component** (`ActorKind`) —
a proxy, and proxies leak. The clearest leak: a deterministic rule consuming AI-derived input produces a
conclusion attributed to the rule, and so inherits the rule's standing. AI judgment launders through a
deterministic wrapper and becomes automation-grade.

Grounded in **`docs/engineering/decisions/EDR-TRUST-01.md` (T1–T12, ACCEPTED 2026-08-06)**, with the
realization detail in **Book III Ch 16**, vocabulary in **Book II Ch 2 §2.7 + Domain Invariant 4**, and the
AI-side contract in **Book IV §2.1–2.3 + Principles 10–17**. Ground rule: **ADR wins; the `internal/` PoC is
reference only.**

This change is **cross-context by construction** — it touches Knowledge, Governance and Intelligence
together, because the trust model is exactly the thing no single-context EDR could own. That is why it
exists as one change rather than three.

## What

- **Evidence trust classes** (T2) — `Observed` / `Asserted` / `Inferred`, decided by **derivable vs
  declared**: *can this be re-derived, or must someone be believed?* Classification is a **per-source
  mapping**, not a per-fact field — Knowledge Proposals already carry `source`.
- **Trust propagation** (T3) — a conclusion takes the **highest-risk** class among its evidence, and
  propagation is **monotonic**: no step may raise a class.
- **The constitutional stage** (T4/T6) — Governance evaluates in two ordered stages: a fixed constitutional
  check (chiefly, **`Inferred` may never be auto-accepted, under any policy**), then the existing
  configurable policy. Governance stops branching on producer identity.
- **Reservations** (T12) — an acceptance resting on `Asserted` evidence is an **ordinary acceptance whose
  inputs say so**. Derived from immutable `PositionInputs`, **surfaced in read models**, never persisted as
  state. There is **no** "accepted with warning" status.
- **Deterministic Inference** (T5/T11) — provable rules run **before** AI, as a **stage inside
  evidence-owning contexts**, never a service. The **version-range rule moves out of the AI runtime**, where
  it is today reachable only by invoking an optional plane.
- **Selection** (T9) — the capability entry point becomes a **type plus a set** with declared min/max
  cardinality, replacing the bare `subjectFindingID`. Selection Types are **Finding** and **Release**.
- **Domain Projections** (T10) — the context owning a Selection Type owns reusable, business-named
  projections (`ReleasePosture` is the first). The AI Runtime **gathers nothing**; it may only shape what it
  receives, bounded by four rules — no orchestration, information-preserving shaping, full provenance,
  grounding anchors to authority.
- **Two capability classes** (T7/T8) — **Information** (ephemeral response, never truth) and **Decision**
  (governed proposal). Grounding Verification protects reasoning; Business Verification protects truth.

## Non-goals (deferred by construction, not oversight)

- **A Deterministic Inference service.** T11: inference never justifies a bounded context; new evidence does.
  This change adds **no new bounded context and no new deployable**.
- **The Product Applicability context** — named in T11, **not created**. Four of the six anticipated rules
  (feature-disabled, build-time exclusion, static configuration, platform incompatibility) need evidence
  Themis does not collect. It becomes justified when that evidence is collected, and its rules arrive with it.
- **The Decision Proposal payload shape** beyond `{finding, stance}` — cannot be designed before a second
  Decision capability exists to shape it (`EDR-TRUST-01` open question 1).
- **New Information capabilities** (UC-001/002/003/005/006). This change builds the *surface* they need; the
  capabilities themselves are separate work.
- **KS3 external-document retrieval**, the **Δ4** autonomy/LLMOps plane, and **G-AI-1/2/4/5** — unchanged and
  independently tracked.
- **`recommend_position` behaviour.** It is reshaped (loses its rule step and its context gathering) but must
  remain **behaviourally identical** throughout; that is this change's acceptance condition, not a goal.
- **The existing `internal/` PoC tree** stays legacy reference and is **not modified**.

## Realizes (ADRs / EDR)

CON-0002, CON-0003, CON-0009, CON-0015, DOM-0024, DOM-0026, INT-0056, INT-0057, INT-0058, INT-0059,
INT-0061, INT-0062, INT-0066, INT-0068, INT-0069, INT-0070, BCK-0037, BCK-0046, BCK-0051 — via
**EDR-TRUST-01 (T1–T12)**, amending `EDR-INTELLIGENCE-01` (**D5** rewritten, **D2** amended, Revision 5
superseded) and `EDR-GOVERNANCE-01` (**D11** gains a preceding constitutional stage).
