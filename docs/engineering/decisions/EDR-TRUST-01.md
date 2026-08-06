# EDR-TRUST-01 — The Themis Trust Model (constitutional, cross-cutting)

**Status:** PROPOSED (2026-08-06) · **Scope:** cross-cutting — Knowledge, Governance, Intelligence, and the
Deterministic Inference stage · **Supersedes:** `EDR-INTELLIGENCE-01` Revision 5 (Δ3c Subject
Generalization), whose S1–S6 are absorbed or replaced here.

## Purpose

This EDR records the **trust model** of Themis: what makes a conclusion trustworthy, how trust is derived,
how it propagates, and what the enterprise is constitutionally forbidden from automating away.

It exists because a design conversation intended to widen the AI Gateway's invocation surface uncovered
something larger. Themis had been implicitly conflating three independent things:

1. **How** a conclusion was computed — deterministic rule versus AI.
2. **What** evidence it was computed from — observed versus claimed.
3. **How much** Governance should trust it — policy.

Because these were conflated, trust was being inferred from *the component that produced a conclusion*
(`ActorKind` — is the proposer AI, or Governance's own automation?). That is a proxy, and proxies leak. This
EDR replaces the proxy with the real thing: **trust is a property of evidence, and it propagates.**

The decisions here are **constitutional** — they constrain every context, not one. Where a per-context EDR
disagrees, this document wins.

## Decisions

### T1 — Trust derives from evidence provenance, never from the producing component

Decision:

- A conclusion's trustworthiness is determined by **where its supporting facts came from** — not by which
  subsystem computed it, and not by whether the computation was deterministic or generative.
- Governance **must not** classify a proposal by its producer. "AI proposal", "vendor proposal", "rule-engine
  proposal" cease to be trust-bearing categories. They remain **provenance metadata** for explainability
  (CON-0003) and are recorded as such.

Rationale:

- The same deterministic rule may execute over different evidence as Themis matures. A platform-compatibility
  rule fed by hand-entered customer metadata today, and by a signed deployment manifest tomorrow, is *the same
  algorithm* with *materially different* trustworthiness. A trust model attached to the rule cannot express
  that; a trust model attached to the evidence expresses it for free.
- Producer-based classification has a **laundering hole**: a deterministic rule that consumes AI-derived input
  produces a conclusion attributed to the rule, and so inherits the rule's higher trust. The AI's judgment
  passes through a deterministic wrapper and emerges as automation-grade. Evidence-based propagation (T3)
  closes this; producer-based classification structurally cannot see it.

ADR basis: CON-0002 (proposal before truth) · CON-0003 (explainability) · Book I Ch 4 (Enterprise Truth Model)
· Book I Ch 10 Law 1 (single authoritative ownership).

### T2 — Three evidence trust classes: Observed, Asserted, Inferred

Decision:

Every fact entering a conclusion carries exactly one **trust class**. The criterion is **derivable versus
declared** — *can this fact be re-derived, or must someone be believed?*

| Class | Criterion | Examples |
| --- | --- | --- |
| **Observed** | **Reproducible.** Mechanically derivable from an artifact Themis holds, or a public record that independent parties publish. Re-run the derivation and you get the same answer. | A component + version read from an ingested SBOM (rescan the artifact, same result); a CVE's affected range from public advisories; an EPSS score; a KEV listing; the existence of a public exploit |
| **Asserted** | **Not reproducible.** A declaration or judgment Themis cannot re-derive. Trust rests entirely on the declarer, who is recorded along with when they said it. | A vendor VEX `not_affected` statement; "this build compiles out the JNDI module", hand-entered; customer or platform metadata typed by a human; a scanner's uncorroborated verdict |
| **Inferred** | The output of **non-deterministic reasoning**. A judgment, not an observation, and not re-derivable even in principle — the same prompt may answer differently. | Any AI capability output; any conclusion whose own evidence included an Inferred fact |

The classes are **ordered by risk**: `Observed < Asserted < Inferred`.

Rationale:

- **Transport does not decide the class.** An affected range and a vendor's `not_affected` may arrive by the
  identical mechanism — an HTTP fetch of a JSON document from the same server. What separates them is that
  the range is a public record anyone can check, while the `not_affected` is a judgment nothing can re-run.
- **Who the fact is about is *not* the criterion**, though it correlates. An SBOM is a claim about our own
  product, yet it is Observed: a tool derived it from the artifact, and rescanning reproduces it. A vendor's
  `not_affected` is Asserted because it is a judgment, **not** because the vendor is unreliable — Red Hat is
  the sole authority on their own build, so nothing can check them. That is a structural fact, not a
  data-quality one.
- **Self-assertion is not observation.** A declaration made by Themis's own operators about their own product
  is still Asserted. "We compiled without JNDI", typed into a field, is Asserted; **the same claim backed by a
  signed build manifest Themis holds becomes Observed**, because it can then be re-derived. This is T3's
  investment gradient made concrete: the model names exactly which artifact to go and collect.
- The distinction Themis already makes for vendor VEX — *gathered, not obeyed* (Domain Invariant 3) — is
  exactly the Observed/Asserted boundary, previously expressed only for one feed family. T2 generalizes it.
- Without the Asserted class, "deterministic" becomes a false comfort: a pure function over an unverified
  claim is precisely as trustworthy as the claim, and no more.

**Classification is per source, not per fact.** Knowledge Proposals already carry a `source` (which feed,
capability or human produced the fact), so the class is **derived from a source-to-class mapping** rather than
stored on every record. Adding a source therefore requires answering one question — *is its output
reproducible, declared, or reasoned?* — and the answer is reviewable in one table instead of scattered across
producers.

ADR basis: Book II Ch 2 Domain Invariant 3 ("Gathering Is Not Knowing") · CON-0002 · `EDR-VEX-01` (vendor VEX
is gathered, never obeyed) · `EDR-KNOWLEDGE-01` D5/D6 (source precedence).

### T3 — Trust propagates monotonically to the highest-risk class of the evidence used

Decision:

- A conclusion's trust class is the **maximum** (highest-risk) class among all evidence it depends on.
- Propagation is **monotonic**: a conclusion can never be more trusted than its weakest input. No
  deterministic step, no validation stage, no human relay may *raise* a trust class.
- Only the arrival of **new, better-classed evidence** can produce a better-classed conclusion — and that is a
  new conclusion, not a promotion of the old one.

```text
Observed + Observed  →  Observed conclusion   (verified)
Observed + Asserted  →  Asserted conclusion   (only as good as the claim)
Asserted + Inferred  →  Inferred conclusion   (a judgment)
```

Rationale:

- Monotonicity is what makes the model auditable. If any step could raise trust, the audit question "why was
  this trusted?" would have no stable answer.
- It also gives the enterprise a real incentive gradient: to move a conclusion from Asserted to Observed you
  must go and *observe something* — ingest the build manifest, sign the deployment record. The model tells you
  precisely which evidence to invest in.

ADR basis: CON-0003 (explainability) · Book I Ch 4 (truth is established, not assumed) · Book I Ch 10 Law 4
(explainability before convenience).

### T4 — Inferred evidence is constitutionally barred from automatic acceptance

Decision:

- A proposal whose trust class is **Inferred** may **never** be accepted automatically — **regardless of
  policy configuration**. There is no setting that enables it. It is an invariant, not a knob.
- Policy retains full discretion over **Observed** and **Asserted** proposals, subject to T6.
- This bar applies to the *conclusion's* class under T3, not to the identity of its producer. A deterministic
  rule that consumed an AI-derived fact yields an Inferred conclusion and is equally barred.

Rationale:

- This preserves — and strengthens — the guarantee currently enforced structurally in Governance's policy
  evaluation (only system-raised proposals are auto-acceptable; an AI proposal never is). Moving to
  evidence-based classification would otherwise **downgrade a code-enforced guarantee into a configuration
  setting**, which is the one regression this model must not introduce.
- It is the direct expression of the standing guardrail: **autonomy of generation, yes; autonomy of authority,
  never** (INT-0056/0066, CON-0015, DOM-0024).

ADR basis: DOM-0024 (AI proposes, humans decide) · CON-0015 (human authority) · INT-0056/INT-0066 · Book I
Ch 5 (Authority Over Automation).

### T5 — Deterministic Inference precedes AI; AI is the last resort for ambiguity

Decision:

- Themis gains **Deterministic Inference**: provable rules executed over assembled evidence, raising **system
  proposals** for the conclusions they reach, **before** any AI Decision capability runs.
- **It is a stage, not a deployable service.** It is realized *inside* whichever context owns the evidence a
  rule consumes (T11). Reading the stage as a box in the service chain is the one misreading this decision
  must prevent.

```text
   Evidence  ─────►  Knowledge  ─────►  Governance  ─────►  Communication
                         ╎                   ╎
                         ╎ deterministic     ╎ deterministic
                         ╎ inference over    ╎ inference over
                         ╎ the evidence      ╎ the evidence
                         ╎ Knowledge owns    ╎ Governance owns
                         ╰───── system proposals ─────►  Governance decides
                                                              ▲
                             AI (Decision capabilities) ──────╯
                             only where inference could not conclude
```

The dotted lines are **stages inside contexts**, not services. The solid line is the deployable pipeline.

- **Rules are deterministic algorithms and carry no trust class of their own** (T1). Their conclusions are
  classed by their inputs (T2/T3).
- An AI **Decision** capability is invoked **only** where deterministic inference could not reach a
  conclusion. Ambiguity is the AI's domain; computation is not.
- This ordering constrains **Decision** capabilities only. **Information** capabilities (T7) are user-initiated
  and may be invoked at any time, including where inference concluded confidently — a user is entitled to ask
  for an explanation of a settled answer.

Rules in scope at adoption (both Observed): **version-range applicability** and **package-not-shipped**.
Anticipated as evidence arrives (initially Asserted): feature-disabled, build-time exclusion, static
configuration, platform incompatibility.

Rationale:

- A provable verdict is a computation, not a reasoning task. Routing it through a language model is slower,
  costlier, less accurate, and — critically — **unavailable when the optional AI plane is switched off**.
- Today the version-range verdict lives inside the AI runtime and is reachable *only* by invoking AI. That
  makes a deterministic correctness feature depend on an optional plane, contradicting the standing rule that
  the pipeline must be correct with AI disabled (`EDR-INTELLIGENCE-01` D13). T5 repairs this.
- Deterministic conclusions over Observed evidence are exactly the class that *should* flow without a human
  bottleneck — and the path already exists and is proven: `EDR-VEX-01`'s reconciled `not_affected` raises a
  system proposal that policy may auto-accept.

ADR basis: Book IV Principle 5 ("SQL before AI") · Book IV Principle 6 (AI invoked only where reasoning adds
value) · `EDR-INTELLIGENCE-01` D13 (AI is an optional plane) · `EDR-VEX-01` (system-proposal path).

### T6 — Governance enforces constitutional invariants before applying configurable policy

Decision:

Governance evaluates a proposal in two ordered stages, and the order is not negotiable:

1. **Constitutional check** (fixed, non-configurable) — the invariants of this EDR, chiefly T4. A proposal
   failing this stage cannot be auto-accepted by any policy.
2. **Policy check** (configurable, enterprise-owned) — the deterministic auto-accept rules Governance already
   owns, applied only to proposals that cleared stage 1.

- Governance's decision outcomes are: **Accepted**, **Accepted with Warning** (accepted while recording a
  named reservation — e.g. an Asserted dependency the enterprise chose to rely on), **Rejected**, and
  **Requires Human Review**.
- Governance reads the proposal's **trust class and evidence provenance**. It does not read, and must not
  branch on, the producing component (T1).

Rationale:

- Separating the constitutional stage from the policy stage is what makes T4 durable. If the bar on Inferred
  lived inside the configurable policy, it would be one misconfiguration away from being absent.
- It also simplifies Governance: it stops maintaining producer-specific branches and evaluates one thing.

ADR basis: `EDR-GOVERNANCE-01` D11 (Governance-owned auto-accept policy) · CON-0009 · DOM-0024 · Book I Ch 10
Law 2 (proposal before truth).

### T7 — Capability outputs are of exactly two classes: Information Response and Decision Proposal

Decision:

- Every AI capability declares an **output class**:
  - **Information** — produces an **Information Response**: an answer rendered for a human. It is
    **ephemeral**. It is not recorded as enterprise truth and there is nothing to accept or reject.
  - **Decision** — produces a **Decision Proposal**: a structured, schema-validated claim that aspires to
    become enterprise truth, and therefore enters Governance.
- **Hard rule:** an Information Response may be shown to a human, but may **never** be stored as enterprise
  truth, nor converted into truth, except by passing through a Decision capability whose proposal is governed.
- Governance participates **only** in the Decision branch.

```text
                        Business Capability
                                │
                ┌───────────────┴───────────────┐
                ▼                               ▼
          Information                       Decision
                │                               │
          AI Runtime                       AI Runtime
                │                               │
     Grounding Verification          Grounding Verification
                │                               │
     Information Response             Decision Proposal
                │                               │
              User                   Business Verification (Governance)
                                                │
                                        Human Decision
                                                │
                                        Enterprise Truth
```

Rationale:

- Five of Book IV's six user use cases produce explanations, plans, or summaries — not decisions. Forcing them
  into a proposal envelope with a vestigial recommendation would misrepresent what they are, and would put
  Governance in the position of "accepting" a paragraph of prose.
- The existing rule that raw natural language never becomes enterprise truth (`EDR-INTELLIGENCE-01` D2,
  INT-0057) is **preserved exactly** — the hard rule above is that principle restated for a world where
  explanation is a first-class output.
- Governance is not validating AI. Governance is validating **only those outputs that aspire to become
  enterprise knowledge**.

ADR basis: INT-0057 (structured, schema-validated proposals; no raw NL into the enterprise) · CON-0015 ·
Book IV §6 (six user use cases) · `EDR-INTELLIGENCE-01` D2 (amended by this decision).

### T8 — Two verification boundaries, protecting two different things

Decision:

Verification is **not** performed twice. Two distinct boundaries protect two distinct properties:

| Boundary | Owner | Protects | Question it answers |
| --- | --- | --- | --- |
| **Grounding Verification** | AI Runtime | the integrity of the **reasoning process** | "Did the model reason only from the supplied context and retrieved evidence — inventing no entity, citing nothing unsupported?" |
| **Business Verification** | Governance | the integrity of **enterprise truth** | "Are these structured claims still consistent with the system of record at the moment of acceptance?" |

- **Grounding Verification applies to both output classes** (T7). For an Information Response it is the **only**
  gate — no Governance stage follows it — and must be treated as load-bearing accordingly.
- **Business Verification applies only to Decision Proposals**, and runs at acceptance time, against current
  truth (not against the context the reasoning used, which may since have changed).

Rationale:

- Once the backend supplies the context (T10), grounding checked inside the runtime is a check against
  *caller-supplied* facts. That remains valuable — it catches the model inventing entities — but it can no
  longer be the enterprise's guarantee of correctness. Business Verification supplies that, at the authority
  that owns the truth.
- Locating the truth check at Governance makes forged or stale context **useless** rather than merely
  unlikely to be accepted.

ADR basis: `EDR-INTELLIGENCE-01` D7 (3-stage validation, generalized here) · Book I Ch 4 (Themis is the system
of record) · Book IV Principle 8 (AI recommendations traceable to deterministic knowledge).

### T9 — Selection is the user-addressable entry point; everything else is assembled Decision Context

Decision:

- A capability is invoked with a **Selection**: a **type** plus a **set** of identifiers of that type, with the
  capability declaring its supported type(s) and its **minimum and maximum cardinality**.
- **Selection Types are not domain entities.** They are *user-addressable entry points* — the things a person
  can point at in a user interface. A type is admitted only when **both** hold:
  1. **It is addressable** — it has a stable identifier that could appear in a URL today.
  2. **A named use case selects it** — a use case treats it as the thing the user picks, not as background
     context the system gathers.
- At adoption the Selection Types are exactly **Finding** and **Release**.
- Everything else — Enterprise Positions, Faultlines, vendor VEX, policies, historical decisions, estate and
  blast-radius — is **Decision Context**: assembled on the user's behalf, never selected.

Rationale:

- Cardinality-as-a-declaration subsumes what would otherwise be a separate fan-out limit: a capability that
  handles one Finding declares a maximum of one, and the boundary is enforced before any work is done.
- The two-part admission rule keeps the API aligned with **user intent** rather than internal data structures,
  and prevents internal constructs from surfacing as first-class API concepts before they are part of the user
  experience. Enterprise Positions are the worked example: they have no independent identity (a Position is
  addressed only as a version of a Finding) and no use case selects one — so they are Decision Context.
- Adding a Selection Type later is purely additive: a new type, a new projection, and nothing already built
  changes.

ADR basis: INT-0058 (capabilities invoked by name against a subject) · Book IV §6 (which subjects use cases
actually select) · Book II Ch 2 (ubiquitous language: one concept, one meaning).

### T10 — Domain Projections are authoritative; the AI Runtime consumes, shapes, and never gathers

Decision — **projection ownership:**

- The bounded context that **owns a Selection Type** owns the reusable **Domain Projections** for it. They are
  assembled using **only** events and read-only APIs from other contexts — never a cross-context import.
- Domain Projections are named for the **business view they represent** (`ReleasePosture`), **never** for a
  consuming capability. AI, dashboards, reports and exports all consume the *same* projection.
- **Capability-specific context is derived from a Domain Projection**, in memory, by the consumer. It is
  **not persisted** and it is **not a second projection**. This is what keeps AI a *consumer* of the domain
  rather than a *driver* of the domain model, and it is what prevents projection sprawl.
- The backend **aggregates before invoking** wherever the aggregate is a reusable business view — grouping is a
  `GROUP BY`, not reasoning.

Decision — **the AI Runtime contract, in four rules:**

1. **No orchestration.** The runtime never gathers business data. It does not know which bounded contexts
   exist, what projections exist, or how one is produced. It issues no business reads and requests no bundles.
2. **Information-preserving shaping.** The runtime may **filter, sort, group and summarise** an authoritative
   projection into the shape a capability reasons over. *Information-preserving* means **nothing may be
   introduced that the projection did not contain** — reduction is permitted, invention is not. (Shaping is
   necessarily lossy; that is not the property being preserved.)
3. **Full provenance.** Every derived element must be traceable back to the received Domain Projection.
4. **Grounding anchors to authority.** Grounding Verification always validates against the authoritative
   Domain Projection — **never solely** against a runtime-generated view.

The runtime additionally retains **semantic retrieval** over its own Operational Semantic Index (KS2 —
derived, rebuildable, runtime-owned), **reasoning**, and **Grounding Verification** itself.

```text
Capability ID + Selection  →  Domain Projection  →  [shape]  →  reason  →  Information Response | Decision Proposal
                              ↑ authoritative                    ↑ Grounding Verification anchors here ─┘
```

Rationale:

- Two things were previously conflated and only one is dangerous: **knowing the backend's topology** (which
  context holds what, in what order to ask) is orchestration and must stay out of the runtime; **shaping data
  the runtime already holds** requires no topology knowledge, issues no calls, and is ordinary consumption.
- Rule 4 exists because a runtime that validated against its own transformed view would be checking the model
  against something it produced itself. A buggy transformation would then be *confirmed* rather than caught.
  Anchoring to the projection keeps the check measured against an artifact an authority vouched for.
- Rules 2 + 3 together make the transformation a **view, not a source**. Combined, the four rules make the
  runtime auditable — every element it reasoned over has a traceable origin — and independently testable: the
  fixture is the Domain Projection, and the shaping is runtime code tested alongside the reasoning.
- The pattern is **already proven in Themis**. `ReleasePosture` composes Governance's own findings, a
  Knowledge-derived `base_score` (arrived by event) and a Registry-derived `blast_multiplier` (one read-API
  call **per release**, fail-safe to 1.0 when unreachable) into one business-named read model — no
  cross-context import, correct aggregation discipline, graceful degradation. Domain Projections are that
  pattern formalized, not a new abstraction.

**ADR compliance note.** ADR-INT-0061 requires context construction to be *deterministic*, *independent of
prompt generation*, and *complete before prompting begins* — it does **not** specify where it executes.
ADR-INT-0068 requires that the *intelligence provider* never query persistence directly and that knowledge
arrive via *dedicated retrieval services*. Backend-owned Domain Projections satisfy both, and satisfy
INT-0068 more literally than runtime-side assembly does. This decision therefore **rewrites
`EDR-INTELLIGENCE-01` D5** (a realization choice) without contradicting any ADR.

ADR basis: ADR-INT-0061 · ADR-INT-0068 · INT-0059 (single provider entry) · Book IV Principles 5 + 6.

### T11 — Behaviour follows ownership

> This decision is **broader than the trust model**. It arose in resolving where Deterministic Inference
> lives, but it governs bounded-context design generally and should be read as such.

Decision:

- **Evidence-owning bounded contexts execute deterministic inference over the evidence they own.**
- **Inference never justifies a bounded context; new evidence does.**
- **A new bounded context is created only when a new class of authoritative business evidence requires
  independent ownership** — for example a future **Product Applicability** context owning what the enterprise
  builds, ships and enables — **never because new deterministic rules are introduced.**
- **"Deterministic Inference" is a stage in the architecture, not a deployable service.**

Rationale:

- Every bounded context in Themis is defined by **what it is the authority on** — Evidence owns artifacts,
  Knowledge owns CVE cards, Registry owns identity, Governance owns Findings and Positions. None was created
  to hold logic. A context whose only asset is behaviour has no authority to defend and no truth to own.
- The pattern is already realized. `FindingService.reactToApplicability` is deterministic inference living in
  Governance — and it is there for a principled reason, not by convenience: `coveringStatement(f *Finding,
  …)` needs a **Finding**, because "is release R affected by CVE C?" is a question about a Finding, and
  Finding is Governance's aggregate. Behaviour followed ownership without anyone naming the rule.
- It also explains why the inference rules felt homeless: **four of the six anticipated rules need evidence
  Themis does not collect** (build options, feature configuration, shipped configuration, platform bindings).
  The gap was never a missing rule engine — it was a missing *authority* over product-applicability facts.
  When that evidence arrives it earns a context, and its rules arrive with it.
- Finally, a separate inference service could not write its conclusions anyway: contexts collaborate only by
  events and read-only APIs, so it could at best emit an event that Governance turns into a proposal — which
  is exactly what Knowledge already does. The service would buy nothing and cost a deployment.

Consequences:

- Version-range and package-not-shipped need **no new context** — their evidence already has owners.
- The **Product Applicability** context is named but **not created**. It becomes justified when the enterprise
  begins collecting what it builds, ships and enables — and not one day earlier.
- Any diagram showing Deterministic Inference must render it as a **stage inside contexts**, never as a box in
  the service chain. Boxes get implemented as services.

ADR basis: Book I Ch 9 (Bounded Contexts) · Book I Ch 10 Law 1 (single authoritative ownership) · Book III
Ch 3 (Bounded Context Realization) · CON-0002.

## Consequences

- **`EDR-INTELLIGENCE-01` Revision 5 (Δ3c) is superseded** in full. S1/S2/S4 are replaced by T9 (Selection with
  declared cardinality); S3 is replaced by T10 (backend projections); S5 is replaced by T8 (two boundaries);
  S6 is replaced by T7 (two output classes).
- **`EDR-INTELLIGENCE-01` D5 is rewritten** (context assembly leaves the Gateway) and **D2 is amended** (two
  output classes, not one).
- **`EDR-GOVERNANCE-01` D11 is amended** — policy evaluation gains a preceding constitutional stage (T6) and
  stops branching on producer identity (T1).
- **Deterministic Inference is introduced as a stage, not a service** (T5 + T11). It needs **no new bounded
  context and no new deployable** — its first two rules run inside the contexts that already own their
  evidence. A future **Product Applicability** context is named but deferred until the evidence exists.
- **The version-range rule moves** out of `internal/intelligence/domain/rule.go` into Deterministic Inference.
  It is currently the only user of the kernel version-range value object outside the AI runtime's own wiring.
  **Precision requirement:** the relocated rule must evaluate the *reconciled, backport-aware* range — not a
  feed's query-time filter — or it will produce wrong `not_affected` verdicts, the most dangerous defect class
  in this system.
- **`recommend_position` is reshaped**: it loses its deterministic rule step (moves to inference), loses its
  context assembly (moves to the backend), and retains semantic retrieval, reasoning, and Grounding
  Verification. Its plan becomes `[Knowledge → LLM]`.
- **Evidence trust class becomes a carried attribute** across Knowledge Proposals, inference inputs, and
  Governance Proposals. Where it is stored and how it is threaded is an implementation decision this EDR does
  not fix.

## Open questions (not decided here)

1. **Whether "Accepted with Warning" is a new Position state** or a recorded reservation on an ordinary
   acceptance.
2. **The Decision Proposal payload shape** beyond `{finding, stance}` — deferred until a second Decision
   capability exists to define it.
3. **Migration order** for the shipped `recommend_position`, whose behaviour must be preserved throughout.

*Closed since drafting:* **projection ownership** → T10 (the context owning the Selection Type, following the
proven `ReleasePosture` pattern) · **Deterministic Inference ownership** → T11 (behaviour follows ownership;
a stage inside evidence-owning contexts, never a service) · **trust-class persistence** → T2 (classification
is a per-**source** mapping, not a per-fact field; Knowledge Proposals already carry `source`, so the frozen
v1 payload contracts are largely untouched, and where a class must ride the wire the existing
`.v2.schema.json` + `schema_ref` versioning already covers it).

## Glossary

- **Selection** — the user-addressable entry point to a capability: a type plus a set of identifiers.
- **Selection Type** — an addressable thing a user can point at. Today: Finding, Release.
- **Decision Context** — everything Themis assembles on the user's behalf; never selected.
- **Domain Projection** — a reusable, persisted read model owned by the context that owns a Selection Type,
  assembled only from events and read-only APIs, and named for the **business view** it represents
  (`ReleasePosture`), never for a consumer. It is **authoritative**: Grounding Verification anchors to it.
- **Capability Context** — the in-memory, **non-persisted** shape a consumer derives from a Domain Projection
  for one capability. A view, not a source; bounded by the four runtime rules (T10).
- **Deterministic Inference** — provable rules executed over assembled evidence, before AI. A **stage**
  realized inside evidence-owning contexts, **never a deployable service** (T11).
- **Behaviour follows ownership** — evidence-owning contexts execute inference over the evidence they own; a
  new bounded context is justified by new authoritative evidence, never by new rules (T11).
- **Product Applicability** — the *named but not yet created* context that would own what the enterprise
  builds, ships and enables. It becomes justified when that evidence begins to be collected.
- **Trust class** — Observed, Asserted, or Inferred; a property of evidence, ordered by risk.
- **Trust propagation** — a conclusion takes the highest-risk class among its evidence; monotonic.
- **Information Response** — an ephemeral answer for a human; never enterprise truth.
- **Decision Proposal** — a structured claim that aspires to become enterprise truth; governed.
- **Grounding Verification** — the AI Runtime boundary protecting reasoning integrity.
- **Business Verification** — the Governance boundary protecting enterprise truth integrity.
