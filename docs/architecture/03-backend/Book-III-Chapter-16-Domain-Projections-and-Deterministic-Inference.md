# Book III --- The Themis Backend Architecture

## Part II --- Core Architecture

## Chapter 16 --- Domain Projections and Deterministic Inference

> *"The backend does not answer AI's questions. The backend decides what
> the facts are, and hands them over finished."*

------------------------------------------------------------------------

> **Placement note.** This chapter is numbered 16 to avoid renaming existing
> files, but it belongs conceptually with the workflow chapters (10--11),
> before the ADR and research appendices. Its reason of record is
> [`EDR-TRUST-01`](../../engineering/decisions/EDR-TRUST-01.md).

------------------------------------------------------------------------

## Chapter Objective

After reading this chapter, the reader should understand:

- What a **Domain Projection** is, and which context owns it.
- Why AI is **just another consumer** of the domain, never a driver of it.
- The **four rules** that define what the AI Runtime may do.
- What **Deterministic Inference** is, why it is a **stage rather than a
    service**, and what it emits.
- Why **behaviour follows ownership** --- and therefore when a new bounded
    context is justified at all.
- What a **Selection** is, and why Selection Types are not domain
    entities.
- How **evidence trust classes** propagate through the backend.
- Why Governance evaluates in **two ordered stages**.

------------------------------------------------------------------------

## 16.1 Why This Chapter Exists

Themis originally placed context assembly inside the AI Runtime: the
runtime was handed an identifier, and it called read APIs to gather what
it needed.

That arrangement has two defects that only become visible at scale.

**It makes the runtime a business orchestrator.** To gather context, the
runtime must know which bounded contexts exist, which of them holds
which fact, and in what order to ask. That is business knowledge, and it
had leaked into a component whose only job is reasoning.

**It inverts the cost model.** A release-scoped question over 500
findings becomes 500 read-API calls issued from the reasoning layer,
inside a single invocation --- a self-inflicted load spike on the very
services the runtime depends on.

The correction is to move assembly to the side that owns the facts.

------------------------------------------------------------------------

## 16.2 The Domain Projection

A **Domain Projection** is a reusable read model owned by the bounded
context that owns a Selection Type. It is:

- **Deterministic** --- the same Selection over the same upstream state
    yields the same projection.
- **Assembled only from events and read-only APIs** --- never from a
    cross-context import.
- **Named for the business view it represents** --- `ReleasePosture`, not
    `ReleaseReadinessContext`. It is named for what it *is*, never for
    who consumes it.
- **Shared** --- AI, dashboards, reports and exports consume the *same*
    projection. None of them is privileged.
- **Replayable** --- deterministic and self-contained, so it is a test
    fixture. Every consumer is independently testable with no live
    database.
- **Authoritative** --- an owning context vouches for it. This is what
    lets Grounding Verification anchor to it (§16.2.3).

### 16.2.1 This pattern already exists in Themis

`GET /releases/{id}/posture` is a Domain Projection in everything but
name. It composes:

| Fact | Origin | How it arrives |
| --- | --- | --- |
| Findings + stances | Governance's own store | direct |
| `base_score` | **Knowledge** | via event, materialized onto the Finding |
| `blast_multiplier` | **Registry** | read-API call, **once per release** |
| `effective_priority` | derived | `base × multiplier` |

Three contexts' facts, no cross-context import, both sanctioned channels,
and the aggregation discipline already correct --- the blast radius is
fetched **once per release, not once per finding**. If Registry is
unreachable the multiplier degrades to 1.0 and the posture still returns.

Domain Projections are this pattern **formalized, not a new
abstraction**.

### 16.2.2 Ownership follows the Selection Type

The context that owns a Selection Type owns its projections. Today both
Selection Types --- Finding and Release --- resolve to Governance. If a
future Selection Type belongs elsewhere, its owner builds the projection.
It is *not* "Governance is the hub"; it is "the owner of the entry point
owns the view".

The naming rule is what keeps this from degenerating. Content-named
projections get reused across consumers; capability-named ones never do.
A backend that accumulates one bespoke read model per AI capability has
let AI become a driver of the domain model, which is precisely the
inversion this chapter exists to prevent.

### 16.2.3 Capability context is derived, never persisted

A capability usually wants a shape narrower than the projection --- ten
component groups rather than five hundred findings. That shape is a
**Capability Context**: derived **in memory** by the consumer, from the
Domain Projection, and **never persisted**.

This is the division that gives reuse without sprawl:

| | Domain Projection | Capability Context |
| --- | --- | --- |
| Owned by | the Selection Type's context | the consumer |
| Persisted | yes | **no** |
| Named for | the business view | the capability |
| Shared | across all consumers | single-use |
| Authoritative | **yes** | no --- it is a *view* |

### 16.2.4 The four rules of the AI Runtime

The AI Runtime is one consumer among several, and exactly these four
rules bound it:

1. **No orchestration.** It never gathers business data. It does not know
    which contexts exist, which projections exist, or how one is
    produced.
2. **Information-preserving shaping.** It may filter, sort, group and
    summarise an authoritative projection. *Information-preserving* means
    **nothing may be introduced that the projection did not contain** ---
    reduction is permitted, invention is not. (Shaping is necessarily
    lossy; that is not the property being preserved.)
3. **Full provenance.** Every derived element traces back to the received
    Domain Projection.
4. **Grounding anchors to authority.** Grounding Verification validates
    against the authoritative Domain Projection, **never solely** against
    a runtime-generated view.

Rule 4 is the one that is easy to get wrong. A runtime validating against
its own transformed view is checking the model against something it
produced itself --- a buggy transformation would be *confirmed* rather
than caught. Anchoring to the projection keeps the check measured against
an artifact an owning context vouched for.

Rules 2 and 3 together make the transformation a **view, not a source**.

### 16.2.5 Aggregate where the aggregate is a business view

Consider grouping a release's findings into engineering workstreams:

```text
openssl 1.1.1k   → 14 findings, worst severity critical, fix available 1.1.1w
glibc 2.31       → 11 findings, worst severity high,     fix available 2.35
log4j-core 2.15  →  3 findings, worst severity critical, fix available 2.17.1
```

Grouping is a `GROUP BY`. It is exact, instantaneous and free; a language
model asked to do it is slower, costlier and occasionally wrong. What the
model is *good* at --- which order, what effort, what breaks --- operates on
the aggregate.

Where the aggregate is itself a reusable business view, the backend
computes it and it becomes part of the Domain Projection. Where it is
specific to one capability's reasoning, the consumer derives it under the
four rules. The test is reuse, not convenience.

------------------------------------------------------------------------

## 16.3 Deterministic Inference --- A Stage, Not a Service

**Deterministic Inference** executes provable rules over assembled
evidence and raises **system proposals** for the conclusions it reaches,
before any AI Decision capability runs.

> **It is a stage in the architecture, not a deployable service.** Each
> rule executes inside the bounded context that owns the evidence it
> consumes. This is the one misreading this section exists to prevent ---
> boxes in a service chain get implemented as services.

```text
   Evidence  ─────►  Knowledge  ─────►  Governance  ─────►  Communication
                         ╎                   ╎
                         ╎ deterministic     ╎ deterministic
                         ╎ inference over    ╎ inference over
                         ╎ the evidence      ╎ the evidence
                         ╎ Knowledge owns    ╎ Governance owns
                         ╰──── system proposals ──────►  Governance decides
                                                              ▲
                             AI (Decision capabilities) ──────╯
                             only where inference could not conclude
```

The dotted lines are stages **inside** contexts. The solid line is the
deployable pipeline.

### Behaviour follows ownership

- **Evidence-owning bounded contexts execute deterministic inference over
    the evidence they own.**
- **Inference never justifies a bounded context; new evidence does.** A
    new context is created only when a new class of authoritative business
    evidence requires independent ownership --- never because new rules
    were introduced.

Themis already does this without having named the rule.
`FindingService.reactToApplicability` is deterministic inference living in
Governance --- and it is there for a principled reason, not a convenient
one: `coveringStatement(f *domain.Finding, …)` needs a **Finding**,
because *"is release R affected by CVE C?"* is a question about a Finding,
and Finding is Governance's aggregate.

A separate inference service could not have written that conclusion
anyway. Contexts collaborate only through events and read-only APIs, so
it could at best emit an event for Governance to turn into a proposal ---
which is precisely what Knowledge already does. The service would buy
nothing and cost a deployment.

Rules at adoption --- both over **Observed** evidence:

| Rule | Conclusion |
| --- | --- |
| **Version-range applicability** | Every matched component version is provably outside the reconciled affected range ⇒ not affected |
| **Package not shipped** | The vulnerable package is absent from the release's inventory ⇒ not affected |

Anticipated --- initially **Asserted**: feature-disabled, build-time
exclusion, static configuration analysis, platform incompatibility.

Note what those four have in common: **Themis does not collect their
evidence.** The gap was never a missing rule engine; it was a missing
*authority* over what the enterprise builds, ships and enables. That
authority is the future **Product Applicability** context --- **named but
not created**. When that evidence begins to be collected it earns a
context, and its rules arrive with it. Until then, the two adoption rules
need no new context at all: their evidence already has owners.

### Rules carry no trust of their own

A rule is a deterministic algorithm and nothing more. The *same* rule may
run over different evidence as Themis matures --- a platform-compatibility
rule fed by hand-entered metadata today and by a signed deployment
manifest tomorrow is the same algorithm with materially different
trustworthiness. Trust therefore attaches to **evidence**, and the
conclusion inherits it (§16.5).

### Why this layer is not "part of the AI runtime"

Today the version-range rule lives inside the AI Runtime and is reachable
only by invoking AI. That makes a deterministic correctness feature
depend on an optional plane: **switch AI off and Themis loses a verdict
it is perfectly capable of computing.** Moving the rule to Deterministic
Inference repairs this and correctly classifies its output --- a
provable, arithmetic-certain verdict, not a model's opinion.

> **Precision requirement.** The relocated version-range rule must
> evaluate the **reconciled, backport-aware** range, not a feed's
> query-time filter. A distro backport --- where upstream flags the version
> but the distribution's build is not vulnerable --- is exactly the case
> the reconciled view catches. Getting this wrong produces silent, wrong
> `not_affected` verdicts, the most dangerous defect class in this system.

------------------------------------------------------------------------

## 16.4 Selection

A capability is invoked with a **Selection**: a **type** plus a **set**
of identifiers of that type. The capability declares its supported
type(s) and its **minimum and maximum cardinality**.

Cardinality-as-a-declaration is also the fan-out control. A capability
that handles one Finding declares a maximum of one, and the boundary is
enforced before any projection is built --- no separate global limit is
needed.

**Selection Types are not domain entities.** They are *user-addressable
entry points* --- the things a person can point at in an interface. A type
is admitted only when both hold:

1. **It is addressable** --- it has a stable identifier that could appear
    in a URL today.
2. **A named use case selects it** --- a use case treats it as the thing
    the user picks, not as background context the system gathers.

At adoption: **Finding** and **Release**.

Enterprise Positions are the instructive rejection. A Position has no
independent identity --- it is addressed only as a version of a Finding ---
and no use case asks a user to pick one. It is therefore **Decision
Context**: assembled, never selected. Admitting it would have exposed an
internal versioning construct as a first-class API concept before it was
part of anyone's user experience.

------------------------------------------------------------------------

## 16.5 Trust Propagation in the Backend

Every fact carries a **trust class**, decided by one question: **can this
be re-derived, or must someone be believed?**

- **Observed** --- reproducible from an artifact Themis holds or a public
    record. *An SBOM component list: rescan the artifact, same answer.*
- **Asserted** --- a declaration or judgment Themis cannot re-derive.
    *A vendor `not_affected`.*
- **Inferred** --- the output of non-deterministic reasoning.

The classes are ordered by risk. Note that **transport does not decide the
class** --- an affected range and a vendor's `not_affected` may arrive by
the identical HTTP fetch --- and neither does **who the fact is about**: an
SBOM describes our own product and is still Observed, while our own
operators typing "feature is off" is Asserted until a signed artifact
makes it re-derivable.

A conclusion takes the **highest-risk class among the evidence it used**,
and propagation is **monotonic** --- no deterministic step, no validation
stage, and no human relay may raise a class:

```text
Observed + Observed  →  Observed conclusion
Observed + Asserted  →  Asserted conclusion
Asserted + Inferred  →  Inferred conclusion
```

Two consequences matter for backend design.

**Trust is carried, not recomputed.** Whatever produces a proposal must
carry forward the classes of the facts it consumed. Where the class is
persisted and how it threads through the frozen v1 event contracts is an
open implementation question.

**Producer identity stops being a trust signal.** Governance must not
branch on whether a proposal came from AI, a vendor feed, or the rule
engine. Producer remains recorded --- for explainability --- but the
decision reads the trust class. This closes a laundering path that
producer-based classification cannot see: a deterministic rule consuming
AI-derived input would otherwise emerge with the rule's higher standing.

------------------------------------------------------------------------

## 16.6 Governance Evaluates in Two Ordered Stages

1. **Constitutional check** --- fixed, non-configurable. Chiefly: a
    proposal whose class is **Inferred** may never be auto-accepted, under
    any policy. A proposal failing this stage is not eligible for any
    automatic acceptance.
2. **Policy check** --- configurable, enterprise-owned, applied only to
    proposals that cleared stage 1.

Outcomes remain the two Governance already has: **Accepted** and
**Rejected**. A proposal clearing neither stage stays **open**
(`StatusProposed`) --- awaiting a human is not a third outcome, it is the
absence of an automatic one.

### Decisions and evidence are different concepts

There is **no "accepted with warning" state.** A Position's lifecycle
state records Governance's *decision*; the **evidential confidence** of
that decision is derived exclusively from its immutable
`PositionInputs` --- the field that already exists to record "the evidence
a Position version rested on, so any past decision is fully
reconstructable".

**Reservations are properties of evidence, not of decisions.** An
acceptance resting on Asserted evidence is an ordinary acceptance whose
inputs say so. Read models **shall surface that reservation explicitly**,
beside `stance` and `effective_priority`; it **shall never be persisted
as independent state**.

Three properties follow. A derived reservation **cannot drift** from the
evidence it describes. It **composes with append-only history** --- when a
signed artifact later makes a claim Observed, a new Position version
carries no reservation and the history simply shows it lifting, with no
migration. And it **avoids forking every consumer** of proposal status for
a distinction that does not change whether the proposal was accepted.

The obligation: *derived* must not mean *invisible*. A reservation nobody
computes is a reservation nobody sees. Surfacing it in the read model is
part of the decision, not an optional refinement.

The separation is what makes the bar on Inferred durable. Inside a
configurable policy it would be one misconfiguration away from absent;
as a preceding stage it cannot be switched off.

------------------------------------------------------------------------

## 16.7 What This Changes in the Current Implementation

| Area | Change |
| --- | --- |
| AI Runtime | Loses context *gathering*. Retains shaping (under the four rules), reasoning, semantic retrieval, and Grounding Verification |
| Governance read models | `ReleasePosture` is recognised as the first Domain Projection; further ones follow its pattern and naming rule |
| Version-range rule | Moves out of the AI Runtime into Deterministic Inference |
| `recommend_position` | Plan becomes `[Knowledge → LLM]`; the deterministic step runs before it, in the backend |
| Governance policy | Gains a preceding constitutional stage; stops branching on producer identity |
| Knowledge / Evidence | Must carry evidence trust class forward |
| Read APIs | Gain projection endpoints; existing read APIs are unchanged |

------------------------------------------------------------------------

## Chapter Summary

- The context owning a Selection Type produces **Domain Projections** ---
    reusable, business-named, authoritative, replayable. Every consumer
    uses the same one; AI is not privileged among them.
- **Capability Context is derived in memory, never persisted.** That is
    what gives reuse without projection sprawl, and it keeps AI a
    consumer of the domain rather than a driver of it.
- The AI Runtime is bound by **four rules**: no orchestration;
    information-preserving shaping; full provenance; grounding anchors to
    authority.
- **Deterministic Inference** executes provable rules before AI, raising
    system proposals. AI is the last resort for ambiguity. It is a
    **stage, not a service**.
- **Behaviour follows ownership.** Evidence-owning contexts run inference
    over the evidence they own; a new bounded context is justified by new
    authoritative evidence, never by new rules.
- **Selection** is the user-addressable entry point: a type plus a set,
    with declared cardinality. Selection Types are entry points, not
    domain entities.
- **Trust attaches to evidence, not to rules or producers**, and
    propagates monotonically to the highest-risk class.
- **Governance evaluates constitutionally first, then by policy** --- so
    the bar on Inferred cannot be configured away.
