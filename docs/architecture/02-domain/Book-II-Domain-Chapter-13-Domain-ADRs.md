# Book II --- The Themis Enterprise Security Domain

## Part IV --- Domain Decisions

## Chapter 13 --- Domain ADRs

> *"A mature domain model is not defined only by its final structure,
> but by the reasoning that shaped it."*

## Chapter Objective

After reading this chapter, the reader should understand:

- Why the Domain Architecture is supported by Architectural Decision
    Records (ADRs).
- How ADRs preserve architectural intent.
- The major domain decisions that define Themis.
- How future domain evolution should remain consistent with these
    decisions.

------------------------------------------------------------------------

## 13.1 Why Domain ADRs?

A domain model evolves through discussion, exploration, and trade-offs.

Without documenting those decisions, future contributors may unknowingly
reverse important architectural choices or introduce inconsistencies.

Themis therefore treats Domain ADRs as permanent architectural knowledge
rather than temporary design notes.

------------------------------------------------------------------------

## 13.2 Relationship Between the Constitution and Domain ADRs

The Constitution establishes architectural principles.

Domain ADRs apply those principles to the enterprise domain.

Every Domain ADR should be traceable back to one or more constitutional
principles such as:

- Single Authoritative Ownership
- Proposal Before Truth
- Explainability Before Convenience
- Controlled Enterprise Evolution

This traceability preserves architectural coherence.

------------------------------------------------------------------------

## 13.3 Canonical Domain Decisions

The current domain model is founded on several key decisions.

### ADR-D01 --- Release Is the Governance Boundary

Governance is performed within the context of a Release.

Products and Projects provide organizational context.

Releases provide decision context.

### ADR-D02 --- Findings Are Release-Scoped

Every Finding belongs to exactly one Release.

Findings never exist independently of a Release.

### ADR-D03 --- Faultlines Are Enterprise Knowledge Identities

Faultlines are enterprise-wide knowledge identities.

They are not owned by Releases and are reused across multiple Findings.

### ADR-D04 --- Findings Reference Exactly One Faultline

A Finding references one Faultline to reuse enterprise knowledge while
preserving release-specific governance.

### ADR-D05 --- Enterprise Position Represents Authority

Enterprise Position is the enterprise's authoritative business decision.

It is owned exclusively by Governance.

### ADR-D06 --- Evidence Is Immutable

Evidence records enterprise observations.

Enterprise understanding evolves by adding new Evidence rather than
modifying historical observations.

### ADR-D07 --- Ownership Is Explicit

Every authoritative business object has exactly one owner.

References never imply ownership.

------------------------------------------------------------------------

## 13.4 Architectural Trade-offs

The Domain ADRs intentionally favor:

- clarity over convenience,
- explicit ownership over shared state,
- reusable knowledge over duplicated analysis,
- controlled evolution over direct mutation,
- explainability over optimization.

These trade-offs reflect long-term maintainability rather than
short-term implementation simplicity.

------------------------------------------------------------------------

## 13.5 Evolving the Domain

Future changes to the domain should first evaluate whether existing ADRs
remain sufficient.

A new Domain ADR should be created only when:

- a new business invariant is introduced,
- ownership changes,
- aggregate boundaries change,
- ubiquitous language changes,
- or a constitutional principle requires extension.

Implementation changes alone do not justify a Domain ADR.

------------------------------------------------------------------------

## Domain Invariant 13 --- Domain Decisions Are Preserved

Significant domain decisions shall be documented through ADRs.

Future evolution shall extend the domain deliberately rather than
redefining established business concepts.

------------------------------------------------------------------------

## Chapter Summary

Key observations include:

- Domain ADRs preserve architectural intent.
- Every major business invariant is supported by an explicit
    architectural decision.
- Constitutional principles guide Domain ADRs.
- Domain evolution is deliberate, explainable, and reviewable.

The final chapter captures research notes, deferred decisions, and
future directions for the Enterprise Security Domain.
