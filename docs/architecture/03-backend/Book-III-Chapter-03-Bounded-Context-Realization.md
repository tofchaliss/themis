# Book III --- The Themis Backend Architecture

## Part I --- Realizing the Domain

## Chapter 3 --- Bounded Context Realization

> *"The Backend is not divided by services. It is divided by business
> responsibility."*

------------------------------------------------------------------------

## Chapter Objective

After reading this chapter, the reader should understand:

- Why bounded contexts are the primary architectural units of the
    backend.
- How the Domain bounded contexts are realized in software.
- Why ownership, persistence, and business rules remain within a
    single context.
- How bounded contexts collaborate without violating architectural
    boundaries.

------------------------------------------------------------------------

## 3.1 From Domain to Backend

The Domain book introduced four primary bounded contexts:

- Evidence
- Knowledge
- Governance
- Communication

These contexts describe business ownership.

The Backend Architecture realizes these ownership boundaries as
independently executable capabilities.

The backend therefore mirrors the Domain rather than reorganizing it for
technical convenience.

------------------------------------------------------------------------

## 3.2 Why Bounded Contexts?

Many backend systems are organized around technical layers such as APIs,
databases, or microservices.

Themis deliberately avoids this approach.

Instead, the primary unit of architecture is the **Bounded Context**.

Each bounded context encapsulates:

- Business ownership
- Aggregate invariants
- Application services
- Persistence
- Domain events
- Transaction boundaries

Everything required to protect a business capability exists within its
bounded context.

------------------------------------------------------------------------

## 3.3 Backend Contexts

### Evidence Context

Responsibilities:

- Register Evidence
- Validate Evidence
- Preserve provenance
- Maintain Evidence Registry
- Publish Evidence events

The Evidence Context never performs enterprise reasoning.

------------------------------------------------------------------------

### Knowledge Context

Responsibilities:

- Create Faultlines
- Correlate Evidence
- Enrich enterprise knowledge
- Maintain knowledge history
- Publish knowledge events

Knowledge never establishes authoritative enterprise decisions.

------------------------------------------------------------------------

### Governance Context

Responsibilities:

- Create Findings
- Maintain release-specific state
- Establish Enterprise Positions
- Preserve governance history
- Publish governance events

Governance owns enterprise authority.

------------------------------------------------------------------------

### Communication Context

Responsibilities:

- Materialize Enterprise Positions
- Generate VEX
- Generate advisories
- Publish notifications
- Maintain publication history

Communication never modifies Enterprise Positions.

------------------------------------------------------------------------

## 3.4 Context Collaboration

Bounded contexts collaborate through published business facts.

The interaction model is intentionally directional.

``` text
Evidence
    │
    ▼
Knowledge
    │
    ▼
Governance
    │
    ▼
Communication
```

No downstream context modifies upstream business state.

This preserves ownership and architectural independence.

------------------------------------------------------------------------

## 3.5 Persistence Ownership

Each bounded context owns its persistence.

This principle ensures:

- independent evolution,
- autonomous transactions,
- clear ownership,
- simplified recovery.

Repositories are never shared between bounded contexts.

Cross-context data access occurs through events, APIs, or read models
rather than direct database access.

------------------------------------------------------------------------

## 3.6 Transaction Boundaries

Every transaction remains inside a bounded context.

Examples:

- Evidence registration completes within the Evidence Context.
- Faultline evolution completes within the Knowledge Context.
- Enterprise Position updates complete within the Governance Context.

Cross-context workflows rely on events rather than distributed
transactions.

------------------------------------------------------------------------

## 3.7 Race Condition Prevention

Bounded contexts significantly reduce concurrency risks.

Because each context owns its aggregates:

- concurrent modification is localized,
- transactional consistency is simplified,
- reconciliation is explicit,
- ownership conflicts are avoided.

Race conditions become architectural concerns rather than accidental
implementation defects.

------------------------------------------------------------------------

## Backend Invariant 3 --- Bounded Contexts Own Business Capabilities

Every bounded context owns its aggregates, persistence, transactions and
business rules.

Cross-context collaboration occurs through published business facts
while ownership remains local.

------------------------------------------------------------------------

## Implementation Readiness Checklist

| Question | Status |
| --- | --- |
| Domain ownership preserved | ✓ |
| Context responsibilities defined | ✓ |
| Shared persistence avoided | ✓ |
| Transaction boundaries localized | ✓ |
| Event-driven collaboration established | ✓ |
| Ready for Application Layer | ✓ |

------------------------------------------------------------------------

## Chapter Summary

This chapter establishes the realization of the Enterprise Security
Domain within the Backend Architecture.

The Backend mirrors the Domain through bounded contexts that own their
business capabilities, persistence, transactions and events.

Subsequent chapters explore how these bounded contexts implement
application services, domain models, repositories and event-driven
collaboration while preserving constitutional and domain principles.
