# Book II --- The Themis Enterprise Security Domain

## Part III --- Domain Behaviour

## Chapter 11 --- Domain Relationships

> *"A mature domain is defined not only by its business concepts, but by
> the relationships and responsibilities that bind them together."*

## Chapter Objective

After reading this chapter, the reader should understand:

- How the core domain concepts relate to one another.
- Why ownership and references are intentionally separated.
- The aggregate boundaries within Themis.
- The domain invariants that preserve architectural integrity.

------------------------------------------------------------------------

## 11.1 Relationships Define Meaning

Business concepts rarely exist in isolation.

A Product has little meaning without Releases.

A Finding has little meaning without a Release.

A Faultline has little value unless it explains Findings.

Enterprise Position cannot exist without Governance.

Themis therefore defines relationships explicitly rather than allowing
them to emerge implicitly through implementation.

------------------------------------------------------------------------

## 11.2 The Core Domain Graph

``` text
Product
   │
   ▼
Project
   │
   ▼
Release
   │ owns
   ▼
Finding ───────────────┐
   │ references        │
   ▼                   │
Faultline ◄────────────┘
   ▲
   │ evolves from
Evidence

Finding
   │ governed by
   ▼
Enterprise Position
   │
   ▼
Communication
```

This graph captures business ownership rather than deployment or
implementation.

------------------------------------------------------------------------

## 11.3 Ownership vs. Reference

Themis distinguishes two kinds of relationships.

### Ownership

Ownership defines lifecycle responsibility.

Examples:

- Product owns Projects.
- Project owns Releases.
- Release owns Findings.
- Governance owns Enterprise Positions.

Deleting or archiving an owner affects the lifecycle of its owned
objects.

### Reference

References establish business association without transferring
ownership.

Examples:

- Findings reference Faultlines.
- Faultlines evolve from Evidence.
- Communication references Enterprise Positions.

References allow enterprise knowledge to be reused without duplicating
business state.

------------------------------------------------------------------------

## 11.4 Aggregate Boundaries

Each aggregate protects its own business invariants.

| Aggregate | Primary Responsibility |
| --- | --- |
| Product | Business identity |
| Project | Engineering boundary |
| Release | Governance boundary |
| Evidence | Enterprise observations |
| Faultline | Enterprise knowledge |
| Finding | Release-specific security concern |
| Enterprise Position | Authoritative enterprise decision |

Aggregates collaborate through references and proposals rather than
shared mutable state.

------------------------------------------------------------------------

## 11.5 Cross-Bounded Context Relationships

Relationships across bounded contexts are intentionally directional.

- Evidence supplies observations to Knowledge.
- Knowledge supplies enterprise understanding to Governance.
- Governance supplies authoritative decisions to Communication.

No downstream context mutates upstream business objects.

This directional model prevents circular ownership and preserves
architectural independence.

------------------------------------------------------------------------

## 11.6 Domain Invariants

The following invariants govern all relationships:

- Every Project belongs to exactly one Product.
- Every Release belongs to exactly one Project.
- Every Finding belongs to exactly one Release.
- Every Finding references exactly one Faultline.
- Faultlines never own Findings.
- Enterprise Positions belong to Governance.
- Communication never owns business truth.
- Ownership and reference relationships shall never be confused.

These invariants are implementation-independent and remain valid
regardless of technology.

------------------------------------------------------------------------

## Domain Invariant 11 --- Ownership Defines Responsibility

Ownership determines lifecycle responsibility.

References establish business association.

A business object may reference many concepts, but it shall have exactly
one authoritative owner.

------------------------------------------------------------------------

## Chapter Summary

Key observations include:

- Domain relationships are explicit architectural contracts.
- Ownership and reference are fundamentally different relationships.
- Aggregate boundaries preserve business invariants.
- Directional relationships prevent architectural coupling.
- The domain graph provides a unified view of enterprise security
    reasoning.

The next chapter introduces Domain Events and explains how business
state evolves through meaningful enterprise events rather than technical
notifications.
