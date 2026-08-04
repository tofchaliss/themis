# Book III --- The Themis Backend Architecture

## Part II --- Core Architecture

## Chapter 5 --- Domain Layer

> *"The Domain Layer is the executable realization of the Enterprise
> Security Domain. It protects business truth regardless of how software
> is delivered."*

------------------------------------------------------------------------

## Chapter Objective

After reading this chapter, the reader should understand:

- The purpose of the Domain Layer.
- How the Domain Layer differs from the Application Layer.
- The responsibilities of aggregates, entities, value objects and
    domain services.
- Why business invariants are enforced within the Domain Layer.

------------------------------------------------------------------------

## 5.1 The Purpose of the Domain Layer

The Domain Layer contains the executable business model of Themis.

It is responsible for enforcing business rules, protecting aggregate
invariants and preserving the semantics defined in the Enterprise
Security Domain.

Unlike the Application Layer, the Domain Layer does not orchestrate
workflows. It owns business behaviour.

------------------------------------------------------------------------

## 5.2 The Domain Layer Is Independent

The Domain Layer has no knowledge of:

- HTTP
- REST
- Messaging protocols
- Databases
- User interfaces
- Deployment topology

Its behaviour remains identical regardless of delivery mechanism or
infrastructure.

This independence ensures that business logic remains stable even as
implementation technologies evolve.

------------------------------------------------------------------------

## 5.3 Aggregates

Aggregates represent consistency boundaries within a bounded context.

Each aggregate protects a specific business capability and guarantees
that its invariants remain valid after every successful transaction.

Application Services invoke aggregates; they never replace them.

------------------------------------------------------------------------

## 5.4 Entities

Entities possess stable business identity throughout their lifecycle.

Examples within Themis include concepts such as Products, Projects,
Releases, Evidence, Faultlines and Findings.

Their identity persists even as their state evolves according to
business rules.

------------------------------------------------------------------------

## 5.5 Value Objects

Value Objects represent descriptive business concepts that are defined
by their value rather than identity.

Typical examples include:

- Version identifiers
- Software digests
- Package URLs (PURLs)
- Severity representations
- Risk classifications
- Provenance descriptors

Value Objects are immutable and may be freely shared without affecting
ownership.

------------------------------------------------------------------------

## 5.6 Domain Services

Some business operations cannot naturally belong to a single aggregate.

These operations are implemented as Domain Services.

Domain Services encapsulate business behaviour while remaining free from
application orchestration and infrastructure concerns.

They coordinate business rules without becoming owners of business
state.

------------------------------------------------------------------------

## 5.7 Business Invariants

Every aggregate protects its own invariants.

Typical examples include:

- Evidence remains immutable after registration.
- A Faultline preserves its enterprise identity.
- A Finding belongs to exactly one Release.
- Enterprise authority is established only through Governance.

The Domain Layer is the final authority for enforcing these invariants.

------------------------------------------------------------------------

## 5.8 Domain Events

When an aggregate successfully completes a business operation, it may
produce one or more Domain Events.

These events represent completed business facts.

They are consumed by the Application Layer for publication and
collaboration but remain defined by the Domain.

------------------------------------------------------------------------

## 5.9 Dependency Direction

Dependency always flows inward.

``` text
Presentation
      │
      ▼
Application
      │
      ▼
Domain
      │
      ▼
Infrastructure
```

The Domain Layer depends on nothing outside itself.

This protects the business model from implementation drift.

------------------------------------------------------------------------

## Backend Invariant 5 --- The Domain Owns Business Behaviour

Business behaviour, invariants and enterprise meaning reside exclusively
within the Domain Layer.

Neither the Application Layer nor Infrastructure may redefine business
rules for implementation convenience.

------------------------------------------------------------------------

## Implementation Readiness Checklist

| Question | Status |
| --- | --- |
| Business rules isolated from infrastructure | ✓ |
| Aggregate boundaries established | ✓ |
| Value Objects identified | ✓ |
| Domain Services introduced | ✓ |
| Invariants protected | ✓ |
| Ready for Persistence Layer | ✓ |

------------------------------------------------------------------------

## Chapter Summary

The Domain Layer is the heart of the Backend Architecture.

It transforms the Enterprise Security Domain into executable business
behaviour while preserving ownership, invariants and constitutional
principles. Every subsequent backend component---repositories,
persistence, events and workflows---exists to support the Domain Layer
rather than replace it.
