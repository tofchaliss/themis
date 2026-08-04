# Book III --- The Themis Backend Architecture

## Part IV --- Infrastructure

## Chapter 12 --- Repository Strategy

> *"Repositories preserve aggregates. They never become an alternative
> Domain Layer."*

------------------------------------------------------------------------

## Chapter Objective

After reading this chapter, the reader should understand:

- The purpose of repositories within the Backend Architecture.
- How repository ownership follows bounded-context ownership.
- Why repositories remain free from business behaviour.
- How repository contracts support persistence while preserving Domain
    integrity.

------------------------------------------------------------------------

## 12.1 Purpose of the Repository

A repository provides the persistence abstraction for aggregate roots.

It shields the Domain Layer from storage technology while providing
reliable access to authoritative business state.

Repositories exist to persist aggregates---not to interpret business
meaning.

------------------------------------------------------------------------

## 12.2 Repository Ownership

Every bounded context owns its own repositories.

Repository ownership follows the same ownership rules as aggregates and
persistence.

Examples include:

- Evidence Repository
- Faultline Repository
- Finding Repository
- Enterprise Position Repository

Repositories are never shared across bounded contexts.

------------------------------------------------------------------------

## 12.3 Repository Responsibilities

A repository is responsible for:

- Loading aggregate roots.
- Persisting successful aggregate state changes.
- Maintaining aggregate identity.
- Supporting optimistic versioning.
- Retrieving historical state where required.

Repositories shall not:

- enforce business rules,
- orchestrate workflows,
- publish events,
- coordinate other bounded contexts.

------------------------------------------------------------------------

## 12.4 Aggregate-Centric Persistence

Repositories are designed around aggregate boundaries rather than
database tables.

Each repository protects the transactional consistency of the aggregate
it owns.

Storage optimization must never weaken aggregate integrity.

------------------------------------------------------------------------

## 12.5 Read Models

Some enterprise queries span multiple bounded contexts.

These views should be implemented as read models or projections rather
than by bypassing repository ownership.

Read models improve query efficiency while preserving authoritative
ownership.

------------------------------------------------------------------------

## 12.6 Technology Independence

The repository contract remains stable even if storage technology
changes.

Whether the implementation uses relational databases, document
databases, graph stores, or future persistence technologies, the Domain
Layer remains unaffected.

Architecture depends on repository contracts---not storage products.

------------------------------------------------------------------------

## 12.7 Repository Evolution

As business capabilities evolve, repository implementations may change.

The contract with the Domain Layer should remain stable wherever
possible, allowing infrastructure to evolve independently from business
behaviour.

------------------------------------------------------------------------

## Backend Invariant 12 --- Repositories Preserve Domain Integrity

Repositories persist and retrieve aggregate state while remaining
subordinate to the Domain Layer.

They shall never contain business logic, redefine ownership, or bypass
aggregate invariants.

------------------------------------------------------------------------

## Implementation Readiness Checklist

| Question | Status |
| --- | --- |
| Repository ownership defined | ✓ |
| Aggregate-centric persistence established | ✓ |
| Read model strategy introduced | ✓ |
| Technology independence preserved | ✓ |
| Domain integrity protected | ✓ |
| Ready for Event Catalog | ✓ |

------------------------------------------------------------------------

## Chapter Summary

Repositories provide the persistence boundary between the Domain Layer
and storage infrastructure.

By aligning repository ownership with bounded contexts and aggregate
boundaries, Themis preserves business integrity while allowing
persistence technologies to evolve independently of the Enterprise
Security Domain.

The next chapter introduces the Backend Event Catalog, establishing the
canonical business events that enable collaboration across the platform.
