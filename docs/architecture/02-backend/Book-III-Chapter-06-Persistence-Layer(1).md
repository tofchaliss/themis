# Book III --- The Themis Backend Architecture

## Part II --- Core Architecture

## Chapter 6 --- Persistence Layer

> *"Persistence preserves enterprise state. It never becomes the source
> of enterprise truth."*

------------------------------------------------------------------------

## Chapter Objective

After reading this chapter, the reader should understand:

- The role of persistence in the Backend Architecture.
- Why persistence is subordinate to the Domain Layer.
- How repository ownership follows bounded-context ownership.
- How versioning, auditability, and recovery preserve enterprise
    integrity.

------------------------------------------------------------------------

## 6.1 Purpose of the Persistence Layer

The Persistence Layer is responsible for storing and retrieving the
authoritative state of aggregates.

It does not define business behaviour, enforce business meaning, or
coordinate workflows. Those responsibilities belong to the Domain and
Application layers.

Its purpose is to ensure that business state survives process failures,
restarts, and deployments while remaining faithful to the Enterprise
Security Domain.

------------------------------------------------------------------------

## 6.2 Persistence Follows Ownership

Persistence ownership mirrors bounded-context ownership.

Each bounded context owns:

- Its repositories
- Its database schema or storage model
- Its persistence lifecycle
- Its migration strategy

This prevents hidden coupling and preserves autonomous evolution.

No bounded context shall directly modify another context's persistent
state.

------------------------------------------------------------------------

## 6.3 Repository Responsibilities

Repositories provide the persistence abstraction for aggregate roots.

A repository is responsible for:

- Loading aggregate roots.
- Persisting successful state transitions.
- Maintaining aggregate identity.
- Supporting optimistic versioning.
- Recovering authoritative state.

Repositories shall not contain business rules, orchestration logic, or
cross-context coordination.

------------------------------------------------------------------------

## 6.4 Aggregate Persistence

Each aggregate is persisted as a consistency boundary.

Persistence is organized around aggregate ownership rather than
relational convenience.

Typical aggregate persistence includes:

- Product
- Project
- Release
- Evidence
- Faultline
- Finding
- Enterprise Position

The storage representation may evolve, but aggregate ownership remains
stable.

------------------------------------------------------------------------

## 6.5 Versioning and Auditability

Enterprise security decisions must remain explainable.

The Persistence Layer therefore preserves:

- Aggregate version history.
- Change timestamps.
- Proposal lineage.
- Authoritative state transitions.
- Audit metadata.

Historical state is retained to support replay, investigations,
compliance, and customer communication.

------------------------------------------------------------------------

## 6.6 Optimistic Concurrency

Themis prefers optimistic concurrency for aggregate updates.

Every aggregate version represents an expected business state.

If concurrent modifications occur, the update is rejected and the
operation is retried or reconciled according to the owning bounded
context.

Concurrency protection is an architectural capability rather than a
database feature.

------------------------------------------------------------------------

## 6.7 Recovery

Recovery always begins from authoritative persisted state.

After a failure, the backend restores aggregates from persistence before
continuing business execution.

Recovery mechanisms shall never invent business state or bypass
aggregate invariants.

------------------------------------------------------------------------

## 6.8 Storage Independence

The architecture intentionally avoids dependence on any specific storage
technology.

Whether persistence is implemented using relational databases, document
stores, graph databases, or future technologies, the architectural
contracts remain unchanged.

Technology may evolve.

Business ownership shall not.

------------------------------------------------------------------------

## Backend Invariant 6 --- Persistence Preserves, It Does Not Decide

The Persistence Layer preserves authoritative aggregate state.

It never introduces business meaning, bypasses aggregate invariants, or
transfers ownership between bounded contexts.

------------------------------------------------------------------------

## Implementation Readiness Checklist

| Question | Status |
| --- | --- |
| Repository ownership aligned with bounded contexts | ✓ |
| Aggregate persistence defined | ✓ |
| Versioning strategy established | ✓ |
| Auditability preserved | ✓ |
| Optimistic concurrency introduced | ✓ |
| Ready for Event Architecture | ✓ |

------------------------------------------------------------------------

## Chapter Summary

The Persistence Layer provides durable storage for the Enterprise
Security Domain while remaining subordinate to the Domain Model.

By aligning persistence with bounded-context ownership, preserving
version history, supporting optimistic concurrency, and maintaining
auditability, it enables reliable execution without compromising
architectural integrity.

The next chapter introduces the Event Architecture and explains how
bounded contexts collaborate through authoritative business events.
