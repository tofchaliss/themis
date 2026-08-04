# Book III --- The Themis Backend Architecture

## Part IV --- Infrastructure

## Chapter 13 --- Event Catalog

> *"The Event Catalog defines the canonical business vocabulary through
> which bounded contexts collaborate."*

------------------------------------------------------------------------

## Chapter Objective

After reading this chapter, the reader should understand:

- The purpose of the Backend Event Catalog.
- How canonical events preserve the ubiquitous language.
- Why event ownership follows bounded-context ownership.
- How event evolution is managed without breaking enterprise
    collaboration.

------------------------------------------------------------------------

## 13.1 Purpose of the Event Catalog

The Backend Event Catalog is the authoritative registry of business
events used within Themis.

It provides a common vocabulary for collaboration between bounded
contexts while preserving business meaning and architectural
consistency.

Every published event shall originate from an accepted business
capability.

------------------------------------------------------------------------

## 13.2 Canonical Business Events

The initial canonical event catalog includes:

### Evidence Context

- Evidence Registered
- Evidence Validated
- Evidence Archived

### Knowledge Context

- Faultline Created
- Faultline Updated
- Knowledge Enriched

### Governance Context

- Finding Created
- Finding Updated
- Enterprise Position Established
- Enterprise Position Revised

### Communication Context

- Communication Requested
- Communication Published
- Communication Failed

The catalog evolves with the Domain and Backend ADRs.

------------------------------------------------------------------------

## 13.3 Event Ownership

Each event has one authoritative publisher.

Only the bounded context that owns the underlying business capability
may publish that event.

Consumers subscribe to events but never assume ownership of the
originating business object.

------------------------------------------------------------------------

## 13.4 Event Structure

Every event should contain sufficient metadata to support reliable
collaboration.

Typical attributes include:

- Event Identifier
- Event Type
- Aggregate Identifier
- Aggregate Version
- Event Timestamp
- Correlation Identifier
- Source Bounded Context
- Business Payload

The exact serialization format is an implementation concern and is
intentionally outside the scope of this architecture.

------------------------------------------------------------------------

## 13.5 Event Versioning

Business capabilities evolve over time.

Events should therefore support versioning while preserving backward
compatibility wherever practical.

Previously published events remain part of the enterprise history and
must continue to be interpretable.

------------------------------------------------------------------------

## 13.6 Event Lifecycle

A business event progresses through the following lifecycle:

``` text
Business Operation
        │
        ▼
Domain Event Created
        │
        ▼
Persist Aggregate
        │
        ▼
Publish Event
        │
        ▼
Consume Event
```

This sequence ensures that only authoritative business facts are
communicated.

------------------------------------------------------------------------

## 13.7 Governance of the Event Catalog

The Event Catalog is an architectural artifact.

Changes to canonical events should be reviewed through the Backend ADR
process to ensure consistency with:

- Constitution
- Enterprise Security Domain
- Backend Architecture

This governance prevents uncontrolled evolution of enterprise
collaboration.

------------------------------------------------------------------------

## Backend Invariant 13 --- Canonical Events Preserve Business Language

The Event Catalog shall represent the authoritative business vocabulary
of the Backend Architecture.

Events shall evolve through architectural governance while preserving
ownership, traceability, and enterprise meaning.

------------------------------------------------------------------------

## Implementation Readiness Checklist

| Question | Status |
| --- | --- |
| Canonical events identified | ✓ |
| Ownership preserved | ✓ |
| Event metadata defined | ✓ |
| Versioning introduced | ✓ |
| Governance established | ✓ |
| Ready for Backend ADRs | ✓ |

------------------------------------------------------------------------

## Chapter Summary

The Backend Event Catalog provides the canonical language through which
bounded contexts collaborate.

By standardizing business events, preserving ownership, supporting
controlled evolution, and aligning event definitions with the Enterprise
Security Domain, the Event Catalog enables reliable and explainable
enterprise collaboration.
