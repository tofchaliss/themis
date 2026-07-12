# Book III --- The Themis Backend Architecture

## Part II --- Core Architecture

## Chapter 7 --- Event Architecture

> *"Events are the language through which bounded contexts collaborate
> without surrendering ownership."*

------------------------------------------------------------------------

## Chapter Objective

After reading this chapter, the reader should understand:

- Why Event Architecture is fundamental to the Backend Architecture.
- The distinction between Domain Events and Integration Events.
- How events preserve bounded-context autonomy.
- Why events communicate business facts rather than business intent.

------------------------------------------------------------------------

## 7.1 Why Event Architecture?

Themis is composed of independently owned bounded contexts.

These contexts must collaborate while preserving their autonomy.

Rather than sharing databases or invoking internal business logic
directly, Themis uses business events to communicate meaningful state
changes.

An event represents something that has already become true within the
enterprise.

------------------------------------------------------------------------

## 7.2 Events Represent Business Facts

Events are not requests.

Events are not commands.

Events are not implementation messages.

An event communicates a completed business fact.

Examples include:

- Evidence Registered
- Evidence Validated
- Faultline Created
- Faultline Evolved
- Finding Created
- Enterprise Position Established
- Communication Published

Every event belongs to the ubiquitous language established in the
Enterprise Security Domain.

------------------------------------------------------------------------

## 7.3 Domain Events and Integration Events

The Backend distinguishes between two categories of events.

### Domain Events

Domain Events are produced within a bounded context after a successful
business operation.

They describe changes to business state and remain part of the Domain
Model.

### Integration Events

Integration Events expose selected Domain Events to other bounded
contexts or external systems.

They provide a stable collaboration contract while allowing each bounded
context to evolve internally.

This separation protects internal domain models from external
dependencies.

------------------------------------------------------------------------

## 7.4 Event Ownership

Every event has exactly one authoritative publisher.

The publisher is always the bounded context that owns the underlying
aggregate.

Examples:

- Evidence Context publishes Evidence events.
- Knowledge Context publishes Faultline events.
- Governance Context publishes Finding and Enterprise Position events.
- Communication Context publishes publication events.

Consumers react to events but never assume ownership of the originating
business object.

------------------------------------------------------------------------

## 7.5 Event Publication

Business events are published only after authoritative state has been
successfully persisted.

The sequence is therefore:

``` text
Application Service
        │
        ▼
Domain Model
        │
        ▼
Persistence
        │
        ▼
Commit Successful
        │
        ▼
Publish Event
```

This ordering prevents publication of business facts that have not been
durably recorded.

------------------------------------------------------------------------

## 7.6 Event Consumption

Bounded contexts consume events according to their own business
responsibilities.

Consumption does not imply synchronous execution.

Consumers determine:

- when to process,
- how to process,
- whether additional business actions are required.

This preserves bounded-context independence.

------------------------------------------------------------------------

## 7.7 Event Evolution

Business vocabulary evolves.

Events therefore require versioning and compatibility strategies.

New event versions should extend existing meaning without redefining
previously published business facts.

Historical events remain valid representations of enterprise history.

------------------------------------------------------------------------

## 7.8 Reliability

The Backend Architecture assumes that failures may occur during event
publication.

Reliable publication therefore requires:

- durable persistence,
- deterministic publication,
- retry capability,
- idempotent consumption,
- reconciliation support.

Reliability strengthens collaboration without compromising ownership.

------------------------------------------------------------------------

## Backend Invariant 7 --- Events Communicate Facts

Events communicate completed business facts.

They shall never bypass ownership, redefine business meaning, or
transfer authoritative responsibility between bounded contexts.

------------------------------------------------------------------------

## Implementation Readiness Checklist

| Question | Status |
| --- | --- |
| Event ownership defined | ✓ |
| Domain and Integration Events separated | ✓ |
| Publication order established | ✓ |
| Consumer autonomy preserved | ✓ |
| Reliability considerations introduced | ✓ |
| Ready for Consistency Boundaries | ✓ |

------------------------------------------------------------------------

## Chapter Summary

The Event Architecture enables independent bounded contexts to
collaborate while preserving ownership and architectural integrity.

By treating events as completed business facts, separating Domain Events
from Integration Events, and publishing events only after authoritative
state changes, the Backend realizes a collaboration model that is
resilient, explainable, and consistent with the Enterprise Security
Domain.

The next chapter introduces Consistency Boundaries and explains how
Themis maintains enterprise consistency without relying on distributed
transactions.
