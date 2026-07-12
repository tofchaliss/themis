# Book II --- The Themis Enterprise Security Domain

## Part IV --- Domain Decisions

## Chapter 12 --- Domain Events

> *"Business events describe that something meaningful has happened to
> the enterprise. They do not describe how software communicates."*

## Chapter Objective

After reading this chapter, the reader should understand:

- What constitutes a Domain Event in Themis.
- Why Domain Events are business concepts rather than messaging
    constructs.
- How Domain Events preserve bounded-context independence.
- The core event catalog of the Themis domain.

------------------------------------------------------------------------

## 12.1 Why Domain Events?

Themis is an event-aware domain, but it is not an event-driven domain by
definition.

The domain evolves because meaningful business events occur:

- Evidence is registered.
- Enterprise knowledge evolves.
- Governance establishes a new position.
- Communication publishes an authoritative decision.

These events describe changes in business state, independent of
implementation technology.

------------------------------------------------------------------------

## 12.2 Business Events vs. Technical Events

A Domain Event records something that became true within the business.

Examples:

- Evidence Registered
- Faultline Evolved
- Finding Created
- Enterprise Position Established

A message published to Kafka, RabbitMQ, or another broker is merely one
possible implementation.

The Domain Model defines **what happened**, not **how it is
transported**.

------------------------------------------------------------------------

## 12.3 Principles of Domain Events

Every Domain Event follows these principles:

- It represents a completed business fact.
- It is expressed using the ubiquitous language.
- It originates from exactly one bounded context.
- It never transfers ownership.
- It may be consumed by multiple bounded contexts.

These principles preserve consistency across the platform.

------------------------------------------------------------------------

## 12.4 Core Event Catalog

| Event | Owner | Meaning |
| --- | --- | --- |
| Evidence Registered | Evidence | New enterprise evidence accepted. |
| Evidence Validated | Evidence | Evidence passed business validation. |
| Faultline Created | Knowledge | New enterprise knowledge identity established. |
| Faultline Evolved | Knowledge | Enterprise understanding has matured. |
| Finding Created | Governance | Release-specific security concern established. |
| Finding Updated | Governance | Governance state changed. |
| Enterprise Position Established | Governance | Official enterprise position created. |
| Enterprise Position Revised | Governance | Authoritative position evolved. |
| Communication Requested | Governance | Publication requested from Communication. |
| Communication Published | Communication | Authoritative communication materialized. |

This catalog captures business semantics rather than transport
semantics.

------------------------------------------------------------------------

## 12.5 Event Ownership

Events belong to the bounded context that owns the underlying business
object.

For example:

- Evidence publishes Evidence events.
- Knowledge publishes Faultline events.
- Governance publishes Finding and Enterprise Position events.
- Communication publishes publication events.

Consumers react to events but never acquire ownership of the originating
business object.

------------------------------------------------------------------------

## 12.6 Event Evolution

The event catalog is expected to evolve as the domain grows.

However:

- Existing event meanings shall remain stable.
- Event names shall remain part of the ubiquitous language.
- New events shall be introduced only when new business behaviour
    emerges.

This preserves compatibility and architectural consistency.

------------------------------------------------------------------------

## Domain Invariant 12 --- Events Describe Business Facts

Domain Events represent completed business facts.

They shall describe meaningful changes in enterprise state and shall
remain independent of messaging technologies, transport protocols, or
implementation mechanisms.

------------------------------------------------------------------------

## Chapter Summary

Key observations include:

- Domain Events describe business facts, not technical messages.
- Every event has exactly one authoritative owner.
- Events preserve bounded-context independence.
- The event catalog forms the business contract between bounded
    contexts.
- Implementation technologies may change without altering Domain Event
    semantics.

The next chapter consolidates the Domain ADRs that shaped the Enterprise
Security Domain and explains the reasoning behind its most significant
architectural decisions.
