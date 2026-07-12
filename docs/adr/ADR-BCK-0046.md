# ADR-BCK-0046: Integration Events Shall Be Stable Collaboration Contracts

Status

Accepted

Category

Integration

Decision

Integration Events shall serve as the stable collaboration contracts between bounded contexts.

They are derived from Domain Events but are not identical to Domain Events.

The Backend shall distinguish internal business events from externally consumable integration contracts.

Context

Domain Events describe business facts within a bounded context.

Not every Domain Event is appropriate for publication outside the owning context.

A stable collaboration model requires explicit integration contracts.

Problem Statement

How should bounded contexts collaborate without exposing internal implementation details?

Decision

The Backend shall distinguish:

- Domain Events
- Integration Events

Domain Events remain internal business events.

Integration Events are stable contracts published for other bounded contexts.

The mapping from Domain Event to Integration Event belongs to the owning bounded context.

Rationale

Separating Domain Events from Integration Events:

- protects internal implementation,
- enables independent evolution,
- preserves loose coupling,
- simplifies versioning.

Alternatives Considered

Expose Domain Events Directly

Rejected.

Internal business evolution would break external consumers.

Generic Messaging Layer

Rejected.

Messages without business meaning weaken collaboration.

Consequences

Positive

- Stable event contracts.
- Independent evolution.
- Better version management.

Negative

- Additional event mapping required.

Implementation Impact

Each bounded context shall own the transformation from Domain Events to Integration Events.

Related ADRs

ADR-CON-0012

ADR-DOM-0033

ADR-BCK-0041

Confidence

Very High

References

Book III

Event Architecture
