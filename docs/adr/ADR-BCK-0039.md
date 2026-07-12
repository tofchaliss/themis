# ADR-BCK-0039: Domain Layer Owns Executable Business Behaviour

Status

Accepted

Category

Domain Layer

Decision

The Backend Domain Layer shall contain all executable business behaviour.

No other Backend layer shall redefine enterprise rules.

Context

Business rules naturally migrate into controllers, repositories, and infrastructure.

The architecture prevents this.

Problem Statement

Where should executable enterprise behaviour reside?

Decision

The Domain Layer owns:

- aggregates,
- value objects,
- domain services,
- business validation,
- business invariants,
- domain events.

Rationale

Enterprise behaviour remains stable while implementation evolves.

Alternatives Considered

Repository-centric behaviour.

Rejected.

Infrastructure-centric behaviour.

Rejected.

Consequences

Positive

- Stable business behaviour.
- Cleaner architecture.

Negative

- Rich domain modelling required.

Implementation Impact

Repositories persist aggregates.

Application Services coordinate aggregates.

Infrastructure supports aggregates.

Related ADRs

ADR-DOM-0031

ADR-CON-0001

Confidence

Very High

References

Book III

Chapter 5
