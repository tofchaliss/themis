# ADR-BCK-0040: Persistence Exists to Preserve Business State

Status

Accepted

Category

Persistence

Decision

Persistence shall preserve authoritative business state without introducing business behaviour.

Persistence follows the Domain.

Context

Persistence technologies evolve independently from enterprise architecture.

Business ownership must remain independent of storage mechanisms.

Problem Statement

What is the architectural responsibility of persistence?

Decision

Persistence is responsible for:

- aggregate storage,
- retrieval,
- optimistic versioning,
- historical state,
- recovery.

Persistence shall never:

- enforce business rules,
- publish events,
- coordinate workflows.

Rationale

Persistence preserves business state.

It does not own business meaning.

Alternatives Considered

Repository business logic.

Rejected.

Database-driven architecture.

Rejected.

Consequences

Positive

- Clean persistence.
- Technology independence.

Negative

- Additional abstraction.

Implementation Impact

Repositories remain subordinate to the Domain.

Related ADRs

ADR-DOM-0031

ADR-CON-0005

Confidence

Very High

References

Book III

Chapter 6
