# ADR-BCK-0042: Repositories Persist Aggregate Roots Only

Status

Accepted

Category

Persistence

Decision

Repositories shall persist Aggregate Roots.

Repositories shall never expose persistence operations for internal entities or value objects independently of their
owning Aggregate.

Context

Aggregate Roots define transactional consistency boundaries.

Allowing repositories for internal entities bypasses aggregate invariants.

Problem Statement

What should a Repository own?

Decision

One Repository corresponds to one Aggregate Root.

Internal entities are persisted only through their Aggregate Root.

Repositories expose aggregate operations rather than CRUD interfaces.

Rationale

This preserves:

- aggregate consistency,
- business invariants,
- transactional integrity.

Alternatives Considered

Repository Per Entity

Rejected.

Entity independence violates aggregate consistency.

Generic CRUD Repository

Rejected.

CRUD abstractions ignore business behaviour.

Consequences

Positive

- Rich Domain Model.
- Stable aggregate boundaries.
- Simplified consistency.

Negative

- Repository interfaces become domain-specific.

Implementation Impact

Repositories shall expose business-oriented methods rather than generic persistence operations.

Related ADRs

ADR-DOM-0031

ADR-BCK-0039

Confidence

Very High

References

Book III

Repository Strategy
