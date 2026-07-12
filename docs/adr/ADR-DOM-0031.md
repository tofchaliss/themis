# ADR-DOM-0031: Aggregate Roots Define Transactional Consistency Boundaries

Status

Accepted

Category

Aggregate Design

Decision

Every Aggregate Root shall define the smallest business consistency boundary within the Enterprise Security Domain.

All business invariants shall be maintained within the Aggregate boundary.

No transaction shall span multiple Aggregate Roots.

Context

The Enterprise Security Domain consists of multiple independent business objects including Products, Projects, Releases,
Evidence, Faultlines, Findings, Enterprise Positions, and Communication artifacts.

Each object evolves independently while collaborating with others.

Problem Statement

How should business consistency be maintained without creating tightly coupled domain objects?

Decision

Each Aggregate Root owns:

- its lifecycle,
- business invariants,
- transactional consistency,
- internal entities,
- value objects.

Business collaboration across aggregates shall occur through references and domain events rather than shared
transactions.

Rationale

Aggregate consistency boundaries provide:

- deterministic business behaviour,
- simpler transactions,
- clearer ownership,
- scalable evolution.

Alternatives Considered

Single Large Aggregate

Rejected.

Large aggregates reduce scalability and increase contention.

Shared Aggregate Ownership

Rejected.

Ownership ambiguity weakens domain integrity.

Consequences

Positive

- Clear transactional boundaries.
- Simplified consistency.
- Independent aggregate evolution.

Negative

- Eventual consistency required between aggregates.

Implementation Impact

Repositories shall persist complete Aggregate Roots.

Application Services shall never modify multiple Aggregate Roots within one business transaction unless coordinated
through workflow orchestration.

Related ADRs

ADR-CON-0001

ADR-DOM-0028

ADR-DOM-0030

Confidence

Very High

References

Book II – Aggregate Design

Book III – Domain Layer
