# ADR-BCK-0038: Application Services Coordinate Use Cases

Status

Accepted

Category

Application Layer

Decision

Application Services coordinate backend use cases but shall never contain enterprise business rules.

Business behaviour remains within the Domain.

Context

Application Services interact with APIs, workflows, and repositories.

Without discipline they become procedural business engines.

Problem Statement

Where should orchestration stop and business behaviour begin?

Decision

Application Services may:

- validate requests,
- authorize operations,
- manage transactions,
- coordinate aggregates,
- publish events.

Application Services shall never:

- enforce aggregate invariants,
- own business rules,
- establish enterprise truth.

Rationale

Coordination and business behaviour represent different architectural responsibilities.

Alternatives Considered

Rich Application Services

Rejected.

Business behaviour becomes duplicated.

Consequences

Positive

- Rich Domain Model.
- Clear separation.
- Easier testing.

Negative

- More domain modelling effort.

Implementation Impact

Application Services delegate business decisions to Aggregates and Domain Services.

Related ADRs

ADR-DOM-0031

Confidence

Very High

References

Book III

Chapter 4
