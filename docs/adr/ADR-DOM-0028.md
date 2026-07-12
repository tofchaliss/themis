# ADR-DOM-0028: Aggregate Relationships Shall Preserve Ownership

Status

Accepted

Category

Relationships

Decision

Relationships between aggregates shall be established through stable business identities.

Aggregates shall reference one another without transferring ownership.

Context

Business capabilities naturally collaborate.

Releases reference Projects.

Findings reference Faultlines.

Enterprise Positions reference Findings.

Communication references Enterprise Positions.

These relationships must preserve independent ownership.

Problem Statement

How can aggregates collaborate without becoming tightly coupled?

Decision

Relationships shall use business references.

No aggregate may directly own another aggregate belonging to a different bounded context.

Aggregate ownership always remains local.

Rationale

Reference-based collaboration preserves:

- autonomy,
- consistency,
- scalability,
- independent evolution.

Alternatives Considered

Nested aggregate ownership

Rejected.

Cross-context ownership violates bounded-context autonomy.

Consequences

Positive

- Loose coupling.
- Stable references.
- Independent lifecycle management.

Negative

- Relationship traversal requires coordination.

Implementation Impact

Repositories and Domain Models shall preserve aggregate independence.

Related ADRs

ADR-CON-0001

ADR-CON-0011

ADR-DOM-0027

Confidence

Very High

References

Book II – Aggregate Relationships
