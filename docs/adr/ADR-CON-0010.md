# ADR-CON-0010: Communication Publishes Enterprise Truth

Status

Accepted

Category

Communication

Decision

Communication shall publish enterprise truth but shall never establish, modify, or reinterpret enterprise decisions.

Communication exists solely to materialize authoritative enterprise information for consumers.

Context

Enterprise information is consumed by:

- Customers
- Internal engineering
- Security teams
- Compliance organizations
- External systems

These consumers require information that has already been approved by the enterprise.

Communication therefore represents publication rather than decision making.

Problem Statement

How can enterprise information be communicated without allowing publication mechanisms to redefine enterprise decisions?

Decision

Communication shall consume authoritative enterprise state produced by Governance.

Communication may transform presentation.

Communication may select audience.

Communication may generate reports.

Communication shall never modify enterprise authority.

Rationale

Separating governance from communication preserves:

- enterprise consistency,
- audience independence,
- publication flexibility,
- architectural ownership.

Alternatives Considered

Communication Determines Customer Truth

Rejected.

Presentation layers must never redefine enterprise decisions.

Shared Governance and Communication

Rejected.

Decision making and publication are separate business capabilities.

Consequences

Positive

- Consistent enterprise messaging.
- Multiple publication channels.
- Independent communication evolution.

Negative

- Publication depends upon Governance completion.

Implementation Impact

Communication services consume Enterprise Positions but never modify them.

Related ADRs

ADR-CON-0001

ADR-CON-0009

Confidence

Very High

References

Book II – Communication

Book III – Event Architecture

Book III – Workflow Orchestration
