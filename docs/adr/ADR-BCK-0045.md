# ADR-BCK-0045: Background Workers Execute Asynchronous Business Capabilities

Status

Accepted

Category

Execution

Decision

Background Workers execute asynchronous business capabilities while preserving all Domain ownership rules.

Workers execute business operations but never become owners of enterprise state.

Context

Knowledge enrichment, reconciliation, notification, synchronization, and reporting execute outside interactive request
processing.

Problem Statement

How should asynchronous work be incorporated into the Backend?

Decision

Workers may:

- consume events,
- schedule work,
- execute background processing,
- trigger workflows.

Workers shall modify only Aggregates owned by their bounded context.

Rationale

Background execution improves scalability without changing ownership.

Alternatives Considered

Shared Worker Pool

Rejected.

Ownership becomes ambiguous.

Infrastructure-Only Workers

Rejected.

Business processing belongs within bounded contexts.

Consequences

Positive

- Better scalability.
- Independent execution.
- Simpler scheduling.

Negative

- Worker monitoring required.

Implementation Impact

Background Workers belong to exactly one bounded context.

Related ADRs

ADR-BCK-0037

ADR-CON-0001

Confidence

Very High

References

Book III

Background Workers
