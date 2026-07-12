# ADR-BCK-0044: Workflow Orchestration Coordinates but Does Not Own Business Behaviour

Status

Accepted

Category

Workflow

Decision

Workflow Orchestration coordinates long-running business processes without owning business rules or aggregate state.

Business ownership always remains within the participating bounded contexts.

Context

Enterprise workflows span Evidence, Knowledge, Governance, and Communication.

Coordination is required without introducing a central business engine.

Problem Statement

What is the architectural responsibility of Workflow Orchestration?

Decision

Workflow Orchestration may:

- sequence work,
- wait for events,
- resume execution,
- coordinate retries,
- monitor progress.

Workflow Orchestration shall never:

- modify aggregates directly,
- enforce business rules,
- establish enterprise truth.

Rationale

Coordination and business ownership are independent architectural concerns.

Alternatives Considered

Workflow Owns Business Logic

Rejected.

Business ownership becomes centralized.

Distributed Workflow Logic

Rejected.

Reasoning becomes fragmented.

Consequences

Positive

- Clean separation.
- Easier recovery.
- Independent bounded contexts.

Negative

- Event-driven coordination required.

Implementation Impact

Workflow engines coordinate Application Services rather than Domain objects.

Related ADRs

ADR-BCK-0038

ADR-DOM-0026

Confidence

Very High

References

Book III

Workflow Orchestration
