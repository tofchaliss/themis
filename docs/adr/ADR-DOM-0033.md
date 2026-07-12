# ADR-DOM-0033: Domain Events Represent Completed Business Facts

Status

Accepted

Category

Domain Events

Decision

Every Domain Event shall represent a completed business fact resulting from a successful state transition within an
Aggregate.

Domain Events shall never represent commands, requests, or incomplete business operations.

Context

Business collaboration depends upon communicating meaningful changes.

Incorrectly using events as commands weakens ownership and introduces implementation coupling.

Problem Statement

What should a Domain Event represent?

Decision

A Domain Event communicates that something has already become true within the Domain.

Examples include:

- Evidence Registered
- Faultline Created
- Finding Created
- Enterprise Position Established

Domain Events remain part of the ubiquitous business language.

Rationale

Completed business facts:

- preserve ownership,
- simplify collaboration,
- improve explainability,
- enable event-driven architectures.

Alternatives Considered

Command Events

Rejected.

Commands request work.

Events communicate completed work.

Infrastructure Events

Rejected.

Infrastructure concerns should remain outside the Domain.

Consequences

Positive

- Stable business collaboration.
- Clear event semantics.
- Better traceability.

Negative

- Event publication discipline required.

Implementation Impact

Backend Event Architecture shall publish Domain Events only after successful Aggregate persistence.

Related ADRs

ADR-CON-0012

ADR-DOM-0031

Confidence

Very High

References

Book II – Domain Events

Book III – Event Architecture
