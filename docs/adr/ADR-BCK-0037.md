# ADR-BCK-0037: Bounded Contexts Are the Primary Backend Modularization Strategy

Status

Accepted

Category

Architecture

Decision

The Backend shall be modularized around Domain Bounded Contexts.

Implementation packages, services, repositories, workflows, and background workers shall belong to exactly one Bounded
Context.

Context

The Domain defines independent business capabilities.

The Backend must preserve these boundaries throughout implementation.

Problem Statement

How should the Backend be partitioned?

Decision

Every Bounded Context owns:

- Application Layer
- Domain Layer
- Persistence
- Events
- Repositories
- Workers

No implementation component belongs to multiple contexts.

Rationale

This preserves:

- ownership,
- scalability,
- maintainability,
- independent deployment.

Alternatives Considered

Layer-first modularization

Rejected.

Business ownership becomes fragmented.

Consequences

Positive

- Stable modular architecture.
- Clear ownership.
- Independent evolution.

Negative

- Cross-context communication required.

Implementation Impact

Source code organization shall mirror Bounded Context ownership.

Related ADRs

ADR-CON-0011

ADR-DOM-0035

Confidence

Very High

References

Book III

Chapter 3
