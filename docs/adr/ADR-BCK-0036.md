# ADR-BCK-0036: Backend Architecture Realizes the Enterprise Security Domain

Status

Accepted

Category

Architecture

Decision

The Backend Architecture shall exist solely to realize the Enterprise Security Domain.

The Backend shall never redefine business concepts, ownership, relationships, or enterprise semantics established by the
Domain.

Context

The Enterprise Security Domain defines the authoritative business model of Themis.

The Backend transforms that business model into executable software while preserving all architectural decisions
established by the Constitution and Domain.

Problem Statement

How should the Backend relate to the Enterprise Security Domain?

Decision

The Backend is an implementation architecture.

Its responsibilities include:

- executing business use cases,
- preserving aggregate consistency,
- coordinating workflows,
- persisting business state,
- publishing business events.

Business meaning always remains within the Domain.

Rationale

Separating Domain from Backend ensures that implementation technologies may evolve without affecting enterprise
semantics.

Alternatives Considered

Backend defines business model.

Rejected.

Business semantics belong exclusively to the Domain.

Consequences

Positive

- Stable architecture.
- Clear implementation boundaries.
- Easier future evolution.

Negative

- Backend engineers must understand the Domain before implementation.

Implementation Impact

Every Backend component shall trace its responsibilities to the Domain Model.

Related ADRs

ADR-DOM-0035

ADR-CON-0005

Confidence

Very High

References

Book III

Chapter 1
