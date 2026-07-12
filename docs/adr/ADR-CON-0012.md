# ADR-CON-0012: Event-Driven Collaboration Between Bounded Contexts

Status

Accepted

Category

Collaboration

Decision

Bounded contexts shall collaborate by exchanging authoritative business events rather than through direct modification
of another bounded context's business state.

Events communicate completed business facts and preserve the autonomy of collaborating bounded contexts.

Context

Enterprise workflows naturally span multiple business capabilities.

Evidence influences Knowledge.

Knowledge influences Governance.

Governance influences Communication.

Without a disciplined collaboration mechanism, bounded contexts become tightly coupled and begin sharing ownership of
business logic.

Problem Statement

How can independently owned business capabilities collaborate without compromising ownership or introducing hidden
coupling?

Decision

The architecture adopts Event-Driven Collaboration.

Business collaboration shall occur through authoritative business events published by the owning bounded context.

Consumers may react to events but shall never assume ownership of the originating business object.

Events communicate facts rather than commands.

Rationale

Event-driven collaboration provides:

- loose coupling,
- independent deployment,
- asynchronous processing,
- clearer ownership,
- resilient workflows.

The architecture remains scalable while preserving enterprise integrity.

Alternatives Considered

1. Shared Database

   Rejected.

   Shared persistence violates ownership.

2. Direct Service Invocation

   Rejected.

   Synchronous dependencies increase coupling and reduce autonomy.

3. Shared Business Objects

   Rejected.

   Shared ownership weakens architectural boundaries.

Consequences

Positive

- Independent bounded contexts.
- Improved scalability.
- Simplified evolution.
- Reliable enterprise collaboration.

Negative

- Event versioning must be managed.
- Eventual consistency becomes part of the architecture.

Implementation Impact

Events shall be published only after authoritative state changes.

Every event shall have exactly one authoritative publisher.

Related ADRs

ADR-CON-0001

ADR-CON-0009

ADR-CON-0011

Confidence

Very High

References

Book III – Event Architecture

Book III – Event Catalog
