# ADR-CON-0011: Bounded Contexts Are the Unit of Architectural Ownership

Status

Accepted

Category

Architecture

Decision

The enterprise architecture shall be organized around Bounded Contexts rather than implementation constructs such as
services, APIs, databases, or deployment units.

Every bounded context represents a complete business capability with clearly defined ownership, responsibilities, and
lifecycle.

Implementation structures may evolve over time, but bounded-context ownership shall remain stable.

Context

Enterprise security platforms naturally consist of multiple collaborating capabilities including Evidence, Knowledge,
Governance, and Communication.

Traditional architectures often organize systems around technical layers or microservices, leading to duplicated
business logic, unclear ownership, and tight coupling between implementation components.

The architecture requires a stable organizational unit that reflects business capabilities rather than implementation
technologies.

Problem Statement

How should enterprise responsibilities be partitioned to maximize autonomy, maintainability, and long-term architectural
stability?

Decision

The architecture adopts Bounded Contexts as the primary unit of architectural ownership.

Each bounded context owns:

- Business capabilities
- Business rules
- Aggregate roots
- Persistence
- Events
- Transaction boundaries
- Internal implementation

Collaboration between bounded contexts shall occur only through well-defined architectural contracts.

Implementation structures shall never redefine bounded-context boundaries.

Rationale

Bounded contexts provide:

- clear ownership,
- business autonomy,
- independent evolution,
- localized complexity,
- scalable implementation.

This decision aligns the software architecture directly with enterprise capabilities rather than implementation
mechanisms.

Alternatives Considered

1. Service-Oriented Ownership

   Rejected.

   Services are implementation units and frequently change as technology evolves.

2. Database Ownership

   Rejected.

   Persistence should follow business ownership rather than define it.

3. Layer-Oriented Architecture

   Rejected.

   Technical layers do not represent business capabilities.

Consequences

Positive

- Stable business boundaries.
- Independent implementation.
- Reduced coupling.
- Simplified reasoning.
- Easier future evolution.

Negative

- Cross-context collaboration requires explicit interfaces.
- Initial architectural design requires greater discipline.

Implementation Impact

Every backend component shall belong to exactly one bounded context.

Repositories, events, workflows, and background workers shall preserve bounded-context ownership.

Related ADRs

ADR-CON-0001

ADR-CON-0005

ADR-CON-0006

Confidence

Very High

References

Book II – Bounded Contexts

Book III – Bounded Context Realization
