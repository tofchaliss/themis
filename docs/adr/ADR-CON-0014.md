# ADR-CON-0014: Business Capability Separation

Status

Accepted

Category

Architecture

Decision

Each enterprise business capability shall have a single, well-defined responsibility.

Business capabilities shall collaborate but shall never absorb the responsibilities of another capability.

Architectural convenience shall never justify merging independent business responsibilities.

Context

The Enterprise Security Platform consists of multiple collaborating capabilities including Evidence, Knowledge,
Governance, and Communication.

Each capability exists because it solves a different enterprise problem.

As software evolves, implementation teams often move business logic between components for convenience, gradually
creating overlapping responsibilities and architectural ambiguity.

The architecture therefore requires explicit separation of business capabilities.

Problem Statement

How can enterprise capabilities evolve independently without becoming tightly coupled or duplicating business
responsibilities?

Decision

The architecture adopts Business Capability Separation.

Each bounded context shall own exactly one business capability.

Responsibilities shall remain explicit.

Business collaboration shall occur through architectural contracts rather than shared business logic.

No capability shall assume responsibilities belonging to another capability.

Examples include:

Evidence observes.

Knowledge understands.

Governance decides.

Communication publishes.

These responsibilities remain independent throughout the lifetime of the architecture.

Rationale

Clear business capability separation:

- simplifies ownership,
- reduces coupling,
- enables independent evolution,
- improves maintainability,
- preserves enterprise reasoning.

Alternatives Considered

1. Shared Responsibilities

   Rejected.

   Shared responsibilities create ambiguous ownership and duplicated business logic.

2. Convenience-Based Refactoring

   Rejected.

   Implementation convenience should not redefine enterprise responsibilities.

Consequences

Positive

- Stable business architecture.
- Independent bounded contexts.
- Clear enterprise reasoning.
- Easier long-term maintenance.

Negative

- Collaboration requires explicit interfaces.
- Initial architecture requires greater discipline.

Implementation Impact

Application Services, Domain Services, repositories, workflows, and events shall preserve business capability
separation.

Related ADRs

ADR-CON-0001

ADR-CON-0011

ADR-CON-0012

Confidence

Very High

References

Book II – Domain Architecture

Book III – Bounded Context Realization
