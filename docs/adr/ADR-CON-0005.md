# ADR-CON-0005: Architecture Before Technology

Status

Accepted

Category

Architecture

Decision

Architectural decisions shall be driven by enterprise business requirements, constitutional principles, and domain
models rather than implementation technologies, programming languages, frameworks, databases, deployment platforms, or
vendor products.

Technology exists to realize the architecture.

The architecture shall never be modified solely to accommodate a particular technology.

Context

Modern software development offers a rapidly evolving ecosystem of technologies including programming languages,
frameworks, cloud platforms, messaging systems, databases, AI platforms, and infrastructure services.

These technologies continuously evolve throughout the lifetime of an enterprise system.

If architecture becomes dependent upon specific technologies, the architecture becomes unstable, difficult to evolve,
and constrained by implementation choices.

Themis is intended to remain relevant over many years despite inevitable technological change.

Problem Statement

How can the architecture remain stable while implementation technologies continue to evolve throughout the lifetime of
the platform?

Decision

The architecture adopts Architecture Before Technology as a constitutional principle.

Every architectural decision shall first answer:

- What business problem is being solved?
- Which constitutional principle applies?
- Which domain concept is being realized?

Only after these questions have been answered may implementation technologies be selected.

Technology selection shall never redefine:

- business ownership,
- domain boundaries,
- enterprise truth,
- governance,
- architectural responsibilities.

Implementation technologies remain replaceable.

Architectural principles remain stable.

Rationale

Enterprise architecture should outlive individual technologies.

Separating architecture from implementation provides:

- technology independence,
- easier modernization,
- reduced vendor lock-in,
- stable domain evolution,
- longer architectural lifetime.

This principle also allows future adoption of new technologies without rewriting enterprise architecture.

Alternatives Considered

1. Framework-Driven Architecture

   Rejected.

   Frameworks evolve faster than enterprise architecture.

   Allowing frameworks to dictate architecture results in frequent redesign.

2. Database-Centric Design

   Rejected.

   Persistence technology should support business architecture rather than define it.

3. Cloud Provider Architecture

   Rejected.

   Deployment platforms influence implementation but shall not redefine business architecture.

Consequences

Positive

- Long architectural lifetime.
- Easier technology replacement.
- Reduced implementation coupling.
- Stable domain model.
- Vendor independence.

Negative

- Initial implementation may require additional abstraction.
- Engineers must distinguish architectural concerns from implementation concerns.
- Some framework-specific optimizations may be intentionally avoided.

Implementation Impact

Every implementation decision shall demonstrate alignment with accepted architectural principles before selecting
implementation technologies.

Technology evaluations become implementation exercises rather than architectural redesign.

Related ADRs

ADR-CON-0001
Single Authoritative Ownership

ADR-CON-0002
Proposal Before Truth

ADR-CON-0003
Explainability Before Convenience

ADR-CON-0004
Controlled Architectural Evolution

Confidence

Very High

This principle has consistently guided every architectural discussion throughout the creation of Themis.

References

Book I — Constitution

- Constitutional Principles
- Architecture Philosophy

Book II — Enterprise Security Domain

- Domain Independence

Book III — Backend Architecture

- Backend Design Principles
- Repository Strategy
