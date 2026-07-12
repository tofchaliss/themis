# ADR-CON-0006: Business Language Before Implementation Language

Status

Accepted

Category

Domain-Driven Design

Decision

The enterprise shall define and communicate architecture using a ubiquitous business language.

Business terminology shall remain independent of programming languages, database terminology, framework abstractions,
infrastructure concepts, or implementation-specific vocabulary.

Implementation shall adopt the enterprise language rather than introducing competing terminology.

Context

Large software systems frequently evolve multiple vocabularies.

Business stakeholders speak in terms of products, releases, findings, governance, and enterprise positions.

Developers often replace this language with technical terminology such as services, tables, DTOs, APIs, queues, or
microservices.

Over time, these competing vocabularies obscure business intent and weaken architectural consistency.

Problem Statement

How can the architecture preserve a consistent understanding of enterprise concepts across business stakeholders,
architects, developers, and future implementation teams?

Decision

The architecture adopts Business Language Before Implementation Language.

Every architectural artifact shall use enterprise terminology as the primary language.

Examples include:

- Evidence
- Faultline
- Finding
- Enterprise Position
- Proposal
- Knowledge
- Governance
- Communication

Implementation concepts such as:

- Controllers
- REST endpoints
- Database tables
- DTOs
- Framework components
- Infrastructure services

shall remain implementation details and shall not replace enterprise terminology within the architecture.

Rationale

Architecture exists to model enterprise behaviour rather than implementation mechanisms.

Maintaining a ubiquitous business language:

- improves communication,
- reduces ambiguity,
- strengthens domain modeling,
- simplifies onboarding,
- preserves architectural intent,
- allows implementation technologies to evolve independently.

This decision aligns closely with Domain-Driven Design while remaining independent of any particular implementation
methodology.

Alternatives Considered

1. Technology-Oriented Vocabulary

   Rejected.

   Technical terminology changes as technologies evolve and does not accurately represent enterprise behaviour.

2. Multiple Parallel Terminologies

   Rejected.

   Maintaining separate business and technical vocabularies increases translation effort, introduces ambiguity, and
   weakens architectural consistency.

3. Framework Naming Conventions

   Rejected.

   Framework terminology should remain local to implementation and shall not redefine enterprise concepts.

Consequences

Positive

- Consistent communication.
- Strong ubiquitous language.
- Easier collaboration between business and engineering.
- Improved architectural clarity.
- Reduced implementation bias.

Negative

- Developers must consciously distinguish business terminology from implementation terminology.
- Documentation requires continued discipline to preserve the ubiquitous language.

Implementation Impact

Implementation artifacts should map directly to enterprise concepts wherever practical.

Code, APIs, repositories, events, and documentation should reinforce the ubiquitous language instead of introducing
competing terminology.

Related ADRs

ADR-CON-0001
Single Authoritative Ownership

ADR-CON-0005
Architecture Before Technology

Confidence

Very High

This principle has guided the creation of the Constitution, Domain Model, and Backend Architecture and is considered
fundamental to long-term architectural consistency.

References

Book I — Constitution

- Ubiquitous Language
- Enterprise Concepts

Book II — Enterprise Security Domain

- Domain Vocabulary
- Bounded Contexts

Book III — Backend Architecture

- Application Layer
- Domain Layer
- Event Catalog:
