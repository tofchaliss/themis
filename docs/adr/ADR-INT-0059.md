# ADR-INT-0059: Intelligence Gateway Is the Exclusive Entry Point

Status

Accepted

Category

Gateway

Decision

All intelligence providers shall be accessed through a single Intelligence Gateway.

No bounded context shall communicate directly with an intelligence provider.

Context

Multiple intelligence technologies may coexist.

Examples include:

- LLMs
- Knowledge Graphs
- Rule Engines
- Local Models
- Cloud Models

The enterprise requires one architectural abstraction.

Problem Statement

How can intelligent services evolve without affecting business capabilities?

Decision

The Intelligence Gateway owns:

- provider selection
- authentication
- retries
- caching
- telemetry
- rate limiting
- prompt execution
- response validation

Business capabilities remain provider-agnostic.

Rationale

Centralizing provider interaction:

- simplifies maintenance
- enables provider replacement
- improves governance
- reduces duplication

Alternatives Considered

Each bounded context manages AI independently.

Rejected.

Consequences

Positive

- Centralized intelligence management.
- Consistent operational behaviour.
- Easier provider migration.

Negative

- Gateway becomes shared infrastructure.

Implementation Impact

Every intelligence request shall traverse the Intelligence Gateway.

Related ADRs

ADR-BCK-0036

ADR-BCK-0052

ADR-INT-0058

Confidence

Very High

References

Book IV

Gateway Architecture
