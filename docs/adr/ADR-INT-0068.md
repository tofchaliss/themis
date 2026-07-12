# ADR-INT-0068: Enterprise Knowledge Is the Primary Context Source

Status

Accepted

Category

Knowledge Retrieval

Decision

Enterprise Knowledge shall be the primary context source for intelligence capabilities.

Intelligence providers shall consume enterprise knowledge through defined retrieval services rather than directly
accessing persistence stores.

Context

Themis maintains enterprise knowledge independently of any intelligence provider.

Direct database access would couple intelligence implementation to persistence technology.

Problem Statement

Where should intelligence obtain enterprise knowledge?

Decision

Knowledge retrieval shall occur through dedicated Knowledge Providers.

Knowledge Providers may combine:

- Enterprise Knowledge
- Domain Aggregates
- Historical Enterprise Positions
- Security Intelligence
- Policies

The intelligence provider never queries persistence directly.

Rationale

Dedicated retrieval services preserve domain boundaries and technology independence.

Alternatives Considered

LLM queries database.

Rejected.

Prompt Builder performs SQL.

Rejected.

Consequences

Positive

- Strong architectural boundaries.
- Replaceable retrieval implementations.
- Better security.

Negative

- Additional retrieval layer.

Implementation Impact

Knowledge Providers become reusable infrastructure services for all intelligence capabilities.

Related ADRs

ADR-DOM-0021

ADR-DOM-0035

ADR-INT-0061

Confidence

Very High

References

Book IV

Knowledge Retrieval
