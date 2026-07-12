# ADR-INT-0061: Context Construction Is Deterministic

Status

Accepted

Category

Context Management

Decision

Every intelligence capability shall receive context through a deterministic Context Construction Pipeline.

Context construction shall be independent of prompt generation and independent of the underlying intelligence provider.

Context

Enterprise intelligence depends on information originating from multiple sources including Domain Aggregates, Enterprise
Knowledge, Policies, Customer Context, Historical Decisions, and Security Intelligence.

Providing inconsistent or incomplete context leads to inconsistent intelligence recommendations.

Problem Statement

How should enterprise context be assembled before invoking an intelligence capability?

Decision

The architecture introduces a Context Construction Pipeline responsible for assembling, validating, and normalizing
enterprise context.

The pipeline may retrieve information from:

- Domain Aggregates
- Enterprise Knowledge
- Enterprise Positions
- Policies
- Customer-specific configuration
- External intelligence

Context construction shall complete before prompt generation begins.

Rationale

Separating context construction from prompt generation provides:

- deterministic execution
- reusable context providers
- simpler testing
- provider independence

Alternatives Considered

Prompt Builder retrieves information directly.

Rejected.

Consequences

Positive

- Consistent intelligence execution.
- Easier debugging.
- Better reuse.

Negative

- Additional pipeline stage.

Implementation Impact

Capability execution shall invoke the Context Builder before Prompt Construction.

Related ADRs

ADR-INT-0058

ADR-INT-0059

ADR-INT-0060

Confidence

Very High

References

Book IV

Context Construction
