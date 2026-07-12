# ADR-INT-0063: Every Intelligence Response Shall Be Validated

Status

Accepted

Category

Validation

Decision

Every response produced by an intelligence capability shall undergo structural and business validation before entering
the Enterprise Security Domain.

Unvalidated responses shall never become Proposals.

Context

Intelligence systems may produce incomplete, malformed, or inconsistent responses.

Enterprise software requires deterministic behaviour.

Problem Statement

How should enterprise software ensure the correctness of intelligence outputs?

Decision

Response validation shall occur in three stages:

- Schema Validation
- Business Validation
- Proposal Construction

Only validated responses proceed to Governance.

Rationale

Validation protects enterprise integrity while allowing intelligence providers to evolve independently.

Alternatives Considered

Direct response consumption.

Rejected.

Schema validation only.

Rejected.

Consequences

Positive

- Reliable processing.
- Reduced failures.
- Better auditability.

Negative

- Additional validation layer.

Implementation Impact

Response Validators belong to the Intelligence Gateway.

Related ADRs

ADR-CON-0002

ADR-INT-0057

ADR-INT-0059

Confidence

Very High

References

Book IV

Response Validation
