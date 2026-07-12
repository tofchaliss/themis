# ADR-DOM-0023: Enterprise Position Represents Authoritative Enterprise Truth

Status

Accepted

Category

Governance

Decision

The Enterprise Position is the authoritative enterprise decision regarding a Finding.

It represents the official enterprise stance and supersedes all proposals, recommendations, observations, and
intermediate assessments.

Context

Evidence provides observations.

Knowledge provides understanding.

Governance evaluates Findings.

Customers require a single authoritative enterprise answer.

Problem Statement

Which business object represents official enterprise truth?

Decision

Enterprise Position becomes the authoritative enterprise truth.

Every Enterprise Position belongs to exactly one Finding.

Only Governance may establish or revise an Enterprise Position.

Rationale

Separating Findings from Enterprise Positions distinguishes investigation from enterprise commitment.

This allows governance to evolve without altering historical observations.

Alternatives Considered

1. Finding is enterprise truth

   Rejected.

   Findings represent assessment, not official enterprise commitment.

2. Communication establishes truth

   Rejected.

   Communication publishes truth; it does not create it.

Consequences

Positive

- Clear enterprise authority.
- Explainable governance.
- Stable customer communication.

Negative

- Additional governance lifecycle.

Implementation Impact

Customer-facing artifacts shall consume Enterprise Positions rather than Findings.

Related ADRs

ADR-CON-0009

ADR-CON-0010

ADR-DOM-0022

Confidence

Very High

References

Book II – Enterprise Position
