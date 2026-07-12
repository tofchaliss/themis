# ADR-DOM-0021: Knowledge Owns Faultlines

Status

Accepted

Category

Knowledge

Decision

The Knowledge bounded context shall be the sole authoritative owner of Faultlines.

Faultlines represent enterprise knowledge identities and shall never be owned, modified, or versioned by Governance,
Evidence, or Communication.

Context

A Faultline represents enterprise understanding of a security issue independent of where it appears.

Multiple Releases may reference the same Faultline.

Governance consumes this knowledge but does not own it.

Problem Statement

Which business capability owns enterprise knowledge?

Decision

Knowledge owns the complete lifecycle of Faultlines including:

- creation,
- enrichment,
- correlation,
- evolution,
- retirement.

Other bounded contexts may reference Faultlines but shall never modify them.

Rationale

Separating enterprise knowledge from enterprise governance allows knowledge to evolve independently while preserving
governance stability.

Alternatives Considered

1. Governance owns Faultlines

   Rejected.

   Governance makes decisions; it does not own enterprise knowledge.

2. Release owns Faultlines

   Rejected.

   Knowledge must remain enterprise-wide rather than release-specific.

Consequences

Positive

- Enterprise knowledge is reusable.
- Independent knowledge evolution.
- Reduced duplication.

Negative

- Cross-context references become necessary.

Implementation Impact

Only the Knowledge bounded context may persist or modify Faultlines.

Related ADRs

ADR-CON-0001

ADR-CON-0008

ADR-DOM-0020

Confidence

Very High

References

Book II – Knowledge
