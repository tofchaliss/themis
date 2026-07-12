# ADR-DOM-0026: Enterprise Knowledge and Governance Shall Evolve Independently

Status

Accepted

Category

Knowledge & Governance

Decision

Enterprise Knowledge and Enterprise Governance shall evolve independently while remaining connected through stable
business references.

Knowledge evolution shall never directly modify Governance decisions.

Governance decisions shall never redefine Enterprise Knowledge.

Context

Knowledge continuously evolves as new intelligence becomes available through vulnerability feeds, vendor advisories,
customer deployments, and enterprise analysis.

Governance evolves according to business policy, customer commitments, product lifecycle, and organizational decisions.

Although related, these capabilities evolve at different rates and for different reasons.

Problem Statement

How can Knowledge continuously improve without destabilizing enterprise governance?

Decision

Knowledge and Governance are independent bounded contexts.

Knowledge owns Faultlines.

Governance owns Findings and Enterprise Positions.

The relationship between them is maintained through immutable business references rather than shared ownership.

Governance may react to Knowledge evolution, but Knowledge shall never directly modify Governance state.

Rationale

Independent evolution preserves:

- stable governance,
- reusable enterprise knowledge,
- simpler reasoning,
- independent lifecycle management.

Alternatives Considered

1. Governance owns Knowledge

   Rejected.

   Knowledge must remain reusable across Releases.

2. Shared Ownership

   Rejected.

   Shared ownership weakens architectural boundaries.

Consequences

Positive

- Independent evolution.
- Stable governance.
- Reusable knowledge.

Negative

- Cross-context synchronization required.

Implementation Impact

Knowledge events may trigger governance workflows, but Governance remains responsible for its own state transitions.

Related ADRs

ADR-DOM-0021

ADR-DOM-0022

ADR-CON-0012

Confidence

Very High

References

Book II – Knowledge

Book II – Governance
