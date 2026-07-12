# ADR-DOM-0020: Faultline Represents Enterprise Knowledge Identity

Status

Accepted

Category

Knowledge

Decision

A Faultline represents the enterprise-wide identity of a security issue.

Faultlines belong to the Knowledge capability and exist independently of Products, Projects, Releases, Findings, or
customer deployments.

Context

The same vulnerability may appear across multiple releases, products, and engineering projects.

Enterprise knowledge requires a stable identity independent of release-specific governance.

Problem Statement

How can enterprise knowledge remain stable while individual Releases evolve independently?

Decision

The architecture introduces Faultline as the canonical enterprise knowledge identity.

Every Finding shall reference exactly one Faultline.

Faultlines shall never belong to Releases.

Faultlines remain enterprise-wide.

Rationale

Separating enterprise knowledge from release governance enables:

- knowledge reuse,
- enterprise reasoning,
- simplified enrichment,
- independent governance.

Alternatives Considered

Release-specific Knowledge

Rejected.

Knowledge would become duplicated across Releases.

Finding owns Knowledge

Rejected.

Governance should consume Knowledge rather than own it.

Consequences

Positive

- Enterprise-wide knowledge.
- Reduced duplication.
- Independent evolution.

Negative

- Cross-reference management required.

Implementation Impact

Knowledge services own Faultline lifecycle.

Governance references Faultlines without modifying them.

Related ADRs

ADR-CON-0008

ADR-CON-0009

Confidence

Very High

References

Book II – Knowledge
