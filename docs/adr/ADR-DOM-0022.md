# ADR-DOM-0022: Findings Are Release-Scoped Governance Records

Status

Accepted

Category

Governance

Decision

A Finding represents Governance's assessment of how a specific Faultline affects a specific Release.

Every Finding belongs to exactly one Release and references exactly one Faultline.

Findings shall never exist independently of a Release.

Context

Enterprise knowledge is global.

Enterprise governance is release-specific.

The architecture requires a business object that connects these two worlds.

Problem Statement

How should Governance represent the impact of enterprise knowledge on individual software Releases?

Decision

The architecture introduces Findings as release-scoped governance records.

A Finding represents:

- one Release,
- one Faultline,
- one governance assessment.

Findings do not own knowledge.

They reference enterprise knowledge.

Rationale

This separation enables:

- independent release assessment,
- enterprise knowledge reuse,
- simplified governance.

Alternatives Considered

1. Faultlines contain Release information

   Rejected.

   Knowledge should remain enterprise-wide.

2. Release contains vulnerability knowledge

   Rejected.

   Governance would become tightly coupled to knowledge evolution.

Consequences

Positive

- Clear governance ownership.
- Enterprise knowledge reuse.
- Stable architecture.

Negative

- Additional relationship management.

Implementation Impact

Finding aggregates shall reference Faultlines through immutable identifiers.

Related ADRs

ADR-DOM-0020

ADR-DOM-0021

Confidence

Very High

References

Book II – Findings
