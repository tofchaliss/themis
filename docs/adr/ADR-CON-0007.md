# ADR-CON-0007: Immutable Enterprise Evidence

Status

Accepted

Category

Evidence

Decision

Enterprise Evidence shall be immutable once it has been registered as an authoritative observation.

Subsequent corrections, enrichments, annotations, classifications, or governance decisions shall create new business
information without modifying the original Evidence.

The architecture preserves the original observation throughout its lifecycle.

Context

Enterprise security continuously consumes observations originating from external systems including Software Bills of
Materials (SBOMs), vulnerability databases, scanners, vendor advisories, and customer submissions.

These observations represent historical facts.

If Evidence can be modified after registration, the enterprise loses the ability to reconstruct historical reasoning and
explain how decisions were reached.

Problem Statement

How can the enterprise preserve historical truth while allowing knowledge and governance to evolve?

Decision

Evidence is immutable.

Business evolution shall occur by creating new business objects that reference existing Evidence rather than modifying
the Evidence itself.

Knowledge evolves.

Governance evolves.

Enterprise Positions evolve.

Evidence remains unchanged.

Rationale

Immutable Evidence provides:

- reproducible enterprise reasoning,
- complete auditability,
- deterministic investigations,
- historical traceability,
- stable knowledge evolution.

Evidence becomes the permanent foundation upon which enterprise reasoning is constructed.

Alternatives Considered

1. Mutable Evidence

   Rejected.

   Updating Evidence destroys historical observations and weakens auditability.

2. Replace Existing Evidence

   Rejected.

   Replacing Evidence makes historical investigations impossible.

Consequences

Positive

- Complete historical reconstruction.
- Stable audit trail.
- Deterministic reasoning.
- Simplified governance.

Negative

- Additional storage required.
- Evolution occurs through additional business objects rather than updates.

Implementation Impact

Evidence repositories shall preserve original observations.

Business evolution shall occur through Knowledge and Governance rather than Evidence modification.

Related ADRs

ADR-CON-0001
ADR-CON-0002
ADR-CON-0003

Confidence

Very High

References

Book I – Constitution

Book II – Evidence Domain

Book III – Persistence Layer
