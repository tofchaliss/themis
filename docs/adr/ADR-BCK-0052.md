# ADR-BCK-0052: External Systems Shall Be Isolated Through Anti-Corruption Layers

Status

Accepted

Category

Integration

Decision

All external systems shall interact with the Backend through explicit Anti-Corruption Layers (ACLs).

External data models shall never become part of the Enterprise Security Domain.

Context

Themis integrates with:

- SBOM generators,
- Vulnerability feeds,
- Security scanners,
- Vendor advisories,
- Customer systems,
- Future AI services.

Each system has its own terminology, identifiers, and semantics.

Problem Statement

How can external integrations evolve without corrupting the Enterprise Security Domain?

Decision

Every external integration shall define an Anti-Corruption Layer responsible for:

- protocol translation,
- data transformation,
- identifier mapping,
- semantic normalization,
- validation.

The ACL converts external concepts into enterprise concepts before entering the Domain.

Rationale

Isolation preserves:

- Domain purity,
- implementation independence,
- long-term maintainability,
- vendor neutrality.

Alternatives Considered

Direct Domain Integration

Rejected.

External models would gradually redefine enterprise semantics.

Shared Data Models

Rejected.

Shared models increase coupling between enterprise architecture and external systems.

Consequences

Positive

- Stable Domain.
- Independent integrations.
- Simplified external evolution.

Negative

- Additional translation layer.

Implementation Impact

Every adapter connecting external systems shall implement an Anti-Corruption Layer before interacting with Application
Services.

Related ADRs

ADR-CON-0005

ADR-CON-0006

ADR-DOM-0035

Confidence

Very High

References

Book III

Application Layer

Event Architecture
