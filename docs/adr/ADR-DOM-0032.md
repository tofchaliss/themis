# ADR-DOM-0032: Business Relationships Are Explicit Domain Concepts

Status

Accepted

Category

Domain Relationships

Decision

Relationships between business objects shall be modeled explicitly within the Domain Model.

Relationships shall represent enterprise meaning rather than implementation convenience.

Context

Enterprise security depends heavily upon relationships.

Examples include:

- Product owns Projects.
- Project owns Releases.
- Findings reference Faultlines.
- Enterprise Positions reference Findings.

These relationships define enterprise reasoning.

Problem Statement

How should relationships be represented within the Domain Model?

Decision

Relationships shall be first-class domain concepts.

Every relationship shall have:

- business meaning,
- ownership,
- lifecycle,
- traceability.

Relationships shall never exist solely because of persistence or implementation requirements.

Rationale

Explicit relationships preserve:

- domain clarity,
- explainability,
- architectural stability.

Alternatives Considered

Database Relationships Only

Rejected.

Persistence relationships do not adequately express enterprise meaning.

Implicit Relationships

Rejected.

Implicit relationships reduce architectural clarity.

Consequences

Positive

- Rich Domain Model.
- Better reasoning.
- Easier onboarding.

Negative

- More detailed domain modeling.

Implementation Impact

Domain Models shall express relationships independently of repository implementation.

Related ADRs

ADR-CON-0006

ADR-DOM-0028

Confidence

Very High

References

Book II – Domain Relationships
