# ADR-DOM-0030: Business Lifecycle Shall Be Explicitly Modeled

Status

Accepted

Category

Lifecycle

Decision

Every major aggregate shall possess an explicit business lifecycle represented through well-defined business state
transitions.

Lifecycle progression shall occur through business operations rather than direct state modification.

Context

Enterprise objects naturally evolve.

Releases mature.

Findings change.

Enterprise Positions are revised.

Communication progresses.

Without explicit lifecycle modeling, business state becomes inconsistent and difficult to reason about.

Problem Statement

How should business evolution be represented within the Enterprise Security Domain?

Decision

Aggregate lifecycle shall be modeled explicitly.

Valid state transitions are governed by business rules.

State changes shall be auditable and reproducible.

Lifecycle history becomes part of enterprise reasoning.

Rationale

Explicit lifecycle models provide:

- predictable behaviour,
- auditability,
- easier governance,
- deterministic workflows.

Alternatives Considered

Implicit lifecycle

Rejected.

Hidden state transitions reduce explainability.

Direct state modification

Rejected.

Business evolution should remain governed.

Consequences

Positive

- Clear business evolution.
- Strong auditability.
- Predictable workflows.

Negative

- Additional lifecycle modeling required.

Implementation Impact

Application Services shall invoke lifecycle operations defined by the Domain rather than modifying aggregate state
directly.

Related ADRs

ADR-CON-0003

ADR-DOM-0027
ADR-DOM-0028

Confidence

Very High

References

Book II – Aggregate Lifecycle

Book III – Domain Layer
