# ADR-DOM-0029: Enterprise State Is Classified as Global or Release Scoped

Status

Accepted

Category

State Management

Decision

Enterprise business state shall be explicitly classified as either Enterprise-wide or Release-scoped.

The scope of every aggregate shall be defined during domain modeling.

Context

Some information applies across the enterprise.

Other information exists only within a specific Release.

Mixing these responsibilities results in duplicated knowledge and inconsistent governance.

Problem Statement

How should enterprise information be scoped?

Decision

Enterprise-wide state includes:

- Faultlines
- Enterprise Knowledge

Release-scoped state includes:

- Findings
- Enterprise Positions
- Release Governance

The scope of every aggregate shall remain explicit.

Rationale

Explicit scoping prevents:

- duplicated knowledge,
- inconsistent governance,
- ownership ambiguity.

Alternatives Considered

Everything Release-scoped

Rejected.

Enterprise knowledge would become fragmented.

Everything Enterprise-wide

Rejected.

Release governance would lose independence.

Consequences

Positive

- Clear ownership.
- Simplified governance.
- Better scalability.

Negative

- Scope analysis required during modeling.

Implementation Impact

Repository ownership and event publication shall respect aggregate scope.

Related ADRs

ADR-DOM-0020

ADR-DOM-0022

ADR-DOM-0023

Confidence

Very High

References

Book II – Enterprise Scope
