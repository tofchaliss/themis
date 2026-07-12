# ADR-INT-0062: Model Selection Is a Runtime Infrastructure Decision

Status

Accepted

Category

Model Routing

Decision

Selection of an intelligence model shall occur at runtime based on capability requirements rather than business logic.

Business capabilities shall remain unaware of model identity.

Context

Different intelligence providers have varying strengths, costs, latency, privacy characteristics, and reasoning
capabilities.

Problem Statement

How should the platform select the most appropriate intelligence provider?

Decision

Model selection shall be performed by the Intelligence Gateway.

Selection criteria may include:

- reasoning capability
- latency
- cost
- privacy
- regulatory requirements
- provider availability
- enterprise policy

Business workflows specify capability requirements rather than provider names.

Rationale

Runtime model selection preserves:

- provider independence
- operational flexibility
- cost optimization

Alternatives Considered

Hardcoded provider selection.

Rejected.

Business-layer provider selection.

Rejected.

Consequences

Positive

- Flexible routing.
- Easier provider replacement.
- Improved resilience.

Negative

- Routing policies require governance.

Implementation Impact

Capability Registry shall declare capability requirements instead of provider names.

Related ADRs

ADR-INT-0058

ADR-INT-0059

Confidence

Very High

References

Book IV

Model Routing
