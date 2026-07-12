# ADR-INT-0058: Capability-Based Intelligence Invocation

Status

Accepted

Category

Capabilities

Decision

Application Services shall invoke intelligence capabilities rather than specific AI models or providers.

The Backend shall remain unaware of prompt engineering, model selection, or vendor-specific APIs.

Context

Intelligence providers evolve rapidly.

Business workflows should remain independent of implementation technologies.

Problem Statement

How can the Backend remain independent of AI vendors?

Decision

Business workflows invoke named capabilities.

Examples include:

- Summarize Vulnerability
- Cluster Findings
- Recommend Enterprise Position
- Explain Risk
- Generate Customer Summary

Capability implementations remain replaceable.

Rationale

Capabilities provide:

- provider independence
- easier testing
- centralized governance
- technology flexibility

Alternatives Considered

Direct LLM invocation.

Rejected.

Vendor-specific SDK integration.

Rejected.

Consequences

Positive

- Stable APIs.
- Vendor independence.
- Easier future migration.

Negative

- Capability registry required.

Implementation Impact

Application Services invoke Capability interfaces rather than LLM SDKs.

Related ADRs

ADR-CON-0005

ADR-BCK-0038

ADR-INT-0056

Confidence

Very High

References

Book IV

Capability Architecture
