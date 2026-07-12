# ADR-INT-0067: Intelligence Capabilities Shall Be Independently Versioned

Status

Accepted

Category

Versioning

Decision

Each intelligence capability shall maintain its own independent version lifecycle.

Capability evolution shall not require modification of business workflows or Domain Models.

Context

Prompts, retrieval strategies, evaluation criteria, and providers evolve frequently.

Business workflows should remain stable despite intelligence improvements.

Problem Statement

How should intelligence capabilities evolve without destabilizing enterprise workflows?

Decision

Capability versioning shall include:

- prompt version,
- retrieval strategy version,
- provider version,
- evaluation version,
- schema version.

Business capabilities invoke a capability identifier rather than a specific implementation version.

Rationale

Independent versioning enables experimentation, rollback, and continuous improvement.

Alternatives Considered

Business workflow controls capability versions.

Rejected.

Provider versions become business versions.

Rejected.

Consequences

Positive

- Safe experimentation.
- Controlled rollout.
- Easier rollback.

Negative

- Version management infrastructure required.

Implementation Impact

Capability Registry manages version selection independently of business workflows.

Related ADRs

ADR-INT-0058

ADR-INT-0062

ADR-INT-0065

Confidence

Very High

References

Book IV

Capability Registry
