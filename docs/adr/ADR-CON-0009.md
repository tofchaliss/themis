# ADR-CON-0009: Governance Establishes Enterprise Authority

Status

Accepted

Category

Governance

Decision

Only the Governance capability may establish authoritative enterprise decisions.

Evidence observes.

Knowledge understands.

Governance decides.

Communication publishes.

No other architectural component may establish enterprise authority.

Context

Multiple architectural capabilities participate in enterprise reasoning.

Without explicit separation, every component becomes capable of making enterprise decisions.

The architecture requires one authoritative decision-making capability.

Problem Statement

Which architectural capability is responsible for establishing authoritative enterprise decisions?

Decision

Governance is the sole authority responsible for:

- Findings
- Enterprise Positions
- Enterprise acceptance
- Enterprise rejection
- Enterprise risk decisions

Other bounded contexts provide information.

Governance establishes enterprise authority.

Rationale

Separating observation, reasoning, and authority creates:

- clear responsibility,
- explainability,
- simpler evolution,
- stronger governance.

Alternatives Considered

Knowledge Makes Decisions

Rejected.

Knowledge understands enterprise state but does not own enterprise authority.

Distributed Authority

Rejected.

Shared authority weakens enterprise consistency.

Consequences

Positive

- Clear enterprise authority.
- Simplified governance.
- Strong auditability.

Negative

- Governance becomes a critical architectural capability.

Implementation Impact

Only Governance aggregates may establish authoritative enterprise state.

Related ADRs

ADR-CON-0001

ADR-CON-0002

ADR-CON-0003

Confidence

Very High

References

Book II – Governance

Book III – Workflow Orchestration
