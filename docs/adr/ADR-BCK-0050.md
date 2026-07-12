# ADR-BCK-0050: Reconciliation Restores Enterprise Consistency

Status

Accepted

Category

Recovery

Decision

Reconciliation shall restore enterprise consistency after interrupted or partially completed business workflows.

Reconciliation verifies authoritative business state rather than replaying implementation history.

Context

Failures are inevitable.

Enterprise workflows may stop because of infrastructure failures, deployment interruptions, network partitions, or
external dependencies.

Problem Statement

How should interrupted enterprise workflows recover?

Decision

Reconciliation shall:

- inspect authoritative business state,
- determine incomplete work,
- safely continue execution.

Reconciliation shall never invent business state.

Recovery always begins from persisted authoritative state.

Rationale

State-based recovery is deterministic and independent of infrastructure failures.

Alternatives Considered

Replay Entire Workflow

Rejected.

Historical execution may no longer represent current enterprise state.

Manual Recovery

Rejected.

Enterprise recovery should be systematic rather than operational.

Consequences

Positive

- Deterministic recovery.
- Simplified operations.
- Better resilience.

Negative

- Recovery logic requires careful design.

Implementation Impact

Workflow engines and Background Workers shall support reconciliation as a first-class capability.

Related ADRs

ADR-CON-0013

ADR-BCK-0044

ADR-BCK-0045

Confidence

Very High

References

Book III

Consistency

Workflow Orchestration
