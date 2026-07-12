# ADR-BCK-0049: Idempotency Shall Be Preserved Across Distributed Processing

Status

Accepted

Category

Reliability

Decision

Business operations executed through asynchronous processing shall be idempotent wherever practical.

Repeated execution shall not produce different authoritative business outcomes.

Context

Distributed systems inevitably experience retries, duplicate messages, worker failures, and partial execution.

Business correctness must not depend upon exactly-once delivery.

Problem Statement

How should repeated execution be handled?

Decision

Business operations shall produce identical enterprise state regardless of duplicate execution.

Duplicate requests shall either:

- return existing business results, or
- safely perform no additional work.

Rationale

Idempotency simplifies:

- retries,
- recovery,
- event processing,
- workflow execution.

Alternatives Considered

Exactly Once Delivery

Rejected.

Infrastructure cannot guarantee exactly-once execution reliably across distributed systems.

Duplicate Detection Everywhere

Rejected.

Business behaviour should remain deterministic.

Consequences

Positive

- Reliable retries.
- Simpler recovery.
- Better resilience.

Negative

- Business identifiers become important.

Implementation Impact

Application Services, Workers, and Event Consumers shall preserve idempotent behaviour.

Related ADRs

ADR-BCK-0043

ADR-BCK-0045

Confidence

Very High

References

Book III

Concurrency

Background Workers
