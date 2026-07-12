# Book II --- The Themis Enterprise Security Domain

## Part II --- The Domain Model

## Chapter 8 --- Enterprise Position

> *"Knowledge explains. Governance decides. Enterprise Position records
> the enterprise's authoritative decision."*

## Chapter Objective

After reading this chapter, the reader should understand:

- Why Enterprise Position is the authoritative business decision of
    the enterprise.
- How Enterprise Position differs from Findings and Faultlines.
- Why Enterprise Positions evolve independently while preserving
    historical integrity.
- Why Enterprise Position is the foundation for enterprise
    communication.

------------------------------------------------------------------------

## 8.1 The Need for an Authoritative Position

Evidence records observations.

Faultlines capture enterprise understanding.

Findings establish release-specific governance context.

None of these answer the most important enterprise question:

> **"What is the enterprise's official position?"**

The answer is represented by the Enterprise Position.

Enterprise Position is the authoritative business decision established
through governance after evaluating all relevant knowledge and
release-specific context.

------------------------------------------------------------------------

## 8.2 Enterprise Position Is Authority

Enterprise Position represents the enterprise's official stance
regarding a Finding or related business concern.

Typical positions may include:

- Affected
- Not Affected
- Under Investigation
- Mitigated
- Accepted Risk
- Deferred

These values are examples rather than fixed vocabulary.

The business meaning is that Enterprise Position communicates the
organization's authoritative decision, independent of how that decision
is ultimately presented to customers.

------------------------------------------------------------------------

## 8.3 Relationship to Findings

Enterprise Positions are established within the context of Findings.

``` text
Release
     │
 owns
     ▼
Finding
     │
governed by
     ▼
Enterprise Position
```

A Finding provides the business context.

Enterprise Position provides the enterprise's authoritative decision.

This separation allows investigations to continue while preserving a
stable governance model.

------------------------------------------------------------------------

## 8.4 Relationship to Faultlines

Enterprise Position does not replace enterprise knowledge.

Instead:

- Faultlines explain what the enterprise understands.
- Findings explain how that knowledge applies to a Release.
- Enterprise Position records what the enterprise officially decides.

Understanding and authority therefore remain intentionally separated.

------------------------------------------------------------------------

## 8.5 Evolution of Enterprise Position

Enterprise Positions are expected to evolve.

New evidence may emerge.

Knowledge may mature.

Customer requirements may change.

Engineering investigations may complete.

Governance therefore establishes new versions of Enterprise Position
rather than modifying historical decisions.

Historical enterprise positions remain available for auditability,
replay, regulatory compliance, and customer communication.

------------------------------------------------------------------------

## 8.6 Ownership

Enterprise Positions are owned exclusively by the Governance bounded
context.

Governance is responsible for:

- Establishing authoritative positions.
- Maintaining position history.
- Recording governance rationale.
- Managing position evolution.

Other bounded contexts may propose changes but never directly establish
enterprise authority.

------------------------------------------------------------------------

## 8.7 Relationship to Communication

Enterprise Position is not itself customer communication.

Instead, Communication materializes Enterprise Position into
audience-specific artifacts such as:

- VEX documents
- Security advisories
- Customer notifications
- Audit reports
- Executive summaries

Communication reflects enterprise authority but never becomes the source
of that authority.

------------------------------------------------------------------------

## 8.8 Domain Invariants

Enterprise Positions obey the following invariants:

- Every Enterprise Position belongs to Governance.
- Enterprise Positions are authoritative.
- Enterprise Positions evolve through versioning.
- Historical positions remain immutable.
- Communication materializes Enterprise Positions without modifying
    them.

------------------------------------------------------------------------

## Domain Invariant 8 --- Enterprise Position Is the Authoritative Business Decision

Enterprise Position represents the organization's authoritative decision
regarding a release-specific security concern.

Enterprise Position is owned by Governance, evolves through controlled
versioning, and forms the authoritative basis for all enterprise
communication.

------------------------------------------------------------------------

## Chapter Summary

Key observations include:

- Enterprise Position is the enterprise's authoritative decision.
- Governance owns Enterprise Position.
- Enterprise Position is distinct from both Findings and Faultlines.
- Enterprise Positions evolve while preserving historical integrity.
- Communication materializes Enterprise Positions but never owns
    enterprise truth.

The next chapter begins Part III by exploring how enterprise knowledge
evolves continuously through evidence, correlation, and governance.
