# Book II --- The Themis Enterprise Security Domain

## Part II --- The Domain Model

## Chapter 6 --- Faultlines

> *"A Finding belongs to a Release. A Faultline belongs to the
> enterprise."*

## Chapter Objective

After reading this chapter, the reader should understand:

- Why Faultlines exist.
- Why Faultlines are enterprise-wide knowledge identities.
- How Faultlines enable knowledge reuse across Products and Releases.
- Why Faultlines are intentionally independent of Governance.

------------------------------------------------------------------------

## 6.1 Why Faultlines Exist

As enterprises evolve, the same security issue frequently appears across
multiple products, projects, and releases.

If each Release stored its own independent reasoning, the enterprise
would repeatedly rediscover the same knowledge.

Themis introduces the **Faultline** to solve this problem.

A Faultline represents the enterprise's reusable knowledge identity for
a security concern.

It captures enterprise understanding independently of any specific
Release.

------------------------------------------------------------------------

## 6.2 Faultlines Are Not Findings

A common misunderstanding is to equate Faultlines with Findings.

They are fundamentally different.

A Finding represents a release-specific observation requiring
governance.

A Faultline represents enterprise knowledge that may be referenced by
many Findings.

The relationship is therefore:

``` text
Release
   │
 owns
   ▼
Finding
   │
references
   ▼
Faultline
```

A Finding cannot exist without a Release.

A Faultline can exist without any active Findings.

------------------------------------------------------------------------

## 6.3 Enterprise Knowledge Identity

A Faultline provides a stable identity for enterprise knowledge.

Over time, evidence may increase, investigations may conclude, vendors
may publish new guidance and engineering understanding may mature.

The knowledge evolves.

The Faultline identity remains stable.

This allows enterprise reasoning to accumulate instead of being
recreated.

------------------------------------------------------------------------

## 6.4 Relationship with Evidence

Faultlines do not own Evidence.

Instead, they evolve because of Evidence.

Multiple Evidence records may contribute to the evolution of a single
Faultline.

Likewise, one Evidence record may influence multiple Faultlines where
appropriate.

Evidence records observations.

Faultlines capture enterprise understanding.

------------------------------------------------------------------------

## 6.5 Relationship with Findings

Every Finding references exactly one Faultline.

Multiple Findings across different Releases may reference the same
Faultline.

This enables:

- reusable enterprise reasoning,
- consistent security analysis,
- reduced duplication,
- historical continuity.

Governance remains release-specific while knowledge remains
enterprise-wide.

------------------------------------------------------------------------

## 6.6 Lifecycle

Faultlines evolve continuously.

Typical lifecycle stages include:

- Created
- Enriched
- Correlated
- Mature
- Superseded (where applicable)

A Faultline is never recreated simply because a new Release is
introduced.

Knowledge evolves under the same enterprise identity.

------------------------------------------------------------------------

## 6.7 Ownership

Faultlines are owned by the Knowledge bounded context.

Responsibilities include:

- Knowledge evolution
- Correlation
- Enrichment
- Knowledge versioning
- Enterprise reasoning

Governance may reference Faultlines but never owns or mutates them
directly.

------------------------------------------------------------------------

## 6.8 Domain Invariants

Faultlines obey the following invariants:

- Every Faultline has one stable enterprise identity.
- Faultlines are enterprise-wide, not release-specific.
- Findings reference exactly one Faultline.
- Faultlines never own Findings.
- Faultlines evolve independently through enterprise knowledge.

------------------------------------------------------------------------

## Domain Invariant 6 --- Faultlines Are Enterprise Knowledge Identities

A Faultline represents reusable enterprise knowledge.

It exists independently of Products, Projects and Releases, allowing
enterprise understanding to evolve continuously while governance remains
contextual to individual Releases.

------------------------------------------------------------------------

## Chapter Summary

Key observations include:

- Faultlines are reusable enterprise knowledge identities.
- Findings and Faultlines are intentionally separate concepts.
- Knowledge is reused through Faultlines while governance remains
    Release-specific.
- Faultlines evolve continuously without changing their identity.
- The Knowledge bounded context is the authoritative owner of
    Faultlines.

The next chapter introduces **Findings**, the release-specific business
concept through which Governance evaluates and establishes Enterprise
Positions.
