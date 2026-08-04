# Book II --- The Themis Enterprise Security Domain

## Part II --- The Domain Model

## Chapter 7 --- Findings

> *"Enterprise knowledge explains the problem. Findings explain how that
> problem affects a specific Release."*

## Chapter Objective

After reading this chapter, the reader should understand:

- Why Findings are release-specific business objects.
- Why Findings belong to Governance rather than Knowledge.
- How Findings relate to Releases and Faultlines.
- Why Findings evolve independently while reusing enterprise
    knowledge.

------------------------------------------------------------------------

## 7.1 The Purpose of a Finding

A Finding represents the enterprise's security concern within the
context of a specific Release.

Unlike Evidence, which records observations, or Faultlines, which
capture reusable enterprise knowledge, a Finding answers:

> **"How does this security concern affect this Release?"**

A Finding therefore becomes the primary business object through which
Governance evaluates and maintains the security posture of a Release.

------------------------------------------------------------------------

## 7.2 Findings Are Release-Specific

Every Release represents a unique software composition, configuration,
and delivery context.

Consequently, the same Faultline may affect different Releases in
different ways.

One Release may be affected.

Another may include a backported fix.

A third may never contain the vulnerable component.

For this reason, Findings are always scoped to exactly one Release.

------------------------------------------------------------------------

## 7.3 Relationship to Faultlines

Findings do not duplicate enterprise reasoning.

Instead, every Finding references exactly one Faultline.

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

This relationship allows enterprise knowledge to be reused while
preserving independent governance decisions for each Release.

------------------------------------------------------------------------

## 7.4 Findings and Enterprise Position

A Finding does not itself express the enterprise's official decision.

Instead, Governance evaluates the Finding and establishes the
corresponding Enterprise Position.

The Finding therefore provides the business context from which
authoritative decisions are made.

------------------------------------------------------------------------

## 7.5 Lifecycle

A Finding evolves throughout the lifetime of a Release.

Typical lifecycle stages include:

- Identified
- Under Investigation
- Position Established
- Monitoring
- Resolved
- Archived

The lifecycle reflects governance activity rather than knowledge
evolution.

------------------------------------------------------------------------

## 7.6 Ownership

Findings are owned exclusively by the Governance bounded context.

Governance is responsible for:

- Creating Findings
- Maintaining release-specific state
- Associating Enterprise Positions
- Preserving governance history

Knowledge contributes understanding.

Governance owns the business decision.

------------------------------------------------------------------------

## 7.7 Domain Invariants

Findings obey the following invariants:

- Every Finding belongs to exactly one Release.
- Every Finding references exactly one Faultline.
- Findings never own enterprise knowledge.
- Findings are governed independently for each Release.
- Findings evolve without changing the underlying Faultline identity.

------------------------------------------------------------------------

## Domain Invariant 7 --- Findings Are Release-Scoped

A Finding represents the enterprise's release-specific security concern.

It exists only within the context of a single Release and references
reusable enterprise knowledge through exactly one Faultline.

------------------------------------------------------------------------

## Chapter Summary

Key observations include:

- Findings are release-specific governance objects.
- Releases own Findings.
- Findings reference---but never own---Faultlines.
- Governance owns Findings and their lifecycle.
- Enterprise Positions are established from Findings rather than
    directly from Evidence or Faultlines.

The next chapter introduces **Enterprise Position**, the authoritative
business decision produced by Governance and communicated throughout the
enterprise.
