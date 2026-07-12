# Book II --- The Themis Enterprise Security Domain

## Part II --- The Domain Model

## Chapter 5 --- Evidence

> *"Enterprise knowledge begins with trustworthy evidence. Without
> evidence, every conclusion is opinion."*

## Chapter Objective

After reading this chapter, the reader should understand:

- Why Evidence is the foundational business concept of Themis.
- What qualifies as Evidence.
- Why Evidence is immutable.
- How Evidence differs from Enterprise Knowledge.
- Why Evidence is owned independently of Governance and Communication.

------------------------------------------------------------------------

## 5.1 Evidence Is the Foundation of Enterprise Reasoning

Every enterprise decision begins with observations.

These observations may originate from vulnerability databases, SBOMs,
VEX documents, vendor advisories, scanners, engineering investigations,
penetration tests, runtime monitoring, or customer reports.

Within Themis, these observations become **Evidence** only after they
are accepted into the enterprise evidence model.

Evidence is therefore the foundation upon which all enterprise reasoning
is built.

------------------------------------------------------------------------

## 5.2 What Is Evidence?

Evidence is an immutable business record describing an observation that
is relevant to the enterprise.

Evidence answers one question:

> **"What information should the enterprise consider?"**

Evidence deliberately avoids answering:

- Is the product affected?
- Is the vulnerability exploitable?
- What should the customer be told?

Those questions belong to later stages of enterprise reasoning.

------------------------------------------------------------------------

## 5.3 Sources of Evidence

Evidence may originate from many independent sources, including:

- Software Bills of Materials (SBOMs)
- Vulnerability databases (CVE, OSV, GHSA)
- Vendor advisories
- VEX and CSAF documents
- Static and dynamic security scanners
- Runtime observations
- Internal engineering investigations
- Customer-reported issues

The source influences confidence and provenance but does not change the
fundamental business meaning of Evidence.

------------------------------------------------------------------------

## 5.4 Immutability

Evidence represents what the enterprise observed at a specific point in
time.

For that reason, Evidence is immutable.

If external information changes, new Evidence is registered.

Historical Evidence is preserved to maintain auditability, replay, and
historical reasoning.

Enterprise understanding evolves.

Historical observations do not.

------------------------------------------------------------------------

## 5.5 Evidence and Enterprise Knowledge

Evidence and Enterprise Knowledge are intentionally separated.

Evidence records observations.

Enterprise Knowledge interprets those observations.

This separation enables multiple pieces of Evidence to contribute to a
single body of enterprise understanding without duplicating business
reasoning.

------------------------------------------------------------------------

## 5.6 Ownership

The Evidence capability owns the Evidence lifecycle.

Its responsibilities include:

- Registration
- Validation
- Identity
- Provenance
- Integrity
- Retention

Other bounded contexts consume Evidence but never mutate it.

Knowledge derives meaning from Evidence.

Governance derives decisions from Knowledge.

Communication publishes authoritative outcomes.

------------------------------------------------------------------------

## 5.7 Domain Invariants

Evidence obeys the following invariants:

- Every Evidence record has a stable identity.
- Evidence is immutable after registration.
- Evidence retains provenance.
- Evidence never establishes enterprise truth.
- Evidence may contribute to many Knowledge evolutions.

------------------------------------------------------------------------

## Domain Invariant 5 --- Evidence Is Immutable

Evidence records enterprise observations.

Once accepted into the enterprise evidence model, Evidence shall not be
modified.

Enterprise understanding evolves through new Evidence rather than
altering historical observations.

------------------------------------------------------------------------

## Chapter Summary

Key observations include:

- Evidence is the first immutable business concept in Themis.
- Evidence records observations rather than conclusions.
- Enterprise Knowledge is derived from Evidence but remains a separate
    business concept.
- Immutability preserves explainability, replay, and historical
    integrity.
- Evidence is independently owned and reused throughout the
    enterprise.

The next chapter introduces **Faultlines**, the enterprise-wide
knowledge identity that connects reusable enterprise understanding
across products and releases.
