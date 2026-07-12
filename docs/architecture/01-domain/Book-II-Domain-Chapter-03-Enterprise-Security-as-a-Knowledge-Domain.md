# Book II --- The Themis Enterprise Security Domain

## Part I --- Understanding the Domain

## Chapter 3 --- Enterprise Security as a Knowledge Domain

> *"Security information becomes valuable only when it contributes to
> enterprise knowledge. Enterprise knowledge becomes valuable only when
> it enables enterprise decisions."*

## Chapter Objective

After reading this chapter, the reader should understand:

- Why enterprise security is fundamentally a knowledge domain.
- The distinction between information, evidence, knowledge, and
    enterprise position.
- Why enterprise knowledge must evolve continuously.
- Why knowledge is treated as a first-class business concept within
    Themis.

------------------------------------------------------------------------

## 3.1 From Information Management to Knowledge Management

For many years, enterprise security concentrated on collecting
information.

Organizations invested heavily in scanners, vulnerability databases,
dashboards, and reporting systems. These capabilities dramatically
improved visibility into software risk.

However, visibility alone does not answer the questions enterprises ask
every day.

Security information tells the enterprise **what has been observed**.

The enterprise must determine **what those observations mean**.

This distinction transforms enterprise security from an information
management problem into a knowledge management problem.

------------------------------------------------------------------------

## 3.2 The Enterprise Knowledge Continuum

Themis models enterprise understanding as a progression.

``` text
Information
      ↓
Evidence
      ↓
Enterprise Knowledge
      ↓
Enterprise Position
```

Each stage represents a different business concept.

Information describes external observations.

Evidence contextualizes those observations for the enterprise.

Enterprise Knowledge captures organizational understanding.

Enterprise Position represents the enterprise's authoritative decision.

No stage replaces another.

Each builds upon the previous stage.

------------------------------------------------------------------------

## 3.3 Why Knowledge Is a Business Asset

Knowledge is often treated as an informal by-product of engineering
investigations.

Themis treats knowledge differently.

Enterprise knowledge is a business asset.

It captures:

- engineering understanding,
- vendor intelligence,
- historical investigations,
- enterprise experience,
- product context,
- release context,
- organizational reasoning.

Unlike individual reports or tickets, enterprise knowledge is reusable
across releases, products, and future investigations.

------------------------------------------------------------------------

## 3.4 Knowledge Evolves Continuously

Enterprise knowledge is never complete.

New vulnerabilities are published.

Vendor guidance changes.

Engineering investigations conclude.

Customer deployments reveal new context.

Every new observation has the potential to refine enterprise
understanding.

The domain therefore models knowledge as continuously evolving rather
than permanently established.

Evolution is expected.

Contradiction is resolved through authoritative governance.

------------------------------------------------------------------------

## 3.5 Knowledge Is Independent of Governance

Knowledge explains.

Governance decides.

This distinction is fundamental.

Knowledge may indicate that a vulnerability is unlikely to affect a
product.

Governance determines whether the enterprise officially communicates
"Not Affected."

By separating understanding from authority, Themis preserves both
technical reasoning and business accountability.

------------------------------------------------------------------------

## 3.6 Why Themis Centers the Domain on Knowledge

Many security platforms organize their domain around vulnerabilities.

Themis organizes its domain around enterprise knowledge.

Vulnerabilities are observations.

Knowledge is enterprise understanding.

Enterprise understanding is the foundation upon which governance,
communication, and customer trust are built.

This architectural choice influences every aggregate, relationship, and
bounded context defined throughout the remainder of this book.

------------------------------------------------------------------------

## Domain Invariant 3 --- Knowledge Is an Enterprise Asset

Enterprise Knowledge is a persistent business asset.

It evolves continuously, may be reused across products and releases, and
shall not be treated as transient analysis or implementation detail.

------------------------------------------------------------------------

## Chapter Summary

Key observations include:

- Enterprise security is fundamentally a knowledge domain.
- Information, Evidence, Knowledge, and Enterprise Position are
    distinct business concepts.
- Knowledge evolves continuously through new evidence.
- Governance establishes authority but does not replace knowledge.
- The Domain Model is centered on enterprise knowledge rather than
    vulnerability records.

The next chapter begins the Domain Model itself by defining Products,
Projects, and Releases as the primary business boundaries within Themis.
