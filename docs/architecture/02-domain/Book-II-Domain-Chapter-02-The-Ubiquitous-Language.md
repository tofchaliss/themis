# Book II --- The Themis Enterprise Security Domain

## Part I --- Understanding the Domain

## Chapter 2 --- The Ubiquitous Language

> *"A shared language is the foundation of a shared understanding.
> Without it, every system eventually models a different enterprise."*

## Chapter Objective

After reading this chapter, the reader should understand:

- Why Themis adopts a ubiquitous language.
- How business terminology differs from technical terminology.
- The core business concepts that appear throughout the architecture.
- Why consistent language is essential for architectural integrity.

------------------------------------------------------------------------

## 2.1 Why Language Matters

Enterprise security involves product managers, software architects,
developers, security analysts, release managers, customer support teams,
auditors, and customers. Each group naturally develops its own
vocabulary.

When the same concept is described using different terms, ambiguity
becomes inevitable. Ambiguity eventually produces inconsistent reports,
conflicting decisions, and architectural drift.

Themis therefore adopts a single ubiquitous language that is used
consistently across documentation, domain models, architecture, APIs,
and implementation.

------------------------------------------------------------------------

## 2.2 Principles of the Ubiquitous Language

The language of Themis follows five principles:

- Every important business concept has one authoritative name.
- One name represents one business meaning.
- Technical implementation must never redefine business terminology.
- New terminology requires architectural review.
- Documentation, code, and conversations should use the same
    vocabulary.

------------------------------------------------------------------------

## 2.3 Core Business Vocabulary

### Product

The highest business entity representing a deliverable offered by the
enterprise.

### Project

A logical subdivision of a Product that evolves independently while
contributing to the overall product.

### Release

A governed business snapshot of one or more Projects delivered to
customers.

### Evidence

An immutable observation relevant to the enterprise.

### Information

Gathered or machine-produced input that the enterprise has **not yet
accepted** --- a feed's claim about a vulnerability, an external source
or crawl result, an AI recommendation. Information is a *suggestion*: it
may be reconciled, weighted, or rejected. It is never authoritative on
arrival and never becomes business truth until an explicit acceptance
step promotes it into Enterprise Knowledge.

Information reflects an outside (or machine) perspective; Enterprise
Knowledge reflects the enterprise's own considered perspective.

### Enterprise Knowledge

The enterprise's understanding of evidence after correlation,
enrichment, and analysis --- the view the enterprise **stands behind**,
as distinct from the raw Information it was derived from.

The boundary runs *through* the Faultline: the raw source claims
recorded on it are Information; its reconciled enterprise view is
Enterprise Knowledge.

### Faultline

The enterprise-wide knowledge identity that groups related enterprise
understanding across products and releases.

A Faultline is **not** owned by a Release. It exists independently and
may be referenced by many Findings.

### Finding

A release-specific security observation owned by Governance.

Each Finding references exactly one Faultline.

### Enterprise Position

The authoritative business decision established by Governance for a
Finding or related business concern.

### Communication

A published representation of an Enterprise Position prepared for a
specific audience.

Communication never becomes business truth.

------------------------------------------------------------------------

## 2.4 Vocabulary and Ownership

Names are not merely labels.

Each business concept has a clearly defined owner.

- Evidence owns observations.
- Knowledge owns Faultlines and Enterprise Knowledge.
- Governance owns Findings and Enterprise Positions.
- Communication owns published artifacts.

Gatherers --- feeds, external sources, and the Intelligence Gateway ---
produce Information only. They never write Enterprise Knowledge directly;
crossing that boundary always requires a deliberate acceptance step
(reconciliation by Knowledge, or a governed decision by Governance).

Ownership gives terminology operational meaning.

------------------------------------------------------------------------

## 2.5 Language as an Architectural Boundary

The ubiquitous language forms a contract between business and
implementation.

Developers may introduce new classes.

Architects may introduce new services.

Infrastructure may introduce new deployment models.

None of these should change the business meaning of Product, Release,
Faultline, Finding, Enterprise Position, or Evidence.

The language remains stable while implementations evolve.

------------------------------------------------------------------------

## 2.6 Event Infrastructure Vocabulary (M5)

The words the contexts use to collaborate **over the event bus**, not domain concepts but a
shared, transport-independent vocabulary (`EDR-EVENTBUS-01`). They survive a future swap from
the PostgreSQL realization to a broker.

### Event Log

The single ordered channel of published integration events — a Postgres stand-in for a Kafka
topic, one append-only `bus.event_log` table. Every producing context's relay appends its
outbox notes here; readers drain it in `seq` order.

### Stream

The unit of **routing and ordering** a consumer subscribes to — today one stream per producing
context (`source_context`). Ordering guarantees are properties *of a stream*; there is no
global order across streams.

### Interest set

The event types a consumer **dispatches on** within its stream. Purely a dispatch filter —
types outside it are ignored — it never affects routing or ordering, so narrowing it is always
safe.

### Inbox (`processed_events`)

The consumer-side dedup ledger in each context's **own** database, keyed by envelope id. The
inbound apply records the envelope id and does its business writes in **one transaction**, so a
redelivered envelope is a no-op.

### Exactly-once application vs at-least-once transport

The transport (relay → log → reader) is **at-least-once**: an envelope may be delivered more
than once. Correctness is the consumer's — the inbox makes the *application* of an envelope
happen **exactly once**. Ordering (the stream) and de-duplication (the inbox) are orthogonal
safety nets; a cursor/offset is only a read-position optimization and carries no correctness.

------------------------------------------------------------------------

## 2.7 Trust and Capability Vocabulary

Reason of record:
[`EDR-TRUST-01`](../../engineering/decisions/EDR-TRUST-01.md).

### Evidence Trust Class

How a fact was obtained. Every fact carries exactly one class, and the
classes are ordered by risk:

- **Observed** --- Themis obtained the fact itself, from an artifact it
    parsed or a source it fetched. No third party had to be believed.
    *A component version read from an ingested SBOM.*
- **Asserted** --- a party outside Themis stated the fact. Themis records
    who stated it and when, and cannot independently verify it.
    *A vendor VEX `not_affected`; "this build excludes the JNDI module".*
- **Inferred** --- the output of non-deterministic reasoning. A judgment,
    not an observation. *Any AI capability output.*

### Trust Propagation

A conclusion takes the **highest-risk** trust class among the evidence it
depends on. Propagation is **monotonic** --- no deterministic step,
validation stage, or human relay may raise a class. Only new,
better-classed evidence produces a better-classed conclusion, and that is
a new conclusion rather than a promotion.

### Deterministic Inference

The layer that executes **provable rules** over assembled evidence and
raises system proposals for the conclusions it reaches. It runs between
Knowledge and Governance, and before AI. **Rules carry no trust of their
own** --- a rule is an algorithm; its conclusion is classed by its inputs.

### Selection

The **user-addressable entry point** to a capability: a type plus a set
of identifiers of that type, with a declared minimum and maximum
cardinality.

**Selection Types are not domain entities.** They are the things a person
can point at. A type qualifies only when it is addressable today *and* a
named use case treats it as the thing the user picks. Today: **Finding**
and **Release**.

### Decision Context

Everything Themis assembles on the user's behalf --- Enterprise Positions,
Faultlines, vendor VEX, policies, historical decisions, estate and
blast-radius. Decision Context is **never selected**; it is gathered
because the Selection implies it.

### Domain Projection

A **reusable, persisted** read model owned by the bounded context that
owns a Selection Type, assembled **only** from events and read-only APIs
from other contexts, and named for the **business view it represents**
(`ReleasePosture`) --- never for a consumer. Every consumer uses the same
projection: AI, dashboards, reports, exports. It is **authoritative** ---
an owning context vouches for it.

### Capability Context

The **in-memory, non-persisted** shape a consumer derives from a Domain
Projection for one capability. It is a **view, not a source**: it may
reduce (filter, sort, group, summarise) but may introduce nothing the
projection did not contain, and every element remains traceable to it.

Keeping capability-specific shaping unpersisted is what makes AI a
*consumer* of the domain rather than a *driver* of the domain model.

### Information Response

An answer rendered for a human --- an explanation, summary, or plan. It is
**ephemeral**: read and discarded, never recorded as Enterprise
Knowledge.

### Decision Proposal

A structured, schema-validated claim that **aspires to become Enterprise
Knowledge**, and therefore enters Governance.

------------------------------------------------------------------------

## Domain Invariant 2 --- One Concept, One Meaning

Every significant business concept within Themis has exactly one
authoritative definition.

Alternative terminology, aliases, or implementation-specific meanings
shall not replace the ubiquitous language.

------------------------------------------------------------------------

## Domain Invariant 3 --- Gathering Is Not Knowing

Information and Enterprise Knowledge are distinct.

Anything that gathers or generates --- feeds, external sources, crawlers,
or the Intelligence Gateway --- produces Information, never Enterprise
Knowledge. Information becomes Enterprise Knowledge only through an
explicit, governed acceptance step (Knowledge reconciliation, or a
Governance decision). No gatherer writes business truth directly.

------------------------------------------------------------------------

## Domain Invariant 4 --- Trust Is Inherited, Never Granted

Trust is a property of **evidence**, not of the component that produced a
conclusion. A conclusion inherits the highest-risk trust class among the
evidence it used, and no step may raise it.

It follows that a conclusion drawn from **Inferred** evidence may never
be accepted automatically, under any policy configuration --- a
constitutional bar, not a setting. A deterministic rule that consumes an
AI-derived fact yields an Inferred conclusion and is equally barred:
determinism launders nothing.

This invariant generalizes Domain Invariant 3. "Gathering Is Not Knowing"
states that a gatherer never writes truth; Invariant 4 states what the
gathered thing is *worth* once something reasons over it.

------------------------------------------------------------------------

## Chapter Summary

Key observations include:

- The ubiquitous language provides a shared vocabulary across the
    enterprise.
- Business concepts are independent of implementation.
- Ownership reinforces terminology.
- Stable language prevents architectural drift.

The next chapter introduces Enterprise Security as a Knowledge Domain
and explains why Themis models enterprise understanding rather than
vulnerability data.
