# Book I --- The Themis Architecture Constitution

## Part III --- The Architecture

## Chapter 9 --- Bounded Contexts

> *"Architectural integrity is preserved not by what components know,
> but by what they are responsible for."*

## Chapter Objective

After reading this chapter, the reader should understand:

- Why Themis is partitioned into bounded contexts.
- How responsibilities are assigned.
- Why ownership is more important than interaction.
- How bounded contexts preserve enterprise truth while enabling
    independent evolution.

## 9.1 Why Bounded Contexts Matter

As enterprise platforms grow, complexity rarely arises from individual
capabilities. It arises from unclear ownership. Themis partitions the
platform into bounded contexts with explicit ownership. Boundaries are
architectural contracts rather than implementation details.

## 9.2 The Four Core Contexts

The Architecture Equation is realized by four primary bounded contexts.

    Evidence
          ↓
    Knowledge
          ↓
    Governance
          ↓
    Communication

Each context owns one stage of enterprise reasoning.

## 9.3 Evidence

Responsibilities: - Evidence acquisition - Evidence registration -
Canonical evidence representation - Immutable evidence storage

Evidence answers: *What should the enterprise consider?*

## 9.4 Knowledge

Responsibilities: - Correlation - Enrichment - Faultline management -
Knowledge evolution

Knowledge answers: *What does this mean for the enterprise?*

## 9.5 Governance

Responsibilities: - Finding management - Enterprise Position evolution -
Governance policy evaluation - Position lifecycle

Governance answers: *What is the enterprise's official position?*

## 9.6 Communication

Responsibilities: - Report generation - VEX publication - Customer
communication - Audit artifacts

Communication answers: *How should the enterprise communicate its
position?*

Communication never owns business truth.

## 9.7 Context Relationships

    Evidence
       │
       ▼
    Knowledge
       │
       ▼
    Governance
       │
       ▼
    Communication

Each context consumes authoritative outputs from the previous context
while preserving independent ownership.

## 9.8 Independent Evolution

Evidence sources, knowledge algorithms, governance policies and
communication formats may evolve independently without changing
constitutional principles.

## Constitutional Principle 6 --- Single Authoritative Ownership

Every authoritative business object belongs to exactly one bounded
context. Other contexts may submit proposals but never directly mutate
business objects they do not own.

## Chapter Summary

- Bounded contexts partition responsibility rather than functionality.
- Ownership is the primary architectural boundary.
- Evidence, Knowledge, Governance and Communication realize the
    Architecture Equation.
- Independent evolution is enabled through clear ownership.

The next chapter introduces the Architectural Laws that govern every
implementation of Themis regardless of technology.
