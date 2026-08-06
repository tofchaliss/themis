# Book IV - AI Assisted Security Operations

## 1. Purpose

The purpose of AI within Themis is to assist users in making better security decisions.

AI is not introduced to replace deterministic processing or business logic. Instead, it complements Themis by providing explanations, recommendations, summaries, and decision support where deterministic queries alone cannot sufficiently assist the user.

Themis remains the system of record.

AI remains advisory.

---

# 2. Design Philosophy

Themis owns deterministic security knowledge.

AI never owns business truth.

If deterministic queries (SQL/Graph/Business Logic) can answer a question, AI should not be invoked.

AI is used only when additional reasoning, explanation or external context adds value.

Human users remain responsible for governance decisions.

## 2.1 Two classes of capability

Every AI capability belongs to exactly one class, and the class determines the entire path its output takes.

**Information capabilities** answer a question for a person. They produce an **Information Response** — an
explanation, a summary, a plan. It is **ephemeral**: read by a human and discarded. Nothing is recorded, and
there is nothing to accept or reject.

**Decision capabilities** produce a **Decision Proposal** — a structured claim that aspires to become
enterprise truth, and therefore enters Governance.

```text
                        Business Capability
                                │
                ┌───────────────┴───────────────┐
                ▼                               ▼
          Information                       Decision
                │                               │
          AI Runtime                       AI Runtime
                │                               │
     Grounding Verification          Grounding Verification
                │                               │
     Information Response             Decision Proposal
                │                               │
              User                   Business Verification (Governance)
                                                │
                                        Human Decision
                                                │
                                        Enterprise Truth
```

**Governance is not validating AI. Governance is validating only those outputs that aspire to become
enterprise knowledge.**

The rule that protects this: an Information Response may be shown to a human, but may **never** be stored as
enterprise truth, nor converted into truth, except by passing through a Decision capability whose proposal is
governed. Explanations are disposable; proposals are governed.

## 2.2 Deterministic inference precedes AI

"AI only where reasoning adds value" is not a guideline about taste. It is an ordering:

```text
   Evidence  ─────►  Knowledge  ─────►  Governance  ─────►  Communication
                         ╎                   ╎
                         ╎ deterministic     ╎ deterministic
                         ╎ inference over    ╎ inference over
                         ╎ the evidence      ╎ the evidence
                         ╎ Knowledge owns    ╎ Governance owns
                         ╰──── system proposals ──────►  Governance decides
                                                              ▲
                             AI (Decision capabilities) ──────╯
                             only where inference could not conclude
```

**Deterministic Inference** executes provable rules over assembled evidence — version-range applicability,
package-not-shipped, and, as the evidence to support them arrives, feature-disabled, build-time exclusion,
static configuration, platform incompatibility. A provable verdict is a computation, not a reasoning task.
Routing it through a language model is slower, costlier, less accurate, and unavailable whenever the optional
AI plane is switched off.

**It is a stage, not a service.** The dotted lines above are stages *inside* contexts; the solid line is the
deployable pipeline. Each rule executes inside the bounded context that owns the evidence it consumes —
*behaviour follows ownership*. Inference never justifies a new bounded context; **new evidence does.**

**AI is the last resort for ambiguity, not the first tool for every problem.**

This ordering constrains **Decision** capabilities only. **Information** capabilities are user-initiated and
may be invoked at any time — a user is entitled to ask for an explanation of an answer that inference already
settled confidently.

## 2.3 Trust comes from evidence, not from the component that produced the conclusion

Themis classifies every fact by whether it can be **re-derived** — **Observed** (reproducible from an artifact
or a public record), **Asserted** (a declaration or judgment nothing can re-run), **Inferred** (the output of
non-deterministic reasoning) — and a conclusion inherits the highest-risk class among the evidence it used.

The consequence for AI is absolute and non-negotiable: **an Inferred conclusion may never be accepted
automatically, under any policy configuration.** Autonomy of generation, yes. Autonomy of authority, never.

The full model — the classes, monotonic propagation, and the constitutional bar — is
[`EDR-TRUST-01`](../../engineering/decisions/EDR-TRUST-01.md). Book IV assumes it.

---

# 3. Actors

## Release Manager

Responsible for deciding whether a release is ready.

Typical questions:

- Can I release?
- What blocks my release?
- What should I fix first?

---

## Security Engineer

Responsible for vulnerability analysis.

Typical questions:

- Why is this vulnerability applicable?
- What is the best mitigation?
- Can this become a Product VEX?

---

## Product Owner

Responsible for product risk.

Typical questions:

- Which releases are affected?
- What is the overall security posture?
- What is the engineering effort required?

---

## AI Runtime

Provides reasoning services. It is **one consumer of the domain among several** — alongside dashboards,
reports and exports — and is privileged over none of them.

```text
Capability ID + Selection  →  Domain Projection  →  [shape]  →  reason  →  Information Response | Decision Proposal
                              ↑ authoritative                   ↑ Grounding Verification anchors here ─┘
```

**The four rules define what the AI Runtime is allowed to do:**

1. **No orchestration.** The runtime never gathers business data. It does not know which bounded contexts
   exist, which projections exist, or how one is produced.
2. **Information-preserving shaping.** It may filter, sort, group and summarise an authoritative projection
   into the shape a capability reasons over. *Information-preserving* means **nothing may be introduced that
   the projection did not contain** — reduction is permitted, invention is not.
3. **Full provenance.** Every derived element must be traceable back to the received Domain Projection.
4. **Grounding anchors to authority.** Grounding Verification always validates against the authoritative
   Domain Projection — **never solely** against a runtime-generated view.

Responsibilities:

- Reasoning — summarization, recommendation, explanation
- **Semantic retrieval** over its own Operational Semantic Index (KS2 — derived, rebuildable, runtime-owned)
- Prompt construction and model routing
- Deriving a **Capability Context** from a Domain Projection — in memory, never persisted (rules 2 + 3)
- **Grounding Verification** — proving the model reasoned only from the authoritative projection and the
  evidence it retrieved, inventing no entity and citing nothing unsupported

Explicitly **not** its responsibilities:

- **Gathering.** It receives a Domain Projection. It issues no business reads and requests no fact-bundles.
- **Deterministic inference.** Provable rules run before it, in the backend.
- **Deciding anything.** It never owns security objects and never establishes truth.

## Themis Backend

Owns deterministic security knowledge, **capability definitions**, and the projections that feed reasoning.

Responsibilities:

- Products, Projects, Releases
- SBOM / Evidence
- Findings, Faultlines, Enterprise Positions
- Product VEX, Policies
- **Deterministic Inference** — provable rules, raising system proposals
- **Domain Projections** — reusable read models owned by the context that owns a Selection Type, assembled
  only from events and read-only APIs, and named for the **business view** they represent (`ReleasePosture`),
  never for a consumer. Where an aggregate is itself a reusable business view, the backend computes it.
- **Business Verification** — validating a returned Decision Proposal against the system of record at
  acceptance time

Because a Domain Projection is deterministic and self-contained, it is also **replayable** — every consumer,
AI included, is independently testable without a live database.

`GET /releases/{id}/posture` is the first Domain Projection: it already composes Governance's own findings, a
Knowledge-derived score and a Registry-derived blast multiplier, with no cross-context import.

---

# 4. Workflow Overview

```
SBOM Upload

↓

Knowledge Builder

↓

Findings

↓

Knowledge Consolidation

↓

Themis Security Knowledge

↓

User Decision

↓

AI Runtime (optional)

↓

Decision Support

↓

Human Decision
```

---

# 5. Automatic Workflows

## WF-001 SBOM Processing

Actor

System

Trigger

SBOM Upload

Workflow

- Parse SBOM
- Store Components
- Create Release
- Schedule Knowledge Builder

Output

Release with Components

---

## WF-002 Security Intelligence Correlation

Actor

Knowledge Builder

Trigger

SBOM Parsed

Workflow

- Match Components
- Query Vulnerability Feeds
- Create Findings
- Associate Components

Output

Release Findings

---

## WF-003 Knowledge Consolidation

Actor

Knowledge Builder

Trigger

Findings Created

Workflow

- Associate Enterprise Position
- Associate Vendor VEX
- Associate Faultlines
- Associate Previous Release Information

Output

Context-aware Findings

---

## WF-004 Semantic Index Preparation

Actor

AI Runtime

Trigger

New Enterprise Position / Faultline (internal corpus), or new CVE / updated external knowledge (external corpus)

Workflow

Internal corpus — Knowledge Space 1 → 2 (RC-1 semantic precedent):

- Read the Position / Finding via read-API
- Generate embedding
- Upsert into the Operational Semantic Index

External corpus — Knowledge Space 3 → 2 (RC-2 supporting documents):

- Retrieve external documents
- Normalize
- Chunk
- Generate embeddings
- Update the Operational Semantic Index

Output

A searchable Operational Semantic Index (precedent + supporting knowledge)

This workflow never creates or modifies business objects in Themis. The index is derived and rebuildable.

---

# 6. User Use Cases

Each use case declares its **capability class** (§2.1), the **Selection** the user points at, and — for
Decision capabilities only — what enters Governance. Note that most user-facing AI in Themis is
**Informational**: it explains and plans, it does not decide.

| Use case | Class | Selection | Enters Governance? |
| --- | --- | --- | --- |
| UC-001 Release Readiness Assessment | Information | Release | No |
| UC-002 Engineering Planning | Information | Release | No |
| UC-003 Explain Vulnerability | Information | Finding | No |
| UC-004 Generate Product VEX Draft | **Decision** | Finding (set) | Yes — a draft artifact for human review |
| UC-005 Remediation Recommendation | Information | Finding (set) | No |
| UC-006 Risk Explanation | Information | Release | No |

`recommend_position` — the shipped affected/not-affected triage capability — is a **Decision** capability over
a Finding Selection, and is the reference implementation of the Decision branch.

**Selection Types are Finding and Release only.** They are *user-addressable entry points*, not domain
entities: a type qualifies when it is addressable today **and** a use case treats it as the thing the user
picks. Everything the system gathers on the user's behalf — Enterprise Positions, Faultlines, vendor VEX,
policies, historical decisions, estate and blast-radius — is **Decision Context**, never a Selection.

## UC-001 Release Readiness Assessment

### Actor

Release Manager

### Trigger

User opens Release Dashboard.

### Input

- Release
- Findings
- Enterprise Positions
- Product VEX
- Release Policy

### Workflow

Themis

↓

Collect deterministic security information.

↓

Determine blockers.

↓

If user requests explanation,

invoke AI Runtime.

↓

AI Runtime retrieves supporting documentation.

↓

Generate release summary.

### Output

- Ready / Not Ready
- Blocking Findings
- Recommended Actions
- Estimated Engineering Work

---

## UC-002 Engineering Planning

### Actor

Release Manager

### Problem

A release contains many findings.

The user wants to minimise engineering effort.

### Workflow

Themis

↓

Collect Findings

↓

Determine dependency relationships

↓

Invoke AI Runtime

↓

Cluster findings

↓

Suggest engineering workstreams

Example

Upgrade OpenSSL

↓

14 Findings resolved

Upgrade glibc

↓

11 Findings resolved

### Output

Engineering work plan

---

## UC-003 Explain Vulnerability

### Actor

Security Engineer

### Trigger

User selects a Finding.

### Workflow

Themis

↓

Provide Finding context

↓

Invoke AI Runtime

↓

Retrieve:

- Vendor Advisory
- CWE
- OWASP
- Best Practices

↓

Generate explanation

### Output

Human-readable explanation

---

## UC-004 Generate Product VEX Draft

### Actor

Security Engineer

### Trigger

User selects Findings.

### Workflow

Themis

↓

Collect

- Findings
- Enterprise Position
- Existing Vendor VEX

↓

Invoke AI Runtime

↓

Retrieve

Vendor guidance

↓

Generate draft Product VEX

↓

Human review

↓

Publish

### Output

Draft Product VEX

---

## UC-005 Remediation Recommendation

### Actor

Security Engineer

### Trigger

User requests remediation.

### Workflow

Themis

↓

Collect

- Findings
- Component Versions
- Release Context

↓

Invoke AI Runtime

↓

Retrieve

- Vendor migration guides
- Security guidance
- Best practices

↓

Generate remediation recommendations

### Output

Recommended remediation plan

---

## UC-006 Risk Explanation

### Actor

Release Manager

### Trigger

User asks

"Why should I care?"

### Workflow

Themis

↓

Collect

- Findings
- Product
- Release
- Enterprise Position

↓

Invoke AI Runtime

↓

Retrieve external context

↓

Generate explanation specific to the customer's environment.

### Output

Environment-specific risk explanation

---

# 7. Background AI Workflows

## AI-001 Vendor Guidance Updated

Trigger

Vendor publishes new advisory.

Workflow

Update external knowledge.

Future AI requests automatically use latest guidance.

---

## AI-002 Draft VEX Candidates

Trigger

Scheduled Job

Workflow

Identify Findings that have sufficient evidence.

Suggest Product VEX draft candidates.

---

## AI-003 Recommendation Refresh

Trigger

External knowledge changes.

Workflow

Re-evaluate previously generated recommendations.

Notify users when guidance changes.

---

# 8. Semantic Retrieval

Semantic retrieval is how the AI Runtime finds *relevant* knowledge when exact deterministic queries
cannot — it embeds text into vectors and ranks by similarity, then feeds the top matches to the LLM as
grounding.

The retrieval **mechanism is independent of the corpus it indexes.** One mechanism — embed → vector
similarity → rank → ground the LLM — serves every corpus below. Separating the mechanism from its
targets is what keeps the AI architecture internally consistent as capabilities grow: retrieval targets
evolve, the governance rule does not.

## The three Knowledge Spaces

**Knowledge Space 1 — System of Record (owned by Themis).**
Products · Releases · Findings · Enterprise Positions · Faultlines · Product VEX. Deterministic security
truth, queried by SQL / services. **Never the AI Runtime's to own or mutate.**

**Knowledge Space 2 — Operational Semantic Index (owned by the AI Runtime).**
Embeddings · Vectors · Similarity. A **derived, rebuildable** index built *from* KS1 and KS3 — never a
source of truth. It can be dropped and reconstructed at any time from its sources. All vectors live here;
it is the AI Runtime's only datastore.

**Knowledge Space 3 — Supporting Documentation (external).**
Vendor Advisories · Vendor Migration Guides · CWE · OWASP · MITRE · Security Research. External reference
material, retrieved / normalized / chunked / embedded into KS2 — never business truth.

KS1 and KS3 are **sources**. KS2 is a **derived lens** over them. The AI Runtime owns only the lens.

## Retrieval capabilities (the corpora evolve; the rule does not)

**RC-1 — Semantic Precedent over Enterprise Positions — the first concrete capability.**
Embeds a Finding's text and searches KS2 for the enterprise's **own** semantically similar past
Positions — precedent for a recommendation even when the CVE differs. Source corpus: KS1 (Enterprise
Positions), indexed into KS2; populated incrementally as Positions are established, rebuildable by
backfill. Fully aligned with the architecture: the Position stays owned by Themis (KS1); only its
derived vector lives in KS2.

**RC-2 — External Document Retrieval — a later corpus, not an exception.**
Embeds and searches KS3 (vendor / OWASP / MITRE / research) to explain vulnerabilities, draft
remediation, and ground risk narratives (UC-003, UC-005, UC-006). Source corpus: KS3, chunked and
indexed into KS2 — a *second* retrieval target behind the *same* mechanism.

Both capabilities are the same mechanism over different source corpora. RC-2's documents require
chunking / loaders that RC-1's structured records do not — the only mechanism-level difference, and the
point at which document-retrieval tooling is (re)evaluated.

## Governing invariants (unchanged principle, evolving targets)

1. **KS2 is never the system of record.** Derived from KS1 / KS3 and fully reconstructible — an
   operational cache, not knowledge. Losing it loses no truth.
2. **AI never owns business truth.** Themis owns KS1; external sources own KS3; the AI Runtime owns only
   KS2 — vectors, not the objects they point back to.
3. **Every retrieved item is grounding, not a decision.** Precedent and documentation inform the LLM; the
   human (or policy) still decides. Retrieval widens context, never authority.
4. **Retrieval is traceable.** Every match resolves back to its KS1 object or KS3 document, preserving
   Principle 8 (recommendations trace to deterministic knowledge).

> Implementation direction for RC-1 is recorded in `docs/engineering/decisions/EDR-INTELLIGENCE-01.md`
> (Revision 4 — Δ3 concrete cut). Book IV Chapter 8 is the governance philosophy; the EDR is the build.

---

# 9. Architectural Principles

1. Themis is the system of record.

2. AI Runtime never owns business objects.

3. AI Runtime provides decision support.

4. Human users make governance decisions.

5. SQL before AI.

6. AI is invoked only when additional reasoning or explanation adds value.

7. Semantic retrieval indexes (Knowledge Space 2) are derived, rebuildable lenses — not business truth.

8. AI recommendations must always be traceable to deterministic security knowledge.

9. The retrieval mechanism is independent of the corpus it indexes; new retrieval targets never change the rule.

10. Every capability is either Information or Decision. Only Decision outputs enter Governance.

11. An Information Response is ephemeral. It may never become enterprise truth except by passing through a
    governed Decision capability.

12. Deterministic inference precedes AI. AI is the last resort for ambiguity in Decision capabilities, never
    the first tool. Inference is a **stage, not a service** — behaviour follows ownership, and new evidence
    justifies a bounded context, never new rules.

13. Trust derives from evidence provenance, not from the component that produced the conclusion.

14. Trust propagates monotonically. A conclusion is never more trusted than its weakest evidence.

15. Inferred evidence is constitutionally barred from automatic acceptance, under any policy configuration.

16. The AI Runtime never gathers. It may shape an authoritative Domain Projection without introducing anything
    the projection did not contain, every derived element remains traceable to it, and Grounding Verification
    anchors to the projection — never solely to a runtime-generated view. AI is a consumer of the domain,
    never a driver of the domain model.

17. Grounding Verification protects the reasoning process; Business Verification protects enterprise truth.
    They are two boundaries, not one check performed twice.

## Use case diagrams:

### Business Workflow (Actor View)

Release Manager
        │
        ▼
Select Release
        │
        ▼
View Findings
        │
        ▼
Request Release Readiness
        │
        ▼
Review AI Recommendation
        │
        ▼
Approve / Reject Release

### System Wokflow

User
 │
 ▼
Themis API
 │
 ▼
Release Service
 │
 ▼
Finding Service
 │
 ▼
Enterprise Position
 │
 ▼
Policy Service
 │
 ▼
Decision Point
 │
 ▼
Return Deterministic Data

### AI Interaction workflow

Themis Backend

        │

        ▼

Decision

Needs Explanation?

        │

        ├──────── No

        │

        ▼

Return Response

        │

        Yes

        │

        ▼

AI Runtime

        │

        ▼

Retrieve Supporting Context

        │

        ▼

LLM

        │

        ▼

Recommendation

        │

        ▼

Themis

### Semantic Retrieval workflow

AI Runtime

      │

      ▼

Needs Context

      │

      ▼

Select Corpus

      ├─► Enterprise Positions   (KS1 → KS2)   — RC-1 semantic precedent

      └─► Supporting Documents   (KS3 → KS2)   — RC-2 vendor / MITRE / OWASP / research

      │

      ▼

Vector Similarity Search   (Operational Semantic Index, KS2)

      │

      ▼

Top-k Matches   (precedent and / or chunks)

      │

      ▼

LLM

### UC01 Sequence diagram

Release Manager

      │  open Release Dashboard

      ▼

Themis Backend

      │  collect deterministic security info (Findings, Positions, Product VEX, Policy)

      ▼

Decision Point

      │  determine blockers → Ready / Not Ready

      ▼

Needs Explanation?

      ├─► No   — return deterministic readiness

      └─► Yes  — AI Runtime

                    │  semantic retrieval (RC-1 precedent + RC-2 supporting docs)

                    ▼

                 LLM

                    │  release summary + recommended actions

                    ▼

Release Manager   — Approve / Reject

### Ownership diagram

                    OWNER

Product --------------------------- Themis

Release --------------------------- Themis

Finding --------------------------- Themis

Faultline ------------------------- Themis

Enterprise Position --------------- Themis

Product VEX ----------------------- Themis

Vendor Advisory ------------------- External

OWASP ----------------------------- External

MITRE ----------------------------- External

Prompt ---------------------------- AI Runtime

Embedding ------------------------- AI Runtime

Vector DB ------------------------- AI Runtime

LLM ------------------------------- AI Runtime

Knowledge Space mapping (see Chapter 8):

KS1 System of Record ------------- Themis      (Products, Findings, Positions, Faultlines)

KS2 Operational Semantic Index --- AI Runtime  (Embeddings, Vectors, Similarity — derived, rebuildable)

KS3 Supporting Documentation ----- External    (Vendor, OWASP, MITRE, Research)


### Master diagram

                    SBOM Upload
                          │
                          ▼
                 Knowledge Builder
                          │
                          ▼
                    Themis Knowledge
                          │
          ┌───────────────┼───────────────┐
          │               │               │
          ▼               ▼               ▼
     Findings      Enterprise Position   VEX
          │               │               │
          └───────────────┴───────────────┘
                          │
                          ▼
                  User Requests Action
                          │
                 Needs Deterministic?
                  ├───────────────┐
                  │ Yes           │ No / Needs Reasoning
                  ▼               ▼
           SQL / Services     AI Runtime
                                  │
                                  ▼
                           Retrieve Context
                                  │
                                  ▼
                          Vendor / MITRE / OWASP
                                  │
                                  ▼
                                 LLM
                                  │
                                  ▼
                     Decision Support Response
                                  │
                                  ▼
                                User