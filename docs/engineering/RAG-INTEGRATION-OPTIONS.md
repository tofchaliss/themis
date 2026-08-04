# RAG Integration Options — themis-ai (Intelligence Gateway)

**Status:** Session 1 — options survey + first-pass matrix (+ corpus size answered: **≤ ~50k**).
**No decision yet.**
**Updated:** 2026-08-03 · **Owner:** Intelligence context.
**Decision of record (once made):** folds into
[`decisions/EDR-INTELLIGENCE-01.md`](decisions/EDR-INTELLIGENCE-01.md) Revision 4 (Δ3 concrete cut);
[`STACK.md`](STACK.md) rows updated to match. This working doc grows one section per session.

---

## 1. Purpose

Choose how to add **Retrieval-Augmented Generation** to the Intelligence Gateway (delta **Δ3**), driven
by Themis's real use cases rather than by what a generic RAG tutorial assumes. We evaluate two
**independent** decisions and then the viable combinations — deliberately, because conflating them
("LlamaIndex + Qdrant vs pgvector") mixes a framework choice with a storage choice and muddies the
comparison.

- **Axis 1 — Vector store / index:** where embeddings live and how nearest-neighbour search runs.
- **Axis 2 — RAG orchestration:** who assembles retrieval → context → prompt → validation.

## 2. What RAG buys Themis (the concrete use case)

Today (Δ2) `recommend_position` grounds the LLM with past Enterprise Positions on the **exact same
CVE** (the `adapters/readapi/precedent.go` seam). RAG generalises that to **semantic** precedent:

> A new Finding: `CVE-2026-9xxx`, a Jackson deserialization flaw in `service-payments`. We have never
> dispositioned this CVE — but we marked four structurally-similar deserialization CVEs in that same
> service `not_affected` ("the deserializing endpoint isn't exposed; polymorphic typing off"). Exact
> match finds nothing; **semantic retrieval surfaces those four past decisions** as grounding.

This is backlog **G-AI-3** ("rank precedent by similarity"). The corpus being retrieved is **the
enterprise's own accumulated triage judgment** — a fact that dominates the whole evaluation (§4).

## 3. Binding constraints (from EDR-INTELLIGENCE-01 + STACK.md — not up for debate)

| # | Constraint | Consequence for RAG |
|---|---|---|
| D5 | Retrieval via read-APIs / Knowledge Providers, **never a foreign DB read** | The index is built *from* events/read-APIs; it never queries Knowledge/Governance tables. |
| D12 | Intelligence owns **operational state only** | The index is a **derived, rebuildable cache**, never truth — it can be dropped and rebuilt. |
| D10 | Sensitive data **local-only** | Embeddings + search run **locally**; no cloud embedding API on the routine path. |
| D13 | Intelligence is an **optional plane** | RAG is off when AI is off; the pipeline stays correct. |
| — | Single-static-binary, Go-first, **minimal-dependency, no-external-broker-up-front** (STACK.md) | A new stateful service must *earn* its operational weight against an in-Postgres option. |
| — | Database-per-context; existing `pgx` / `golang-migrate` / `embedded-postgres` / store conventions | An in-Postgres store reuses the entire proven stack; anything else is net-new integration. |

## 4. The two facts that pre-shrink the option space

1. **The corpus is small and rebuildable.** It is *our own* past Positions/Findings — **≤ ~50k vectors**
   (owner estimate, 1–3 yr), **low QPS** (human-triggered reactive + scheduled batch), latency-tolerant,
   and (D12) disposable. At 50k, an **in-memory brute-force cosine scan in Go runs in ~47 ms** single-
   threaded (measured — Session 2; ~6 ms across 8 cores), negligible against the LLM step, so even
   pgvector's ANN index is unnecessary *for search*. This is far below the 10⁷–10⁹ / high-QPS regime
   that dedicated vector databases (Qdrant/Milvus/Weaviate) are engineered for — at this size their
   headline features (sharding, quantization, distributed HNSW) are **unused weight**.
2. **The corpus is structured records, not documents.** Each Position/Finding is one record → one
   embedding. There is **no PDF ingestion, chunking, splitting, or multi-vector** problem — which is
   exactly the machinery LlamaIndex/LangChain exist to provide. Most of an orchestration framework's
   value therefore **does not apply**, while its cost (a Python runtime + a large dependency tree) does.

These two facts, not vendor benchmarks, are what should drive the call.

## 5. Use cases (score options against these)

| # | Use case | Corpus | QPS | Latency | Privacy | Delta |
|---|---|---|---|---|---|---|
| U1 | **Reactive precedent retrieval** (`recommend_position`) — the primary case | our Positions/Findings (≤ ~50k) | low (human-triggered) | tolerant (seconds) | local-only | Δ3 |
| U2 | **Autonomous analysts** — batch cluster/pattern scans | same + growth | batch | batch | local-only | Δ4 |
| U3 | **External-intel semantic linking** — embed CVE/advisory prose | larger, noisier (10⁶+) | low | tolerant | mixed | later, optional |

### 5.1 Demoable outcome after Δ3a (maps to `../current-changes/themis-ai-use-cases.md`)

The RAG pipeline makes **Use Case #4 — Vulnerability Validation / Triage Automation** genuinely
demoable, and that is the **north-star demo**:

- **Demo (#4):** point at a Finding for a CVE we have **never dispositioned**; the Gateway retrieves our
  **semantically similar past Positions** (different CVEs, same component / bug-class), grounds the local
  LLM, and returns a `recommend_position` (affected / not_affected / mitigated) **citing the precedent
  decisions** — advisory, human decides. This is the Δ2 `recommend_position` seam upgraded from
  exact-CVE to semantic precedent (**G-AI-3**). Fully API-drivable — no UI needed.
- **Stretch (#5 Root Cause Analysis, lightweight):** expose the same retrieval as "findings similar to
  this one" — the embedding-similarity grouping primitive, a near-free byproduct of the index.
- **Foundation only (not a hard demo from Δ3a):** #6 remediation context, #9 analyst-copilot Q&A, #15
  continuous-learning loop — RAG is the substrate, but each needs a later delta (Δ4 autonomy/LLMOps or a
  dedicated Q&A capability).
- **Sync note:** the use-cases doc's "v0.4.0 thin slice = CVE Summarizer" describes the **frozen
  monolith** (themis-phase-2b); the greenfield already ships `recommend_position` (#4), so RAG lands
  directly on the live triage seam — no new capability first. The demo == the Δ3a acceptance test (a
  semantic precedent changes a recommendation).

## 6. Evaluation criteria

| Criterion | Why it matters here |
|---|---|
| Fit to corpus / QPS | 10³–10⁶ vectors, low QPS — simplicity wins; scale features are dead weight |
| Integration cost | New service? new client? new language/runtime? or reuse pgx/migrate/store patterns? |
| Privacy / local-only (D10) | Must run fully local on the routine path; no data egress |
| Ops surface | A schema in an existing DB vs a new stateful service to run/back up/monitor |
| Boundary fit (D5/D12) | Derived, rebuildable operational cache; retrieval never a foreign DB read |
| Testability | Works under `embedded-postgres` / unit tests? (pgvector-in-embedded-PG is a known gap) |
| Reversibility | Swappable later behind a port with a config change, not a rewrite? |
| Duplication vs Gateway | Does an Axis-2 framework re-own D5/D6/D7 that Go already owns? |

Scale: **✓✓ strong · ✓ adequate · △ marginal · ✗ poor** (for *this* problem, not in the abstract).

## 7. Axis 1 — Vector store / index

Grounding discipline per option: rule-basis · chosen-for · named alternatives · why (better/worse here).

### 7.1 In-memory Go search + embeddings persisted in plain Postgres — **REVISED FRONT-RUNNER (≤50k)**
- **What:** embeddings held in the Intelligence process for search — a linear cosine scan (~9 ms at
  10⁴, ~47 ms at 5×10⁴ single-thread; measured, Session 2) or a small Go HNSW lib. Persist each vector in
  a **plain Postgres table**
  (`float4[]` / `bytea`, **no pgvector extension**) so we **load on boot and never re-embed on restart**;
  the bus consumer keeps it fresh. **No new dependency, no extension, no new service.**
- **Fit:** U1/U2 at ≤50k comfortably. Leans hardest into D12 (derived/rebuildable) + the
  minimal-dependency ethos, and — because it stores vectors as ordinary SQL columns — **eliminates the
  embedded-postgres/pgvector test gap** (plain SQL works under `embedded-postgres`).
- **Weak:** memory (~150 MB at 5×10⁴×768×f32); each replica holds its own copy (fine — single-instance
  AI plane, derived data); if the corpus ever passes ~10⁶, revisit pgvector/HNSW **behind the same port**.

### 7.2 pgvector (Postgres extension)
- **What:** a `vector` column + HNSW/IVFFlat ANN inside a **new Intelligence database** (the 7th DB).
  Reuses `pgx` + `golang-migrate` + the `adapters/store/migrations` convention verbatim.
- **Fit:** U1–U3 comfortably (millions of vectors); persistent (no rebuild-on-boot); standard ANN.
- **Weak:** **`embedded-postgres` does not bundle the compiled extension** → the integration-test gap
  (mitigation in §10); adds one DB to the topology.

### 7.3 Qdrant (dedicated vector DB, self-hosted)
- **What:** a Rust vector service; HNSW + rich payload filtering + quantization; Go client
  (`qdrant/go-client`), gRPC/HTTP.
- **Fit:** scales to 10⁸–10⁹, high QPS, advanced metadata filtering — **none of which U1/U2 need.**
- **Weak:** a **new stateful service** to deploy/secure/back up/monitor — a real ops surface against the
  "no external broker up front" ethos; net-new client + wiring. Justified only if a use case reaches its
  scale (not on the horizon).

### 7.4 Weaviate / Milvus
- **What:** heavier dedicated vector DBs (Milvus is distributed — needs etcd + object storage; Weaviate
  adds GraphQL + module system).
- **Fit:** 10⁸+ scale, cloud-native deployments.
- **Weak:** heaviest ops of all options; strongly over-scaled for U1–U3. **Not a contender now.**

### 7.5 Others (Redis-vector, Chroma, FAISS)
- **Redis-vector (RediSearch):** only sensible if Redis were already in the stack — it is **not** (STACK.md
  deliberately avoids extra infra). Adds a service. ✗
- **Chroma:** Python-embedded vector DB — excellent for Python prototyping, **not Go-native**; wrong
  runtime for a Go service. ✗ for prod (possible spike aid).
- **FAISS:** C++/Python library — great ANN, but no first-class Go binding and no server; would drag in
  cgo/Python. Its role here is conceptual (what §7.1 approximates in pure Go). ✗ as an integration.

### Axis 1 first-pass matrix (for U1, the primary case)

| Option | Corpus/QPS fit | Integration cost | Local (D10) | Ops surface | D5/D12 fit | Testability | Reversibility |
|---|---|---|---|---|---|---|---|
| **In-memory + plain-PG persist** (front-runner) | ✓✓ (≤50k) | ✓✓ none | ✓✓ | ✓✓ none | ✓✓ | ✓✓ plain SQL | ✓✓ behind port |
| pgvector (upgrade path) | ✓✓ | ✓✓ reuses stack | ✓✓ | ✓ +1 DB | ✓✓ | △ embedded-PG gap | ✓✓ behind port |
| Qdrant | ✓✓ (over-scaled) | △ new svc+client | ✓✓ self-host | △ new service | ✓✓ | △ needs container | ✓ behind port |
| Weaviate/Milvus | ✓✓ (over-scaled) | ✗ heavy | ✓ self-host | ✗ heavy | ✓ | ✗ | ✓ |
| Redis/Chroma/FAISS | ✓/△ | ✗ new infra/runtime | ✓/△ | ✗ | ✓ | △ | △ |

## 8. Axis 2 — RAG orchestration

The Gateway **already owns** D5 (deterministic context construction), D6 (prompt = Gateway infra), D7
(3-stage validation) — in Go, on purpose. So Axis 2's real question is narrow: does an external
framework add enough to justify re-owning those, plus a new runtime?

### 8.1 Hand-rolled Go retrieval
- **What:** embed the query → `VectorIndex.Search` → rank → fill `AssembledContext.Precedents`. Retrieval
  is ~50 lines over the existing seams; no chunking needed (§4, fact 2).
- **Fit:** U1/U2. Full control, deterministic, 100%-unit-testable, zero new dep/lang, no duplication of
  D5/D6/D7.
- **Weak:** we build reranking/relevance ourselves — but for structured records that is small and ours.

### 8.2 DSPy (Python)
- **What:** programmatic prompts with typed signatures, compiled/optimised against metrics.
- **Fit:** **reasoning**, not retrieval — belongs behind the provider port for a capability that needs
  optimised prompting or the eval loop (INT-0065). This is the Δ3b candidate.
- **Weak:** a Python service + dep tree; adds nothing to *retrieval*.

### 8.3 LlamaIndex (Python)
- **What:** batteries-included RAG — loaders, node parsers, retrievers, query engines, many store
  connectors.
- **Fit:** shines for **unstructured document** ingestion — which Themis does not have (§4, fact 2).
- **Weak:** would **re-own D5/D6/D7**, imposes opinionated abstractions, heavy Python dependency tree
  against the Go-first ethos. Most of its value is inapplicable here.

### 8.4 LangChain / LangGraph (Python)
- **What:** LangChain = chains/agents; LangGraph = stateful agent graphs.
- **Fit:** LangGraph is interesting for **Δ4 autonomous analysts** (multi-step agents), not Δ3 reactive
  retrieval.
- **Weak:** heavy, churny API, agent-framework lock-in; premature for Δ3.

### Axis 2 first-pass matrix (for U1)

| Option | Adds to retrieval | Duplicates D5/D6/D7 | New runtime | Fit to structured corpus | Best role |
|---|---|---|---|---|---|
| **Hand-rolled Go** | ✓✓ enough | ✓✓ none | ✓✓ none | ✓✓ | Δ3 retrieval |
| DSPy | △ (not retrieval) | ✓ (reasoning only) | ✗ Python | ✓ | Δ3b reasoning engine |
| LlamaIndex | △ | ✗ re-owns | ✗ Python | ✗ (docs, not records) | not now |
| LangChain/LangGraph | △ | ✗ | ✗ Python | △ | maybe Δ4 agents |

## 9. Viable combinations

| Stack | When it wins | Verdict for Δ3 |
|---|---|---|
| **In-memory Go + plain-PG persist + hand-rolled Go** | ≤50k private vectors, zero new dependency, no test gap | **Front-runner** (corpus confirmed ≤50k) |
| pgvector + hand-rolled Go | corpus grows past memory (~10⁶) or wants standard ANN | Upgrade path — same `VectorIndex` port, config swap |
| Qdrant + Go client | corpus/QPS outgrows Postgres, or heavy metadata filtering needed | Defer — no use case at that scale |
| Qdrant/pgvector + LlamaIndex | lots of unstructured-doc ingestion, fast prototyping | Poor fit — no documents; fights D5–D7 |
| pgvector + DSPy engine | retrieval in Go, *reasoning* wants prompt optimisation | Δ3b option, behind the provider port |

## 10. Preliminary lean — revised after the corpus answer (working hypothesis, NOT a decision)

The owner's **≤50k** estimate flips Axis 1 from pgvector to the simplest option that fits:

- **Axis 1: in-memory Go search over embeddings persisted in a plain Postgres table**
  (`float4[]` / `bytea`, **no pgvector extension**), behind an `app.VectorIndex` port. At ≤50k it is
  ~47 ms per query single-thread (measured, Session 2 — ~6 ms across 8 cores; negligible vs the LLM),
  adds no dependency, persists (no re-embed on restart), and **avoids the
  embedded-postgres/pgvector test gap outright** (plain SQL). **pgvector** (HNSW) and dedicated stores
  (Qdrant/Milvus) become **upgrade paths behind the same port** if the corpus ever passes ~10⁶ — a config
  swap, not a rewrite.
- **Axis 2: hand-rolled Go** retrieval for U1; reserve a **Python DSPy** engine (Δ3b) behind the provider
  port only if a reasoning task needs it. **No LlamaIndex/LangChain** — they solve an unstructured-
  document problem Themis does not have and would duplicate D5/D6/D7.

Rationale: the corpus is small, private, structured, and rebuildable; the Go stack + Gateway already
provide storage, retrieval plumbing, and context/prompt/validation. This is the project's consistent
"in-Postgres, minimal ops until scale forces otherwise" posture taken to its conclusion — even the
pgvector extension is deferred until the corpus warrants it. The `VectorIndex` port keeps the choice
reversible.

### Testability — the gap the front-runner sidesteps
Storing vectors as ordinary SQL columns means the `app.VectorIndex` store runs under
`fergusstrange/embedded-postgres` with **no extension** — so its integration tests run inside `make
check` with no special Postgres. (Leading with pgvector would have needed an opt-in, build-tagged test
against a real Postgres, like `make e2e-llm`; the ≤50k answer lets us avoid that.)

## 11. Open questions → later sessions

1. **Corpus reality-check — ANSWERED (≤ ~50k, 1–3 yr).** Confirms the in-memory + plain-PG front-runner.
   Remaining sub-question: the growth curve — a hard cap, or could a large multi-tenant install approach
   ~10⁶ and warrant the pgvector upgrade path?
2. **Latency/recall spike (S2):** measure in-memory cosine vs pgvector HNSW on representative volumes;
   is recall@k acceptable with `nomic-embed-text` (768-dim)?
3. **Embedding model (S2):** local `nomic-embed-text` (PoC precedent) vs alternatives (bge-small, e5);
   quality vs latency vs memory on our text (CVE descriptions + rationales).
4. **What text do we embed?** Rationale only, or rationale + CVE description + component context?
   Affects retrieval quality and the "structured record → one embedding" assumption.
5. **Freshness model:** event-driven re-embed (bus consumer) vs periodic backfill — cost vs staleness.
6. **KB-first threshold:** if we add a similarity short-circuit later, what cutoff (PoC used 0.92) and
   is it ever more than advisory? (Stays advisory per "Gathering Is Not Knowing".)
7. **Δ4 lookahead:** would autonomous analysts (U2) or LangGraph-style agents change the Axis-2 call?

## 12. Session log

- **Session 1 (2026-08-03):** framed the two axes; enumerated options; set use cases + criteria; first-
  pass matrices. **Corpus size answered mid-session: ≤ ~50k.** Revised lean = **in-memory Go search +
  embeddings persisted in plain Postgres + hand-rolled Go retrieval** (pgvector demoted to an upgrade
  path behind the `VectorIndex` port); Python **DSPy** reserved for Δ3b reasoning only. Demoable target
  fixed = **Use Case #4 (triage automation)**. No decision recorded.
- **Session 2 (planned):** confirm in-memory latency/memory at 10k/50k; the persistence approach
  (plain-PG `float4[]`/`bytea` load-on-boot) + rebuild-on-boot embedding cost; embedding-model eval
  (`nomic-embed-text` vs bge/e5) + what text to embed.
- **Session 3 (planned):** record the Axis-1 + Axis-2 decision here → fold into EDR-INTELLIGENCE-01
  Rev 4 + reconcile STACK.md line 58.
