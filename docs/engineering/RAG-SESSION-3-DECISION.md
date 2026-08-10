# RAG Integration — Session 3: Decision + EDR Fold

**Status:** Session 3 — **decision APPROVED and FOLDED (2026-08-03).** R1–R4 + R6 are recorded in
`EDR-INTELLIGENCE-01` **Revision 4** and reconciled in `STACK.md`; the Δ3a implementation is unblocked.
**R5 (embedding model) remains pending** the local Ollama eval (Session 2 §4) — not runnable in the
current environment (no Ollama); leaning `nomic-embed-text`.
**Updated:** 2026-08-03 · **Owner:** Intelligence context.
**Reads with:** [`RAG-INTEGRATION-OPTIONS.md`](RAG-INTEGRATION-OPTIONS.md) (S1) ·
[`RAG-SESSION-2-SPIKE.md`](RAG-SESSION-2-SPIKE.md) (S2 data).
**Demoable cases reference:** [`../current-changes/themis-ai-use-cases.md`](../current-changes/themis-ai-use-cases.md).

---

## 1. The decision (proposed)

For Δ3 RAG in the Intelligence Gateway, driven by the confirmed corpus (**≤ ~50k** own Positions/Findings,
low QPS, local-only, structured records) and the Session-2 measurements:

- **Axis 1 — Vector store:** **in-memory Go cosine search over embeddings persisted in a plain Postgres
  table** (`float4[]` / `bytea`, **no pgvector extension**), all behind an `app.VectorIndex` port.
  **pgvector (HNSW)** and dedicated stores (**Qdrant/Milvus**) are **upgrade paths behind the same port**,
  triggered only if the corpus passes ~10⁵–10⁶ vectors.
- **Axis 2 — Orchestration:** **hand-rolled Go** retrieval (embed query → `VectorIndex.Search` → rank →
  fill `AssembledContext.Precedents`); reuse the Gateway's existing D5/D6/D7. A **Python DSPy** engine is
  reserved for **Δ3b** behind the provider port, added **only if** a reasoning task needs it. **No
  LlamaIndex/LangChain** (they solve an unstructured-document problem Themis does not have and would
  duplicate D5/D6/D7).
- **Embedding model:** **`nomic-embed-text`** (768 dims) on the existing Ollama runtime — **pending final
  confirmation** by the Session-2 §4 eval; Matryoshka-truncate to 256 only if ever needed (not at 50k).

**Evidence:** search ~47 ms/query @ 50k single-thread (8× parallel headroom), ~150 MB memory; persistence
via plain SQL columns (load-on-boot cheap, re-embed rare) removes the `embedded-postgres`/pgvector test
gap. See [`RAG-SESSION-2-SPIKE.md`](RAG-SESSION-2-SPIKE.md).

## 2. Component & technology decisions (EDR-ready — rule-basis · chosen · alternatives · why)

| # | Decision | Rule basis | Chosen | Alternatives considered | Why the chosen option |
|---|---|---|---|---|---|
| R1 | Vector index | D12 (operational, rebuildable) · corpus ≤50k · STACK "minimal deps" | **In-memory Go cosine over persisted plain-PG vectors**, behind `app.VectorIndex` | pgvector; Qdrant; Weaviate/Milvus; Redis-vector; Chroma; FAISS | ≤50k → brute force is ~47 ms (negligible vs LLM); no extension, no new service, no test gap; persists so no re-embed on boot; port keeps pgvector/Qdrant a config-swap upgrade if scale ever demands |
| R2 | Persistence | D12 · store convention · `embedded-postgres` testability | **Plain Postgres table** (`float4[]`/`bytea`) in a new Intelligence DB | pgvector column; a dedicated vector DB; in-memory-only (no persistence) | vectors as ordinary columns run under `embedded-postgres` (no extension); load-on-boot is cheap, re-embed is minutes → persist vectors; in-memory-only would re-embed 50k every restart |
| R3 | Retrieval orchestration | D5/D6/D7 already Go-owned · Go-first ethos · structured (not document) corpus | **Hand-rolled Go** (~embed→search→rank) | LlamaIndex; LangChain/LangGraph; DSPy for retrieval | records → one embedding each; no chunking/loader problem; a framework would re-own D5/D6/D7 and add a heavy Python dep tree for value that doesn't apply |
| R4 | Advanced reasoning (Δ3b) | INT-0070 (provider port) · reactive-first | **Python DSPy behind the provider port — deferred to Δ3b, only if needed** | LlamaIndex/LangChain agents; Go-only reasoning | keep retrieval in Go; add Python only for a reasoning step that wants prompt optimisation/eval; isolated as a provider (process isolation), optional plane (D13) |
| R5 | Embedding model | D10 (local-only) · PoC precedent | **`nomic-embed-text` (768)** — pending S2 eval | bge-small (384); e5-small (384); cloud embeddings (OpenAI) | reuses deployed Ollama, local/private, PoC-precedented; cloud violates D10; smaller models only if memory/latency demanded (they aren't at 50k) |
| R6 | Freshness / population | D5 (read-APIs, never foreign DB) · M5 bus | **Event-driven incremental** (bus consumer on `PositionEstablished`/`FaultlineEnriched`) + **backfill/rebuild** command | poll-and-rebuild; lazy embed-per-request | steady-state cost = one embed per new decision; index derived + rebuildable (D12); consumes events + read-APIs, never foreign tables (D5) |

## 3. EDR fold + reconcile (the execution of this decision)

1. **`EDR-INTELLIGENCE-01` Revision 4 — Δ3 concrete cut.** Add the Δ3 decisions (R1–R6 above) mirroring the
   Δ1/Δ2 "concrete cut" revisions, split into Δ3a (RAG, all-Go) and Δ3b (Python reasoning, if needed). The
   authority spine (D1/D2/D7/D8/D10) is unchanged; RAG feeds the LLM step, never auto-decides.
2. **`STACK.md` reconcile.** Fix line 58 (RAG is **Δ3 reactive**, not "Δ4-autonomous, deferred"); replace
   the pgvector row with **plain-PG persisted vectors + in-memory Go search** (front-runner) and list
   pgvector/Qdrant as **upgrade paths**; add the `nomic-embed-text` embedder row (pending §4).
3. **Unblock implementation** — the Δ3a groups become live (see the plan appendix):
   A1 store (plain-PG `position_embeddings` + migrations) · A2 embedder port + Ollama/nomic adapter +
   fake · A3 `EngineKnowledge` + `VectorIndex` (in-memory) + ranked retrieval · A4 bus-consumer population
   + backfill · A5 plan `[Rule → Knowledge → LLM]` + provenance · A6 e2e (fake embedder + fake provider) +
   telemetry + docs.

## 4. Demoable cases (ref: `../current-changes/themis-ai-use-cases.md`)

This decision exists to make **Use Case #4 — Vulnerability Validation / Triage Automation** demoable: a
never-before-seen CVE gets a `recommend_position` grounded in semantically similar **past** enterprise
decisions, citing them (advisory; human decides). The demo **is** the Δ3a acceptance test.
- **#4 (primary demo):** precedent-grounded triage recommendation.
- **#5 (stretch):** "findings similar to this one" — same retrieval primitive. **DELIVERED 2026-08-10** as
  `GET /findings/{id}/similar`, and the evidence since promoted it from stretch to the *lead* use case: the
  primitive scored recall@1 = 1.00 (R5), and its one known weakness argues **for** the human-facing form.
  Contradictory precedent makes `recommend_position` decline; for an engineer, "we ruled this two ways on
  two releases" is the most useful thing on the page. Serving it needs no model, so it costs no tokens, has
  no budget ceiling, no `204` taxonomy and nothing to hallucinate.
- **#6 / #9 / #15:** foundation only; need later deltas (Δ4 autonomy/LLMOps or a Q&A capability).

## 5. Open items / caveats before this is final

- **Embedding-model pick** — R5 is *pending* the Session-2 §4 Ollama eval (latency + recall@10 on labeled
  similar pairs; what-text-to-embed A/B). Everything else is data-backed.
- **Growth curve** — decision holds for ≤50k. If a large multi-tenant install could approach ~10⁶, the
  `VectorIndex` port makes pgvector/Qdrant a config-swap; no rework. Recorded as the upgrade trigger.
- **Δ3b (Python)** — remains deferred; revisit only when a concrete reasoning task can't be expressed in
  the Go path. Adding it is a new module/service (a CLAUDE.md "Must ask").

## 6. Recommendation

Approve R1–R4 + R6 now (data-backed); confirm R5 (`nomic-embed-text`) after the Ollama eval; then execute
§3 (EDR Rev 4 + STACK reconcile) and start the Δ3a groups. The demo target is fixed and testable: a
semantic precedent changes a recommendation.
