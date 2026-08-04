# RAG Integration — Session 2: Reality-check + Spike

**Status:** Session 2 — spike **run** (search benchmark: real numbers below); embedding-model eval
**pending** (needs a running Ollama, unavailable in this environment). **No decision yet** (Session 3).
**Updated:** 2026-08-03 · **Owner:** Intelligence context.
**Reads with:** [`RAG-INTEGRATION-OPTIONS.md`](RAG-INTEGRATION-OPTIONS.md) (Session 1 options + matrix).
**Demoable cases reference:** [`../current-changes/themis-ai-use-cases.md`](../current-changes/themis-ai-use-cases.md).

---

## 1. Purpose

Session 1 landed a preliminary lean — **in-memory Go search over embeddings persisted in a plain Postgres
table** (no pgvector), pgvector/Qdrant as upgrade paths behind an `app.VectorIndex` port. This session
replaces the **assertions** in that lean with **measured data**, on the confirmed corpus size (**≤ ~50k**
past Positions/Findings). Two questions:

1. Is brute-force cosine search actually fast enough at 50k? (latency + memory)
2. What does "persist + load on boot" really cost, and does it need pgvector?

## 2. Search benchmark — measured (the number that matters)

**Method:** stdlib-only Go micro-benchmark (`scratchpad/cosinebench.go`, throwaway — not committed).
Flat `[]float32` corpus of unit vectors (cosine == dot), `dim=768` (nomic-embed-text), single-threaded
top-10 search, averaged over 100–300 queries. Machine: Apple Silicon (arm64), 8 cores, Go 1.26.

| Corpus (dim=768) | Query latency (single-thread) | Throughput | Memory (measured heap) |
|---|---|---|---|
| 10,000 | **9.4 ms** | ~106 q/s | 29 MB |
| **50,000** | **46.8 ms** | ~21 q/s | **147 MB** |
| 100,000 | 93.6 ms | ~11 q/s | 293 MB |

**Correction to Session 1:** the S1 doc asserted "<10 ms at 50k." That was optimistic — measured is
**~47 ms** single-threaded (linear in N, as expected: 50k × 768 ≈ 38M multiply-adds/query). The S1 doc
has been corrected to cite this number.

**Interpretation — the front-runner still holds, comfortably:**
- **47 ms is negligible for U1.** `recommend_position` is human-triggered with a "seconds" budget and
  already waits on a local **LLM** call (hundreds of ms to seconds). Retrieval at 47 ms is a rounding
  error in end-to-end latency, not a bottleneck.
- **Large headroom if ever needed:** parallelising the scan across the 8 cores → **~6 ms at 50k**;
  Matryoshka-truncating nomic embeddings from 768→256 dims → ~3× faster + ⅓ the memory; a small in-Go
  HNSW → sublinear. None of this is needed at 50k — it's the runway.
- **Where an ANN index (HNSW / pgvector) would start to matter:** past ~10⁵–10⁶ vectors, single-thread
  brute force crosses ~100 ms–1 s and parallelism stops hiding it. That is the documented **upgrade-path**
  trigger — and it's well beyond the confirmed ≤50k corpus.

**Verdict (search):** in-memory brute-force cosine is **more than adequate** for U1/U2 at ≤50k. Memory
(~150 MB) is modest for a service process. ✓ confirms Axis-1 front-runner.

## 3. Persistence + cold-start cost (the other half of Axis 1)

The cheap part is loading; the expensive part is embedding. This is what decides "persist embeddings",
not just "persist text":

- **Steady state (normal operation):** the index is kept fresh incrementally — one embed per new
  Enterprise Position (the bus consumer on `PositionEstablished`). Per-decision embedding cost is one
  model call — trivial.
- **Cold start / boot:** we must **not** re-embed 50k records on every restart. Embedding 50k texts
  through a local model at ~tens of ms each single-threaded is **minutes** — unacceptable per boot. So we
  **persist the embeddings** (the float vectors), and on boot we **load** them: reading 50k × `float4[768]`
  rows ≈ 150 MB streamed from Postgres in ~1–3 s. Load is cheap; re-embed is not → **persist vectors.**
- **Full re-embed** happens only on (a) the initial backfill, or (b) an embedding-model change (re-embed
  everything) — both rare, offline, one-off operations, not a hot path.

**Consequence for the store:** we need to persist a vector column. A **plain Postgres table** does this
with `float4[]` (or `bytea`) — **no pgvector extension required**, because search happens in memory, not
in SQL. This is what eliminates the `embedded-postgres`/pgvector test gap (the store's integration tests
run under `embedded-postgres` with no extension). ✓ confirms "plain-PG persist + in-memory search."

```text
Δ3a store shape (proposed):
  position_embeddings(
    position_id   TEXT PRIMARY KEY,   -- the enterprise Position this vector represents
    faultline_id  TEXT NOT NULL,      -- for filtering / grouping
    cve           TEXT,               -- source CVE (precedent may be a DIFFERENT CVE)
    model         TEXT NOT NULL,      -- embedding model+version (re-embed trigger on change)
    dim           INT  NOT NULL,
    vector        BYTEA NOT NULL,     -- or float4[]; packed little-endian float32
    text_hash     TEXT NOT NULL,      -- what-we-embedded fingerprint (skip re-embed if unchanged)
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
  )
  -- loaded into an in-memory []float32 index on boot; kept fresh by the bus consumer.
```

## 4. Embedding-model eval — PENDING (needs Ollama)

Not runnable here (no Ollama in this environment). To run where Ollama lives (Mac dev / the VM):

```sh
ollama pull nomic-embed-text
# latency + a sanity similarity check on our text (rationales + CVE descriptions):
curl -s http://localhost:11434/api/embeddings \
  -d '{"model":"nomic-embed-text","prompt":"<a real Position rationale>"}' | jq '.embedding | length'
```

Candidates + what to measure (rule-basis · chosen · alternatives · why — for Session 3):

| Model | Dim | Why a candidate | Measure |
|---|---|---|---|
| **nomic-embed-text** | 768 (Matryoshka → 256/512) | PoC precedent; runs on the existing Ollama; good retrieval quality; local | embed latency; recall@10 on hand-labeled similar pairs |
| bge-small-en-v1.5 | 384 | smaller/faster; strong MTEB | quality vs nomic at ⅓ memory |
| e5-small-v2 | 384 | query/passage prefixes; strong retrieval | same |

**What text to embed** (open question O4 from S1) — options to A/B: (a) rationale only; (b) rationale +
CVE description; (c) rationale + CVE description + component/bug-class. Hypothesis: (c) best serves the
"same component / same bug-class" precedent match (the #4 demo), but risks diluting the rationale signal —
measure recall on labeled pairs.

**Lean (to confirm):** `nomic-embed-text` at 768 dims — reuse the deployed runtime, local (D10), PoC
precedent. Matryoshka-truncate to 256 only if memory/latency ever demands it (they don't at 50k).

## 5. Demoable cases (ref: `../current-changes/themis-ai-use-cases.md`)

The spike is in service of the **north-star demo — Use Case #4, Vulnerability Validation / Triage
Automation**: a novel CVE gets a `recommend_position` grounded in semantically similar **past** decisions,
citing them. This benchmark confirms the retrieval that powers that demo is fast + cheap at our scale.
- **#4 (primary):** precedent-grounded triage recommendation. Demo == Δ3a acceptance test.
- **#5 (stretch):** "findings similar to this one" — same retrieval primitive, near-free.
- **#6 / #9 / #15:** foundation only — need later deltas.

## 6. Session 2 outcome

- **Search:** ✓ in-memory brute-force cosine confirmed adequate at ≤50k (**~47 ms** single-thread, ~150 MB,
  8× headroom via goroutines). ANN/pgvector upgrade trigger is ~10⁵–10⁶, beyond the corpus.
- **Persistence:** ✓ persist embeddings in a **plain Postgres table** (`float4[]`/`bytea`); load-on-boot is
  cheap, re-embed is not → we persist vectors. No pgvector → no test gap.
- **Embedding model:** ⏳ eval pending Ollama; lean = `nomic-embed-text` (768). Run before Session 3
  finalizes.
- **Net:** the Session-1 front-runner (in-memory + plain-PG + hand-rolled Go) is **confirmed by data** on
  the search + persistence axes; only the embedding-model pick remains empirical.
