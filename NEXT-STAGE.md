# Themis AI — Next Stage (v0.4.1+ roadmap)

> The **v0.4.0** slice (`openspec/changes/themis-ai-1/`) ships the thin **advisory CVE Summarizer**:
> one worker, Ollama `qwen2.5:7b`, two systems over a Postgres seam, advisory-only. Everything below
> is **deliberately deferred beyond v0.4.0** — this is the next stage. Traces to the decision log in
> [`phase-2b-grilling.md`](phase-2b-grilling.md) and the north-star catalogue in
> [`themis-ai-use-cases.md`](themis-ai-use-cases.md). Use-case numbers (`#1`…`#15`) reference the
> latter.

## Release targets

| Release | Theme | Gate |
| --- | --- | --- |
| **v0.4.0** | Basic AI enrichment (CVE Summarizer) — *design resolved, ready for task breakdown* | — |
| **v0.4.1** | Deepen the AI layer — memory/RAG, more workers, latency + scale | v0.4.0 shipped **+** a real `ai.analyses` corpus to embed |
| **v0.5.0 (Phase 2c)** | AI-assisted VEX — auto-apply, false-positive, confidence thresholds | KB seeded with real analyst decisions |

---

## v0.4.1 — deepen the AI layer

### 1. Agentic memory / pgvector KB / RAG (P3)
- **What:** embed past summaries, triage decisions, and FP patterns; retrieve them as grounding for
  the workers (RAG).
- **Why deferred:** day-one memory is empty → RAG adds nothing until a corpus exists; re-embedding the
  `ai.analyses` corpus later is cheap.
- **Home:** themis-ai's **own** store (pgvector / a vector DB), **not** the shared Postgres — P3 is
  JOIN-free (never joined to backend findings). Traces to **D-MEMORY-1 / D-KB-1**.

### 2. Additional AI workers
The generic `ai.analyses` table + `worker_type` discriminator already supports these — each is
**additive** (new `worker_type`, its own prompt, its own row shape). Component-specific workers may add
`component_purl` to their **own** key (per **D-GRAIN-1**), without touching the Summarizer's CVE-grain.

| Worker | Use case | Notes |
| --- | --- | --- |
| CWE Mapper | #1 | classify/normalise weakness when the catalogue lacks a CWE |
| Exploitability Analyzer | #3 / #8 | fuse EPSS/KEV/exploit signals into a narrative |
| Context / Asset enrichment | #2 | ownership, criticality, reachability (uses the L1a asset graph) |
| VEX Recommender | #4 | proposes a VEX verdict → **feeds Phase 2c** |
| Remediation advisor | #6 | fix steps / patch version / workaround |
| False-positive classifier | #4 | flags likely FPs for analyst review (advisory) |

### 3. Latency — `LISTEN/NOTIFY`
- **What:** push-notify themis-ai on eligibility change instead of waiting for the poll interval.
- **Why deferred:** advisory + off-by-default → poll (30–60 s) is fine. Additive **on top of** the
  same `v_ai_enrich_context` view; the reconcile stays the source of truth. Traces to **D-QUEUE-1**.

### 4. Scale — reconcile watermark
- **What:** expose `max(signals.updated_at)` on the view so themis-ai skips unchanged CVEs instead of
  re-hashing every eligible row per pass.
- **Why deferred:** at hundreds–low-thousands of eligible CVEs, per-pass hashing is trivial; the
  watermark matters at **tens of thousands**. Additive to the view. Traces to **D-QUEUE-1**.

### 5. Notification wiring
- **What:** wire the summary into a notification event.
- **Why deferred:** prove the summary's value via the read API first; avoid re-notifying an
  already-notified finding from an async job. Traces to **D-NOTIFY-1**.

### 6. Semantic eval (LLM-as-judge)
- **What:** BLEU/ROUGE or a judge model over the golden set.
- **Why deferred:** v0.4.0 eval is **deterministic structural checks only** (schema valid,
  `primary_weakness ∈ context CWEs`, ≤500 chars, no hallucinated CVE id). Judge scoring needs a 2nd
  model. Traces to **D-TEST-1**.

### 7. Transparency `?history`
- **What:** `GET /api/v1/vulnerabilities/{id}/ai?history=true` — the append-only ledger of every
  enrichment attempt (re-enrichment appends; v0.4.0 returns only the latest).
- **Why deferred:** latest record is enough for the first slice. Traces to **D-API-1**.

### 8. Model + runtime options
- **CyberPal-2.0** as a first-class opt-in alternative once eval proves it better (**D-MODEL-1**).
- **External-hosted runtimes / router** — opt-in, off-by-default, with a data-egress ack; targets the
  OpenAI-compatible `/v1/chat/completions` contract (**D-RUNTIME-1**).
- **Finer Ollama duration splits** as Prometheus histogram labels (not ledger columns) (**D-TYPES-1 /
  D-METRICS-1**).

---

## v0.5.0 (Phase 2c) — AI-assisted VEX

- **What:** confidence thresholds → **auto-apply** a VEX verdict; false-positive suppression; analyst
  override loop; continuous-learning feedback (#4, #15).
- **Why deferred / gated:** requires the KB (item 1) seeded with **real analyst decisions** before
  thresholds are tunable. Until then **D-WRITE-1** holds — AI is advisory-only, never writes
  `risk_context.effective_state`; state changes require a human.
- **Boundary this preserves:** the v0.4.0 seam (advisory-only, single-writer) is exactly what makes
  auto-apply a *config flip on a proven pipeline* rather than a rebuild.

---

## Separate track (not AI-gated)

### GHSA feed
- **What:** GitHub Security Advisories for ecosystem-precise fix versions + CWE ids.
- **Why separate:** it's a **correlation / vuln-data feed** (NVD/OSV family), *not* an AI feature —
  belongs in a feed-expansion change decided on `intel-source-tiers` merits (2a lineage). No hard
  dependency: the Summarizer already gets CWE ids from the NVD/OSV catalogue. Post-2b it enriches AI
  context cleanly — a new context field → new `input_context_hash` → **natural re-enrichment**. Traces
  to **D-SCOPE-2**.

---

## Why the v0.4.0 design already makes all of the above cheap

The thin slice was shaped so the next stage is **additive, not a rewrite**:

- **Generic `ai.analyses` + `worker_type`** → new workers drop in without schema churn.
- **CVE-context grain + `input_context_hash`** → any new context field re-enriches naturally; no
  migration to re-key.
- **`ai` schema owned by themis-ai (Alembic)** → the AI layer evolves without touching the Go
  `golang-migrate` chain or the schema-skew guard.
- **Level-triggered reconcile over a view** → `LISTEN/NOTIFY` (latency) and the watermark (scale) are
  additive; the view stays the contract.
- **themis-ai's own store for P3** → memory/RAG never touches the shared Postgres.
- **Advisory-only single-writer seam** → Phase 2c auto-apply is a config flip on a proven pipeline.

---

_Maintained alongside `phase-2b-grilling.md`. When an item is picked up, move it into its own OpenSpec
change and strike it here._
