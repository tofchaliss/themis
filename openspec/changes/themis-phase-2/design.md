# Themis Phase 2 Design

> **Architecture Reference Document.**
> This document contains the authoritative design decisions for the full Phase 2 AI
> Intelligence layer. Implementation is split across three sub-phase changes:
>
> | Sub-phase | Change | Implements |
> | --- | --- | --- |
> | **2a** | `themis-phase-2a` | Decisions 1 (L1+L2), 2, 10, 12, 13, 14, 15, 16, 18, 19 |
> | **2b** | `themis-phase-2b` | Decisions 1 (L3), 3, 4, 5, 6, 7, 11, 16, 17 |
> | **2c** | `themis-phase-2c` | Decisions 8, 9, 16 |
>
> Each sub-phase references this document for architectural context.
> Each sub-phase has its own `tasks.md` under `openspec/changes/<name>/`.

## Context

Phase 1 delivered a complete Go REST API backed by PostgreSQL: ingestion, VEX overlay,
CVE watch, triage, and notifications. Risk scores are deterministic — `f(severity,
vex_state)`. Every DETECTED finding looks identical regardless of whether a Metasploit
module was published yesterday or the CVE has never been weaponised.

Phase 2 makes Themis useful for real security workflows. The core challenge: add AI
enrichment without making the system fragile — AI must never block ingestion, must
degrade gracefully when unavailable, and must never override human decisions.

**Key constraints carried from Phase 1:**

- Single binary + PostgreSQL — no new runtime services beyond Ollama
- Clean Architecture import rule preserved — all new packages follow the same layering
- `domain/` imports stdlib only; new AI ports live in `domain/ports.go`
- `InProcessQueue` remains the job backend — Redis is Phase 3
- `StubVerifier` remains — CosignVerifier is Phase 3
- All 15 Phase 1 acceptance criteria remain in force

**New constraints for Phase 2:**

- AI is never in the synchronous ingestion path — `202 Accepted` returns before any
  model call
- Internal KB (past analyst decisions) is the most authoritative signal — ranked above
  all external feeds including NVD
- The system must work correctly with Ollama offline (graceful degradation to Layers 1+2)
- No data leaves the deployment — all inference is local via Ollama

---

## Goals / Non-Goals

**Goals by sub-phase:**

Phase 2a — Signal Foundation:

- EPSS/KEV daily sync → improved deterministic risk scoring
- ExploitDB CSV → `ExploitPublic` signal for Layer 1
- Upstream vendor VEX feeds (Red Hat, Alpine, Ubuntu, etc.)
- Layer 1 deterministic rules (CVSS + KEV + EPSS + ExploitPublic)
- Layer 2 graph reasoning (blast-radius, team notifications)
- Microservice / Deployment / Customer as first-class entities (resolves OQ-9)
- VEX export endpoint (CycloneDX VEX or OpenVEX JSON)
- GHSA integration for ecosystem-precise fix versions

Phase 2b — AI Intelligence:

- Seven specialised AI workers with typed JSON I/O (Layer 3 async)
- Local SLM via Ollama (CyberPal-2.0 / Qwen2.5-7B)
- Internal KB via pgvector semantic memory (L1c RAG)
- KB-first optimisation (similarity ≥ 0.92 → skip model)
- Risk Explanation narrative synthesis
- `enrichment_status` field in findings API response

Phase 2c — AI-Assisted VEX:

- AI-assisted VEX auto-apply with configurable confidence threshold (OQ-5)
- False Positive auto-apply with configurable threshold (OQ-6)
- Four-eyes rule for strict trust policy (OQ-10)
- `FINDING_AUTO_SUPPRESSED` notification event
- VEX overlay re-triggered immediately after AI VEX creation (G1 fix)

**Non-Goals (Phase 3):**

- Apache AGE / Cypher queries — SQL graph tables only in Phase 2
- Redis job queue — InProcessQueue sufficient for Phase 2
- CosignVerifier / real signature verification
- CI/CD webhook ingestion (GitHub, GitLab, Bitbucket)
- Runtime protection analysis — Q6 requires WAF/eBPF data
- Business impact analysis — Q7 requires customer criticality matrix
- Full tracked remediation with ticket integration — advisory output only in Phase 2
- Web UI / React SPA
- RBAC / OIDC
- Air-gapped ExploitDB mirror — remote CSV only in Phase 2

---

## Quality Gates

Phase 2 follows the same two-stage gate as Phase 1 (task-wise gates then full build).
Gates are applied per sub-phase: only packages touched by that sub-phase are checked
before moving on. `make verify-build` is always the final gate for every sub-phase.

**Coverage thresholds by sub-phase:**

| Sub-phase | Package | Threshold |
| --- | --- | --- |
| 2a | `domain/` (new entities) | 100% |
| 2a | `adapter/epsskev/` | ≥ 90% |
| 2a | `adapter/exploitdb/` | ≥ 90% |
| 2a | `adapter/vexfeed/` | ≥ 90% |
| 2a | `adapter/assetgraph/` | ≥ 90% |
| 2a | `usecase/vexgen/` (base) | 100% |
| 2b | `adapter/ai/` | ≥ 90% |
| 2b | `adapter/ghsa/` | ≥ 90% |
| 2b | `usecase/remediation/` | 100% |
| 2c | `usecase/vexgen/` (auto-apply) | 100% |

**Integration test requirements:**

- **2a:** standard PostgreSQL integration tests using `THEMIS_TEST_DATABASE_DSN`
- **2b:** pgvector extension must be installed in the test PostgreSQL instance;
  tests requiring a live Ollama endpoint are tagged `//go:build integration_ai`
  and skipped in standard CI; standard tests use a stub AI worker with deterministic fixtures
- **2c:** same as 2b; add acceptance tests for auto-apply + notification event

---

## Decisions

### Decision 1: Three-Layer Intelligence Collector `[2a: L1+L2]` `[2b: L3]`

Every finding passes through three processing layers. Layers 1 and 2 run synchronously
before the API response. Layer 3 runs asynchronously via `JobQueue`.

```text
LAYER 1 — DETERMINISTIC RULES          (sync · no AI · always explainable)
──────────────────────────────────────────────────────────────────────────
Pure logic. No model. No external call. Sub-millisecond.

Rules:
  CVSS ≥ 9.0  ∧  KEV = true       →  Critical
  CVSS ≥ 9.0  ∧  ExploitPublic    →  High+
  KEV = true  ∧  CVSS < 9.0       →  High
  EPSS ≥ 0.5  ∧  CVSS ≥ 7.0      →  Elevated
  CVSS ≥ 9.0  (no other signals)  →  High (deterministic floor)

Output written to risk_context.deterministic_level immediately.
These rules always win — no AI score can override a Critical determination.

LAYER 2 — GRAPH REASONING              (sync · no AI · fast SQL traversal)
──────────────────────────────────────────────────────────────────────────
SQL traversal of L1b Security Knowledge Graph.

  CVE → Package → Product → Microservice → Deployment → Customer (Team)

Output:
  blast_radius_score  (1 team = 1.0×; 10+ teams = 2.0× cap)
  affected_teams[]    (Customer nodes reachable from this CVE)
  notification_queue  (deterministic — no AI input required)

Written to: risk_context.blast_radius_score; notification events enqueued.

LAYER 3 — AI REASONING                 (async · CyberPal/Qwen · KB-first)
──────────────────────────────────────────────────────────────────────────
Seven workers. KB check fires first (see Decision 5).
If Ollama is offline: skip silently; risk_context retains Layer 1+2 values.
Output enriches risk_context.ai_* columns when complete.
```

**Why:** Separating determinism from probabilism means the system is always correct
at Layer 1+2 and sometimes better with Layer 3. An Ollama outage is a quality
degradation, not a system failure. Layers 1+2 are also the fastest audit trail —
every Critical determination is traceable to an explicit rule, not a model output.

---

### Decision 2: Five-Layer Data Model `[2a: migrations 000014/017]` `[2b: migrations 000015/016]`

The Phase 1 three-layer model is superseded. The revised model adds graph storage
(L1a/L1b), semantic memory (L1c), and AI output tables (L2) as distinct layers.

```text
L0  RAW IMMUTABLE INVENTORY
    All Phase 1 tables. Append-only. Never mutated.

L1a ASSET & DEPENDENCY GRAPH          (new in Phase 2)
    SQL graph tables: asset_graph_nodes, asset_graph_edges
    Nodes: Component, Microservice, Deployment, Customer
    Phase 3: migrate to Apache AGE (Cypher).

L1b SECURITY KNOWLEDGE GRAPH          (new in Phase 2)
    Traversal: CVE ↕ CWE ↕ Package ↕ Product ↕ Microservice
               ↕ Deployment ↕ Customer
    Built by Vulnerability Intelligence Collector.

L1c SEMANTIC MEMORY                   (new in Phase 2)
    Table: embeddings (entity_type, entity_id, vector, model, created_at)
    Populated by: every analyst triage decision, every AI output.
    Queried by: Layer 3 workers via ANN search.

L2  AI ENRICHMENT                     (new in Phase 2)
    Immutable per (worker_id, input_hash). Re-run = new row.
    Tables: ai_summaries, ai_cwe_mappings, ai_exploitability,
            ai_vex_recommendations, ai_remediation_advice, ai_fp_analysis

L3  HUMAN VALIDATION
    Extends Phase 1 triage_history. Adds: approvals, vex_overrides.
    Rule: append-only. Human decisions are permanent record.

CONVERGENCE: risk_context
    Phase 2 score: h(severity, vex_state, epss_score, kev_flag,
                     ai_exploitability, ai_reachability_confidence,
                     blast_radius_score)
```

**Why:** The five layers have fundamentally different mutation, trust, and caching
characteristics. L0 is evidence. L1a/L1b are derived structure. L1c is a searchable
memory. L2 is probabilistic output. L3 is authoritative human record. Mixing them
breaks auditability.

> ✅ **DECIDED:** Formula confirmed with EPSS weighting as proposed:
>
> ```text
> base      = f(severity, vex_state)              [Phase 1 formula]
> layer1    = if deterministic_level=Critical → 100, else base
> epss_adj  = base × (1 + epss_score × 0.3)      [up to +30%]
> kev_adj   = if kev_listed → +15 points          [hard bump]
> blast_adj = base × blast_radius_score            [1.0–2.0×]
> ai_adj    = if ai_exploitability=Critical → ×1.2; Low → ×0.7
> final     = min(100, layer1 + epss_adj + kev_adj + blast_adj + ai_adj)
> ```
>
> Layer 1 deterministic rules override the formula for Critical findings.
> EPSS contributes up to +30% to amplify high-probability exploitation signal.

---

### Decision 3: Local SLM via Ollama `[2b]`

AI inference runs locally via Ollama. No data leaves the deployment. The model
backend is configurable via the `domain.AIWorkerRuntime` port.

```text
Default model:   CyberPal-2.0     (IBM; security-fine-tuned; preferred)
Fallback model:  Qwen2.5-7B       (strong reasoning; good JSON output)
Embedding model: nomic-embed-text (for pgvector; 768-dim; fast)

Config:
  ai.model_name:           cyberpal-2.0
  ai.ollama_endpoint:      http://localhost:11434
  ai.embedding_model:      nomic-embed-text
  ai.worker_concurrency:   3     (bounded pool size — see Decision 17)
  ai.request_timeout_s:    45    (per-call timeout — see Decision 17)

The AIWorkerRuntime interface accepts any OpenAI-compatible API:
  type AIWorkerRuntime interface {
      Complete(ctx context.Context, model, prompt string) (string, error)
      Embed(ctx context.Context, model, text string) ([]float32, error)
  }
Swappable to OpenAI, Anthropic, or any Ollama model via config.
```

#### Hardware Prerequisites

Phase 2b requires Ollama running alongside Themis and PostgreSQL on the same host
or reachable over the local network. All three processes share host resources.

```text
Minimum viable:
  RAM:    16 GB  (Ollama model ~4.5 GB + PostgreSQL ~4 GB + pgvector + OS)
  CPU:    Modern x86-64 or Apple Silicon, 8+ cores
  Disk:   NVMe SSD — model weights ~4.5 GB; pgvector index grows with KB size
  GPU:    Optional but strongly recommended

Inference latency by hardware:
  NVIDIA CUDA / Apple Metal / AMD ROCm:   1–8 seconds per model call
  CPU-only (no GPU):                      60–180 seconds per model call

CPU-only implication for G7 (batch size unbounded):
  50 findings × 7 workers × 90 s average = ~5 hours per large SBOM
  CPU-only deployments must set ai.worker_concurrency=1 and enable
  priority ordering (CRITICAL/HIGH findings first). Warn at startup.

Recommended minimum:   16 GB RAM + GPU with ≥ 8 GB VRAM
```

#### CyberPal-2.0 Availability

CyberPal-2.0 is an IBM Research model. Its presence in Ollama's public registry
is not guaranteed. Most Phase 2b deployments will run on Qwen2.5-7B in practice.

```text
If available in Ollama registry:
  ollama pull cyberpal-2.0   ← automatic at startup

If not in registry (two options):
  a) Manual import:
       download GGUF weights from HuggingFace / IBM
       Modelfile: FROM /path/to/cyberpal-2.0.Q4_K_M.gguf
       ollama create cyberpal-2.0 -f Modelfile
  b) Accept the Qwen2.5-7B fallback (no manual action needed)

ai.model_name config overrides auto-selection for either path.
```

#### Startup Health Check Sequence

```text
1. GET {ollama_endpoint}/api/tags
   Unreachable → ai_available=false; log WARNING; continue without AI enrichment

2. Attempt ollama pull {ai.model_name}  (default: cyberpal-2.0)
   Fails → attempt ollama pull qwen2.5:7b
   Fails → ai_available=false; log WARNING

3. Log active model name at INFO level on every startup

4. First enrichment job triggers model warm-up:
   first-token latency is 2–3× higher while model loads into VRAM
   subsequent calls benefit from hot weights (Ollama keep-alive TTL: 5 min default)
```

**Why:** Data sovereignty is a hard requirement for security tooling. CVE data,
service descriptions, and past analyst decisions must not transit third-party APIs.
CyberPal-2.0 is preferred because it is fine-tuned on security corpora (NVD, CVE,
security advisories) — better CWE classification and CVSS vector parsing at 7B than
a 70B general model. Qwen2.5-7B is the automatic fallback when CyberPal is
unavailable or not yet published in Ollama's registry.

> ✅ **DECIDED:** Attempt `ollama pull cyberpal-2.0` at startup. If the model is not
> in the Ollama registry or pull fails, fall back to `qwen2.5:7b` automatically.
> The adapter logs which model is active at startup. `ai.model_name` config overrides
> the auto-selection. Hardware prerequisites and startup sequence above are part of
> the Phase 2b deployment guide (extends G8 fix).

---

### Decision 4: RAG Architecture — Small Model + Rich Context `[2b]`

The AI workers inject all knowledge at query time from authoritative local sources.
The model reasons over injected context; it does not rely on parametric recall.

```text
CONTEXT ASSEMBLY (per worker call)
  ──────────────────────────────────────────────────────────────────
  Always injected:
    CVE description, CVSS vector, CWE classification
    EPSS score, KEV status, ExploitDB records
    GitHub SA version ranges for this package
    Service name, service description

  Retrieved (pgvector ANN):
    Top-k past decisions with cosine similarity ≥ 0.60
    Sorted by: similarity DESC, decision_date DESC
    Limit: 5 records (token budget constraint)

  Prompt structure:
    System: [authoritative context block]
    System: [retrieved KB decisions block]
    User:   "Answer exactly: [question N]. Output JSON only."

ZERO-DAY HANDLING
  ──────────────────────────────────────────────────────────────────
  For a brand-new CVE with no KB history:
    1. Class reasoning:  CWE + CVSS vector → historical exploitation rate
    2. Vector analysis:  AV/AC/PR/UI/S parsed as structured data
    3. KB retrieval:     similar CWE class + service type (may find analogs)
  No model retraining needed. Architecture designed around this constraint.
```

**Why:** A 7B model with the right context outperforms a 70B model without it for
domain-specific tasks. Context is curated, versioned, and auditable. Model calls
are cheap (local), so rich prompts are preferable to larger models.

> ✅ **DECIDED:** Layer 3 enrichment triggers when:
> `CVSS ≥ 7.0 OR kev_listed = true OR exploit_public = true`
>
> This enriches all actionable findings without wasting model calls on informational
> CVEs. A MEDIUM CVE with a public Metasploit module is more urgent than a CRITICAL
> CVE with no exploitation history — the trigger rule reflects this.

---

### Decision 5: KB-First Optimisation `[2b]`

Before any model call, the system checks L1c for a past decision that closely matches
the current finding. A high-similarity hit bypasses the model entirely.

```text
KB CHECK (runs before every worker chain)
  ─────────────────────────────────────────────────────────────────
  Query: ANN search on (cve_id ∥ component_purl ∥ service_name ∥ cwe_id)
  If top result cosine similarity ≥ BYPASS_THRESHOLD:
    → apply past decision directly
    → set ai_*.source = "kb_direct"
    → skip all model calls for this finding
    → embed new context to keep KB current

  If similarity < BYPASS_THRESHOLD:
    → proceed to seven workers
    → embed outputs after completion → grow KB
```

**Why:** Recurring findings (same CVE class, same component, same service type) are
the majority of analyst workload in stable systems. Applying KB directly is faster,
cheaper, and more consistent — the model would produce the same answer anyway.
KB growth is self-reinforcing: the more decisions recorded, the more findings are
resolved without model calls.

> ⚠️ **NEEDS DISCUSSION — KB bypass threshold:**
> Proposed threshold: **0.92 cosine similarity**.
> Trade-off: higher = safer but misses near-identical cases; lower = more coverage
> but risks incorrect auto-application on superficially similar cases.
> 0.92 was chosen conservatively for Phase 2. Recommend A/B testing with real
> triage data before locking. Consider separate thresholds per worker type
> (FP Analyzer may need a stricter threshold than CVE Summarizer).

---

### Decision 6: Seven Specialised AI Workers (Skills Pattern) `[2b]`

Instead of one monolithic model call per finding, seven specialised workers each
answer one question with a typed input/output schema.

```text
Worker          Question              Input key fields              Output key fields
──────────────  ────────────────────  ────────────────────────────  ─────────────────────────────
CWE Mapper      CWE classification    description, cvss_vector      cwe_id, category, owasp_class
CVE Summarizer  Why vulnerable?       description, cwe_id           summary, attack_type
Exploitability  Can it be exploited?  cvss, epss, kev, exploitdb    exploitability, confidence
Context         Reachable?            purl, service_desc, kb_hits   reachable, confidence
VEX Recommender VEX state?            summarizer+exploit+context    recommended_state, auto_apply
FP Analyzer     Known FP pattern?     purl, service, kb_fps         likely_fp, pattern
Remediation     Safest fix?           purl, version, fixed_versions action, urgency, target_version

Risk Explanation synthesises all worker outputs into a human-readable narrative.
```

**Why:** Monolithic calls produce unstructured output that is hard to validate and
store. Specialised workers produce structured JSON that is schema-validatable,
independently testable, and independently replaceable. A worker that underperforms
can be improved without touching others. Workers can also be run selectively (e.g.
skip Remediation Advisor for informational findings).

---

### Decision 7: AI Enrichment is Strictly Async `[2b]`

All seven workers run via `domain.JobQueue` (currently `InProcessQueue`). No worker
is in the synchronous ingestion path.

```text
SYNC PATH (returns 202 Accepted):
  Trust gate → Parse → Store → Correlate → Layer 1 → Layer 2 → risk_context written
  → 202 Accepted

ASYNC PATH (starts after 202 is sent):
  JobQueue ← AIEnrichmentJob{findings: [...]}
  → KB check → workers → risk_context.ai_* updated
  → VEX Generator (if VEX Recommender confidence ≥ threshold)
  → Notification updated (if blast radius changes)
```

**Why:** AI inference takes 1–30 seconds per finding batch. Blocking ingestion on
AI completion would make upload unusable for large SBOMs. The system is already
eventually consistent (notifications are async) — AI enrichment is one more async
stage in the same pipeline.

---

### Decision 8: AI-Assisted VEX with Configurable Threshold `[2c]`

The VEX Generator reads VEX Recommender output and applies it based on confidence
and trust policy.

```text
VEX GENERATION RULES
  ───────────────────────────────────────────────────────────────────
  confidence ≥ threshold ∧ state = not_affected
    → vex_document created (source=ai_generated, status=draft)
    → trust_policy=strict:       status=draft, queued for human review
    → trust_policy=standard:     status=active, auto-applied
    → trust_policy=permissive:   status=active, auto-applied

  confidence < threshold OR state ≠ not_affected
    → queued for analyst review in triage UI
    → AI output visible as enrichment context (not a VEX document)

VEX PRECEDENCE (immutable rule)
  human_triage > user_supplied > ai_generated > upstream_vendor

  Human VEX ALWAYS overrides. AI VEX is never "more trusted" than a
  human decision regardless of confidence score.
```

**Why:** Human analysts should not need to review every AI recommendation — that
defeats the purpose. High-confidence `not_affected` recommendations for well-understood
patterns (gVisor sandbox, test-only dependency, etc.) should auto-apply. Low-confidence
or `affected` findings need human eyes. The trust policy gives operators control.

> ⚠️ **NEEDS DISCUSSION — VEX auto-apply threshold (OQ-5):**
> Proposed: **0.85** for `standard` and `permissive` trust policies.
> Three questions to settle before implementation:
>
> 1. What is the acceptable false-negative rate for `not_affected` auto-VEX?
> 2. Should the threshold differ per VEX state (not_affected at 0.85 vs. affected at 0.95)?
> 3. Should the first N findings of a new deployment always require human review
>    to seed the KB before auto-apply is trusted?

---

### Decision 9: False Positive Analyzer as Dedicated Worker `[2b: worker]` `[2c: auto-apply]`

FP detection is separated from Context Analysis into a distinct worker because
the question is different: "does this match a known false positive pattern?" vs.
"is the code path reachable?". The distinction matters for prompt design and
output semantics.

```text
FP Analyzer:
  Input:   finding context + top-k pgvector hits WHERE past_state=FALSE_POSITIVE
  Output:  likely_fp: bool, confidence: float, pattern: string
  Action:  confidence ≥ FP_THRESHOLD → auto-sets effective_state=FALSE_POSITIVE
                                        (subject to trust_policy)

Context Analyzer:
  Input:   finding context + top-k pgvector hits (any past state)
  Output:  reachable: bool, confidence: float, recommended_vex_state
  Action:  feeds VEX Recommender
```

**Why:** False positive patterns are highly specific to the deployment. A past FP on
"test-only dependency never shipped" applies to other test-only findings but not to
production findings of the same CVE. The FP Analyzer is the highest-value worker
for analyst time: a correct FP identification eliminates a finding from the queue
permanently (via `ai_generated` VEX with `false_positive` status).

> ⚠️ **NEEDS DISCUSSION — FP auto-apply threshold:**
> Should the FP auto-apply threshold be stricter than the VEX threshold?
> A false-positive auto-application that is wrong causes a real vulnerability to
> be silently dismissed. Proposed: **0.90** for FP (vs 0.85 for VEX). Confirm.
> Also: should `trust_policy=strict` require two-analyst approval for FP
> auto-applications (four-eyes principle)?

---

### Decision 10: SQL Graph Tables for Phase 2, Apache AGE for Phase 3 `[2a]`

The Security Knowledge Graph (L1b) is implemented as relational tables with SQL
recursive CTEs in Phase 2. Apache AGE (PostgreSQL graph extension) is deferred.

```text
Phase 2 schema (SQL):
  asset_graph_nodes (id, node_type, entity_id, properties JSONB)
  asset_graph_edges (id, from_node_id, to_node_id, edge_type, weight)

  node_type ∈ { CVE, CWE, Package, Product, Microservice, Deployment, Customer }

Traversal query pattern (blast radius):
  WITH RECURSIVE blast AS (
    SELECT id FROM asset_graph_nodes WHERE entity_id = $cve_id
    UNION ALL
    SELECT e.to_node_id FROM asset_graph_edges e
    JOIN blast b ON e.from_node_id = b.id
    WHERE depth < 7
  )
  SELECT * FROM asset_graph_nodes WHERE id IN (SELECT id FROM blast)
    AND node_type = 'Customer'

Phase 3: migrate to Apache AGE. Same schema maps to Cypher property graph.
  No data migration needed — AGE reads PG tables.
```

**Why:** Apache AGE adds a new PostgreSQL extension with its own installation and
operational overhead. Phase 2 graph traversals are shallow (7 levels maximum) and
infrequent enough that recursive SQL performs adequately. Phase 3 introduces SRC
ingestion that generates dense call graphs requiring Cypher. The SQL schema is
designed to migrate cleanly.

---

### Decision 11: pgvector for Semantic Memory (L1c) `[2b]`

Past analyst decisions, AI outputs, and CVE summaries are stored as vector embeddings
in PostgreSQL via the `pgvector` extension.

```text
Table: embeddings
  entity_type  TEXT       (triage_decision, ai_summary, cve_description, vex_assertion)
  entity_id    UUID
  model        TEXT       (nomic-embed-text, cyberpal-embed)
  vector       vector(768)
  created_at   TIMESTAMPTZ

Index: HNSW (hierarchical navigable small world) on vector column
  ef_construction=64, m=16 (good balance of build time vs. query accuracy)

Query at inference time:
  SELECT entity_id, 1 - (vector <=> $query_vector) AS similarity
  FROM embeddings
  WHERE entity_type = 'triage_decision'
  ORDER BY vector <=> $query_vector
  LIMIT 5
```

**Why:** Same PostgreSQL instance, no new service, no new operational dependency.
pgvector ANN search is fast enough for Phase 2 workloads (< 100k embeddings). When
the KB grows beyond ~500k embeddings the HNSW index may need tuning — that is a
Phase 3 concern.

> ⚠️ **NEEDS DISCUSSION — Embedding model:**
> `nomic-embed-text` (768-dim, fast, general-purpose) is the proposed default.
> Alternative: a security-specific embedding model if CyberPal provides one.
> The choice is consequential — embedding model determines retrieval quality.
> A test retrieval experiment on 50 real CVE/triage pairs should be run before
> locking. Changing the model later requires re-embedding all existing records
> (migration cost).

---

### Decision 12: Intelligence Source Priority `[2a: all external feeds]` `[2b: Internal KB]`

Nine feeds are classified into four priority tiers. The tier determines how conflicts
are resolved and how retrieval failures are handled.

| Feed | Tier | Feed down behaviour | Phase |
| --- | --- | --- | --- |
| Internal KB | Critical | Block enrichment — KB is authoritative | Phase 2 |
| NVD | Mandatory | Retry 3× with backoff; alert ops if down > 1h | Phase 1 |
| CISA KEV | Mandatory | Retry 3×; stale flag on risk_context | Phase 2 |
| GitHub SA (GHSA) | Mandatory | Retry 3×; log gap; continue enrichment | Phase 2 |
| MITRE CVE | Mandatory | Retry 3×; fall back to NVD if MITRE lags | Phase 2 |
| Vendor Advisories | Mandatory | Retry 3×; log gap; continue enrichment | Phase 2 |
| ExploitDB | Recommended | Skip gracefully; log gap; no alert | Phase 2 |
| EPSS | Recommended | Skip gracefully; log gap; no alert | Phase 2 |
| OSV | Recommended | Skip gracefully; log gap; no alert | Phase 1 |

**Why:** Mandatory feeds affect correctness. Recommended feeds affect quality.
The system must not fail to ingest because ExploitDB is temporarily unavailable.
Internal KB cannot be degraded — if the KB is unavailable, AI enrichment should
wait rather than run without it.

> ⚠️ **NEEDS DISCUSSION — GitHub SA API authentication:**
> Unauthenticated: 60 req/hr. Authenticated (PAT): 5,000 req/hr.
> For a deployment tracking 100+ products, 60 req/hr is insufficient.
> Options: (a) require a GitHub PAT in config (recommended), (b) use GitHub App
> (better for teams), (c) cache aggressively with 6-hour TTL.
> How should the PAT be managed? Config YAML (risky if committed) vs. env var
> vs. secret management? Recommend env var: `THEMIS_GITHUB_TOKEN`.

---

### Decision 13: ExploitDB via CSV Download `[2a]`

ExploitDB data is ingested from the `files_exploits.csv` in the public
`offensive-security/exploitdb` GitHub repository.

```text
Phase 2 (remote):
  Scheduler: daily at 02:00 UTC
  URL: https://raw.githubusercontent.com/offensive-security/exploitdb/master/
       files_exploits.csv
  Parse: EDB-ID, CVE, type (remote/local/DoS/webapps), date, title
  Store: exploit_records table in L0 (append-only, deduplicated by EDB-ID)
  Auth: none (public repo; subject to GitHub rate limits)

Phase 3 (local mirror, air-gap):
  config.exploitdb.source = local_mirror
  config.exploitdb.mirror_path = /data/exploitdb
  git pull on schedule → read CSV from local path
  Zero code change — only config switch via domain.ExploitSource port swap.
```

**Why:** The CSV approach is simpler than the ExploitDB API and more reliable. The
GitHub repo is the canonical mirror of the ExploitDB database. Air-gap readiness is
built into the port design from day one.

---

### Decision 14: Microservice and Deployment as First-Class Domain Entities `[2a]`

`Microservice` and `Deployment` are new domain entities in Phase 2. They are required
for the blast-radius graph and for deployment-scoped notifications.

```text
Microservice:
  Fields: id, product_id, name, description, tech_stack JSONB,
          owner_team_id, created_at
  Meaning: a named service within a Product (e.g. "amf-core" within "5G Platform")

Deployment:
  Fields: id, microservice_id, environment (prod/staging/dev), region,
          runtime_config JSONB, customer_id, deployed_at
  Meaning: a running instance of a Microservice in a specific environment

Customer (Team/Owner):
  Fields: id, name, contact_email, notification_preferences JSONB
  Meaning: the internal team that owns and operates a Deployment
           and receives security notifications for it
  NOT a B2B customer — a local user/team of Themis
```

**Why:** Without Microservice and Deployment, blast-radius traversal terminates at
Product level — the same level as Phase 1. Phase 2 adds deployment-specific
context ("prod-eu is affected, staging is not") that drives actionable notifications.
Customer = internal team maps to the `notification_rules` model from Phase 1,
extending it to deployment scope.

> ⚠️ **NEEDS DISCUSSION — Microservice registration workflow:**
> How does a Microservice get registered in Themis? Options:
> (a) API endpoint (`POST /api/v1/products/{id}/microservices`) — explicit registration
> (b) Auto-discovered from SBOM `metadata.component.name` field
> (c) Both — auto-discover with manual override
> Option (c) is recommended for smooth adoption but adds complexity.
> The SBOM `metadata.component.name` field is already parsed in Phase 1 —
> auto-registration from existing data is low-cost.

---

### Decision 15: VEX Export as Standards-Compliant Document `[2a: base export]` `[2c: AI justification text]`

The VEX export endpoint serialises `risk_context` and `vex_assertions` into a
standards-compliant document.

```text
GET /api/v1/products/{id}/versions/{v}/vex
  ?format=cyclonedx (default) | openvex

CycloneDX VEX response:
  vulnerabilities[]:
    bom-ref: component PURL
    id: CVE ID
    analysis.state: not_affected | affected | in_triage | exploitable | resolved
    analysis.justification: AI-generated text (if available)
    analysis.response: workaround | update | will_not_fix | ...
    ratings.severity: from raw CVSS
    ratings.score: from risk_context.risk_score
    affects: component version range

  Non-normative extension fields (x-themis-*):
    x-themis-ai-confidence: float (from VEX Recommender)
    x-themis-epss-score: float
    x-themis-kev-listed: bool
    x-themis-blast-radius: int

Why non-normative: CycloneDX and OpenVEX specs do not define AI confidence fields.
Extensions preserve interoperability — consumers that don't understand x-themis-*
fields simply ignore them.
```

**Why:** VEX export is the primary interoperability surface — it lets downstream
consumers (other tools, audit systems, customers) consume Themis intelligence without
a proprietary API. Standards compliance (CycloneDX 1.5+, OpenVEX 0.2+) is
non-negotiable. AI-specific metadata goes in extensions to preserve forward
compatibility.

#### Upstream VEX Feed Matching `[2a]`

Vendor VEX documents (Red Hat, Alpine, Rocky Linux, Ubuntu, Debian, SUSE, Wolfi) are
stored as `vex_documents(source=upstream_vendor)` with per-assertion rows in
`vex_assertions`. Three design requirements apply to the `adapter/vexfeed/` implementation:

##### Requirement 1 — PURL Normalisation and Vendor-Authoritative Matching

Vendor-published VEX PURLs and SBOMs generated by Trivy/Syft use different formats.
Exact PURL match fails silently for the most common Linux distributions:

```text
Alpine VEX:     pkg:apk/alpine/busybox@1.35.0
Trivy SBOM:     pkg:apk/alpine/busybox@1.35.0-r5     ← -rN build revision suffix

Rocky Linux:    pkg:rpm/rocky/busybox@1.35.0-3.el9
Syft SBOM:      pkg:rpm/rocky/linux/busybox@1.35.0-3.el9  ← extra namespace segment

Red Hat VEX:    pkg:rpm/redhat/openssl@1.1.1k-6.el8_5
Trivy SBOM:     pkg:rpm/rhel/openssl@1.1.1k-6.el8_5   ← rhel vs redhat namespace
```

**Vendor VEX is the authoritative source for backported patches.**
Distro vendors backport security fixes into older package versions. A naive upstream
version comparison would incorrectly flag such packages as vulnerable:

```text
Apache httpd upstream: CVE-2023-25690 fixed in httpd@2.4.57
RHEL 8 ships:          pkg:rpm/rhel/httpd@2.4.37-51.el8

Naive comparison:      2.4.37 < 2.4.57  →  VULNERABLE  ← WRONG
Red Hat VEX:           pkg:rpm/redhat/httpd@2.4.37-51.el8  →  not_affected
                       (backport applied in RHSA-2023:1570)
```

Rule: once a vendor VEX assertion is matched (by any phase below), the vendor's
judgment is accepted. Do not compare to upstream version ranges after a vendor
VEX match.

`adapter/vexfeed/` implements four-phase matching (Phase 2a scope: apk + RPM only):

```text
Phase 1 — Exact PURL match
  Compare SBOM PURL to VEX assertion PURL byte-for-byte.
  match_type: exact

Phase 2 — Namespace alias normalisation (version unchanged):
  rhel        → redhat      (Red Hat RHEL namespace)
  rocky/linux → rocky       (Rocky Linux extra namespace segment)
  alma        → almalinux   (AlmaLinux alias)
  Lowercase namespace and name. Re-attempt exact match.
  match_type: namespace_normalised

Phase 3 — Errata suffix normalisation + version direction check (RPM only):
  Strip errata revision from installed version: -6.el8_5.1  →  -6.el8_5
  If base version matches assertion version (after Phase 2 namespace normalise):
    installed_version >= assertion_version (RPM EVR compare):
      → match_type: version_inherited  (errata on top of patched base — safe)
    installed_version < assertion_version (RPM EVR compare):
      → no_match; upstream_vex_coverage = purl_mismatch  (too old to inherit)

Phase 4 — Alpine build revision strip + OSV range check (apk only):
  Alpine publishes via OSV format with version ranges, not PURL-based assertions.
  Match on ecosystem="Alpine" + package name; check installed version against
  affected range using Alpine apk version comparator.
  OSV range semantics: [introduced, fixed) — fixed version is NOT in affected range.
    In range:     match_type: range_matched, state: affected
    Not in range: match_type: range_matched, state: not_affected
```

**Phase 2a scope:** Alpine (apk) and RPM ecosystems (Red Hat, Rocky Linux, AlmaLinux,
Wolfi). Debian and Ubuntu use different formats (DSA/USN) and version ordering — deferred
to a post-2a follow-on (see project-backlog.md). The `Matcher` interface supports
additional ecosystems via new implementations without changing shared logic.

A normalisation failure after all four phases must be logged as `purl_mismatch`,
not silently discarded.

##### Requirement 2 — Retroactive overlay re-run after feed sync

When the VEX feed scheduler stores new `vex_assertions` rows, it must enqueue a
`ReEnrichJob` for every `risk_context` row where `(component_purl_normalised, cve_id)`
matches a newly stored assertion. Without this, existing findings in the triage queue
stay `DETECTED` even when the vendor says `not_affected` — the data is correct but the
computed state is stale.

```text
VEX feed scheduler flow:
  fetch → parse → normalise PURLs → upsert vex_assertions
  → for each new/changed assertion:
      enqueue ReEnrichJob { component_purl, cve_id, trigger: upstream_vex_sync }
  → ReEnrichJob re-runs VEX overlay → updates risk_context.effective_state
  → if state changed DETECTED → not_affected:
      emit FINDING_AUTO_SUPPRESSED notification (see Decision 8 / G4 fix)
```

This is the same retroactive update pattern as G2 (EPSS/KEV sync) and G1 (AI VEX).
All three share a common fix shape: signal arrives → `ReEnrichJob` → overlay re-runs.

##### Requirement 3 — Coverage gap visibility

The findings API response must expose per-finding upstream VEX coverage status so
analysts can distinguish between three materially different situations:

```text
upstream_vex_coverage field on risk_context:

  covered       → vendor VEX matched (exact or normalised); state applied to
                  effective_state via VEX precedence rules
  not_covered   → no vendor VEX record exists for this (purl, cve_id) pair;
                  manual triage required
  purl_mismatch → vendor VEX record found for this CVE but no PURL matched
                  after normalisation; signals a gap in normalisation rules

Aggregate on product version:
  GET /api/v1/products/{id}/versions/{v}/vex-coverage
  → { covered: 23, not_covered: 18, purl_mismatch: 6 }

purl_mismatch findings are the highest-value operational signal:
  they can be resolved by fixing the normalisation rules rather than
  by analyst triage, so surfacing them separately saves analyst time.
```

**Why these three requirements together:** Without PURL normalisation, upstream VEX
has near-zero effect on Alpine/RPM-based images. Without retroactive re-run, it has
zero effect on findings that already exist. Without coverage visibility, analysts
cannot tell what the system has done on their behalf vs. what needs manual review.
All three are required for upstream VEX to deliver value. Missing any one makes the
feature appear broken even when it is technically functional.

---

### Decision 16: Clean Architecture Preserved — New Port Interfaces `[2a+2b+2c]`

All Phase 2 packages follow the same Clean Architecture import rule as Phase 1.
New domain ports are added to `internal/domain/ports.go`.

```text
New ports (domain layer — stdlib only):
  AIWorkerRuntime   — AI inference backend (Ollama adapter)
  ExploitSource     — ExploitDB data (remote CSV or local mirror adapter)
  AdvisorySource    — GHSA / MITRE advisory feeds
  ThreatSignalFetcher — EPSS + KEV feeds
  GraphStore        — asset graph read/write (SQL adapter)
  EmbeddingStore    — pgvector read/write (SQL adapter)

Import rule remains absolute:
  domain/     → stdlib only
  usecase/    → domain/ only
  adapter/    → domain/, usecase/
  infra/      → all inner layers
  cmd/        → infra/ only

`make clean-arch` must pass after every task group.
```

**Why:** The clean architecture boundary is what enables port swapping
(InProcessQueue → Redis, SQL graph → AGE, Ollama → OpenAI) with zero business
logic changes. Every new Phase 2 package that violates this will create technical
debt that compounds in Phase 3.

---

### Decision 17: AI Adapter Implementation Contracts `[2b]`

Five contracts apply to all code in `adapter/ai/` and any caller of
`AIWorkerRuntime`. These are correctness requirements, not style guidelines.
Violations produce goroutine leaks, misleading risk scores, or silent data loss.

#### Contract 1 — Bounded Concurrency

Ollama processes one request at a time. Unbounded goroutines hold stacks and HTTP
connections for the full request duration (up to 45 s each).

```text
Pool size: config.ai.worker_concurrency  (default: 3; CPU-only deployments: 1)
Pattern:   semaphore channel — acquire before model call, release in defer

  select {
  case pool.sem <- struct{}{}: defer func() { <-pool.sem }()
  case <-ctx.Done():           return ErrPoolFull
  }
```

#### Contract 2 — Per-Call Timeout

Every `Complete()` and `Embed()` call must run under a context deadline.

```text
Timeout:  config.ai.request_timeout_s  (default: 45 seconds)
Pattern:  ctx, cancel := context.WithTimeout(parent, timeout); defer cancel()
On DeadlineExceeded: return ErrModelTimeout
  → caller logs metric ai_timeout{worker=X}; returns degraded output; does NOT
    propagate as a Go error (model timeout is a data event, not a server error)
http.Client.Timeout must also be set as a hard backstop.
```

#### Contract 3 — Structured Output Validation

`"format":"json"` forces valid JSON from Ollama. It does not guarantee your schema.
Every worker output is treated as untrusted data — same discipline as user HTTP input.

```text
Pattern:
  1. json.Unmarshal([]byte(raw), &typedOutput)
     On error: log metric ai_schema_error{worker=X}; apply safe defaults; continue
  2. Validate required fields: non-empty strings, floats in [0.0, 1.0], valid enums
     On invalid value: apply safe default (confidence=0.0, level="Unknown", etc.)
  3. Never return an AI validation failure as a Go error to the job queue.
     A bad model output is a data quality event — not a server error.
     Propagating it would abort the entire worker chain for one bad output.
```

#### Contract 4 — Token Budget Cap

Context assembly must not exceed the model's effective context window.

```text
Hard cap:         6000 tokens  (proxy: 24 000 characters for prompt assembly)
Truncation order: KB hits first → service description → ExploitDB records
Never truncate:   CVE description, CVSS vector, EPSS score, KEV flag
Rationale:        Qwen2.5-7B has a 32k token window but quality degrades past
                  ~8k tokens; CyberPal-2.0's window may differ. The 6k cap is
                  conservative and leaves headroom for output tokens.
```

#### Contract 5 — Graceful Degradation Shape

AI enrichment must never surface as an ingestion failure or block the sync path.

```text
Ollama unreachable at startup:  ai_available=false; log WARNING; continue
Model call fails / times out:   log metric; ai_* columns stay NULL;
                                enrichment_status=skipped; job not retried
Structured output invalid:      safe defaults applied (Contract 3); chain continues
Worker pool full:               log metric ai_queue_full; job deferred to next cycle

The 202 Accepted response and Layer 1+2 risk_context values are never
affected by AI adapter failures. Ollama is an intelligence amplifier, not a
correctness dependency. Graceful degradation is the observable state, not panic.
```

**Why:** Without these contracts a single model timeout or schema mismatch can
cascade into a stalled worker chain, a misleading risk score, or a goroutine leak
that grows with every ingestion. The contracts establish a blast boundary: AI
failures stay inside `adapter/ai/` and emerge as observable metrics, never as
panics or ingestion errors.

---

### Decision 18: System Status, SBOM List, and SBOM Delete APIs `[2a]`

Three endpoints delivered together as SBOM management primitives. They share a
database migration that adds `deleted_at TIMESTAMPTZ DEFAULT NULL` to
`sbom_documents`.

#### GET /api/v1/status

System-wide overview. No product scope — intentionally a single global view.
Query param `?top=N` (default 10, max 50) controls the top-component list.

```text
Response 200:
{
  "components": {
    "total_registered": 1547,        ← COUNT(DISTINCT component_versions) from active SBOMs
    "with_vulnerabilities": 83,      ← those with ≥ 1 non-suppressed finding
    "clean": 1464                    ← total_registered − with_vulnerabilities
  },
  "vulnerabilities": {
    "total_findings": 312,           ← COUNT(component_vulnerabilities) active rows
    "unique_cves": 187,              ← COUNT(DISTINCT vulnerability_id)
    "by_severity": {
      "critical": 12, "high": 45, "medium": 98, "low": 157
    },
    "by_state": {
      "detected": 201, "not_affected": 87, "in_triage": 18, "false_positive": 6
    }
  },
  "top_components": [
    {
      "name": "openssl",
      "version": "1.1.1f-1ubuntu2",
      "purl": "pkg:deb/ubuntu/openssl@1.1.1f-1ubuntu2",
      "product_name": "Platform Core",
      "vulnerability_count": 18,
      "highest_severity": "CRITICAL",
      "highest_cvss_score": 9.8,
      "highest_cve_id": "CVE-2022-0778"
    }
  ],
  "as_of": "2026-06-10T14:32:00Z"   ← time of query, not a cache timestamp
}

SQL shape for top_components:
  SELECT cv.component_purl, c.name, cv.version, p.name,
         COUNT(cvu.id) AS vuln_count,
         MAX(v.cvss_score) AS highest_cvss
  FROM component_vulnerabilities cvu
  JOIN component_versions cv ON cv.id = cvu.component_version_id
  JOIN components c ON c.id = cv.component_id
  JOIN sbom_documents sd ON ... JOIN products p ON ...
  WHERE sd.deleted_at IS NULL
    AND cvu.effective_state != 'NOT_AFFECTED'
  GROUP BY cv.component_purl, c.name, cv.version, p.name
  ORDER BY vuln_count DESC, highest_cvss DESC
  LIMIT $top
```

#### GET /api/v1/sboms and GET /api/v1/products/{id}/sboms

System-wide and product-scoped SBOM listings respectively. Both paginated
(cursor-based, consistent with existing list endpoints).

```text
Response 200:
{
  "sboms": [
    {
      "id": "<uuid>",
      "product_name": "Platform Core",
      "product_version": "v2.1.0",
      "image_name": "platform-core",
      "image_digest": "sha256:abc123...",
      "format": "cyclonedx",
      "component_count": 247,
      "vulnerability_count": 18,
      "uploaded_at": "2026-06-09T10:15:00Z",
      "is_latest": true
    }
  ],
  "next_cursor": "<opaque token or null>",
  "total": 47
}
```

#### DELETE /api/v1/sboms/{id}

Soft delete: sets `sbom_documents.deleted_at = NOW()`. Data is never hard-deleted
via API — the column is a tombstone that excludes the SBOM from all active queries.

```text
Constraints:
  1. If is_latest=true: blocked unless ?force=true is present.
     Without force: returns 409 CANNOT_DELETE_LATEST_SBOM (see Decision 19).
  2. Deletion is irreversible via API (no undelete endpoint in Phase 2).
  3. Deletion event written to audit_log with API key, timestamp, sbom_id.

Response 200:
{
  "message": "SBOM for 'platform-core v2.1.0' has been removed. 247 components
              and 18 vulnerability findings are no longer included in reports.",
  "archived": {
    "sbom_id": "<uuid>",
    "product_name": "Platform Core",
    "image_digest": "sha256:abc123...",
    "component_count": 247,
    "finding_count": 18
  }
}

All active queries must already filter: WHERE sbom_documents.deleted_at IS NULL
This is enforced at the store layer, not caller-by-caller.
```

**Migration:** add `deleted_at TIMESTAMPTZ DEFAULT NULL` to `sbom_documents` as part
of the Phase 2a migration batch. Add a partial index:
`CREATE INDEX ... WHERE deleted_at IS NULL` to keep active-SBOM queries fast.

**Why:** Without a status endpoint, operators have no single view of what Themis
has ingested or what the current risk exposure is without crafting their own queries.
The SBOM list and delete complement each other: list gives the operator visibility
into what is stored; delete gives them control to remove incorrect or test SBOMs.
Soft delete is chosen over hard delete to preserve audit trails and stay consistent
with the "raw findings are never destroyed" principle — deleted data is archived,
not erased.

---

### Decision 19: Layman-Friendly API Error Responses `[2a+2b+2c]`

Every error response uses a three-field envelope. This applies to all existing
and future API endpoints, not just the new Phase 2a ones.

```text
{
  "error": {
    "code":    "<SCREAMING_SNAKE_CASE>",   ← machine-readable; stable across releases
    "message": "<plain English>",           ← what went wrong and why; no jargon
    "hint":    "<actionable next step>"     ← how to fix it
  }
}
```

**Error catalogue:**

| Code | HTTP | Message | Hint |
| --- | --- | --- | --- |
| `SBOM_NOT_FOUND` | 404 | "We couldn't find an SBOM with that ID. It may have already been deleted." | "Use GET /api/v1/sboms to see all available SBOMs." |
| `PRODUCT_NOT_FOUND` | 404 | "That product doesn't exist in Themis." | "Use GET /api/v1/products to see all registered products." |
| `IMAGE_NOT_FOUND` | 404 | "That image hasn't been registered yet." | "Register the image first with POST /api/v1/products/{id}/images, then upload the SBOM." |
| `CANNOT_DELETE_LATEST_SBOM` | 409 | "This is the most recent SBOM for {product}. Removing it would leave that product with no security data." | "Upload a newer SBOM to replace it, or add ?force=true to this request if you're sure." |
| `INVALID_SBOM_FORMAT` | 422 | "The SBOM couldn't be read. {reason}." | "Check the format is CycloneDX JSON or SPDX. The field '{field}' is missing or has an unexpected value." |
| `INVALID_REQUEST` | 400 | "The request couldn't be processed. {field} {reason}." | "Check the field value and try again." |
| `MISSING_API_KEY` | 401 | "No API key was provided." | "Add your API key in the X-API-Key request header." |
| `INVALID_API_KEY` | 401 | "That API key isn't recognised or may have been revoked." | "Check the key is correct. Use themis-cli list-keys to see active keys." |
| `INTERNAL_ERROR` | 500 | "Something went wrong on our end. The problem has been logged." | "If this keeps happening, check the Themis server logs for details." |

**Two hard rules:**

1. No raw database errors, Go error strings, constraint names, or stack traces in any
   response body — ever. Map every internal error to a catalogue code before responding.
2. Messages use plain language: "couldn't find" not "404 Not Found", "removed" not
   "soft-deleted", "incorrect format" not "JSON unmarshal error at offset 42".

**Why:** Operators who are not Go developers need to understand errors without reading
source code. "record not found" or "pq: foreign key constraint violation" in a
production error response forces the operator to read code or Slack the team. A
message that says "That image hasn't been registered yet — use POST .../images first"
is self-service. This reduces support load and makes the tool accessible to the full
security team, not just the person who deployed it.

---

## Open Questions Summary

The following items are marked ⚠️ throughout this document and require a decision
before the relevant sub-phase implementation begins.

| # | Question | Status | Sub-phase | Blocking | Section |
| --- | --- | --- | --- | --- | --- |
| OQ-1 | Composite risk score weights | ✅ Decided — formula confirmed with EPSS weighting | 2a | Yes — blocks epss-kev | Decision 2 |
| OQ-2 | AI enrichment trigger threshold | ✅ Decided — CVSS ≥ 7.0 OR KEV OR ExploitPublic | 2b | Yes — blocks ai-enrichment | Decision 4 |
| OQ-3 | CyberPal-2.0 Ollama registry availability | ✅ Decided — try CyberPal first, fall back to Qwen2.5-7B | 2b | Yes — blocks ai-enrichment | Decision 3 |
| OQ-4 | KB bypass threshold | ⚠️ Open — 0.92 proposed; validate with real data | 2b | No — use 0.92 as initial value | Decision 5 |
| OQ-5 | VEX auto-apply threshold | ⚠️ Open — 0.85 proposed; confirm acceptable FP rate | **2c** | Yes — blocks VEX auto-apply | Decision 8 |
| OQ-6 | FP auto-apply threshold | ⚠️ Open — 0.90 proposed (stricter than VEX) | **2c** | Yes — blocks FP auto-apply | Decision 9 |
| OQ-7 | Embedding model | ⚠️ Open — nomic-embed-text proposed; run quality test | 2b | No — can swap later with re-embed | Decision 11 |
| OQ-8 | GitHub SA API auth | ⚠️ Open — THEMIS_GITHUB_TOKEN env var proposed | 2a | Yes — blocks adapter/ghsa/ | Decision 12 |
| OQ-9 | Microservice registration workflow | ✅ Decided — explicit API (`POST /api/v1/products/{id}/microservices`) as Phase 2a starting point | 2a | No — resolved for 2a | Decision 14 |
| OQ-10 | Four-eyes for FP auto-apply under strict policy | ⚠️ Open — defer to trust policy config | **2c** | No — can use trust_policy flag | Decision 9 |
