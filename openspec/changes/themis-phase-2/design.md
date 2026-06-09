# Themis Phase 2 Design

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

**Goals:**

- Answer nine canonical security questions per finding (Q1–5, Q8–9 in Phase 2)
- Three-layer Intelligence Collector: deterministic rules + graph reasoning + AI workers
- Seven specialised AI workers with typed JSON I/O
- Internal KB via pgvector semantic memory (RAG over past decisions)
- AI-assisted VEX generation with configurable confidence threshold
- Nine intelligence feeds: NVD, KEV, GHSA, MITRE, Vendor, ExploitDB, EPSS, OSV, Internal KB
- Security Knowledge Graph: CVE ↕ CWE ↕ Package ↕ Product ↕ Microservice ↕ Deployment ↕ Customer
- False Positive Analyzer that learns from past analyst decisions
- VEX export endpoint (CycloneDX VEX or OpenVEX JSON)
- Blast-radius notifications extended to microservice/deployment scope

**Non-Goals:**

- Apache AGE / Cypher queries (Phase 3 — SQL graph tables only in Phase 2)
- Redis job queue (Phase 3 — InProcessQueue sufficient)
- CosignVerifier / real signature verification (Phase 3)
- CI/CD webhook ingestion (Phase 3)
- Runtime protection analysis — Q6 requires WAF/eBPF data (Phase 3)
- Business impact analysis — Q7 requires customer criticality matrix (Phase 3)
- Full tracked remediation with ticket integration (Phase 3 — advisory output only)
- Web UI / React SPA (Phase 3)
- RBAC / OIDC (Phase 3)
- Air-gapped ExploitDB mirror (Phase 3 — remote CSV in Phase 2)

---

## Quality Gates

Phase 2 follows the same two-stage gate as Phase 1 (task-wise gates then full build).

**Coverage thresholds (new packages):**

| Package | Threshold |
| --- | --- |
| `domain/` | 100% |
| `usecase/vexgen/` | 100% |
| `usecase/remediation/` | 100% |
| `adapter/ai/` | ≥ 90% |
| `adapter/ghsa/` | ≥ 90% |
| `adapter/exploitdb/` | ≥ 90% |
| `adapter/epsskev/` | ≥ 90% |
| `adapter/vexfeed/` | ≥ 90% |
| `adapter/assetgraph/` | ≥ 90% |

**Integration test requirement:** pgvector extension must be available in the test
PostgreSQL instance. Tests that require a live Ollama endpoint are tagged
`//go:build integration_ai` and skipped in standard CI. Standard integration tests
use a stub AI worker that returns deterministic fixtures.

---

## Decisions

### Decision 1: Three-Layer Intelligence Collector

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

### Decision 2: Five-Layer Data Model

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

### Decision 3: Local SLM via Ollama

AI inference runs locally via Ollama. No data leaves the deployment. The model
backend is configurable via the `domain.AIWorkerRuntime` port.

```text
Default model:   CyberPal-2.0     (IBM; security-fine-tuned; preferred)
Fallback model:  Qwen2.5-7B       (strong reasoning; good JSON output)
Embedding model: nomic-embed-text (for pgvector; 768-dim; fast)

Config:
  ai.model_name:     cyberpal-2.0
  ai.ollama_endpoint: http://localhost:11434
  ai.embedding_model: nomic-embed-text

The AIWorkerRuntime interface accepts any OpenAI-compatible API:
  type AIWorkerRuntime interface {
      Complete(ctx, model, prompt string) (string, error)
      Embed(ctx, model, text string) ([]float32, error)
  }
Swappable to OpenAI, Anthropic, or any Ollama model via config.
```

**Why:** Data sovereignty is a hard requirement for security tooling. CVE data,
service descriptions, and past analyst decisions must not transit third-party APIs.
CyberPal-2.0 is preferred because it is fine-tuned on security corpora (NVD, CVE,
security advisories) — better CWE classification and CVSS vector parsing at 7B than
a 70B general model. Qwen2.5-7B is the fallback when CyberPal is unavailable.

> ✅ **DECIDED:** Attempt `ollama pull cyberpal-2.0` at startup. If the model is not
> in the Ollama registry or pull fails, fall back to `qwen2.5:7b` automatically.
> The adapter logs which model is active at startup. `ai.model_name` config overrides
> the auto-selection. Both models are tested against a benchmark set before release.

---

### Decision 4: RAG Architecture — Small Model + Rich Context

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

### Decision 5: KB-First Optimisation

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

### Decision 6: Seven Specialised AI Workers (Skills Pattern)

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

### Decision 7: AI Enrichment is Strictly Async

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

### Decision 8: AI-Assisted VEX with Configurable Threshold

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

### Decision 9: False Positive Analyzer as Dedicated Worker

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

### Decision 10: SQL Graph Tables for Phase 2, Apache AGE for Phase 3

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

### Decision 11: pgvector for Semantic Memory (L1c)

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

### Decision 12: Intelligence Source Priority

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

### Decision 13: ExploitDB via CSV Download

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

### Decision 14: Microservice and Deployment as First-Class Domain Entities

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

### Decision 15: VEX Export as Standards-Compliant Document

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

---

### Decision 16: Clean Architecture Preserved — New Port Interfaces

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

## Open Questions Summary

The following items are marked ⚠️ throughout this document and require a decision
before the relevant implementation task group begins.

| # | Question | Status | Blocking | Section |
| --- | --- | --- | --- | --- |
| OQ-1 | Composite risk score weights | ✅ Decided — formula confirmed with EPSS weighting | Yes — blocks epss-kev | Decision 2 |
| OQ-2 | AI enrichment trigger threshold | ✅ Decided — CVSS ≥ 7.0 OR KEV OR ExploitPublic | Yes — blocks ai-enrichment | Decision 4 |
| OQ-3 | CyberPal-2.0 Ollama registry availability | ✅ Decided — try CyberPal first, fall back to Qwen2.5-7B | Yes — blocks ai-enrichment | Decision 3 |
| OQ-4 | KB bypass threshold | ⚠️ Open — 0.92 proposed; validate with real data | No — use 0.92 as initial value | Decision 5 |
| OQ-5 | VEX auto-apply threshold | ⚠️ Open — 0.85 proposed; confirm acceptable FP rate | Yes — blocks vex auto-apply logic | Decision 8 |
| OQ-6 | FP auto-apply threshold | ⚠️ Open — 0.90 proposed (stricter than VEX) | Yes — blocks FP auto-apply logic | Decision 9 |
| OQ-7 | Embedding model | ⚠️ Open — nomic-embed-text proposed; run quality test | No — can swap later with re-embed | Decision 11 |
| OQ-8 | GitHub SA API auth | ⚠️ Open — THEMIS_GITHUB_TOKEN env var proposed | Yes — blocks adapter/ghsa/ | Decision 12 |
| OQ-9 | Microservice registration workflow | ⚠️ Open — explicit API proposed as starting point | No — can start with explicit API | Decision 14 |
| OQ-10 | Four-eyes for FP auto-apply under strict policy | ⚠️ Open — can defer to trust policy config | No | Decision 9 |
