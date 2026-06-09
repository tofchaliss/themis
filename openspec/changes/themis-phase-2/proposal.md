# Themis Phase 2 — AI Intelligence + Threat Intelligence

## Prerequisites — Phase 1 Group 16 hardening

**Phase 2 implementation must not start until all 9 Group 16 tasks are complete and
`v0.1.0` is tagged.** These are post-bring-up hardening items that close gaps in the
Phase 1 ingestion pipeline. They are tracked in `project-backlog.md` (§ "Phase 1 —
Remaining hardening") and detailed in
`openspec/changes/archive/2026-06-09-themis-phase-1/tasks.md` §16.

| # | Task | Packages touched |
| --- | --- | --- |
| 16.1 | Normalise Alpine package names for OSV queries (`so:` prefix, `py3-foo` → `python3-foo`) | `adapter/osv/` |
| 16.2 | Integration test: Alpine SBOM ingest → non-zero `component_vulnerabilities` | `adapter/osv/` |
| 16.3 | Integration test: rpm SBOM → ingest succeeds, OSV skip logged cleanly | `adapter/osv/` |
| 16.4 | `POST /api/v1/products/{id}/images` — image registration REST endpoint | `adapter/api/`, `adapter/store/` |
| 16.5 | Upload helper script (`make upload-sbom` or curl wrapper) | `scripts/` |
| 16.6 | `make check` passes clean after all Group 16 items | — |
| 16.7 | `adapter/store/` coverage ≥ 90% | `adapter/store/` |
| 16.8 | `adapter/osv/` coverage ≥ 90% | `adapter/osv/` |
| 16.9 | Merge to `main`, git tag `v0.1.0`, Phase 1 release notes | — |

Each task group follows the standard 6-gate checklist (unit tests → coverage → dead code →
integration tests → clean-arch → `make verify-build`).

---

## Why

Phase 1 delivers a complete, tested ingestion and correlation pipeline. Risk scores are
deterministic (`f(severity, vex_state)`) and signal quality is low: every DETECTED finding
with a CVSS score looks the same regardless of whether it has a public Metasploit module,
a 0.92 EPSS score, and three affected customers in production — or was patched last week.

The critical gap is not more data. It is answering the right questions *per finding*:

| # | Question | Phase 2 | Phase 3 |
| --- | --- | --- | --- |
| 1 | Why is it vulnerable? (CWE, attack class) | AI | — |
| 2 | Can it be exploited? (complexity, probability) | AI | — |
| 3 | Is a public exploit available? (ExploitDB) | Data lookup | — |
| 4 | Is it CISA KEV-listed? | Data lookup | — |
| 5 | Is the vulnerable code path reachable in this service? | AI + RAG | — |
| 6 | Can runtime protection mitigate it? (WAF, eBPF) | — | AI + runtime |
| 7 | Can the customer continue operating if exploited? | — | AI + blast radius |
| 8 | What VEX status should be assigned? | AI-assisted | — |
| 9 | What remediation is safest? (upgrade, patch, workaround) | AI (advisory) | AI (tracked) |

Phase 2 answers questions 1–5, 8, and 9 for every high/critical finding, using a small
cybersecurity-specialised model grounded entirely in authoritative data — not parametric
recall from a large general model. This is the RAG principle: small model + rich, curated
context = better answers than large model + no context.

## Architecture

### Intelligence Collector — Three Processing Layers

Every finding passes through three layers in strict order. Layers 1 and 2 are
**synchronous** and complete before the API returns. Layer 3 is **async** and enriches
asynchronously. The system is fully functional with Layers 1 and 2 alone; Layer 3
improves quality but never blocks.

```text
┌──────────────────────────────────────────────────────────────────────────────┐
│  LAYER 1 — DETERMINISTIC RULES            sync · zero latency · always on   │
│  ──────────────────────────────────────────────────────────────────────────  │
│  Pure logic. No model. Fully explainable. Auditable.                         │
│                                                                              │
│  Rule examples:                                                              │
│    CVSS ≥ 9.0  ∧  KEV = true          →  Critical                           │
│    CVSS ≥ 9.0  ∧  ExploitPublic       →  High+ (pending KEV confirmation)   │
│    KEV = true  ∧  CVSS < 9.0          →  High                               │
│    EPSS ≥ 0.5  ∧  CVSS ≥ 7.0         →  Elevated                           │
│    CVSS ≥ 9.0  (no other signals)     →  High (deterministic floor)         │
│                                                                              │
│  Output: deterministic_risk_level, deterministic_flags                       │
│  Written to: risk_context.deterministic_level immediately                    │
├──────────────────────────────────────────────────────────────────────────────┤
│  LAYER 2 — GRAPH REASONING                sync · fast · always on           │
│  ──────────────────────────────────────────────────────────────────────────  │
│  SQL traversal of L1b Security Knowledge Graph. No model.                    │
│                                                                              │
│  Traversal:  CVE → Package → Product → Microservice → Deployment → Customer │
│                                                                              │
│  Output:                                                                     │
│    blast_radius_score  (1 customer = 1.0×; 10+ customers = 2.0×)            │
│    affected_teams[]    (Customer nodes reachable from this CVE)              │
│    notification_queue  (which teams to alert, deterministically)             │
│                                                                              │
│  "10 teams affected" amplifies the Layer 1 risk level. Graph reasoning       │
│  requires no AI — it is pure traversal of the knowledge graph.               │
│  Written to: risk_context.blast_radius_score, notification events queued     │
├──────────────────────────────────────────────────────────────────────────────┤
│  LAYER 3 — AI REASONING                   async · enriches · graceful       │
│  ──────────────────────────────────────────────────────────────────────────  │
│  CyberPal-2.0 / Qwen2.5-7B via Ollama. RAG from Internal KB (Critical).     │
│                                                                              │
│  KB-first optimisation: if pgvector retrieves a past decision with           │
│  similarity ≥ 0.92, apply it directly — skip the model call entirely.        │
│  Internal KB is ranked Critical above all other sources.                     │
│                                                                              │
│  Workers (async, JobQueue):                                                  │
│    Summarization        — why is it vulnerable?                              │
│    Exploitability       — can it be exploited?                               │
│    Context analysis     — is the code path reachable?                        │
│    VEX suggestion       — what VEX status to assign?                         │
│    Remediation advice   — what is the safest fix?                            │
│    Risk explanation     — narrative for notification/triage UI               │
│    False positive check — does this match a known FP pattern in our KB?     │
│                                                                              │
│  Output enriches risk_context asynchronously. Score is updated in place.    │
│  Graceful degradation: if Ollama is unavailable, Layers 1+2 remain valid.   │
└──────────────────────────────────────────────────────────────────────────────┘
```

### Intelligence Sources

| Feed | Importance | Phase | Adapter |
| --- | --- | --- | --- |
| National Vulnerability Database (NVD) | Mandatory | Phase 1 | `adapter/nvd/` |
| CISA KEV (Known Exploited Vulnerabilities) | Mandatory | Phase 2 | `adapter/epsskev/` |
| GitHub Security Advisories (GHSA) | Mandatory | Phase 2 | `adapter/ghsa/` |
| MITRE CVE Feed | Mandatory | Phase 2 | `adapter/nvd/` (extended) |
| Vendor Advisories (Red Hat, Alpine, Ubuntu…) | Mandatory | Phase 2 | `adapter/vexfeed/` |
| ExploitDB | Recommended | Phase 2 | `adapter/exploitdb/` |
| FIRST.org EPSS | Recommended | Phase 2 | `adapter/epsskev/` |
| OSV Database | Recommended | Phase 1 | `adapter/osv/` |
| Internal KB (past decisions, FP patterns) | **Critical** | Phase 2 | pgvector + `infrastructure/db/` |

**Internal KB is Critical** — ranked above all external feeds. A high-similarity KB
hit (≥ 0.92) bypasses the model entirely. Past analyst decisions are the most
authoritative source for YOUR environment.

**GitHub Security Advisories** fills the ecosystem gap NVD has: NVD is authoritative
on CVSS scores but weak on package version ranges for npm/Go/PyPI/Maven/RubyGems.
GHSA maps GHSA IDs to CVE IDs with precise affected version ranges per package ecosystem.

**MITRE CVE Feed** is the authoritative source for new CVE IDs before NVD enriches
them. NVD can lag 24–48 hours behind MITRE for zero-days. The `adapter/nvd/` extension
polls MITRE's CVE list to surface findings before NVD CVSS data is available.

### Revised Five-Layer Data Model

```text
L0  RAW IMMUTABLE INVENTORY
    sbom_documents, components, component_versions, component_vulnerabilities,
    vulnerabilities (NVD/OSV/ExploitDB), vex_documents, vex_assertions,
    products, images, advisory_records
    Rule: append-only; content-addressed; never mutated.

L1a ASSET & DEPENDENCY GRAPH
    Component → Microservice → Deployment → Customer (Team/Owner)
    Customer = the internal organisational unit (team, product group, owner)
    that owns a deployment and receives security notifications for it.
    Phase 2: SQL graph tables. Phase 3: Apache AGE (Cypher).

L1b SECURITY KNOWLEDGE GRAPH
    Blast-radius traversal: CVE ↕ CWE ↕ Package ↕ Product ↕ Microservice
                           ↕ Deployment ↕ Customer (Team/Owner)
    Terminal node answers: "which internal team must be notified?"
    Extends Phase 1 product-scoped notification to microservice/deployment scope.
    Populated by the Vulnerability Intelligence Collector (L0 → L1b edges).

L1c SEMANTIC MEMORY
    pgvector embeddings. Embeds: CVE descriptions, VEX justifications,
    AI summaries, triage decisions. Powers RAG retrieval for AI workers.

L2  AI ENRICHMENT
    Immutable per (worker, input_hash).
    Tables: ai_summaries (+ risk_explanation column), ai_cwe_mappings,
            ai_exploitability, ai_vex_recommendations, ai_remediation_advice,
            ai_fp_analysis.

L3  HUMAN VALIDATION
    triage_history (Phase 1), approvals, vex_overrides, audit_log.
    Rule: append-only; every human decision is a permanent record.

    CONVERGENCE → risk_context
    Phase 2 score: h(severity, vex_state, epss_score, kev_flag,
                     ai_exploitability, ai_reachability_confidence)
```

### AI Architecture: RAG over Small Model

The AI pipeline uses a 7B cybersecurity-specialised model (CyberPal-2.0 via Ollama) with
all domain knowledge injected at query time from authoritative local sources. The model
reasons; it does not recall.

```text
QUERY TIME (per finding)

Finding { cve_id, component_purl, service_name, version }
                │
    ┌───────────┴────────────┐
    ▼                        ▼
CONTEXT ASSEMBLY         VECTOR RETRIEVAL (L1c)
  from L0/L1/external      pgvector ANN search
                           "similar past findings
  CVE description           for this CWE class
  CWE classification        or component"
  CVSS vector
  EPSS score                Returns: past decisions,
  KEV status                AI assessments,
  ExploitDB records         false positive patterns
  Vendor advisories
  Service description
                │
                └──────────┬──────────┘
                           ▼
                   PROMPT CONSTRUCTION
                   ════════════════════
                   System: authoritative context + retrieved KB
                   User:   "Answer exactly: { question N }"
                           output must be structured JSON
                           │
                           ▼
                     CyberPal-2.0 (7B)
                     Local via Ollama
                     NOT in critical path — async
                           │
                           ▼
                    Structured JSON validated
                    → L2 enrichment table
```

### AI Skill Workers — Typed JSON Contracts

Seven specialised workers, each with a single question, a defined input schema, and a
validated output schema. Workers run async via the existing `JobQueue` interface.

**Execution order within a JobQueue task:**

```text
┌────────────────────────────────────────────────────────────────────────────┐
│  KB CHECK (before any model call)                                          │
│  pgvector similarity ≥ 0.92 on (cve_id, component_purl, service_name)?    │
│    YES → apply past decision directly, skip Steps 0–6                     │
│    NO  → proceed to workers                                                │
└─────────────────────────┬──────────────────────────────────────────────────┘
                          │
          ┌───────────────┼───────────────┐
          ▼               ▼               │
       Step 0          Step 1             │
      CWE Mapper    CVE Summarizer        │  (parallel)
          │               │               │
          └───────┬────────┘               │
                  ▼                        │
              Step 2                       │
         Exploitability Analyzer           │
                  │                        │
                  ▼                        │
              Step 3                       │
           Context Analyzer               │
                  │                        │
          ┌───────┴────────┐              │
          ▼                ▼              ▼
       Step 4           Step 5         Step 6
   VEX Recommender  Remediation    False Positive
                    Advisor        Analyzer
          │                ▼
          └───────► Risk Explanation
                    (narrative synthesis
                     from all outputs)
```

#### Step 0 — CWE Mapper (prerequisite; runs in parallel with CVE Summarizer)

```text
Input:  { cve_id, description, cvss_vector }
Output: { cwe_id, cwe_name, category, owasp_class }
Answers: prerequisite for workers 3 and 4
```

#### Step 1 — CVE Summarizer (Q1: why is it vulnerable?)

```text
Input:  { cve_id, description, cvss_vector, cvss_score, cwe_id }
Output: { summary: string, attack_type: string, impact_summary: string }
```

#### Step 2 — Exploitability Analyzer (Q2: can it be exploited?)

```text
Input:  { cve_id, cwe_id, epss_score, kev_listed,
          exploit_db_records[], cvss_vector, cvss_score }
Output: { exploitability: Critical|High|Medium|Low|Unknown,
          confidence: float,
          exploit_public: bool,  ← answers Q3
          kev_listed: bool,      ← answers Q4
          reasoning: string,
          signal_weights: { epss, kev, exploit_db, cwe_class } }
Rule:   confidence < 0.5 → advisory only; not used in risk_context scoring
```

#### Step 3 — Context Analyzer (Q5: is the vulnerable path reachable?)

```text
Input:  { cve_id, cwe_id, component_purl, version, service_name,
          service_description, cvss_attack_vector,
          kb_similar_decisions[] }  ← from pgvector RAG
Output: { reachable: bool, confidence: float,
          reasoning: string,
          recommended_vex_state: not_affected|affected|under_investigation }
```

#### Step 4 — VEX Recommender (Q8: what VEX status should be assigned?)

```text
Input:  { cve_id, component_purl, service_name,
          cve_summary, exploitability, reachability,
          existing_vex_state, kb_similar_decisions[] }
Output: { recommended_state: VEXState,
          justification: string,
          confidence: float,
          auto_apply: bool }  ← true only if confidence ≥ configured threshold
Answers: Q8 explicitly; feeds VEX Generator
```

#### Step 5 — Remediation Advisor (Q9: what remediation is safest?)

```text
Input:  { cve_id, component_purl, current_version,
          cvss_score, exploitability, kev_listed,
          known_fixed_versions[] }
Output: { action: upgrade|patch|workaround|accept,
          target_version: string,
          breaking_change_risk: High|Medium|Low|Unknown,
          urgency: Critical|High|Medium|Low,
          rationale: string }
Phase 2: advisory output only (stored in ai_remediation_advice)
Phase 3: tracked remediation with ticket integration
```

#### Step 6 — False Positive Analyzer (is this a known false positive?)

```text
Input:  { cve_id, component_purl, service_name, cvss_vector,
          kb_similar_fps[] }  ← pgvector: past FALSE_POSITIVE decisions
Output: { likely_fp: bool,
          confidence: float,
          pattern: string,   ← "matches FP pattern: CVE-YYYY-XXXXX on same
                                component, same service; reason: test-only
                                dependency never shipped to production"
          reasoning: string }
Rule:   likely_fp=true ∧ confidence ≥ 0.85 → auto-sets effective_state=FALSE_POSITIVE
        (subject to trust_policy; strict requires human confirmation)

Why:    Security teams spend 60–80% of analyst time on false positives.
        Recurring FP patterns identified from KB eliminate repeat manual review.
        This worker is the highest-value worker for analyst time savings.
```

#### Risk Explanation (narrative synthesis — runs after Steps 0–6)

```text
Input:  all worker outputs + Layer 1 deterministic_level
        + Layer 2 blast_radius_score + affected_teams[]
Output: { headline: string,      ← one sentence for notification subject
          explanation: string,   ← 3–5 sentence narrative for triage UI
          urgency_rationale: string }

Example output:
  headline:     "CVE-2027-12345 (CVSS 10.0) — Platform Team, 2 prod deployments"
  explanation:  "Heap overflow in Linux kernel 5.14 allows local privilege
                 escalation. Your amf-core service runs this kernel in prod-eu
                 and prod-us. ExploitDB has no public PoC yet but this class of
                 vulnerability (CWE-787, kernel) is typically weaponised within
                 30 days. gVisor sandbox may mitigate — Context Analyzer
                 confidence 0.87: not_affected. Recommend confirming sandbox
                 config and monitoring for exploit publication."
  urgency:      "Patch within 7 days if gVisor confirmed; immediately if not."

Stored in: ai_summaries.risk_explanation column
Used by:   notification body, triage UI, VEX justification text
```

### AI-Assisted VEX Generation

VEX documents in Phase 2 are no longer purely human-authored. The VEX Generator
reads VEX Recommender output and applies precedence rules:

```text
Confidence ≥ threshold + recommended_state = not_affected
→ draft vex_document created automatically (source=ai_generated)
→ status=draft until human review (if trust_policy=strict)
→ auto-applied (if trust_policy=standard or permissive)

Confidence < threshold OR recommended_state = affected
→ queued for analyst review in triage workflow
→ AI output visible as enrichment context

Human VEX assertion ALWAYS overrides AI VEX recommendation.
VEX precedence: human_triage > user_supplied > ai_generated > upstream_vendor
```

The auto-apply threshold is configurable (`config.ai.vex_auto_apply_threshold`, default: `0.85`).

## Capabilities

### ai-enrichment

Three-layer Intelligence Collector:

- **Layer 1 (sync)** — deterministic rules: CVSS ≥ 9 ∧ KEV → Critical; CVSS ≥ 9 ∧
  ExploitPublic → High+; etc. Always runs. Always explainable. No model dependency.
- **Layer 2 (sync)** — graph reasoning: traverses L1b Knowledge Graph
  (CVE → Package → Product → Microservice → Deployment → Customer) to compute
  blast radius and queue deterministic team notifications.
- **Layer 3 (async)** — seven AI skill workers backed by CyberPal-2.0 / Qwen2.5-7B
  via Ollama: CWE Mapper, CVE Summarizer, Exploitability Analyzer, Context Analyzer,
  VEX Recommender, Remediation Advisor, False Positive Analyzer. KB-first optimisation:
  pgvector similarity ≥ 0.92 skips model call and applies past decision directly.
  Risk Explanation synthesises all outputs into a human-readable narrative.

Graceful degradation: Layers 1+2 produce a valid risk score with no AI dependency.
Layer 3 enriches asynchronously. Ollama outage does not degrade ingestion.

New domain entities: Microservice, Deployment, Customer (= internal team/owner that
owns a deployment and receives notifications), CWERecord, ExploitRecord.
New intelligence source: ExploitDB (EDB-ID, exploit type, date, CVE reference).

Zero-day handling: for brand-new CVEs with no model training data, the AI workers
reason from three grounding types — (1) CWE class-level statistics ("CWE-787 in
kernel space historically exploited in 85% of cases"), (2) CVSS vector analysis
("AV:L + AC:L + S:C = local privilege escalation with scope change"), and (3) RAG
retrieval of similar past decisions from L1c. No model retraining is needed for
new CVEs; the architecture is designed around this constraint.

### epss-kev

Daily sync of CISA KEV (Known Exploited Vulnerabilities) list and FIRST.org EPSS
probability scores. Updated composite risk score formula:
`h(severity, vex_state, epss_score, kev_flag, ai_exploitability, ai_reachability_confidence)`.
Stored as `intelligence_signals` with TTL. ExploitDB records also contribute to
the Exploitability Analyzer worker input.

### upstream-vex-feeds

Scheduled fetch of vendor VEX feeds (Red Hat, Alpine, Ubuntu, Debian, SUSE, Wolfi,
Rocky Linux). Applied as `vex_documents` with `source=upstream_vendor`. PURL-based
matching. Precedence: human_triage > user_supplied > ai_generated > upstream_vendor.
Idempotent upsert per `(purl, cve_id)`.

### vex-export

`GET /api/v1/products/{id}/versions/{v}/vex` — export the computed `risk_context` as
a standards-compliant VEX document. Format negotiated via `Accept` header or `?format=`
parameter (CycloneDX VEX or OpenVEX JSON). Includes AI-generated justification text
where available. Includes confidence scores in non-normative extensions.

## Impact

**New packages:**

- `internal/adapter/ai/` — Ollama HTTP client; CyberPal-2.0 adapter; 7 worker
  implementations; prompt templates; JSON response validators; implements
  `domain.AIWorkerRuntime` port
- `internal/adapter/ghsa/` — GitHub Security Advisories API client; GHSA-to-CVE
  mapping; package ecosystem version ranges (npm, Go, PyPI, Maven, RubyGems, Cargo,
  NuGet); implements `domain.AdvisorySource` port
- `internal/adapter/exploitdb/` — ExploitDB CSV ingester (`files_exploits.csv` from
  the public GitHub mirror); CVE-to-EDB-ID lookup; exploit type mapping; implements
  `domain.ExploitSource` port (swappable to local mirror in Phase 3)
- `internal/adapter/epsskev/` — FIRST.org EPSS API client; CISA KEV JSON fetcher;
  daily scheduler; implements `domain.ThreatSignalFetcher` port
- `internal/adapter/vexfeed/` — Vendor VEX feed fetcher; PURL matcher; precedence resolver
- `internal/adapter/assetgraph/` — Asset/dependency graph builder; SQL graph tables;
  blast-radius traversal; Knowledge Graph edge population
- `internal/usecase/vexgen/` — AI-assisted VEX document generation; confidence
  threshold enforcement; precedence rules; draft VEX lifecycle
- `internal/usecase/remediation/` — Remediation Advisor output storage; advisory
  display (Phase 2); tracked remediation (Phase 3)

**Modified packages:**

- `internal/domain/` — new ports: `AIWorkerRuntime`, `ThreatSignalFetcher`; new
  types: `Microservice`, `Deployment`, `Customer`, `CWERecord`, `ExploitRecord`,
  `AIEnrichmentResult`, `VEXRecommendation`; updated risk score formula constants
- `internal/usecase/enrichment/` — updated risk score to incorporate `epss_score`,
  `kev_flag`, `ai_exploitability` from L2/L3 signals
- `internal/adapter/api/` — VEX export handler; AI enrichment status endpoints
- `internal/infrastructure/config/` — new fields: `ai.model_name`, `ai.ollama_endpoint`,
  `ai.vex_auto_apply_threshold`, `ai.embedding_model`; `exploitdb.source`
  (`remote` default / `local_mirror` Phase 3), `exploitdb.mirror_path`
- `cmd/themis/main.go` — registers new schedulers (EPSS/KEV, vendor VEX, AI
  enrichment); wires AI worker handler; registers pgvector store

**Database migrations (planned):**

- 000014: `microservices`, `deployments`, `customers` tables; graph edge tables; ExploitDB records
- 000015: `pgvector` extension; `embeddings` table (`entity_type`, `entity_id`, `vector`, `model`, `created_at`)
- 000016: `ai_summaries` (+ `risk_explanation` column), `ai_cwe_mappings`,
  `ai_exploitability`, `ai_vex_recommendations`, `ai_remediation_advice`,
  `ai_fp_analysis` tables
- 000017: Indexes on `risk_context(epss_score, kev_listed, ai_exploitability)`;
  `ai_assessment_text` column on `risk_context`

**New APIs:**

- `GET /api/v1/products/{id}/versions/{v}/vex` — VEX export (CycloneDX or OpenVEX)
- `GET /api/v1/products/{id}/versions/{v}/findings/{cve_id}/enrichment` — AI enrichment detail for one finding
- `GET /api/v1/products/{id}/blast-radius` — Knowledge Graph blast-radius traversal result

**External dependencies:**

- Ollama HTTP API (local; no auth) — CyberPal-2.0 inference and embedding
- FIRST.org EPSS API — public, no auth required
- CISA KEV JSON feed — public, no auth required
- ExploitDB CSV (`files_exploits.csv`) — downloaded from `offensive-security/exploitdb`
  GitHub repo; public, no auth; Phase 3 switches to local git mirror via
  `exploitdb.source=local_mirror`
- `pgvector` PostgreSQL extension — must be installed on the PostgreSQL instance

**Deferred to Phase 3:**

- Q6 (runtime protection analysis) — requires WAF/eBPF/network policy data
- Q7 (customer business impact) — requires deployment criticality matrix and SLA data
- Apache AGE migration (Cypher queries over the Phase 2 SQL graph)
- Full Remediation Engine (tracked remediation, ticket integration, notifications)
- Redis-backed job queue (InProcessQueue sufficient for Phase 2 load)
