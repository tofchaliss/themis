# Themis Phase 2 — AI Intelligence + Threat Intelligence

> **Architecture Reference Document.**
> This document captures the master design for the Phase 2 AI Intelligence layer.
> It is **not** an implementation task source.
>
> Implementation is split into three sub-phase changes:
>
> | Sub-phase | Change name | Theme | Depends on |
> | --- | --- | --- | --- |
> | 2a | `themis-phase-2a` | Signal Foundation — feeds, graph, VEX export | Group 16 complete |
> | 2b | `themis-phase-2b` | AI Intelligence — workers, RAG, pgvector | 2a complete |
> | 2c | `themis-phase-2c` | AI-Assisted VEX — auto-apply, FP, thresholds | 2b + KB seeded |
>
> Each sub-phase has its own `proposal.md` and `tasks.md` under
> `openspec/changes/<name>/`. Refer to `openspec/STATUS.md` for current
> implementation state.

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

## Capabilities by Sub-Phase

### Phase 2a — Signal Foundation (`themis-phase-2a`)

Delivers improved risk scoring and team notifications with **no AI dependency**.
All capabilities in this sub-phase are synchronous and deterministic.

#### epss-kev

Daily sync of CISA KEV (Known Exploited Vulnerabilities) list and FIRST.org EPSS
probability scores. Updated composite risk score formula:
`h(severity, vex_state, epss_score, kev_flag)`.
Stored as `intelligence_signals` with TTL. ExploitDB records also contribute to
Layer 1 rule evaluation.

#### upstream-vex-feeds

Scheduled fetch of vendor VEX feeds. Applied as `vex_documents` with `source=upstream_vendor`.
Precedence: human_triage > user_supplied > ai_generated > upstream_vendor.
Idempotent upsert per `(purl, cve_id)`.

**Phase 2a scope:** Red Hat, Alpine, Rocky Linux, Wolfi — apk and RPM ecosystems only.
Four-phase PURL normalisation matching (exact → namespace alias → errata version →
OSV range). See design.md Decision 15 for the full algorithm.

**Core principle:** vendor VEX is the authoritative source for backported patches.
Distro vendors backport security fixes into older upstream package versions; the
vendor's `not_affected` assertion must be trusted over any upstream version comparison.
Once a vendor VEX match is found, do not compare to upstream CVE version ranges.

**Debian/Ubuntu follow-on:** Debian (DSA format, dpkg version ordering) and Ubuntu
(USN format, per-series version ranges) share the same matcher interface and storage
model as Phase 2a feeds — they are excluded from 2a scope due to different format
parsers. Implement as a post-2a increment (see project-backlog.md).

#### intelligence-collector-layers-1-2

- **Layer 1 (sync)** — deterministic rules: CVSS ≥ 9 ∧ KEV → Critical; CVSS ≥ 9 ∧
  ExploitPublic → High+; EPSS ≥ 0.5 ∧ CVSS ≥ 7.0 → Elevated; etc.
  Always runs. Always explainable. No model dependency.
- **Layer 2 (sync)** — graph reasoning: traverses L1b Knowledge Graph
  (CVE → Package → Product → Microservice → Deployment → Customer) to compute
  blast radius and queue deterministic team notifications.

New domain entities: `Microservice`, `Deployment`, `Customer` (= internal team/owner
that owns a deployment and receives notifications), `ExploitRecord`.
Resolves OQ-9 (Microservice registration workflow).

#### vex-export

`GET /api/v1/products/{id}/versions/{v}/vex` — export the computed `risk_context` as
a standards-compliant VEX document. Format negotiated via `Accept` header or `?format=`
parameter (CycloneDX VEX or OpenVEX JSON). Human and upstream vendor VEX justification
text included. AI justification text added in Phase 2c.

#### system-status

`GET /api/v1/status?top=N` — single-call system overview for operators: total
components registered, total CVE matches, breakdown by severity and triage state,
and the top-N components with the most open vulnerabilities (name, product, CVE count,
highest CVSS score, highest CVE ID). Answers "what is in Themis and what's most
urgent?" without requiring custom queries.

#### sbom-management

`GET /api/v1/sboms` and `GET /api/v1/products/{id}/sboms` — paginated SBOM inventory
listing: product name, image digest, upload timestamp, component count, is_latest flag.

`DELETE /api/v1/sboms/{id}` — soft-delete a SBOM and archive its associated findings.
Protected: deleting the most recent SBOM for a product requires `?force=true`. Data
is never hard-deleted via API — a `deleted_at` tombstone excludes it from all active
queries while preserving the audit trail (see Decision 18).

#### error-ux

All API error responses adopt a three-field envelope: `code` (machine-readable),
`message` (plain English explanation), `hint` (actionable next step). No raw database
errors, Go error strings, or stack traces in any response. Applied to all existing and
new endpoints (see Decision 19).

---

### Phase 2b — AI Intelligence (`themis-phase-2b`)

Adds the AI reasoning layer on top of the signal foundation from 2a.
Requires 2a to be complete and healthy before 2b implementation starts.

#### ai-enrichment (Layer 3 + workers + KB)

- **Layer 3 (async)** — seven AI skill workers backed by CyberPal-2.0 / Qwen2.5-7B
  via Ollama: CWE Mapper, CVE Summarizer, Exploitability Analyzer, Context Analyzer,
  VEX Recommender, Remediation Advisor, False Positive Analyzer.
- **KB-first optimisation** — pgvector similarity ≥ 0.92 skips model call and applies
  past decision directly. Resolves OQ-4 (threshold) and OQ-7 (embedding model).
- **Risk Explanation** synthesises all worker outputs into a human-readable narrative
  (headline + 3–5 sentence explanation + urgency rationale).

Graceful degradation: Layers 1+2 (from 2a) produce a valid risk score with no AI
dependency. Layer 3 enriches asynchronously. Ollama outage does not degrade ingestion.

New intelligence source: GHSA (GitHub Security Advisories) for ecosystem-precise
fix versions (npm, Go, PyPI, Maven, RubyGems, Cargo, NuGet). New domain entity:
`CWERecord`. New L1c layer: `pgvector` embeddings for semantic KB retrieval.

Zero-day handling: CWE class-level statistics, CVSS vector analysis, RAG retrieval
of similar past decisions from L1c. No model retraining required.

---

### Phase 2c — AI-Assisted VEX (`themis-phase-2c`)

Automates the triage feedback loop. Requires 2b to be running and KB to have
sufficient seeded decisions before thresholds are meaningful.

#### ai-vex-automation

- **VEX auto-apply** — VEX Recommender confidence ≥ threshold auto-creates
  `vex_document` with `source=ai_generated`. Resolves OQ-5 (threshold, default 0.85).
- **FP auto-apply** — False Positive Analyzer confidence ≥ threshold auto-sets
  `effective_state=FALSE_POSITIVE`. Resolves OQ-6 (threshold, default 0.90).
  Subject to `trust_policy=strict` four-eyes rule (OQ-10).
- **Auto-suppressed notification** — new `FINDING_AUTO_SUPPRESSED` notification event
  when AI suppresses a finding. Fixes G4 (silent suppression).
- **VEX overlay re-trigger** — VEX Generator enqueues a `ReEnrichJob` after creating
  an AI VEX document so `effective_state` updates immediately. Fixes G1.
- Confidence thresholds configurable per-org via `config.ai.*_auto_apply_threshold`.

Human VEX assertion ALWAYS overrides AI VEX recommendation.
VEX precedence: human_triage > user_supplied > ai_generated > upstream_vendor.
AI-generated justification text now included in VEX export (from 2a vex-export).

## Impact

Sub-phase annotations: **(2a)** Signal Foundation · **(2b)** AI Intelligence ·
**(2c)** AI-Assisted VEX

**New packages:**

- `internal/adapter/epsskev/` — FIRST.org EPSS + CISA KEV fetcher; daily scheduler **(2a)**
- `internal/adapter/exploitdb/` — ExploitDB CSV ingester; CVE-to-EDB-ID lookup **(2a)**
- `internal/adapter/vexfeed/` — Vendor VEX feed fetcher; PURL matcher; precedence resolver **(2a)**
- `internal/adapter/assetgraph/` — Microservice/Deployment/Customer graph; blast-radius traversal **(2a)**
- `internal/usecase/vexgen/` — VEX document generation; precedence rules; draft lifecycle **(2a/2c)**
- `internal/adapter/ghsa/` — GitHub Security Advisories; GHSA-to-CVE; ecosystem fix versions **(2b)**
- `internal/adapter/ai/` — Ollama HTTP client; 7 worker implementations; prompt templates **(2b)**
- `internal/usecase/remediation/` — Remediation Advisor output; advisory display **(2b)**

**Modified packages:**

- `internal/domain/` — new types: `Microservice`, `Deployment`, `Customer`,
  `ExploitRecord` **(2a)**; `CWERecord`, `AIEnrichmentResult`, `VEXRecommendation`,
  ports `AIWorkerRuntime`, `ThreatSignalFetcher` **(2b)**; risk score formula
  constants **(2a+2b)**
- `internal/usecase/enrichment/` — Layer 1 rules **(2a)**; Layer 3 async wiring **(2b)**;
  VEX overlay re-trigger after AI VEX creation **(2c)**
- `internal/adapter/api/` — VEX export handler **(2a)**; AI enrichment status endpoints,
  blast-radius endpoint **(2b)**; auto-suppressed notification event **(2c)**
- `internal/infrastructure/config/` — EPSS/KEV/ExploitDB config **(2a)**;
  `ai.model_name`, `ai.ollama_endpoint`, `ai.embedding_model` **(2b)**;
  `ai.vex_auto_apply_threshold`, `ai.fp_auto_apply_threshold` **(2c)**
- `cmd/themis/main.go` — EPSS/KEV + vendor VEX schedulers **(2a)**; AI worker
  handler; pgvector store **(2b)**

**Database migrations:**

- 000014: `microservices`, `deployments`, `customers`, graph edge tables,
  `exploit_records` — **(2a)**
- 000015: `pgvector` extension; `embeddings` table — **(2b)**
  ⚠️ `pgvector` extension must be pre-installed on the PostgreSQL instance
- 000016: `ai_summaries` (+ `risk_explanation`), `ai_cwe_mappings`,
  `ai_exploitability`, `ai_vex_recommendations`, `ai_remediation_advice`,
  `ai_fp_analysis` — **(2b)**
- 000017: Indexes on `risk_context(epss_score, kev_listed, ai_exploitability)`;
  `ai_assessment_text` column on `risk_context` — **(2b)**

**New APIs:**

- `GET /api/v1/status` — system-wide component + CVE summary; top-N vulnerable components **(2a)**
- `GET /api/v1/sboms` — paginated list of all ingested SBOMs **(2a)**
- `GET /api/v1/products/{id}/sboms` — paginated list of SBOMs for one product **(2a)**
- `DELETE /api/v1/sboms/{id}` — soft-delete SBOM and archive findings **(2a)**
- `GET /api/v1/products/{id}/versions/{v}/vex` — VEX export **(2a)**
- `GET /api/v1/products/{id}/blast-radius` — blast-radius traversal **(2a)**
- `GET /api/v1/products/{id}/versions/{v}/findings/{cve_id}/enrichment` — AI detail **(2b)**

**External dependencies:**

- FIRST.org EPSS API — public, no auth **(2a)**
- CISA KEV JSON feed — public, no auth **(2a)**
- ExploitDB CSV (`files_exploits.csv`) from `offensive-security/exploitdb` — public **(2a)**
- Ollama HTTP API (local; no auth) — CyberPal-2.0 inference + embedding **(2b)**
- `pgvector` PostgreSQL extension — must be pre-installed **(2b)**

**Deferred to Phase 3:**

- Q6 (runtime protection analysis) — requires WAF/eBPF/network policy data
- Q7 (customer business impact) — requires deployment criticality matrix and SLA data
- Apache AGE migration (Cypher queries over the Phase 2 SQL graph)
- Full Remediation Engine (tracked remediation, ticket integration)
- Redis-backed job queue (InProcessQueue sufficient for Phase 2 load)
