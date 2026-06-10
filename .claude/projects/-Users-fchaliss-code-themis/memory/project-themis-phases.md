---
name: project-themis-phases
description: Themis project phase breakdown — what is in scope per phase, key decisions made
metadata:
  type: project
---

# Themis Phase Breakdown

Themis is an open-source Go backend security intelligence platform (vulnerability assessment
and management). Single binary + PostgreSQL. Full context in `PROJECT_CONTEXT.md`.

## Phase 1 — Core Intelligence Platform (COMPLETE — archived 2026-06-09)

Archive: `openspec/changes/archive/2026-06-09-themis-phase-1/`

- Go REST API only, no UI
- PostgreSQL only (no SQLite)
- In-process job queue behind an interface (goroutine pool) — swappable to Redis in Phase 3
- 8 capabilities: artifact-trust, sbom-parser, sbom-ingestion, sbom-store,
  intelligence-enrichment, cve-triage, cve-watch, notification-service
- intelligence-enrichment = VEX overlay on CycloneDX components only (no EPSS, KEV, AI)
- Phase 1 risk_score = raw severity + VEX effective state only
- API key auth, no RBAC
- StubVerifier for cosign (real verification deferred to Phase 3)
- No AI, no EPSS, no KEV in Phase 1

**Group 16 hardening (9 tasks OPEN — gate for v0.1.0 and Phase 2 start):**
16.1 Alpine PURL normalisation, 16.2 Alpine integration test, 16.3 rpm integration test,
16.4 image registration endpoint, 16.5 upload helper, 16.6 `make check` clean,
16.7 store coverage ≥ 90%, 16.8 osv coverage ≥ 90%, 16.9 tag v0.1.0.

## Phase 2 — AI Intelligence Layer (NOT STARTED)

Active change: `openspec/changes/themis-phase-2/`

**The defining theme is AI enrichment and signal aggregation.**

**Architecture:**

- Five-Layer Data Model: L0 Raw → L1a Asset Graph → L1b Security Knowledge Graph →
  L1c Semantic Memory (pgvector) → L2 AI Enrichment → L3 Human Validation
- Three-Layer Intelligence Collector:
  - Layer 1: Deterministic rules, synchronous, no AI (`CVSS ≥ 9 ∧ KEV → Critical`)
  - Layer 2: Graph reasoning, synchronous, no AI (`CVE → Package → Product → Customer`)
  - Layer 3: 7 AI workers, async via JobQueue (CyberPal-2.0/Qwen2.5-7B via Ollama)
- RAG: small model + 9 context sources (NVD, CISA KEV, GHSA, MITRE, ExploitDB, EPSS,
  OSV, vendor advisories, Internal KB)
- KB-first optimisation: pgvector similarity ≥ 0.92 → apply past decision, skip model
- AI-assisted VEX: confidence ≥ 0.85 → auto-create `vex_document` (source=ai_generated)
- VEX precedence: human_triage > user_supplied > ai_generated > upstream_vendor

**4 capabilities:**

- `ai-enrichment` — 3-layer Intelligence Collector, 7 workers, RAG, KB-first, async jobs
- `epss-kev` — FIRST.org EPSS + CISA KEV → intelligence_signals
- `upstream-vex-feeds` — scheduled vendor VEX fetch (Red Hat, Alpine, Ubuntu, etc.)
- `vex-export` — AI + human triage decisions → standards-compliant CycloneDX VEX documents

**Open questions blocking implementation:**

- OQ-5: VEX auto-apply threshold (0.85 proposed) — BLOCKING
- OQ-6: FP auto-apply threshold (0.90 proposed) — BLOCKING
- OQ-8: GitHub SA API auth (`THEMIS_GITHUB_TOKEN` env var) — BLOCKING
- OQ-9: Microservice registration workflow — explicit API vs SBOM auto-discover

**10 cold-start gaps identified (see `scenario-fresh-deployment.md`):**
G1 VEX overlay re-trigger after AI VEX generation (correctness),
G2 EPSS/KEV retroactive risk_context update (correctness),
G3 image endpoint 16.4 missing (operability),
G4 no auto-suppressed notification event (UX),
G5 Context Analyzer has no service description on day 1 (intelligence),
G6 NVD cold-start latency (performance),
G7 Layer 3 batch size unbounded (performance),
G8 pgvector extension not in setup docs (operability),
G9 no enrichment_status in API response (UX),
G10 malformed PURLs silently degrade matching (data quality).

## Phase 3 — Production Platform + UI (NOT STARTED)

- Docker Compose full production stack (worker containers, Redis queue, Nginx TLS)
- UI / Dashboard (needs design discussion)
- Bitbucket git integration
- Full RBAC + OIDC/OAuth2
- Redis job queue (swap from in-process goroutine pool)
- HA / clustering (leader election for CVE watch scheduler)
- CosignVerifier (real cosign via sigstore — StubVerifier in Phase 1/2)
- themis-cli companion CLI
- Compliance reports, audit exports

## Notes

**Why:** Phase 1 = standalone backend foundation. Phase 2 = AI intelligence + signal
aggregation. Phase 3 = infrastructure, UI, enterprise.

**How to apply:** When suggesting features or scope, check which phase they belong to.
Never add Phase 3 features to Phase 2 code without explicit user direction.
