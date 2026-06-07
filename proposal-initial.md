# Themis

## Why

Organizations building containerized applications lack a unified platform to ingest SBOMs from CI pipelines, correlate vulnerabilities, contextualize findings with VEX intelligence, and continuously monitor for new threats against their component catalog. Existing tools are fragmented — scanners produce reports that rot in CI logs, triage decisions are lost, and there is no continuous monitoring against newly disclosed vulnerabilities.

Themis solves this by providing a Go backend that acts as a **security intelligence platform**: it ingests CI-generated SBOM/VEX artifacts, validates their trust and provenance, correlates vulnerabilities, layers continuously evolving intelligence (VEX, EPSS, KEV, AI enrichment, human triage), and proactively alerts when the threat landscape changes.

## What Changes

- **New system**: Themis security intelligence platform built in Go
- Event-driven ingestion of CI-generated SBOM and VEX artifacts via webhook/API from any CI/CD system (Jenkins, GitHub Actions, GitLab CI, etc.)
- Artifact validation gate — signature verification, provenance validation, schema conformance, hash verification, and supplier identity checks before ingestion
- Scanner-agnostic SBOM/VEX parser layer with pluggable format adapters (CycloneDX + SPDX normalization, Trivy output parsing as first adapter)
- API for manual upload of pre-generated SBOM/VEX documents for testing and review
- Multi-product, multi-project data model from inception
- Vulnerability correlation engine matching ingested components against known CVEs
- SBOM and vulnerability storage with component catalog indexing and scan history
- CVE triage engine combining Level 3 (automated VEX contextualization) and Level 4 (human triage with custom justification from product owners)
- Background CVE watch agents/jobs that monitor NVD/OSV feeds and match new CVEs against the existing component catalog
- Continuous intelligence enrichment — EPSS scoring, KEV sync, threat intel feeds, AI analysis — updating risk context between builds
- Configurable notification service (email + Microsoft Teams) for ingestion results, triage events, and new CVE alerts, with routing rules for who/when/what
- Configuration-driven setup for SBOM parsers, CVE feeds, notification channels, and trust policies

## Architecture Decisions

### ADR-1: Transport/Interchange Layer Decoupling

The platform SHALL treat SBOM/VEX formats (CycloneDX, SPDX, OpenVEX, CSAF) as transport/interchange layers only. The platform SHALL NOT tightly couple internal persistence models directly to CycloneDX or SPDX schemas. The platform SHALL maintain a canonical normalized security model internally.

**Rationale**: Format standards evolve independently (CycloneDX is on v1.6, SPDX on v3.0). Tightly coupling internal models to a specific schema version creates migration burden, limits interoperability, and leaks transport concerns into business logic. When CycloneDX v2.0 ships with breaking changes, only the adapter layer should change — core domain logic, database schema, API contracts, and enrichment pipelines must remain untouched.

**Consequences**:

- All business logic operates exclusively on the internal canonical model
- Format-specific structs exist only in adapter/parser packages — never imported by core domain
- No CycloneDX or SPDX field names appear in core domain types or database column names
- Format-specific metadata is preserved in raw document storage (immutable JSONB) and generic property fields
- Adding a new format (e.g., SWID tags) requires only a new adapter — zero core changes

### ADR-2: Strategic Format Priorities

#### Primary Security Transport Format: CycloneDX

CycloneDX SHALL be treated as the preferred security-focused transport format because it naturally supports:

- SBOM component inventory
- Vulnerability metadata
- Dependency graphs
- VEX assertions
- Service metadata
- Compositions
- Operational security context

CycloneDX SHALL be prioritized for:

- CI/CD ingestion
- Container image analysis
- Vulnerability contextualization
- VEX interoperability
- Runtime security workflows

#### Interoperability and Compliance Format: SPDX

SPDX SHALL also be supported as an interoperability and compliance transport format because many enterprise ecosystems rely on SPDX for:

- License governance
- Supplier attestations
- OSS compliance
- Procurement workflows
- Provenance tracking

SPDX SHALL be normalized into the same internal canonical model.

**Rationale**: CycloneDX's security-first design aligns with Themis's primary mission — vulnerability intelligence, VEX interoperability, and runtime security context. SPDX's ISO standardization (ISO/IEC 5962:2021) and compliance focus makes it essential for enterprise interoperability and procurement workflows. Supporting both through a format-agnostic canonical model avoids forcing ecosystem choices on consumers while allowing the platform to optimize its security workflows around CycloneDX's richer security semantics.

### ADR-3: Three-Layer Data Separation

The platform SHALL separate data into three distinct layers with fundamentally different mutation, trust, and caching characteristics:

#### Layer 1 — Immutable Software Inventory Truth

The following SHALL be treated as immutable or mostly immutable:

- Container image digest
- Build provenance
- SBOM document
- Component inventory
- Dependency graph
- Package metadata

SBOM identity SHALL be tied to immutable artifact digests (e.g., OCI image digest SHA-256). If image digest is unchanged AND SBOM hash is unchanged, the platform SHALL reuse existing SBOM inventory instead of creating duplicate logical inventories.

**Properties**: Append-only. Cryptographically verifiable. Never mutated or deleted. Changes only when a new build occurs. Can be cached aggressively.

#### Layer 2 — Mutable Vulnerability Intelligence

The following SHALL be treated as document-based intelligence that arrives asynchronously and evolves:

- VEX assertions and their lifecycle (active, revoked, superseded)
- Vulnerability findings and their contextualization
- Exploitability status determinations

Each individual VEX document is immutable once ingested (it has its own provenance, signature, and hash). However, the *collection* of intelligence documents evolves as new VEX revisions arrive, assertions are revoked, or new vulnerability disclosures are published. Multiple VEX revisions SHALL be supported for the same immutable SBOM/image combination.

**Properties**: Event-driven updates. Has its own provenance chain (signed, attributable, auditable). Requires event-driven cache invalidation.

#### Layer 3 — Temporal Exploitability Context

The following SHALL be treated as temporal and continuously evolving signals:

- EPSS scores (refreshed daily)
- KEV status (updated as CISA adds entries)
- Runtime exposure (changes with deployments)
- Reachability analysis (recomputed on dependency changes)
- AI enrichment (re-evaluated as models improve)
- Remediation recommendations (evolve with fix availability)

**Properties**: Polling/streaming-driven updates. No inherent provenance — these are computed or fetched values. TTL-based cache expiry. System remains functional (with stale data) during feed outages.

#### Why Three Layers, Not Two

The original two-layer model (Immutable Build Artifacts + Continuously Evolving Intelligence) conflates document-based intelligence (VEX, which arrives as signed documents with verifiable provenance) with temporal signals (EPSS, which refreshes daily from an external feed). These have fundamentally different:

| Characteristic | Layer 2 (Intelligence Documents) | Layer 3 (Temporal Signals) |
|---|---|---|
| Update trigger | Document ingestion event | Feed polling, scheduled refresh |
| Provenance | Signed, attributable, auditable | None — computed/fetched values |
| Trust model | Verifiable (signature, issuer) | Assumed (NIST publishes EPSS) |
| Reversibility | Revocable (VEX can be retracted) | Overwritten (yesterday's EPSS replaced) |
| Caching strategy | Event-driven invalidation | TTL-based expiry |
| Outage behavior | Last known state is authoritative | Last known state goes stale |

These SHALL NOT be merged into a single mutable object. `RiskContext` serves as the convergence point that combines all three layers into a computed effective state.

### ADR-4: VEX Overlay, Never Delete

The platform SHALL NOT delete or suppress raw vulnerability findings based solely on VEX.

Raw findings SHALL remain preserved. VEX SHALL overlay contextual exploitability state.

**Example**:

```
Detected: CVE-2024-1234, severity=HIGH
VEX assertion: status=NOT_AFFECTED, justification=code_not_reachable

Result:
  effective_state = contextually_not_affected
  raw_severity = HIGH  (preserved)
  vex_status = not_affected  (overlaid)

NOT:
  delete vulnerability
  remove finding
```

This is required for:

- **Auditability**: Every vulnerability ever detected is queryable regardless of triage state
- **Explainability**: The reasoning chain (raw finding → VEX → effective state) is always traceable
- **Forensics**: Historical investigations can reconstruct the state at any point in time
- **Compliance traceability**: Regulators can see both "all detected" and "effectively active" independently
- **Safe revocation**: Removing a VEX assertion resurfaces the finding because it was never deleted

### ADR-5: Internal Canonical Model

The internal normalized security graph SHALL contain the following domain entities:

```
  ┌─────────────────────────────────────────────────────────────┐
  │  LAYER 1 — IMMUTABLE SOFTWARE INVENTORY TRUTH               │
  ├─────────────────────────────────────────────────────────────┤
  │  Artifact            Generic artifact (parent of Image)     │
  │  Product             Organizational grouping                │
  │  ProductVersion      Versioned release of a product         │
  │  Image               Container image (digest-identified)    │
  │  SBOMDocument        Immutable SBOM tied to an artifact     │
  │  Component           Package identity (PURL)                │
  │  ComponentVersion    Specific version of a component        │
  │  DependencyRelationship  Dep graph edges (direct/transitive)│
  ├─────────────────────────────────────────────────────────────┤
  │  LAYER 2 — MUTABLE VULNERABILITY INTELLIGENCE               │
  ├─────────────────────────────────────────────────────────────┤
  │  Vulnerability       Known vulnerability (CVE)              │
  │  ComponentVulnerability  Component × vulnerability join     │
  │  VEXDocument         Immutable VEX document with provenance │
  │  VEXAssertion        Individual assertion within VEX doc    │
  ├─────────────────────────────────────────────────────────────┤
  │  LAYER 3 — TEMPORAL EXPLOITABILITY CONTEXT                   │
  ├─────────────────────────────────────────────────────────────┤
  │  IntelligenceSignal  Generalized signal (EPSS, KEV, AI, …) │
  │  RuntimeExposure     Deployment context per artifact        │
  │  RemediationAction   Tracked fix with status & assignment   │
  ├─────────────────────────────────────────────────────────────┤
  │  CONVERGENCE POINT                                           │
  ├─────────────────────────────────────────────────────────────┤
  │  RiskContext         Computed effective state (all 3 layers)│
  └─────────────────────────────────────────────────────────────┘
```

**New entities vs original data model**:

| Entity | Change Type | Rationale |
|--------|------------|-----------|
| Artifact | **New** | Generalizes Image to support non-container artifacts (JARs, binaries, firmware). Image becomes a specialization. Enables future artifact types without schema changes. |
| ProductVersion | **New** | Groups a set of artifacts into a versioned release. Critical for answering "which released products contain CVE-X?" Currently Product → Image is flat; this adds Product → ProductVersion → Artifact → Image. |
| DependencyRelationship | **New** | Makes dependency graph a first-class entity with direct/transitive distinction, scope, and depth. Required for reachability analysis (planned future capability). |
| IntelligenceSignal | **Refactored** | Unifies `threat_intelligence` and `ai_enrichment` into a generic signal model with `signal_type` discriminator. Each signal carries: source, type, value, confidence, timestamp. New intelligence sources become new signal types, not new tables. |
| RuntimeExposure | **Elevated** | Promoted from a column in `threat_intelligence` to a first-class entity. An image may be deployed to multiple environments simultaneously (internet-facing AND internal). Exposure changes over time independently of vulnerability state. |

### ADR-6: Event-Driven Intelligence Architecture

The platform SHALL support asynchronous event-driven ingestion and processing. The following domain events formalize the internal event bus:

| Event | Trigger | Consumers |
|-------|---------|-----------|
| `IMAGE_BUILT` | CI webhook / manual upload | Ingestion pipeline, dedup check |
| `SBOM_AVAILABLE` | SBOM ingested and normalized | Correlation engine, component catalog |
| `SCAN_COMPLETED` | Vulnerability correlation done | VEX contextualization, notification |
| `VEX_UPDATED` | New VEX document ingested or revoked | Risk context recomputation |
| `RISK_CONTEXT_CHANGED` | Effective state changed for any reason | Notification service, dashboard |
| `EXPLOITABILITY_CHANGED` | EPSS/KEV/threat intel update | Risk scoring engine, notification |

These events SHALL trigger asynchronous enrichment agents. This event model extends (not replaces) the existing ingestion lifecycle states (RECEIVED → VALIDATING → CORRELATING → ENRICHING → COMPLETED).

**Recommended ingestion flow**:

```
CI/CD Pipeline                          Security Platform
─────────────                           ─────────────────
Build image                             
  → Generate SBOM                       
  → Sign image                          
  → Sign SBOM                           
  → Upload artifacts                    
  → Emit ingestion event ─────────────▶ Ingest SBOM
                                          → Normalize components
                                          → Correlate vulnerabilities
                                          → Apply VEX assertions
                                          → Trigger enrichment pipeline
                                          → Maintain temporal intelligence state
```

### ADR-7: AI Enrichment Boundaries

AI enrichment workflows MAY include:

- Exploitability reasoning
- False-positive analysis
- Remediation recommendation
- Runtime contextualization
- Reachability analysis
- Prioritization scoring
- Confidence scoring
- Threat intelligence correlation

AI-generated intelligence SHALL remain logically separate from immutable SBOM inventory (Layer 1). AI outputs SHALL be modeled as `IntelligenceSignal` entities in Layer 3 with explicit `model_version`, `confidence_score`, and `timestamp` — enabling auditability and reproducibility. AI signals SHALL never be promoted to Layer 1 or treated as immutable evidence.

### ADR-8: Raw Document Storage

Raw SBOM and VEX documents SHOULD be stored separately from normalized entities.

The platform SHOULD preserve:

- Original raw documents (as-received, unmodified)
- Signatures (detached from document content)
- Provenance metadata (CI job, pipeline, scanner identity)
- Timestamps (build time, ingestion time, processing time)
- Ingestion metadata (source, trigger, validation results)

The platform SHOULD support deduplication using:

- Image digest (OCI content-addressable identity)
- SBOM hash (SHA-256 of raw document content)
- Canonical document fingerprinting (for format-normalized comparison)

### ADR-9: Phase 2 UI Strategy — DefectDojo Integration vs. Themis Native

**Status**: PROPOSED — to be finalized before Phase 2 begins.

**Constraint**: Data flows **one-directionally only** (Themis → DefectDojo). Themis is the sole source of truth. All triage, enrichment, and state changes happen in Themis. DefectDojo, if used, is a **read-only presentation layer** — a display, not an operational tool. No data flows back from DefectDojo to Themis.

**Timeline constraint**: Demoable product required within 3 months.

This constraint eliminates the bidirectional sync problem entirely. But it also fundamentally changes what DefectDojo provides — most of DefectDojo's value comes from its *write* workflows (triage, risk acceptance, SLA management, issue tracker creation). In read-only mode, DefectDojo is essentially a dashboard with a finding browser. The question becomes: **does deploying and syncing to a full vulnerability management platform make sense when you're only using it as a dashboard?**

#### Feature-by-Feature Analysis: DefectDojo (Read-Only) vs. Build Native

Each DefectDojo capability is evaluated on three dimensions:

1. **Usable in read-only mode?** — Does the feature work if all writes go through Themis?
2. **Relevant to Themis's demo?** — Does it showcase Themis's unique value (three-layer model, VEX, intelligence pipeline)?
3. **Build cost from scratch** — How long to build an equivalent natively, using modern frontend tooling (React/Vue + component library like Shadcn/Ant Design)?

```
  ┌──────────────────────────────────────────────────────────────────────────────────────────┐
  │  FEATURE-BY-FEATURE COMPARISON                                                           │
  │  DD = DefectDojo (read-only mode)  |  Native = Build from scratch                        │
  ├──────────────────────┬──────────┬───────────┬───────────┬────────────────────────────────┤
  │ Feature              │ DD Works │ Demo      │ Native    │ Verdict                        │
  │                      │ Read-Only│ Relevant? │ Build Cost│                                │
  ├──────────────────────┼──────────┼───────────┼───────────┼────────────────────────────────┤
  │ Dashboard with       │ ✅ Yes   │ Partially │ 2-3 days  │ COMPARABLE. DD's charts are    │
  │ severity charts      │          │           │ (chart    │ generic. Native can show       │
  │                      │          │           │  library) │ L1/L2/L3 breakdown — more      │
  │                      │          │           │           │ impressive for demo.           │
  ├──────────────────────┼──────────┼───────────┼───────────┼────────────────────────────────┤
  │ Finding list view    │ ✅ Yes   │ Yes       │ 2-3 days  │ COMPARABLE. Table + filters    │
  │ with filters/search  │          │           │ (table    │ is commodity UI. Native can    │
  │                      │          │           │  component│ show RiskContext columns       │
  │                      │          │           │  library) │ (VEX status, EPSS, KEV) that   │
  │                      │          │           │           │ DD can't display natively.     │
  ├──────────────────────┼──────────┼───────────┼───────────┼────────────────────────────────┤
  │ Finding detail view  │ ✅ Yes   │ Yes       │ 1-2 days  │ ★ NATIVE WINS. DD shows flat   │
  │                      │          │           │           │ finding. Native shows full     │
  │                      │          │           │           │ RiskContext: L1 raw finding +  │
  │                      │          │           │           │ L2 VEX overlay + L3 EPSS/KEV   │
  │                      │          │           │           │ signals → effective state.     │
  │                      │          │           │           │ This IS the demo.              │
  ├──────────────────────┼──────────┼───────────┼───────────┼────────────────────────────────┤
  │ Triage workflows     │ ❌ NO    │ Critical  │ 2-3 days  │ ★ NATIVE WINS. DD's triage is  │
  │ (false positive,     │ Read-only│ for demo  │           │ disabled in read-only mode.    │
  │ risk acceptance,     │ mode =   │           │           │ Users MUST triage somewhere.   │
  │ justification)       │ no triage│           │           │ If not DD, then either raw     │
  │                      │          │           │           │ API calls (bad UX) or a        │
  │                      │          │           │           │ native triage UI (must build   │
  │                      │          │           │           │ regardless).                   │
  ├──────────────────────┼──────────┼───────────┼───────────┼────────────────────────────────┤
  │ VEX overlay          │ ❌ NO    │ Critical  │ 2-3 days  │ ★ NATIVE WINS. DD has no VEX   │
  │ visualization        │ DD has   │ for demo  │           │ concept. The "never delete,    │
  │                      │ no VEX   │           │           │ overlay instead" principle —   │
  │                      │ model    │           │           │ Themis's core differentiator   │
  │                      │          │           │           │ — is invisible in DD.          │
  ├──────────────────────┼──────────┼───────────┼───────────┼────────────────────────────────┤
  │ Intelligence signals │ ❌ NO    │ Critical  │ 1-2 days  │ ★ NATIVE WINS. EPSS score      │
  │ (EPSS, KEV, AI)      │ Becomes  │ for demo  │           │ trends, KEV listing status,   │
  │ with temporal data   │ notes/   │           │           │ AI confidence — these are      │
  │                      │ tags only│           │           │ structured temporal signals    │
  │                      │          │           │           │ in Themis. DD renders them     │
  │                      │          │           │           │ as unstructured text.          │
  ├──────────────────────┼──────────┼───────────┼───────────┼────────────────────────────────┤
  │ Integrity chain      │ ❌ NO    │ Yes       │ 2-3 days  │ ★ NATIVE WINS. Image → SBOM →  │
  │ visualization        │ Not in   │           │           │ VEX signature verification    │
  │                      │ DD model │           │           │ chain is unique to Themis.     │
  ├──────────────────────┼──────────┼───────────┼───────────┼────────────────────────────────┤
  │ Product hierarchy    │ ✅ Yes   │ Yes       │ 1-2 days  │ COMPARABLE. Both can display   │
  │ navigation           │          │           │           │ product → project → scans.    │
  ├──────────────────────┼──────────┼───────────┼───────────┼────────────────────────────────┤
  │ Scan history /       │ ✅ Yes   │ Yes       │ 1-2 days  │ COMPARABLE. Table of scans    │
  │ ingestion status     │ (via     │           │           │ with status badges.           │
  │                      │ engage-  │           │           │                                │
  │                      │ ments)   │           │           │                                │
  ├──────────────────────┼──────────┼───────────┼───────────┼────────────────────────────────┤
  │ RBAC (user roles,    │ ✅ Yes   │ Not for   │ 3-5 days  │ DD WINS for now. But for a     │
  │ product-scoped       │          │ initial   │ (basic)   │ 3-month demo, basic auth       │
  │ permissions)         │          │ demo      │ or defer  │ (API key → session) suffices.  │
  │                      │          │           │           │ Full RBAC is Phase 3.          │
  ├──────────────────────┼──────────┼───────────┼───────────┼────────────────────────────────┤
  │ Report generation    │ ✅ Yes   │ Nice to   │ Defer     │ DD WINS for now. But reports   │
  │ (PDF, compliance)    │          │ have      │           │ are not critical for a 3-month │
  │                      │          │           │           │ demo. Defer to Phase 3.        │
  ├──────────────────────┼──────────┼───────────┼───────────┼────────────────────────────────┤
  │ Metrics / trending   │ ✅ Yes   │ Nice to   │ 1-2 days  │ COMPARABLE. Basic trend charts │
  │                      │          │ have      │           │ with a chart library.          │
  ├──────────────────────┼──────────┼───────────┼───────────┼────────────────────────────────┤
  │ Issue tracker        │ ⚠️ Partial│ Nice to  │ Defer     │ DD PARTIAL WIN. DD can create  │
  │ integration (Jira,   │ DD can   │ have      │           │ Jira tickets — but from        │
  │ GitHub Issues)       │ create   │           │           │ findings pushed from Themis.   │
  │                      │ tickets  │           │           │ Useful, but not critical for   │
  │                      │ from     │           │           │ demo. Could be Phase 3.        │
  │                      │ pushed   │           │           │                                │
  │                      │ findings │           │           │                                │
  ├──────────────────────┼──────────┼───────────┼───────────┼────────────────────────────────┤
  │ Deduplication        │ ⚠️ Yes   │ No        │ N/A       │ IRRELEVANT. Themis already     │
  │                      │ but DD's │           │           │ handles dedup. DD's dedup on   │
  │                      │ dedup ≠  │           │           │ top may conflict.              │
  │                      │ Themis's │           │           │                                │
  ├──────────────────────┼──────────┼───────────┼───────────┼────────────────────────────────┤
  │ User management      │ ✅ Yes   │ Not for   │ 2-3 days  │ DD WINS for now. But for a     │
  │                      │          │ initial   │ or defer  │ 3-month demo, a single admin   │
  │                      │          │ demo      │           │ user with API key suffices.    │
  ├──────────────────────┼──────────┼───────────┼───────────┼────────────────────────────────┤
  │ 200+ scanner         │ ✅ Yes   │ No        │ N/A       │ IRRELEVANT. Themis has its own │
  │ import parsers       │ but      │           │           │ parser pipeline. DD's parsers  │
  │                      │ bypasses │           │           │ bypass Themis — breaks source  │
  │                      │ Themis   │           │           │ of truth guarantee.            │
  └──────────────────────┴──────────┴───────────┴───────────┴────────────────────────────────┘
```

#### The Fractured UX Problem (Read-Only DefectDojo)

With one-directional sync, DefectDojo becomes a **view-only dashboard**. But users still need to *act* — triage vulnerabilities, mark false positives, accept risks, add justifications. Since these actions can only happen in Themis, the user experience is fractured:

```
  USER WORKFLOW WITH READ-ONLY DEFECTDOJO
  ════════════════════════════════════════

  Security engineer opens DefectDojo
       │
       ▼
  Sees finding: CVE-2024-1234 in lodash@4.17.21
  Severity: HIGH, EPSS: 0.03 (shown as a note)
       │
       ▼
  Wants to mark as false positive
       │
       ▼
  ❌ CANNOT DO THIS IN DEFECTDOJO (read-only)
       │
       ▼
  Must switch to Themis API:
  POST /api/v1/vulnerabilities/{id}/triage
  {
    "decision": "false_positive",
    "justification": "code_not_reachable"
  }
       │
       ▼
  Wait for Themis → DefectDojo sync to reflect the change
       │
       ▼
  Return to DefectDojo to verify the status update arrived


  vs.

  USER WORKFLOW WITH NATIVE THEMIS UI
  ════════════════════════════════════

  Security engineer opens Themis UI
       │
       ▼
  Sees finding: CVE-2024-1234 in lodash@4.17.21
  Severity: HIGH │ VEX: none │ EPSS: 0.03 ↗ │ KEV: No
  Effective state: DETECTED │ Risk score: 42/100
       │
       ▼
  Clicks "Triage" → selects "False Positive"
  Enters justification: "code_not_reachable"
       │
       ▼
  Immediately sees:
  Effective state: FALSE_POSITIVE
  VEX assertion auto-generated (L4 → L3 upgrade)
  Done. Single system. Immediate feedback.
```

This fractured experience means that **even with DefectDojo deployed, you still need a Themis triage interface**. If you need to build triage UI for Themis anyway, the incremental cost of also building a finding list and dashboard is small — and then DefectDojo adds no value.

#### Effort Comparison: 3-Month Timeline

The 3-month constraint means the backend (Phase 1) consumes the majority of the time. Realistically:

```
  3-MONTH TIMELINE BREAKDOWN
  ══════════════════════════

  Month 1-2.5:  Phase 1 Backend
                ─────────────────
                • SBOM/VEX ingestion + validation
                • Correlation engine
                • VEX contextualization
                • CVE watch + EPSS/KEV enrichment
                • REST API + notification service
                • PostgreSQL schema + migrations

  Month 2.5-3:  Phase 2 UI (2-4 weeks available)
                ─────────────────
                Option A: DefectDojo          Option B: Native UI
                ──────────────────────        ──────────────────────
                • Deploy DD stack (1-2 days)  • Frontend scaffolding (2-3 days)
                • Build sync service:         • Dashboard page (2-3 days)
                  - DD API client (2-3 days)  • Finding list + filters (2-3 days)
                  - Entity mapping (3-5 days) • Finding detail with
                  - Event listener (2-3 days)   RiskContext view (2-3 days)
                  - Error handling (2-3 days)  • Triage action UI (2-3 days)
                  - Testing cross-system       • Scan history page (1-2 days)
                    (3-5 days)                 • Basic auth (2-3 days)
                • STILL need triage UI        ──────────────────────
                  somewhere (2-3 days)         Total: ~3-4 weeks
                ──────────────────────
                Total: ~3-4 weeks

                ⚠️ SAME TIMELINE             ✅ Everything carries forward
                   Sync service is               to Phase 3
                   throwaway if Phase 3
                   replaces DD
```

The effort is comparable. But the native path produces:

- A more impressive demo (shows Themis's unique value, not generic DefectDojo)
- A triage workflow that actually works (not fractured across systems)
- Code that carries forward to Phase 3 (no throwaway sync service)

#### What DefectDojo Genuinely Wins

To be fair, DefectDojo has real advantages that the feature table above identifies. These are the features where DefectDojo integration provides value that is hard to replicate quickly:

1. **RBAC** — DefectDojo has mature role-based access control with product-scoped permissions. Building equivalent RBAC from scratch is 1-2 weeks. **But**: for a 3-month demo, basic auth (admin user + API key session) suffices. RBAC is Phase 3 work regardless.

2. **Report generation** — PDF compliance reports, exportable findings lists, metrics reports. Building report generation from scratch is significant. **But**: not critical for a demo. Defer to Phase 3.

3. **Issue tracker integration** — Jira/GitHub Issues ticket creation from findings. This is genuinely useful and non-trivial to build. **But**: DefectDojo can only create tickets from *its* findings, which are lossy copies of Themis's RiskContext. The Jira ticket would lack VEX context, intelligence signal data, and integrity chain info. Also not critical for a 3-month demo.

4. **Metrics/trending over time** — DefectDojo tracks finding counts, mean-time-to-remediate, etc. **But**: these metrics operate on DefectDojo's flat finding model, not Themis's three-layer model. Themis-specific metrics (VEX coverage rate, EPSS score distribution, KEV exposure, intelligence signal freshness) cannot come from DefectDojo.

**None of DefectDojo's genuine wins are critical for a 3-month demo.** They are all Phase 3 features that can be built natively when needed.

#### What the Demo Actually Needs to Show

The 3-month demo audience (stakeholders, security leadership, potential users) needs to see:

1. **CI pushes SBOM → Themis ingests → correlates → enriches** — this is backend, visible via API or any UI
2. **VEX contextualization working** — SUPPRESSED findings with raw evidence preserved, VEX overlay visible. **DefectDojo cannot show this.**
3. **EPSS/KEV enrichment visible** — temporal signals with scores, trends. **DefectDojo shows this as unstructured notes.**
4. **CVE watch finding new vulns between builds** — new findings appearing. Both can show this.
5. **Triage workflow** — mark false positive, see VEX auto-generated. **DefectDojo cannot do this in read-only mode.**
6. **Notifications firing** — email/Teams alerts. Backend feature, UI-independent.
7. **Cross-product "which products are affected by CVE-X?"** — component catalog query. **DefectDojo cannot do this** (it tracks findings, not component inventory).

**5 out of 7 demo requirements are better served by a native UI.** DefectDojo adds visual polish (mature charts, responsive layout) but hides Themis's differentiators.

#### Decision

**Recommendation: Build Themis native UI (Option B) for Phase 2.** The one-directional sync constraint removes DefectDojo's triage workflows — its strongest feature. What remains (dashboards, finding lists, RBAC, reports) is either commodity UI buildable in comparable time, or Phase 3 features not needed for the demo.

The effort is comparable (~3-4 weeks either path), but native UI:

- Produces a more impressive demo by showcasing Themis's unique value
- Delivers a working triage experience (not fractured across systems)
- Produces no throwaway code (everything carries forward to Phase 3)
- Avoids deploying and operating a second full platform (Django + PostgreSQL + Celery + Redis + Nginx)

**DefectDojo integration is not rejected** — it can be offered as an **optional one-directional export** (Phase 3 add-on) for organizations that already run DefectDojo and want Themis findings visible there. This is a simple push adapter, not a core architectural decision.

**Consequences**:

- Phase 1 REST API must support UI-friendly queries: pagination, filtering, aggregation, sorting
- Frontend technology decision needed at Phase 2 start (React/Vue + component library)
- Basic auth for the UI (API key → session) in Phase 2; full RBAC with OIDC/OAuth2 in Phase 3
- Phase 1 API design should include aggregation endpoints for dashboard data (severity distribution, scan counts, component stats)
- Optional DefectDojo export adapter can be built in Phase 3 as a thin one-directional push service

## Capabilities

### New Capabilities

- `ci-webhook-api`: Webhook/API endpoint to receive CI-generated SBOM/VEX artifacts from any CI/CD system via event-driven ingestion
- `sbom-parser`: Scanner-agnostic parser layer with pluggable format adapters that normalize SBOM (CycloneDX, SPDX) and VEX documents into the internal canonical model (Trivy output adapter as first implementation)
- `sbom-ingestion`: API for uploading pre-generated SBOM/VEX documents for manual testing and review, processed identically to CI-ingested artifacts
- `sbom-store`: Multi-product, multi-project storage for SBOMs, VEX statements, component catalogs, and scan history
- `cve-triage`: Triage engine combining automated VEX-based verification (L3) with human triage workflow including custom justification tracking (L4)
- `cve-watch`: Background agents/jobs that monitor NVD/OSV feeds for new CVEs and match them against the stored component catalog
- `notification-service`: Configurable notification delivery (email, Microsoft Teams) with routing rules for scan results and new CVE alerts
- `artifact-trust`: Validation gate for SBOM/VEX artifact integrity — signature verification, provenance validation, schema conformance, hash verification, and supplier identity checks

### Modified Capabilities

*None — this is a greenfield project.*

## API Design

All endpoints are served under `/api/v1/` with JSON request/response bodies.

**Endpoint inventory:**

| Method | Endpoint | Purpose |
|--------|----------|--------|
| POST | `/api/v1/webhooks/scan` | Receive container image build notification from CI; triggers scan workflow |
| POST | `/api/v1/sbom/upload` | Upload pre-generated SBOM (CycloneDX/SPDX) and/or VEX document |
| GET | `/api/v1/products` | List all products |
| POST | `/api/v1/products` | Register a new product |
| GET | `/api/v1/products/{id}/projects` | List projects under a product |
| POST | `/api/v1/products/{id}/projects` | Register a new project under a product |
| GET | `/api/v1/projects/{id}/scans` | List scan history for a project |
| GET | `/api/v1/scans/{id}` | Get scan details including SBOM summary and vulnerabilities |
| GET | `/api/v1/scans/{id}/vulnerabilities` | List vulnerabilities from a scan, filterable by severity |
| POST | `/api/v1/vulnerabilities/{id}/triage` | Submit triage decision (false positive, accepted risk, etc.) with justification |
| GET | `/api/v1/components` | Query component catalog across products/projects |
| GET | `/api/v1/cve-watch/findings` | List new CVE findings from background watch jobs |
| GET | `/api/v1/config/notifications` | Get notification routing rules |
| PUT | `/api/v1/config/notifications` | Update notification routing rules |
| GET | `/api/v1/config/scanners` | Get scanner configuration |
| PUT | `/api/v1/config/scanners` | Update scanner configuration |
| GET | `/healthz` | Liveness probe |
| GET | `/readyz` | Readiness probe (DB, scanner, CVE feed checks) |

**API conventions:**

- **Versioning**: URL-path versioning (`/api/v1/`); breaking changes get a new version
- **Pagination**: Cursor-based pagination on all list endpoints (`?cursor=...&limit=50`)
- **Error format**: RFC 7807 Problem Details — `{"type", "title", "status", "detail", "instance"}`
- **Filtering**: Query parameters for severity, product, project, date range on list endpoints
- **Idempotency**: Webhook and upload endpoints accept an `Idempotency-Key` header to prevent duplicate processing

## Data Model

### Architecture Principle: Three-Layer Data Separation (see ADR-3)

Themis separates data into three layers with fundamentally different mutation, trust, and caching characteristics. See Architecture Decisions (ADR-3) for the full rationale and layer definitions.

```
  LAYER 1: IMMUTABLE SOFTWARE             LAYER 2: MUTABLE VULNERABILITY      LAYER 3: TEMPORAL
  INVENTORY TRUTH                         INTELLIGENCE                        EXPLOITABILITY CONTEXT
  (persist permanently, never mutate)     (document-based, event-driven)      (continuously refreshing)
  ═══════════════════════════════════     ═══════════════════════════════════  ═══════════════════════
  • Raw SBOM documents                    • VEX assertions (new ones arrive,  • EPSS (Exploit Prediction
  • Raw VEX documents (as received)         old ones may be revoked)            Scoring System)
  • Raw vulnerability findings            • Vulnerability contextualization   • KEV (CISA Known Exploited
  • Provenance records                    • Exploitability determinations       Vulnerabilities) listing
    - CI job ID, pipeline URL                                                 • Runtime exposure context
    - Build timestamp                     Each VEX document is individually   • AI analysis & confidence
    - Scanner identity & version          immutable (signed, hashed), but     • Reachability assessment
    - Trigger source                      the collection evolves as new       • Remediation ranking
  • Digital signatures                    revisions arrive or assertions      • Active exploitation state
    - SBOM signature (cosign/sigstore)    are revoked.                        • Risk score (composite)
    - VEX signature                                                           • Threat intel feed data
    - Signer identity                     Updated by: VEX ingestion,
  • Cryptographic hashes                  CVE disclosure feeds                Updated by: EPSS/KEV sync,
    - Document checksums (SHA-256)
    - Image digest                        AI agents, threat intel feeds,
  • Source metadata                       EPSS/KEV sync jobs, runtime
    - Supplier identity                   monitoring
    - Upstream origin
    - Format & spec version

  Never deleted. Never mutated.           Each document immutable;           No inherent provenance.
  Append-only. Cryptographically          collection evolves.                TTL-based expiry.
  verifiable.                             Event-driven invalidation.         System functional with
                                                                             stale data during outages.

  CONVERGENCE POINT: risk_context
  ═════════════════════════════════════════════════════════════════════════════════════════════
  Combines all three layers into a computed effective state.
  The single entity that answers "what is the current status of this vulnerability?"
```

### End-to-End Processing Pipeline

The CI/CD system is responsible for SBOM generation and signing. Themis receives signed artifacts via event-driven ingestion and processes them through an asynchronous enrichment pipeline with persistent temporal intelligence.

```
  CI/CD SYSTEM (external)                    THEMIS (internal)
  ═══════════════════════                    ═══════════════════

  Build container image
       ↓
  Generate SBOM
  (scanner runs in CI)
       ↓
  Sign SBOM
  (cosign / sigstore / in-toto)
       ↓
  Push SBOM + signature to
  artifact store (OCI registry
  or dedicated SBOM store)
       ↓
  Emit ingestion event ──────────────▶  Artifact Validation Gate
  (webhook POST to Themis)              │
                                        ├─ Verify signature
                                        ├─ Validate provenance
                                        ├─ Check schema conformance
                                        ├─ Verify hashes
                                        ├─ Validate supplier identity
                                        │   (especially for third-party
                                        │    vendors, external suppliers,
                                        │    customer-provided artifacts)
                                        ↓
                                   Ingestion & Normalization
                                        │
                                        ├─ Parse SBOM (CycloneDX/SPDX)
                                        ├─ Extract components, PURLs
                                        ├─ Store raw document (immutable)
                                        ├─ Store normalized canonical form
                                        ↓
                                   Vulnerability Correlation
                                        │
                                        ├─ Match components → known CVEs
                                        ├─ Store raw findings (immutable)
                                        ↓
                                   VEX Contextualization
                                        │
                                        ├─ Apply VEX assertions
                                        ├─ Compute effective state
                                        │   (suppress contextually,
                                        │    NEVER delete)
                                        ↓
                                   Event Bus ──────────────────────┐
                                        │                          │
                                        ↓                          ↓
                                   AI Enrichment              Notification
                                   Agents                     Service
                                        │
                                        ├─ Confidence scoring
                                        ├─ Reachability hints
                                        ↓
                                   Risk Scoring Engine
                                        │
                                        ├─ EPSS score
                                        ├─ KEV listing
                                        ├─ Exploitability
                                        ├─ AI confidence
                                        ├─ VEX context
                                        ├─ → Composite risk score
                                        ↓
                                   Continuous Monitoring
                                        │
                                        ├─ CVE Watch (NVD/OSV polling)
                                        ├─ EPSS score refresh
                                        ├─ KEV list sync
                                        ├─ Threat intel feed updates
                                        ├─ VEX revocation detection
                                        └─ → Re-score, re-notify
                                             when context changes

  ─────────────────────────────────────────────────────────────────────

  SUMMARY: CI-generated SBOM/VEX
           + Event-driven ingestion
           + Asynchronous enrichment
           + Persistent temporal intelligence
```

### Core Entities

PostgreSQL with the following entities, organized by the three-layer model (see ADR-3, ADR-5):

```
  ┌─────────────────────────────────────────────────────────┐
  │  LAYER 1: IMMUTABLE SOFTWARE INVENTORY TRUTH             │
  └─────────────────────────────────────────────────────────┘

  artifacts (NEW — generic artifact abstraction, see ADR-5)
  ┌──────────────────────┐
  │ id                   │
  │ artifact_type:       │     discriminator: image | jar |
  │   image | jar |      │     binary | firmware | ...
  │   binary | firmware  │
  │ product_version_id   │     FK → product_versions
  │   (FK, nullable)     │
  │ created_at           │
  └──────────┬───────────┘
             │ 1:1 (for type=image)
             ▼
  products                     product_versions (NEW, see ADR-5)
  ┌──────────────────┐         ┌──────────────────────────────┐
  │ id               │──1:N──▶ │ id                           │
  │ name             │         │ product_id (FK)              │
  │ description      │         │ version                      │
  │ metadata         │         │ release_status (draft |      │
  │ created_at       │         │   released | deprecated)     │
  └──────────────────┘         │ released_at                  │
                               │ created_at                   │
                               └──────────────────────────────┘

  images
  ┌──────────────────────────────┐
  │ id                           │
  │ artifact_id (FK → artifacts) │     links to generic artifact
  │ product_id                   │
  │ registry                     │
  │ repository                   │
  │ tag                          │ ← mutable alias
  │ digest (sha256) ◄────────────│─ UNIQUE IDENTITY
                               │                              │
                               │ ── Image Signature ──────────│
                               │ image_signature              │
                               │ image_signature_format       │
                               │ image_signer_identity        │
                               │ image_signature_verified     │
                               │                              │
                               │ created_at                   │
                               └──────────────┬───────────────┘
                                              │
                                              │ 1:N (same image,
                                              │      multiple scans)
                                              │
                               ┌──────────────▼───────────────┐
                               │ sbom_documents               │
                               │                              │
                               │ id                           │
                               │ image_id (FK)                │
                               │ image_digest (denormalized)  │ ← fast dedup
                               │                              │
                               │ ── SBOM Identity ────────────│
                               │ checksum_sha256 ◄────────────│─ UNIQUE per
                               │ format (cyclonedx/spdx)      │  content
                               │ spec_version                 │
                               │                              │
                               │ ── Provenance ───────────────│
                               │ scanner_name (trivy/syft/…)  │
                               │ scanner_version              │
                               │ scanner_db_version           │ ← explains why
                               │ ci_job_id                    │   same image →
                               │ ci_pipeline_url              │   different results
                               │ build_timestamp              │
                               │ trigger (webhook/upload/     │
                               │   manual)                    │
                               │ supplier_identity            │
                               │ upstream_origin              │
                               │                              │
                               │ ── SBOM Signature ───────────│
                               │ signature (text)             │
                               │ signature_format (cosign/    │
                               │   sigstore/in-toto/pgp)      │
                               │ signer_identity              │
                               │ signature_verified (bool)    │
                               │ trust_status:                │
                               │   verified | unverified |    │
                               │   failed | unsigned          │
                               │                              │
                               │ ── Dedup & Ordering ─────────│
                               │ is_latest (bool)             │ ← current truth
                               │ supersedes_id (self-FK)      │ ← points to prev
                               │                              │
                               │ raw_document (jsonb)         │
                               │ ingested_at                  │
                               │                              │
                               │ UNIQUE(image_digest,         │
                               │        checksum_sha256)      │ ← dedup key
                               └──────────────┬───────────────┘
                                          │
                    ┌─────────────────────┬┴─────────────────────┐
                    │                     │                      │
          ┌─────────▼──────────┐ ┌────────▼─────────┐  ┌────────▼─────────┐
          │ components         │ │component_versions│  │ vulnerabilities  │
          │                    │ │                  │  │ (raw findings)   │
          │ id                 │ │ id               │  │                  │
          │ purl (unique key)  │ │ component_id     │  │ id               │
          │ type (library/     │ │ version          │  │ cve_id           │
          │   framework/os)    │ │ sbom_document_id │  │ source (scanner/ │
          │ ecosystem (npm/    │ │ first_seen       │  │   nvd/osv)       │
          │   maven/pypi/etc)  │ │ last_seen        │  │ severity         │
          │ name               │ │ licenses[]       │  │ cvss_score       │
          │ namespace          │ │ direct_dependency │  │ cvss_vector      │
          │ first_seen         │ │   (bool)         │  │ description      │
          │ last_seen          │ └──────────────────┘  │ affected_versions│
          └────────────────────┘                       │ fix_versions     │
                    │                                  │ references[]     │
                    │                                  │ published_at     │
                    │                                  │ discovered_at    │
                    ▼                                  └──────────────────┘
          ┌────────────────────┐
          │dependency_         │    FIRST-CLASS DEP GRAPH
          │  relationships     │    (NEW — see ADR-5)
          │                    │
          │ id                 │
          │ sbom_document_id   │    scoped to specific SBOM
          │ from_component_    │
          │   version_id       │    parent in dep tree
          │ to_component_      │
          │   version_id       │    child in dep tree
          │ relationship_type: │
          │   depends_on |     │
          │   dev_depends_on | │
          │   optional |       │
          │   build_depends_on │
          │ scope (runtime |   │
          │   compile | test)  │
          │ depth (int)        │    1=direct, 2+=transitive
          └────────────────────┘

          ┌────────────────────┐
          │component_vulnera-  │    JOIN TABLE: links a specific
          │  bilities          │    component_version to a specific
          │                    │    vulnerability finding
          │ id                 │
          │ component_version_ │
          │   id               │
          │ vulnerability_id   │
          │ sbom_document_id   │
          │ detected_at        │
          └────────────────────┘


          ┌────────────────────┐         ┌────────────────────┐
          │ vex_documents      │         │ vex_assertions     │
          │                    │         │                    │
          │ id                 │──1:N──▶ │ id                 │
          │ sbom_document_id   │         │ vex_document_id    │
          │   (FK)             │         │ vulnerability_id   │
          │ sbom_checksum      │         │ component_purl     │
          │   (denormalized)   │         │ status:            │
          │                    │         │   not_affected |   │
          │ ── VEX Identity ───│         │   affected |       │
          │ checksum_sha256 ◄──│         │   fixed |          │
          │   UNIQUE per       │         │   under_           │
          │   content          │         │   investigation    │
          │ format (cyclonedx/ │         │ justification_type:│
          │   openvex/csaf)    │
          │                    │
          │ source (vendor/    │
          │   upstream/manual/ │
          │   themis_generated)│
          │ issuer             │
          │ raw_document(jsonb)│
          │ timestamp          │
          │                    │
          │ ── VEX Signature ──│
          │ signature (text)   │
          │ signature_format   │
          │ signer_identity    │
          │ signature_verified │
          │ trust_status       │
          │                    │
          │ ingested_at        │
          │                    │
          │ UNIQUE(sbom_checksum│
          │   checksum_sha256) │ ← dedup
          └────────────────────┘
                                         │   code_not_present│
                                         │   code_not_       │
                                         │    reachable |    │
                                         │   requires_config|│
                                         │   requires_env |  │
                                         │   protected_by_   │
                                         │    mitigating_ctrl│
                                         │   inline_mitigat- │
                                         │    ions_exist     │
                                         │ justification_text│
                                         │ action_statement  │
                                         │ valid_from        │
                                         │ valid_until       │
                                         └────────────────────┘


  ┌─────────────────────────────────────────────────────────┐
  │    CONVERGENCE POINT (combines all 3 layers)            │
  └─────────────────────────────────────────────────────────┘

          ┌────────────────────┐
          │ risk_context       │    THE EFFECTIVE STATE
          │                    │    (computed from L1+L2+L3)
          │ id                 │
          │ component_vuln_id  │    Links to a specific
          │   (FK → component_ │    (component_version +
          │    vulnerabilities)│     vulnerability) pair
          │                    │
          │ ── Detected State ─│
          │ raw_severity       │    What the scanner found (L1)
          │ raw_cvss_score     │
          │                    │
          │ ── VEX State ──────│
          │ vex_assertion_id   │    Which VEX assertion applies (L2)
          │ vex_status         │    (not_affected/affected/etc)
          │ vex_justification  │
          │                    │
          │ ── Effective State─│    ◄── THIS IS THE CRUX
          │ effective_state:   │
          │   detected |       │    "scanner found it"
          │   contextually_    │    "VEX says not affected,
          │    not_affected |  │     but we KEEP the finding"
          │   suppressed |     │    "VEX says not affected (legacy)"
          │   confirmed |      │    "VEX confirms affected"
          │   in_triage |      │    "awaiting human decision"
          │   accepted_risk |  │    "human: we know, we accept"
          │   false_positive | │    "human: not real"
          │   resolved         │    "fix applied"
          │                    │
          │ suppression_reason │    Why it's suppressed (not
          │                    │    why it's deleted — it's NOT)
          │ ── Human Triage ───│
          │ triage_decision    │
          │ triage_justificat- │
          │   ion              │
          │ triaged_by         │
          │ triaged_at         │
          │                    │
          │ ── Scoring ────────│
          │ risk_score         │    Composite score (L1+L2+L3)
          │ exploitability     │
          │ exposure_level     │
          │                    │
          │ updated_at         │
          └────────────────────┘


  ┌─────────────────────────────────────────────────────────┐
  │  LAYER 3: TEMPORAL EXPLOITABILITY CONTEXT               │
  └─────────────────────────────────────────────────────────┘

          ┌────────────────────┐
          │ intelligence_      │    GENERALIZED SIGNAL MODEL
          │   signals          │    (replaces ai_enrichment +
          │                    │     threat_intelligence,
          │ id                 │     see ADR-5)
          │ signal_type:       │
          │   epss |           │    Exploit Prediction Scoring
          │   kev |            │    CISA Known Exploited Vulns
          │   exploit_intel |  │    Exploitation maturity/sources
          │   ai_enrichment |  │    AI confidence/reachability
          │   threat_feed      │    External threat intel
          │                    │
          │ ── Target ─────────│
          │ cve_id             │    What this signal is about
          │ component_vuln_id  │    (nullable — some signals
          │   (FK, nullable)   │     are CVE-wide, not per-component)
          │                    │
          │ ── Signal Value ───│
          │ payload (jsonb)    │    Signal-type-specific data:
          │                    │    epss: {score, percentile}
          │                    │    kev: {listed, date_added,
          │                    │      due_date, required_action}
          │                    │    exploit_intel: {available,
          │                    │      maturity, sources[]}
          │                    │    ai_enrichment: {confidence,
          │                    │      reachability, reasoning,
          │                    │      model_version}
          │                    │
          │ ── Provenance ─────│
          │ source             │    Where this signal came from
          │ confidence_score   │    How reliable (0.0-1.0)
          │ valid_from         │    Temporal validity window
          │ valid_until        │    (nullable — some are open-ended)
          │ fetched_at         │    When we got this signal
          │ supersedes_id      │    Previous signal this replaces
          │   (self-FK,        │
          │    nullable)       │
          └────────────────────┘

          ┌────────────────────┐
          │ runtime_exposures  │    ELEVATED TO FIRST-CLASS
          │                    │    (see ADR-5)
          │ id                 │
          │ artifact_id        │    Which artifact is deployed
          │   (FK → artifacts) │
          │ environment:       │
          │   internet_facing |│    Same artifact can have
          │   internal |       │    multiple simultaneous
          │   air_gapped |     │    deployments with different
          │   unknown          │    exposure levels
          │ namespace          │    K8s namespace, AWS account, etc.
          │ cluster            │    Deployment target identifier
          │ discovered_at      │
          │ last_verified_at   │
          │ source             │    How we know (manual, k8s API, etc.)
          └────────────────────┘

          ┌────────────────────┐
          │ remediation_actions│
          │                    │
          │ id                 │
          │ component_vuln_id  │
          │ action_type:       │
          │   upgrade |        │
          │   patch |          │
          │   workaround |     │
          │   accept           │
          │ target_version     │
          │ priority           │
          │ status (pending/   │
          │   in_progress/     │
          │   completed)       │
          │ assigned_to        │
          │ created_at         │
          │ completed_at       │
          └────────────────────┘


  ┌─────────────────────────────────────────────────────────┐
  │                  OPERATIONAL                             │
  └─────────────────────────────────────────────────────────┘

          (NotificationRule, CVEWatchFinding, AuditLog
           as previously defined)
```

### VEX Does Not Delete — It Contextualizes (see ADR-4)

**Critical design principle**: VEX assertions never suppress or delete vulnerability findings. Instead, they add a contextual layer that changes the *effective state* of a vulnerability.

```
  VULNERABILITY STATES — HOW THEY RELATE
  ═══════════════════════════════════════════════════════════

  Scanner detects CVE-2024-1234 in lodash@4.17.21
      │
      ▼
  raw finding stored:  vulnerability = CVE-2024-1234
  (IMMUTABLE)          component_purl = pkg:npm/lodash@4.17.21
                       severity = HIGH
                       ↑ THIS NEVER CHANGES. EVIDENCE IS PERMANENT.
      │
      ▼
  VEX assertion says:  status = not_affected
  (IMMUTABLE)          justification = code_not_reachable
                       ↑ THIS IS ALSO PERMANENT EVIDENCE.
      │
      ▼
  risk_context computes:  effective_state = SUPPRESSED
  (MUTABLE)               suppression_reason = "VEX: code_not_reachable"
                           raw_severity = HIGH  (preserved!)
                           vex_status = not_affected
                           ↑ BOTH TRUTHS COEXIST.
                             The vuln IS high severity.
                             The VEX says not affected.
                             The effective state is suppressed.
                             Nothing is hidden or deleted.
      │
      ▼
  If VEX is later revoked, or new info emerges:
      effective_state reverts to DETECTED
      The raw finding was always there.
```

This means:

- **Auditors** can always see every vulnerability ever detected, regardless of triage state
- **VEX revocation** is safe — removing a VEX assertion resurfaces the finding because it was never deleted
- **Compliance** queries can report on "all detected" vs "effectively active" separately
- **Risk scoring** can factor in both raw severity AND contextual suppression
- **Triage history** is a chain of immutable decisions, not overwrites

### Key Relationships

- **Image digest (SHA-256)** is the anchor identity — tags are mutable aliases, digests are immutable content hashes
- **PURL** is the universal join key across components, VEX assertions, CVE watch, and triage
- **(PURL + CVE ID)** is the fundamental unit of triage — every decision resolves to this pair
- **component_vulnerabilities** is the join table linking a specific component version to a specific vulnerability finding within a specific SBOM document
- **risk_context** sits on top of component_vulnerabilities and holds the computed effective state — this is the single table that answers "what's the current status of this vulnerability?"
- **vex_assertions** link to vulnerabilities by (component_purl + cve_id) — multiple VEX assertions can exist for the same pair (from different sources, over time)
- **ai_enrichment** and **threat_intelligence** feed into risk_context scoring but don't modify raw findings

### Integrity Chain

The full trust chain links every artifact to its source:

```
  image_signature ──verifies──▶ image_digest (SHA-256)
                                     │
  sbom_signature ──verifies──▶ sbom_checksum (SHA-256)
                                     │ sbom references image_digest
                                     │
  vex_signature ──verifies──▶  vex_checksum (SHA-256)
                                     │ vex references sbom_checksum

  At any point, Themis can verify:
  "This VEX (hash Y) was signed by X,
   applies to SBOM with hash Z,
   which describes image with digest W,
   which was signed by V."
```

### Deduplication Strategy

Multiple CI events can trigger ingestion of the same artifact. Dedup prevents redundant processing:

```
  DEDUP KEY = (image_digest + sbom_checksum)

  Same image + same SBOM content  → DUPLICATE. Return existing. Idempotent.
  Same image + DIFF SBOM content  → NEW SCAN. Store. Link to same image.
                                     Mark as latest. (Different scanner,
                                     different DB version, or different time.)
  Different image + any SBOM      → NEW INGESTION. Store normally.
```

- On ingestion, Themis computes SHA-256 of the raw SBOM document and checks `UNIQUE(image_digest, checksum_sha256)`
- Duplicates return `200 OK` with a reference to the existing ingestion — no re-processing
- New SBOMs for existing images set `is_latest = true` on the new record and `is_latest = false` on the previous, with `supersedes_id` linking them
- VEX documents are deduped similarly: `UNIQUE(sbom_checksum, checksum_sha256)`

## Workflows

### Ingestion Lifecycle

```
  ┌──────────┐    ┌───────────┐    ┌───────────┐    ┌───────────┐    ┌──────────┐
  │ RECEIVED │───▶│VALIDATING │───▶│CORRELATING│───▶│ ENRICHING │───▶│COMPLETED │
  └──────────┘    └───────────┘    └───────────┘    └───────────┘    └──────────┘
       │               │                │                │               │
       │               ▼                ▼                │               ▼
       │          ┌──────────┐    ┌──────────┐           │        ┌──────────┐
       │          │ REJECTED │    │  FAILED  │           │        │ NOTIFIED │
       │          │(trust or │    │(correlat-│           │        └──────────┘
       │          │ schema   │    │ ion error│           │
       │          │ failure) │    │ retry-   │           ▼
       │          └──────────┘    │ able)    │    VEX contextualization
       │                          └──────────┘    + risk scoring (L3)
       ▼                                         then human triage
  ┌──────────┐                                   (L4) via API calls
  │ REJECTED │
  │(invalid  │
  │ payload) │
  └──────────┘
```

- **RECEIVED**: Webhook or upload accepted, payload structurally valid
- **VALIDATING**: Artifact validation gate — signature verification, provenance validation, schema conformance, hash verification, supplier identity checks. Trust status assigned.
- **CORRELATING**: SBOM parsed and normalized; components extracted; vulnerability correlation against known CVEs; raw findings stored (immutable)
- **ENRICHING**: VEX contextualization applied; effective state computed; EPSS/KEV/threat intel checked; risk score computed; AI enrichment queued
- **COMPLETED**: All processing done, results stored, risk_context populated
- **NOTIFIED**: Notification dispatched per configured rules
- **FAILED**: Correlation or enrichment error (retryable)
- **REJECTED**: Invalid input, trust validation failure, or schema non-conformance (not retryable)

### CVE Triage Lifecycle (per vulnerability)

Triage changes the **effective state** in `risk_context`, never the raw finding. All states coexist — the raw vulnerability, VEX assertion, and triage decision are all preserved as immutable evidence.

```
  ┌────────────┐    ┌────────────────┐    ┌──────────────┐
  │  DETECTED  │───▶│  SUPPRESSED    │    │   RESOLVED   │
  │(raw finding│    │ (VEX says not  │    │ (fix applied │
  │ preserved) │    │  affected, but │    │  or upgraded)│
  └────────────┘    │  finding stays)│    └──────────────┘
       │            └────────────────┘           ▲
       │                   │                     │
       │                   ▼                     │
       │            ┌────────────────┐           │
       │            │  CONFIRMED     │           │
       │            │ (VEX confirms  │───────────┘
       │            │  affected)     │
       │            └────────────────┘
       │
       ├───────────▶┌────────────────┐
       │            │  IN_TRIAGE     │
       │            │ (awaiting L4   │
       │            │  human review) │
       │            └───────┬────────┘
       │                    │
       │              ┌─────┴──────┐
       │              ▼            ▼
       │     ┌──────────────┐ ┌──────────────┐
       │     │FALSE_POSITIVE│ │ACCEPTED_RISK │
       │     │(human: not   │ │(human: known │
       │     │ exploitable, │ │ risk, defer  │
       │     │ with reason) │ │ remediation) │
       │     └──────────────┘ └──────────────┘
       │
       │  If VEX revoked or new intel arrives:
       │  effective_state reverts to DETECTED
       │  because the raw finding was NEVER deleted
       └──────────────────────────────────────────
```

**State transitions:**

- **DETECTED → SUPPRESSED**: VEX assertion with `status=not_affected` applies. The raw finding remains. The suppression reason is recorded. If the VEX is later revoked, state reverts to DETECTED.
- **DETECTED → CONFIRMED**: VEX assertion with `status=affected` applies, confirming the vulnerability is real and exploitable.
- **DETECTED → IN_TRIAGE**: No VEX applies; escalated for human review (L4).
- **IN_TRIAGE → FALSE_POSITIVE**: Human decides not exploitable, provides justification. Themis generates a VEX assertion from this decision (L4 → L3 upgrade for future scans).
- **IN_TRIAGE → ACCEPTED_RISK**: Human acknowledges the risk but defers remediation, with documented justification.
- **CONFIRMED → RESOLVED**: Remediation applied (upgrade, patch, workaround).
- **Any state → DETECTED**: VEX revocation, new threat intelligence, or version change invalidates prior context. The raw finding resurfaces because it was never deleted.

### CVE Watch Job Flow

```
  ┌─────────┐     ┌───────────┐     ┌────────────┐     ┌───────────┐
  │ Schedule│────▶│ Fetch new │────▶│ Match vs   │────▶│ Create    │
  │ (cron)  │     │ CVEs from │     │ component  │     │ findings  │
  └─────────┘     │ NVD / OSV │     │ catalog    │     │ + notify  │
                  └───────────┘     └────────────┘     └───────────┘
```

## Authentication

Full RBAC is out of scope for v1, but the API must not be completely open. Minimal v1 authentication:

- **API key-based auth**: All API calls require an `X-API-Key` header; keys are stored hashed in the database
- **Webhook signature verification**: CI webhooks include an HMAC-SHA256 signature (`X-Themis-Signature`) computed from a shared secret; Themis validates before processing
- **Key scoping**: API keys are scoped to a product (or global for admin operations); a key scoped to Product A cannot access Product B's data
- **Key management**: Keys are created/rotated via a CLI command (`themis admin create-key --product <id> --scope <read|write|admin>`); no self-service API for key management in v1
- **Future**: OIDC/OAuth2 integration and RBAC with roles (viewer, triager, admin) planned for Phase 3 (Themis native GUI)

## Artifact Trust & Validation

Themis ingests SBOM and VEX documents from multiple sources — CI pipelines, third-party vendors, external suppliers, and customer-provided artifacts. Trust cannot be assumed. Every artifact passes through a validation gate before ingestion.

### Validation Gate

```
  Incoming SBOM/VEX artifact
       │
       ▼
  ┌─────────────────────────────────────────────────────────┐
  │                 VALIDATION GATE                          │
  ├─────────────────────────────────────────────────────────┤
  │                                                         │
  │  1. Signature Verification                              │
  │     ├─ Verify cosign / sigstore / in-toto / PGP         │
  │     ├─ Match signer identity to known/trusted signers   │
  │     ├─ If unsigned: accept with trust_status=unsigned   │
  │     │   (configurable: reject unsigned per product)     │
  │     └─ If signature invalid: reject, log security event │
  │                                                         │
  │  2. Provenance Validation                               │
  │     ├─ Verify CI pipeline provenance fields present     │
  │     ├─ Cross-check: does supplier_identity match the    │
  │     │   registered product owner?                       │
  │     ├─ For third-party: is supplier in the trusted      │
  │     │   supplier registry?                              │
  │     └─ Log provenance gaps as warnings (not blocking)   │
  │                                                         │
  │  3. Schema Conformance                                  │
  │     ├─ Validate against CycloneDX / SPDX JSON schema   │
  │     ├─ Check spec version is supported                  │
  │     ├─ Reject malformed documents with detailed error   │
  │     └─ For VEX: validate against OpenVEX / CSAF schema  │
  │                                                         │
  │  4. Integrity (Hash Verification)                       │
  │     ├─ Compute SHA-256 of raw document                  │
  │     ├─ Compare against provided checksum (if any)       │
  │     └─ Store checksum for future deduplication          │
  │                                                         │
  │  5. Deduplication Check                                 │
  │     ├─ SBOM: lookup UNIQUE(image_digest,                │
  │     │   checksum_sha256)                                │
  │     │   → Match found: return existing ingestion ref    │
  │     │     (200 OK, idempotent, no re-processing)        │
  │     │   → No match, same image: new scan of existing    │
  │     │     image — mark as latest, link via supersedes_id│
  │     │   → No match, new image: new ingestion            │
  │     ├─ VEX: lookup UNIQUE(sbom_checksum,                │
  │     │   checksum_sha256)                                │
  │     │   → Same dedup logic as SBOM                      │
  │     └─ Ensures CI retries and duplicate events are safe │
  │                                                         │
  │  6. Integrity Chain Verification                        │
  │     ├─ SBOM must reference a known image_digest         │
  │     │   (image already registered in Themis)            │
  │     ├─ VEX must reference a known sbom_checksum         │
  │     │   (SBOM already ingested in Themis)               │
  │     └─ If reference target unknown: reject with error   │
  │        "image/SBOM not found — ingest parent first"     │
  │                                                         │
  │  7. Supplier Identity (for external sources)            │
  │     ├─ Third-party vendors: match against trusted       │
  │     │   supplier registry                               │
  │     ├─ External suppliers: validate org identity from   │
  │     │   signing certificate                             │
  │     ├─ Customer-provided: flag for additional review    │
  │     └─ Unknown supplier: accept with elevated trust     │
  │        scrutiny (configurable per product)              │
  │                                                         │
  └─────────────────────────────────────────────────────────┘
       │
       ▼
  trust_status assigned:
    verified    → signature valid, provenance confirmed, schema valid
    unverified  → unsigned but schema valid, provenance present
    failed      → signature invalid (rejected) or schema invalid
    unsigned    → no signature provided, policy allows acceptance
```

### Trust Policies

Trust validation is configurable per product:

- **Strict** (recommended for production): Require signed SBOM, verified supplier, complete provenance. Reject unsigned or unverifiable artifacts.
- **Standard** (default): Accept unsigned artifacts with `trust_status=unsigned`. Require valid schema. Log missing provenance as warnings.
- **Permissive** (for testing/dev): Accept all valid-schema artifacts. Useful for manual upload workflow during initial testing.

## Security Implications

- **Artifact trust**: All SBOM/VEX documents pass through a validation gate verifying signatures, provenance, schema conformance, hashes, and supplier identity before ingestion. Trust status is recorded and queryable.
- **Supply chain trust**: Third-party vendor and external supplier artifacts are validated against a trusted supplier registry; unknown suppliers are flagged. Customer-provided artifacts receive elevated scrutiny.
- **Input validation**: All SBOM/VEX uploads are validated against CycloneDX/SPDX/OpenVEX/CSAF JSON schemas before processing; malformed or oversized payloads are rejected with a 400 response. Maximum upload size is configurable (default 50MB)
- **Webhook signature verification**: Every CI webhook request must include an HMAC-SHA256 signature; unsigned or incorrectly signed requests are rejected with 401 and logged as a security event
- **Secrets management**: Registry credentials, SMTP passwords, Teams webhook URLs, signing keys, and API key salts are loaded from environment variables or a secrets provider (e.g., Vault, K8s Secrets) — never from config files or CLI arguments
- **SQL injection**: All database queries use parameterized statements via Go's `database/sql` or an ORM with prepared statements; no string concatenation in queries
- **SBOM content risks**: SBOMs from untrusted sources could contain excessively large component trees or malicious content in description fields; ingestion enforces component count limits and sanitizes text fields
- **Scanner execution**: Removed from scope — Themis parses CI-generated scanner output, it does not invoke scanners as subprocesses. No shell execution risk from scanner invocation.
- **Data isolation**: Multi-product data is isolated at the query level via product-scoped API keys; database-level row-level security is a future enhancement
- **Audit trail**: All triage decisions, configuration changes, key management actions, and artifact trust validation results are audit-logged with actor identity and timestamp
- **Immutability enforcement**: Raw SBOM documents, VEX documents, and vulnerability findings are stored append-only; no API endpoint permits mutation or deletion of immutable evidence

## Impact

- **New codebase**: Go backend with REST API
- **External dependencies**: NVD/OSV APIs for CVE feeds, EPSS/KEV data sources, SMTP/Teams webhook for notifications
- **Infrastructure**: Requires a database (PostgreSQL likely) for SBOM/vuln storage, a message queue or scheduler for CVE watch and intelligence sync jobs
- **CI/CD integration**: Thin shared pipeline libraries per CI system (Jenkins first) that generate SBOM, sign it, and POST the signed artifact to Themis webhook
- **No scanner dependency**: Themis does not invoke scanners — it parses scanner-generated output. No Trivy/Docker installation required on the Themis host.
- **Phase 2 UI integration**: Web UI approach is an open decision (see ADR-9) — options include DefectDojo integration, Themis native UI, or hybrid. Decision deferred until Phase 1 completes. Phase 1 API must be designed to support any path.
- **Phase 3 full GUI**: Regardless of Phase 2 path, Phase 3 delivers a full-featured Themis-native web experience with separate design rounds

## Development Phases

Development is organized into three phases, each building on the previous. Phase boundaries are gates — a phase is not started until the prior phase achieves its acceptance criteria.

### Phase 1 — Core Intelligence Platform (API-only, No UI)

**Goal**: Deliver the foundational backend that ingests SBOM/VEX artifacts, normalizes data across the three-layer model, correlates vulnerabilities, and exposes results via REST API with email/Teams notifications.

**In scope:**

- Go backend with REST API (no frontend/dashboard)
- Event-driven ingestion of CI-generated SBOM/VEX artifacts via webhook (CI-agnostic)
- Artifact trust validation gate with configurable trust policies per product (strict/standard/permissive)
- SBOM/VEX signature verification (cosign, sigstore, in-toto, PGP) with provenance and supplier identity validation
- Scanner-agnostic SBOM/VEX parser with pluggable format adapters (Trivy output as first adapter)
- Manual SBOM/VEX upload API for testing and iterative review
- Multi-product, multi-project data model and storage (PostgreSQL)
- Three-layer data model: immutable inventory (L1), mutable vulnerability intelligence (L2), temporal exploitability context (L3)
- Vulnerability correlation engine matching components against known CVEs
- CVE triage engine: automated VEX-based contextualization (L3) + human triage with justification (L4)
- Background CVE watch jobs polling NVD/OSV feeds against stored component catalog
- Continuous intelligence enrichment: EPSS scoring, KEV sync, threat intel, AI enrichment
- Configurable notification delivery via email (SMTP) and Microsoft Teams (webhook)
- Configuration-driven setup for SBOM parsers, CVE feeds, notification channels, and trust policies
- API key-based authentication with product-scoped keys
- REST API with query/filter capabilities so that vulnerability posture, scan results, and triage state are visible and actionable without a UI

**Out of scope for Phase 1:**

- Web dashboard / UI (Phase 2 — approach to be decided after Phase 1, see ADR-9)
- Full RBAC with roles and OIDC/OAuth2 integration (API key auth only)
- Compliance framework reporting (SOC2, FedRAMP, etc.)
- Reachability analysis or context-aware rule engine for false positive detection
- Scanner integrations beyond Trivy output parsing (pluggable, but not built in Phase 1)

**Exit criteria**: All Phase 1 acceptance criteria (see Acceptance Criteria section) are met. A CI pipeline can push SBOM/VEX → Themis ingests → correlates → enriches → notifies. Results are queryable via REST API. Email notifications fire on scan completion, triage events, and new CVE discovery.

### Phase 2 — Themis Native Web UI

**Goal**: Deliver a purpose-built web frontend for Themis that showcases the three-layer intelligence model, VEX-centric workflows, and continuous enrichment pipeline. The UI is built incrementally — minimal viable dashboard first, triage workflows second, advanced visualization third.

**Rationale for native UI over DefectDojo integration** (see ADR-9 for full analysis):

Under the one-directional sync constraint (Themis → DefectDojo only, Themis is sole source of truth), DefectDojo loses its strongest features (triage workflows, risk acceptance, SLA management) and becomes a read-only dashboard. A feature-by-feature analysis shows that 5 of 7 demo requirements are better served by native UI, the effort is comparable (~3-4 weeks either path), and native UI produces no throwaway code. DefectDojo integration remains available as an optional one-directional export in Phase 3 for organizations already running DefectDojo.

**Architecture:**

```
  ┌──────────────────────────────────────────────────────────────────┐
  │  THEMIS (Single Deployment)                                       │
  │                                                                   │
  │  ┌──────────────────────────────────────────────────────────────┐ │
  │  │  Go Backend (Phase 1)                                        │ │
  │  │  REST API  │  Ingestion  │  Correlation  │  Enrichment       │ │
  │  │  ──────────┤─────────────┤───────────────┤───────────────    │ │
  │  │  Three-Layer Data Model (PostgreSQL)                         │ │
  │  └────────────────────────────┬─────────────────────────────────┘ │
  │                               │ REST API                          │
  │  ┌────────────────────────────▼─────────────────────────────────┐ │
  │  │  Web Frontend (Phase 2) — React/Vue SPA                      │ │
  │  │                                                              │ │
  │  │  Phase 2a: Dashboard + Finding List + RiskContext Detail      │ │
  │  │  Phase 2b: Triage UI + VEX Viewer + Intelligence Signals     │ │
  │  │  Phase 2c: Integrity Chain + Dep Graph + RBAC                │ │
  │  └──────────────────────────────────────────────────────────────┘ │
  └──────────────────────────────────────────────────────────────────┘
```

**Incremental delivery plan (within 3-month timeline):**

Phase 2a — Minimal Viable Dashboard (~2 weeks):

- Vulnerability posture dashboard: severity distribution chart, scan count, active finding count per product
- Product/project listing with scan status indicators
- Finding list with filters (severity, status, product, CVE, component)
- Finding detail view showing full RiskContext:
  - L1: raw finding (severity, CVE, component, source scanner)
  - L2: VEX assertions applied (status, justification, source, signature verification)
  - L3: intelligence signals (EPSS score, KEV status, AI confidence)
  - Effective state with explanation ("why this score?")
- Scan history / ingestion status per project
- Basic authentication (API key → browser session)

Phase 2b — Triage & Intelligence Workflows (~1.5 weeks):

- Triage decision UI: mark false positive / accepted risk / confirmed, enter justification
- VEX assertion viewer: which assertions apply to a finding, provenance, revocation status
- Intelligence signal panel: EPSS score with trend indicator, KEV listing status, AI enrichment confidence
- Notification configuration UI: manage routing rules, channels, severity thresholds
- Search: cross-product search by CVE ID, component PURL, product name

Phase 2c — Advanced Visualization (~1 week, stretch goal):

- Integrity chain visualization: image → SBOM → VEX with signature verification status per level
- Component catalog browser: "which products contain component X?"
- Basic dependency graph view (direct/transitive)

**Technology choices (to be finalized at Phase 2 start):**

- Frontend framework: React or Vue with TypeScript
- Component library: Shadcn/ui, Ant Design, or MUI (commodity UI components — tables, forms, charts — should not be built from scratch)
- Chart library: Recharts, Chart.js, or similar
- Build tooling: Vite
- Served by: Go backend serves the SPA static assets (single deployment)

**Phase 2 In scope:**

- Web frontend (SPA) for Themis, served from the Go backend
- Dashboard, finding list, finding detail with RiskContext, triage actions
- VEX assertion viewer and intelligence signal display
- Basic authentication (API key → session; single admin user sufficient for demo)
- Scan history and ingestion status views

**Phase 2 Out of scope:**

- Full RBAC with roles and OIDC/OAuth2 (Phase 3)
- Report generation / PDF export (Phase 3)
- Issue tracker integration — Jira, GitHub Issues (Phase 3)
- DefectDojo integration (Phase 3 optional add-on)
- Compliance framework views (Phase 3)
- Configurable dashboard builder (Phase 3)

**Exit criteria**: A security engineer can open the Themis web UI, see vulnerability posture across products, drill into findings with full RiskContext (L1+L2+L3), triage vulnerabilities with justifications, and see VEX assertions and intelligence signals. The demo showcases Themis's unique three-layer model and VEX overlay semantics visually.

### Phase 3 — Full-Featured Platform

**Goal**: Extend the Themis web UI into a comprehensive vulnerability management platform with enterprise features. Phase 3 builds on everything from Phase 2 — no throwaway work.

**Phase 3 capabilities (designed in separate rounds):**

- Comprehensive vulnerability posture dashboards with drill-down (cross-product, cross-version, historical trending)
- Full VEX lifecycle UI: create, view, revoke assertions; visualize overlay semantics; provenance chain
- Intelligence signal timelines: EPSS score evolution, KEV listing history, AI confidence changes over time
- Integrity chain explorer: interactive visualization of image → SBOM → VEX signature verification
- Component catalog browser with dependency graph and impact analysis ("which products use lodash@4.17.21?")
- Triage workflow builder: configurable L3 → L4 escalation rules, SLA tracking, assignment
- Report generation: compliance-oriented exports, executive summaries, audit trail reports
- Full RBAC with OIDC/OAuth2, multi-tenancy, row-level security
- Issue tracker integration (Jira, GitHub Issues, ServiceNow) — push Themis findings with full RiskContext
- Configurable dashboard builder (custom views per role)
- **Optional DefectDojo export adapter**: one-directional push of Themis findings to DefectDojo for organizations already running DefectDojo. Simple adapter, not a sync engine. No data flows back.

**Phase 3 requires separate design rounds** covering UI/UX design, frontend architecture evolution, API surface extensions, and authentication architecture. Phase 3 design begins only after Phase 2 is operational and validated.

### Phase Dependency Diagram

```
  Phase 1                      Phase 2                        Phase 3
  ═══════                      ═══════                        ═══════
  Core Intelligence            Themis Native UI               Full-Featured
  Platform (API-only)          (Incremental)                  Platform

  ┌─────────────────┐          ┌─────────────────────┐        ┌─────────────────────┐
  │ SBOM/VEX        │          │ 2a: Dashboard +     │        │ Compliance Reports  │
  │ Ingestion       │          │     Finding List +   │        │ Executive Dashboards│
  │                 │          │     RiskContext View  │        │ VEX Lifecycle Mgmt  │
  │ Three-Layer     │────────▶ │                     │───────▶│ Intelligence        │
  │ Data Model      │          │ 2b: Triage UI +     │        │   Timelines         │
  │                 │          │     VEX Viewer +     │        │ Full RBAC +         │
  │ Correlation &   │          │     Intel Signals    │        │   OIDC/OAuth2       │
  │ Enrichment      │          │                     │        │ Issue Tracker       │
  │                 │          │ 2c: Integrity Chain  │        │   Integration       │
  │ REST API        │          │     + Dep Graph      │        │ Optional DD Export  │
  │ Notifications   │          │     (stretch)        │        │ Multi-tenancy       │
  │ API Key Auth    │          │                     │        │                     │
  └─────────────────┘          └─────────────────────┘        └─────────────────────┘

  Exit: API works,            Exit: Visual demo of          Exit: Enterprise-ready
  CI→ingest→enrich→notify     Themis intelligence           platform
                              pipeline + triage
```

## Scope

Phase 1 defines the initial scope. See Development Phases above for Phase 2 and Phase 3 scope.

**In scope (Phase 1):**

- Go backend with REST API (no frontend/dashboard)
- Event-driven ingestion of CI-generated SBOM/VEX artifacts via webhook (CI-agnostic)
- Artifact trust validation gate with configurable trust policies per product (strict/standard/permissive)
- SBOM/VEX signature verification (cosign, sigstore, in-toto, PGP) with provenance and supplier identity validation
- Scanner-agnostic SBOM/VEX parser with pluggable format adapters (Trivy output as first adapter)
- Manual SBOM/VEX upload API for testing and iterative review
- Multi-product, multi-project data model and storage (PostgreSQL)
- Vulnerability correlation engine matching components against known CVEs
- CVE triage engine: automated VEX-based contextualization (L3) + human triage with justification (L4)
- Background CVE watch jobs polling NVD/OSV feeds against stored component catalog
- Continuous intelligence enrichment: EPSS scoring, KEV sync, threat intel, AI enrichment
- Configurable notification delivery via email (SMTP) and Microsoft Teams (webhook)
- Configuration-driven setup for SBOM parsers, CVE feeds, notification channels, and trust policies

**Out of scope (Phase 1 — addressed in later phases):**

- Web dashboard / UI (Phase 2 — approach TBD, see ADR-9)
- DefectDojo integration or Themis native GUI (Phase 2 decision point)
- Full RBAC with roles and OIDC/OAuth2 integration (Phase 2b/3; API key auth in Phase 1)
- Compliance framework reporting (SOC2, FedRAMP, etc.)
- Reachability analysis (L1) or context-aware rule engine (L2) for false positive detection
- Scanner integrations beyond Trivy output parsing (BlackDuck, Grype output adapters — pluggable, but not built in Phase 1)
- CI-specific plugins (only thin shared library wrappers via webhook)

## Motivation

Security scanning in CI/CD pipelines today is fire-and-forget: a scanner runs, produces a report, and the report disappears into build logs. There is no persistent catalog of what components are deployed, no institutional memory of triage decisions, and no proactive monitoring when a new CVE is disclosed against a component already in production.

Product teams waste time re-triaging the same false positives across builds. Security teams lack visibility across products. When a critical zero-day drops, there is no quick way to answer "which of our products are affected?"

Themis exists to close these gaps — creating a single source of truth for SBOMs, vulnerability triage history, and proactive CVE alerting, accessible to both security and product teams.

## Affected Components

| Component | Type | Description |
|-----------|------|-------------|
| Themis API Server | New | Go HTTP server exposing REST endpoints for webhooks, SBOM/VEX upload, triage, and configuration |
| Artifact Validation Gate | New | Trust verification layer — signature, provenance, schema, hash, and supplier identity checks |
| SBOM/VEX Parser Layer | New | Pluggable format adapters normalizing CycloneDX, SPDX, OpenVEX, CSAF into internal canonical model (Trivy output adapter first) |
| Vulnerability Correlation Engine | New | Matches ingested components against known CVE databases to produce raw findings |
| SBOM & Vulnerability Store | New | PostgreSQL schema for products, images, SBOMs, components, vulnerabilities, triage decisions |
| CVE Triage Engine | New | Service combining VEX-based auto-contextualization with human triage workflow and justification tracking |
| CVE Watch Agent | New | Background scheduler polling NVD/OSV feeds and matching against component catalog |
| Continuous Intelligence Service | New | EPSS/KEV sync, threat intel feed integration, AI enrichment, risk score computation |
| Notification Service | New | Configurable dispatcher for email (SMTP) and Teams (webhook) notifications |
| CI Shared Libraries | New | Thin wrappers (Jenkins shared lib first) that POST signed SBOM/VEX to Themis webhook after image build |

## User Impact

- **DevOps / CI Engineers**: Add a single webhook call or shared library step to existing pipelines — minimal friction to onboard
- **Security Teams**: Gain cross-product visibility into SBOM inventory and vulnerability posture without manually aggregating scanner outputs
- **Product Owners**: Can triage CVEs with custom justifications (e.g., "dependency present but unused function"), and those decisions persist across future scans
- **Engineering Leads**: Receive proactive alerts when new CVEs affect components in their product catalog, rather than discovering issues reactively

## Acceptance Criteria

1. A CI/CD system can POST a signed SBOM/VEX artifact (generated by the CI scanner) to the Themis webhook, triggering event-driven ingestion
2. Themis parses the ingested SBOM (CycloneDX or SPDX) via pluggable format adapters, normalizes components into the internal canonical model, and stores both the raw document (immutable) and normalized form
3. Pre-generated SBOM/VEX documents can be uploaded via the manual upload API and are processed through the same validation, correlation, and enrichment pipeline as webhook-ingested artifacts
4. Ingested artifacts pass through the artifact validation gate — signature verification, provenance validation, schema conformance, hash verification — and trust status is recorded and queryable per artifact
5. Vulnerability correlation matches ingested components against known CVEs; raw findings are stored immutably and classified by severity (Critical, High, Medium, Low) per product/project
6. Automated VEX-based contextualization (L3) changes the effective state of a vulnerability to SUPPRESSED — the raw finding is preserved, never deleted; if the VEX is revoked, the finding resurfaces
7. Product owners can manually triage CVEs as false positive or accepted risk with a custom justification; Themis generates a VEX assertion from L4 decisions so they auto-apply in future ingestions (L4 → L3 upgrade)
8. Background CVE watch jobs detect newly disclosed CVEs that match components in the stored catalog and create new findings — between builds, not only at ingestion time
9. Continuous intelligence enrichment (EPSS scoring, KEV sync, threat intel) updates risk context between builds; a composite risk score is computed and re-computed as new intelligence arrives
10. Notifications (email and/or Teams) are sent on ingestion completion, triage events, and new CVE discovery, with configurable routing rules (who, when, what severity)
11. The system supports multiple products and multiple projects with data isolation
12. SBOM parser choice is configuration-driven — no hardcoded format/scanner references in core logic; adding a new scanner output adapter does not require core changes
13. Immutable build artifacts (raw SBOMs, VEX documents, vulnerability findings, provenance, signatures) cannot be mutated or deleted through any API; mutable intelligence (Layer 2 vulnerability intelligence, Layer 3 temporal signals) is updated independently without altering raw evidence (Layer 1); AI-generated intelligence remains logically separate from immutable SBOM inventory
14. Duplicate SBOM ingestion for the same image (same image_digest + same sbom_checksum) is idempotent — returns a reference to the existing ingestion without re-processing; different SBOMs for the same image (new scanner version, different scanner) are stored as new evidence with `is_latest` ordering
15. A verifiable integrity chain links VEX → SBOM → image: each VEX references the SBOM checksum it applies to, each SBOM references the image digest it describes, and each level carries its own signature and checksum for independent verification

## Assumptions

- CI/CD pipelines generate SBOM and VEX artifacts at build time (e.g., via Trivy, Syft, or similar scanners running in CI)
- CI pipelines sign SBOM artifacts before posting to Themis (cosign/sigstore/in-toto; unsigned artifacts accepted under permissive trust policy)
- PostgreSQL is used as the primary data store
- NVD and/or OSV provide publicly accessible APIs for CVE feed polling
- EPSS scores and CISA KEV list are publicly accessible for threat intelligence enrichment
- Email delivery is via SMTP; Teams notifications are via incoming webhook connectors
- Themis does NOT need access to container registries or scanner binaries — it receives pre-generated artifacts
- There is no existing authentication system — Themis API is initially deployed in a trusted network or behind a reverse proxy
- CI systems can make outbound HTTP calls to the Themis webhook endpoint

## Risks

| Risk | Severity | Mitigation |
|------|----------|------------|
| Scanner wrapper abstraction may leak tool-specific semantics, making true agnosticism difficult | Medium | Define a minimal common parser interface; accept that edge-case fields may be adapter-specific |
| NVD API rate limits or downtime could disrupt CVE watch functionality | Medium | Implement caching, exponential backoff, and support OSV as a fallback feed |
| SBOM format inconsistencies between CycloneDX and SPDX complicate normalization | Medium | Normalize to an internal canonical model on ingestion; store original alongside |
| False positive triage at L3+L4 requires well-maintained VEX data from upstream vendors, which may be sparse | High | L4 (human triage) serves as fallback; track VEX coverage metrics to identify gaps |
| Multi-product scale could cause CVE watch jobs to become expensive as the component catalog grows | Medium | Index components efficiently; batch NVD/OSV queries; run incremental diffs rather than full scans |
| No auth/RBAC in v1 means the API is open — risk if exposed beyond trusted network | High | Document deployment behind reverse proxy; plan RBAC as a fast-follow capability |
| Notification fatigue from high volume of low-severity CVE alerts | Medium | Default notification rules should filter by severity threshold; make fully configurable |

## Performance Considerations

- **SBOM parsing**: Large SBOMs (10K+ components) are parsed in streaming fashion where possible; ingestion is bounded by a configurable timeout (default: 5 minutes)
- **Database indexing**: Component catalog is indexed by PURL for fast CVE watch matching; vulnerability queries are indexed by `(project_id, severity, status)` for efficient filtering
- **CVE watch batching**: Background jobs query NVD/OSV in batches grouped by component ecosystem (npm, maven, pypi, etc.) rather than per-component to minimize API calls
- **Notification throttling**: Notification dispatch uses a rate limiter to prevent SMTP/Teams throttling; bulk notifications (e.g., CVE watch finds 50 new matches) are aggregated into digest messages
- **Connection pooling**: PostgreSQL connection pool sized to max concurrent scans + API request load; configurable via environment variable
- **Async processing**: Scan orchestration, triage, and notification are asynchronous (queued); the webhook endpoint returns 202 Accepted immediately, keeping API response times under 200ms

## Telemetry & Observability

Themis must be observable from day one. As a backend system processing security-critical data asynchronously, operators need visibility into system health and processing status.

- **Metrics**: Expose Prometheus-compatible metrics — scan queue depth, scan duration histograms, CVE watch job execution time, notification delivery success/failure counts, SBOM ingestion rates per product/project
- **Tracing**: Distributed tracing (OpenTelemetry) across the scan lifecycle — from webhook receipt through scanner invocation, SBOM parsing, triage, to notification dispatch
- **Health checks**: Liveness and readiness endpoints (`/healthz`, `/readyz`) covering database connectivity, scanner availability, and CVE feed reachability
- **Dashboard-ready**: Metrics should be scrapable by Prometheus/Grafana without requiring Themis to ship its own dashboard

## Logging

- **Structured logging**: All logs in JSON format with consistent fields (`timestamp`, `level`, `component`, `request_id`, `product`, `project`)
- **Log levels**: DEBUG, INFO, WARN, ERROR — configurable per component at runtime
- **Audit logging**: Security-sensitive actions must produce audit log entries — triage decisions (marking CVEs as false positive, adding justifications), configuration changes, SBOM uploads, notification rule modifications
- **Correlation**: Every inbound request generates a `request_id` that propagates through all downstream operations (scan, triage, notify) for end-to-end traceability
- **Sensitive data**: SBOM content and CVE details may be logged at DEBUG level; registry credentials, SMTP passwords, and webhook tokens must never appear in logs

## Database Migrations

- **Migration tool**: Use `golang-migrate` for schema versioning — migrations are version-controlled Go files or SQL scripts shipped with the binary
- **Forward-only in production**: All migrations must be forward-compatible; destructive changes (column drops, table renames) require a two-phase approach (deprecate → migrate data → remove)
- **Schema versioning**: Migration version tracked in a `schema_migrations` table; Themis refuses to start if the DB schema is ahead of the binary version
- **Seed data**: Initial migration includes seed data for severity levels and default notification templates
- **Testing**: Every migration must be tested with up + down paths in CI

## Backward Compatibility

- **API versioning**: All REST endpoints are versioned under `/api/v1/`; breaking changes require a new version prefix (`/api/v2/`) with a documented deprecation timeline
- **Webhook contract**: The CI webhook payload schema is versioned; Themis accepts older payload versions with best-effort parsing and logs a deprecation warning
- **SBOM format evolution**: CycloneDX and SPDX spec versions evolve; Themis normalizes to an internal canonical model, isolating core logic from format version changes
- **Configuration**: Config file format changes are backward-compatible; new fields have defaults, removed fields are ignored with a warning
- **Scanner wrapper interface**: The pluggable scanner interface is versioned; older adapters continue to work until explicitly deprecated
