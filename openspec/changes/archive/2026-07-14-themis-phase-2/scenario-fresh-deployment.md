# Scenario: First SBOM Upload on a Fresh Phase 2 Deployment

Captured from design exploration session (2026-06-09). Updated 2026-06-10.
Use this to verify each Phase 2 sub-phase covers cold-start behaviour
and as a regression check during acceptance testing.

Sub-phase annotations used throughout: `[2a]` Signal Foundation ·
`[2b]` AI Intelligence · `[2c]` AI-Assisted VEX.

---

## Setup State

The available capabilities depend on which sub-phase has been deployed.

### Phase 2a entry point — Signal Foundation

```text
PostgreSQL:    migrations 000001–000014 + 000017 applied
               vulnerabilities table:  EMPTY
               graph nodes/edges:      EMPTY — no microservices, deployments, customers
               intelligence_signals:   EMPTY — epss/kev feeds not yet synced
               upstream VEX:           EMPTY — vendor feeds not yet synced
               pgvector / AI tables:   NOT YET — migrations 000015/016 are Phase 2b

Ollama:        NOT required for Phase 2a
ExploitDB:     CSV download: pending or just completed
EPSS/KEV:      first sync: pending or just completed
GHSA:          first sync: pending or just completed
Vendor VEX:    first sync pending (fires daily at ~02:00 UTC)
NVD/OSV:       feeds configured; no local cache yet
```

### Phase 2b entry point — AI Intelligence added

```text
All Phase 2a state above, plus:
  PostgreSQL:    migrations 000015–000016 applied
                 embeddings (L1c):  EMPTY — no KB yet
  Ollama:        running, model pulled (CyberPal-2.0 or Qwen2.5-7B)
```

### Phase 2c entry point — AI-Assisted VEX

```text
All Phase 2b state above, plus:
  KB seeded with ≥ 50 analyst decisions (threshold for auto-apply to be meaningful)
  trust_policy configured (strict / standard / permissive)
```

---

## Prerequisites Before First Upload

```text
Admin must do:
  1. themis-cli create-key --scope product-id  → API key
  2. POST /api/v1/products                     → product_id
  3. POST /api/v1/products/{id}/versions       → version_id
  4. POST /api/v1/products/{id}/images         → image_id (with image_digest)

  ── Group 16 hardening ─────────────────────────────────────────
  ⚠️  Step 4 requires endpoint 16.4 (open). Without it, the admin
     must manually INSERT into the images table via SQL.
     This is a real blocker for a fresh deployment.
  ───────────────────────────────────────────────────────────────

  5. (Optional, but degrades intelligence if skipped) [2a+]
     POST /api/v1/products/{id}/microservices  → microservice_id
     POST /api/v1/microservices/{id}/deployments → deployment_id
     POST /api/v1/customers                    → customer_id
     OQ-9 resolved: explicit registration API is the Phase 2a starting point.
     If skipped: Layer 2 blast-radius = product-only; Context Analyzer
     has no service description → Q5 permanently degraded [2b].

  6. Wait for background syncs before first upload:
     EPSS/KEV sync:      ~2–5 minutes (first pull)          [2a]
     ExploitDB CSV:      ~1–2 minutes                       [2a]
     GHSA sync:          ~5–15 minutes (large dataset)      [2a]
     Vendor VEX feeds:   ~5–30 minutes (multiple vendors)   [2a]
     NVD cache warmup:   LAZY — happens on first component match
```

---

## The Upload

```text
POST /api/v1/sbom
X-API-Key: <key>
{
  "format": "cyclonedx",
  "image_id": "<uuid>",
  "document": { ... 200 components ... }
}
```

---

## Synchronous Path [2a+] (runs before 202 Accepted)

All stages below are Phase 2a capabilities. Stages 1–3 carry forward from Phase 1.

### Stage 1 — Trust Gate

```text
StubVerifier checks:
  ✅ Schema validation (CycloneDX JSON schema)
  ✅ image_id exists in images table
  ✅ image_digest in payload matches images row
  ✅ SBOM checksum computed and stored
  ✅ trust_status = unsigned (standard policy: warning, not rejection)
  ❌ No real cryptographic verification — CosignVerifier is Phase 3

Outcome: passes for standard/permissive policy
         rejected only if schema is invalid or image_id unknown
```

### Stage 2 — Parser

```text
adapter/parser/ converts CycloneDX JSON → CanonicalSBOM
  ✅ Each component gets a PURL assigned
  ✅ Dependency edges extracted
  ✅ SBOM metadata captured (tool, timestamp, target)

⚠️ PURL quality depends on the SBOM generator. Many tools emit
   incomplete PURLs (missing namespace, malformed versions).
   The system does not reject them — it stores what it gets and
   matching quality degrades silently.
   NOTE FOR DISCUSSION (G10): should we validate/normalise PURLs at
   ingest time and reject or warn on malformed ones?
```

### Stage 3 — Store → L0 Population

```text
  ✅ sbom_documents row: raw_document JSONB, checksum_sha256, is_latest=true
  ✅ components / component_versions rows: upserted by PURL
  ✅ dependency_relationships rows: created
  ✅ Deduplication: same (image_digest, checksum_sha256) → idempotent

  ingestion_jobs status: RECEIVED → VALIDATING → CORRELATING
```

### Stage 4 — Vulnerability Correlation

```text
For each of 200 components, the correlator:
  1. Checks local vulnerabilities table → EMPTY on fresh system
  2. Queries NVD API for this package        ← HTTP × 200
  3. Queries OSV API for this package        ← HTTP × 200
  4. Checks GHSA records for this PURL       ← local lookup (if GHSA synced)

⚠️ NVD COLD START PROBLEM (G6):
   Without API key:  rate limit = 5 req/sec → 200 components = ~40 seconds
   With API key:     rate limit = 50 req/sec → 200 components = ~4 seconds
   After first upload: results cached in vulnerabilities table → fast on re-upload

   This is a real operational problem for large SBOMs on a fresh system.
   NOTE FOR DISCUSSION: needs a "warmup mode" — either a pre-population
   job from NVD data dump, or at minimum a documented SLA for first upload.

Result: M component_vulnerabilities rows created (M ≤ 200)
        vulnerabilities table now has all matched CVEs cached
```

### Stage 5 — VEX Overlay

```text
Checks for existing vex_documents matching (component_purl, cve_id) pairs.

Fresh system (Day 1, before first vendor VEX scheduler run):
  vex_documents: EMPTY → no overlay
  All M findings: effective_state = DETECTED ✅ (correct)

After vendor VEX scheduler runs (Day 2+) [2a]:
  vex_assertions has upstream vendor rows (apk + RPM ecosystems)
  Overlay applies vendor not_affected to matched findings:
    effective_state changes DETECTED → NOT_AFFECTED where vendor says so
  VEX precedence enforced: human_triage > user_supplied > ai_generated > upstream_vendor
```

### Stage 6 — Layer 1: Deterministic Rules [2a]

```text
Runs synchronously, per finding:

  CVSS ≥ 9.0 ∧ KEV = true   →  Critical
  CVSS ≥ 9.0 ∧ ExploitPublic →  High+
  KEV = true ∧ CVSS < 9.0   →  High
  EPSS ≥ 0.5 ∧ CVSS ≥ 7.0  →  Elevated
  CVSS ≥ 9.0 (no signals)   →  High (floor)

⚠️ IF EPSS/KEV sync has not yet completed when this upload arrives:
   - kev_listed = false for everything (even genuinely KEV-listed CVEs)
   - epss_score = 0 for everything
   - Layer 1 produces CVSS-only scoring: correct but incomplete
   - The Critical rule (KEV AND CVSS≥9) will NOT fire

⚠️ SCORE STALENESS GAP (G2) — decided:
   When EPSS/KEV sync later completes, it updates intelligence_signals
   rows but must also retroactively update existing risk_context rows.
   Design decision: adapter/epsskev/ enqueues a ReEnrichJob for all
   DETECTED/IN_TRIAGE risk_context rows after each sync. Same ReEnrichJob
   pattern as G12 (upstream VEX) and G1 (AI VEX). [2a]

risk_context.deterministic_level written per finding.
```

### Stage 7 — Layer 2: Graph Reasoning [2a]

```text
SQL traversal: CVE → Package → Product → Microservice → Deployment → Customer

Fresh system (no microservices/deployments/customers registered):
  CVE → Package: ✅ (just correlated)
  Package → Product: ✅ (via product_versions → sbom_documents → component_versions)
  Product → Microservice: ❌ STOPS HERE — no Microservice entities

  blast_radius_score = 1.0 (single product, no amplification)
  affected_teams = []       (no Customer nodes in graph)
  notification queue:       product-scoped only

⚠️ GRAPH EMPTY GAP (G5):
   Layer 2 is structurally correct but produces minimal intelligence.
   "CVE affects 1 product" is all it can say.
   Team-level notifications: impossible (no Customer entities).
   Blast-radius amplification: impossible.

   The graph becomes useful only after Microservices, Deployments,
   and Customers are registered via the Phase 2a registration API (OQ-9 resolved).

✅ This is expected behavior — the system does not fail, it gives partial results.
```

### Stage 8 — risk_context written, 202 Accepted

```text
  ✅ M risk_context rows created with:
     deterministic_level:         set by Layer 1           [2a]
     blast_radius_score:          1.0 (pre-graph)          [2a]
     epss_score:                  NULL or 0 (pre-sync)     [2a]
     kev_listed:                  false (pre-sync)         [2a]
     upstream_vex_coverage:       not_covered (pre-sync)   [2a]
     ai_exploitability:           NULL (Phase 2b pending)
     ai_reachability_confidence:  NULL (Phase 2b pending)

  ✅ Notifications dispatched for findings matching configured rules
     (product-scoped, severity-filtered)

  ingestion_jobs status: CORRELATING → ENRICHING → COMPLETED

→ 202 Accepted returned to caller.

  At Phase 2a: this is the end of the path for this request.
               No async AI workers.
  At Phase 2b+: AIEnrichmentJob is enqueued for findings above the trigger
                threshold (CVSS ≥ 7.0 OR kev_listed OR exploit_public).
```

---

## Async Path [2b+] (starts after 202)

> **Phase 2a:** this section does not apply. The system returns 202 with
> Layer 1+2 results only. No async AI enrichment path exists in Phase 2a.

### Step A — KB Check [2b]

```text
pgvector ANN search on embeddings table:

Fresh system: embeddings table EMPTY
  → top-k similarity = 0
  → KB bypass does not fire
  → proceed to all 7 workers

✅ Correct behavior. KB learns from analyst decisions over time.
⚠️ Day-1 cost (G7): every finding goes through the full worker chain.
   On a 200-component SBOM with 50 findings above threshold:
   50 worker chains × 7 workers = 350 model calls. May take 5–30 minutes.
   NOTE FOR DISCUSSION: should there be a maximum batch size for
   Layer 3 per ingestion? Or a priority queue (CRITICAL first)?
```

### Step B — Workers Execute [2b]

```text
Worker 0 — CWE Mapper
  Input:  CVE description, CVSS vector
  KB:     not needed
  ✅ Works fine on fresh system
  Output: cwe_id, category → stored in ai_cwe_mappings

Worker 1 — CVE Summarizer (parallel with Worker 0)
  Input:  CVE description, CVSS vector, cwe_id
  KB:     not needed
  ✅ Works fine on fresh system
  Output: summary, attack_type → stored in ai_summaries

Worker 2 — Exploitability Analyzer
  Input:  CVSS, CWE, EPSS score, KEV flag, ExploitDB records
  KB:     not needed

  IF Phase 2a feeds synced before upload:
    ✅ All signals present → high confidence output

  IF feeds not yet synced:
    ⚠️ epss_score = 0, kev_listed = false, exploitdb may be empty
    Model reasons from CVSS + CWE only; confidence is lower

  Output: exploitability level, confidence, exploit_public, kev_listed

Worker 3 — Context Analyzer
  Input:  component_purl, service_name, service_description,
          cvss_attack_vector, kb_similar_decisions[]
  KB:     EMPTY on fresh system

  ❌ CRITICAL GAP (G5): service_description is EMPTY
     No Microservice entities registered means no service context.
     The model receives: component_purl + CVSS attack vector only.
     Without knowing what the service does, the model cannot
     determine if the attack path reaches the vulnerable code.

  Output: reachable=unknown, confidence=0.3 (below 0.85 threshold)
          recommended_vex_state: under_investigation

  ✅ The model does NOT hallucinate. It correctly reports low confidence.
  ❌ But this means auto-VEX will never fire on a fresh system.

Worker 4 — VEX Recommender
  Input:  all previous worker outputs, kb_similar_decisions[]
  KB:     EMPTY

  Context Analyzer gave confidence=0.3 → VEX Recommender inherits
  low confidence on reachability.
  Final confidence: < 0.85 for almost all findings
  auto_apply: false for all findings

  ❌ ALL FINDINGS QUEUED FOR HUMAN REVIEW
  ✅ Correct — the system is conservative. Analyst queue fills up on day 1.

Worker 5 — Remediation Advisor
  Input:  CVE, component_purl, current_version, known_fixed_versions[]
  KB:     not needed

  known_fixed_versions sourced from:
    → NVD affected version ranges (coarse)
    → GHSA package fix versions (precise, per ecosystem)

  IF GHSA synced (Phase 2a feed): ✅ can suggest specific target version
  IF GHSA not synced:             ⚠️ NVD-level guidance only

  Output: action, urgency, target_version → stored in ai_remediation_advice

Worker 6 — False Positive Analyzer
  Input:  CVE, component_purl, service_name, kb_similar_fps[]
  KB:     EMPTY — no past FP patterns

  ✅ Correctly outputs: likely_fp=false for everything
  ❌ No FP pattern matching → no analyst time savings
  KB populates as analysts mark findings FALSE_POSITIVE over time

Risk Explanation (narrative synthesis — runs after Workers 0–6)
  Input:  all worker outputs + Layer 1 + Layer 2 results
  ✅ Works — synthesises available signals into narrative
  Quality is lower on day 1 (missing service context, KB) but
  the narrative is honest about which signals are missing
```

### Step C — risk_context Update [2b/2c]

```text
ai_exploitability:          set ✅
ai_reachability_confidence: 0.3 (low) ⚠️
ai_vex_state:               under_investigation for most ⚠️
risk_explanation:           generated ✅
risk_score:                 updated with composite formula

VEX OVERLAY RE-TRIGGER GAP (G1) — decided [2c]:
   Even if VEX Recommender had produced auto_apply=true, the VEX Generator
   creates a vex_document row but there is no trigger that re-runs the VEX
   overlay and updates risk_context.effective_state immediately.
   Design decision: usecase/vexgen/ enqueues a ReEnrichJob after creating
   an AI VEX document. Same ReEnrichJob pattern as G2 (EPSS/KEV) and
   G12 (upstream VEX). Implemented in Phase 2c.
```

---

## Step D — Upstream VEX Feed Scheduler [2a] (fires daily at ~02:00 UTC)

```text
Phase 2a scope: Red Hat (CSAF 2.0), Alpine (OSV), Rocky Linux (OSV), Wolfi (OSV).
Debian and Ubuntu use different formats (DSA/USN, per-series version ranges) —
deferred to a post-2a follow-on with the same Matcher interface.

TWO VENDOR FORMATS — different parsing and matching strategies:

FORMAT A — CSAF 2.0 (Red Hat):
  VEX document uses PURLs with explicit product version strings.
  Parse: vulnerabilities[].affects[].ref (PURL) + versions[].status
  Match: PURL-based with four-phase normalisation (see below)

FORMAT B — OSV (Alpine, Rocky Linux, Wolfi):
  Record uses ecosystem + name + version ranges. No PURL in the record.
  Parse: affected[].package.{ecosystem, name} + ranges[].events
  Match: ecosystem→PURL type mapping + name match + version range comparison

  OSV example (Alpine busybox):
    ecosystem="Alpine", name="busybox"
    events: [ {introduced:"0"}, {fixed:"1.35.0-r5"} ]
    → pkg:apk/alpine/busybox; installed 1.35.0-r3 in [0, 1.35.0-r5) → affected
    → installed 1.35.0-r5 NOT in range (fixed version excluded) → not_affected

PURL MATCHING PROBLEM (G11) — decided:
  Vendor VEX PURLs and Trivy/Syft SBOM PURLs differ in format. Exact match fails
  silently for the most common Linux distributions:

    Red Hat CSAF VEX:  pkg:rpm/redhat/openssl@1.1.1k-6.el8_5
    Trivy SBOM:        pkg:rpm/rhel/openssl@1.1.1k-6.el8_5     ← rhel vs redhat namespace

    Rocky Linux CSAF:  pkg:rpm/rocky/busybox@1.35.0-3.el9
    Syft SBOM:         pkg:rpm/rocky/linux/busybox@1.35.0-3.el9  ← extra namespace segment

  Alpine and Rocky Linux are OSV-format — no PURL in the assertion,
  matched by ecosystem + name + version range instead.

VENDOR VEX IS THE AUTHORITY ON BACKPORTED PATCHES:
  Distro vendors backport security fixes into older upstream package versions.
  A naive upstream version comparison would incorrectly flag these as vulnerable:

    Apache httpd upstream: CVE-2023-25690 fixed in httpd@2.4.57
    RHEL 8 ships:          pkg:rpm/rhel/httpd@2.4.37-51.el8

    Naive comparison:      2.4.37 < 2.4.57  →  VULNERABLE  ← WRONG
    Red Hat VEX:           pkg:rpm/redhat/httpd@2.4.37-51.el8  →  not_affected
                           (backport applied in RHSA-2023:1570)

  Rule: once a vendor VEX assertion is matched by any phase below, trust the
  vendor's judgment. Do not compare to upstream CVE version ranges after a
  vendor VEX match.

FOUR-PHASE MATCHING (adapter/vexfeed/) [2a]:

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
    Strip errata revision suffix from installed version: -6.el8_5.1 → -6.el8_5
    If base version matches assertion version (after Phase 2 normalise):
      installed_version >= assertion_version (RPM EVR compare):
        → match_type: version_inherited  (errata on top of patched base — safe)
      installed_version < assertion_version (RPM EVR compare):
        → no_match; upstream_vex_coverage = purl_mismatch  (too old to inherit)

  Phase 4 — Alpine build revision strip + OSV range check (apk only):
    Alpine uses OSV ranges (no PURL assertions). Match by name + range.
    Check installed version against affected range using Alpine apk comparator.
    OSV range: [introduced, fixed) — fixed version is NOT in the affected range.
    match_type: range_matched

  No match after all four phases:
    → log as purl_mismatch (never silently discarded)
    → upstream_vex_coverage = purl_mismatch or not_covered

RETROACTIVE OVERLAY GAP (G12) — decided [2a]:
  When the VEX feed scheduler stores new vex_assertions rows, it must enqueue a
  ReEnrichJob for every risk_context row where (component_purl_normalised, cve_id)
  matches a newly stored assertion. Without this, existing findings stay DETECTED
  even when the vendor says not_affected.
  Design decision: fine-grained ReEnrichJob per affected risk_context row (not one
  batch per sync). Same ReEnrichJob pattern as G2 (EPSS/KEV) and G1 (AI VEX).

COVERAGE VISIBILITY (G13) — decided [2a]:
  Per-finding upstream_vex_coverage field on risk_context:
    covered         → vendor VEX matched (any phase); state applied
    not_covered     → no vendor VEX exists for this (purl, cve_id) pair
    purl_mismatch   → vendor VEX found for this CVE but no PURL matched

  Aggregate endpoint:
    GET /api/v1/products/{id}/versions/{v}/vex-coverage
    → { covered: N, not_covered: N, purl_mismatch: N }

  purl_mismatch is the most actionable: it signals a normalisation gap
  fixable in code — not by analyst triage effort.
```

---

## What Works — Cold-Start Summary by Sub-Phase

### Phase 2a Day 1 (Signal Foundation, no AI)

```text
THE NINE QUESTIONS — PHASE 2a FRESH SYSTEM
═══════════════════════════════════════════════════════════════════

Q1  Why is it vulnerable?          ❌ Phase 2b only (AI)
Q2  Can it be exploited?           ❌ Phase 2b only (AI)
Q3  Is exploit public?             ⚠️ Works after ExploitDB CSV download (~1–2 min)
Q4  Is it KEV-listed?              ⚠️ Works after CISA KEV sync (~2–5 min)
Q5  Is the code path reachable?    ❌ Phase 2b only (AI + RAG)
Q8  What VEX status?               ⚠️ Vendor VEX: after first scheduler run (~02:00 UTC)
                                      AI VEX: Phase 2b only
Q9  Safest remediation?            ❌ Phase 2b only (AI advisory)

Risk scoring (deterministic):      ✅ CVSS-only until EPSS/KEV syncs; then composite
Upstream VEX application:          ✅ After first scheduler run — apk + RPM findings
                                      suppressed where vendor says not_affected
Blast-radius notifications:        ⚠️ Product-only until Microservice/Customer registered
Auto-VEX (AI):                     ❌ No AI layer in Phase 2a
False positive savings:            ❌ No AI layer in Phase 2a
Analyst load:                      High — all findings except vendor-covered go to
                                   human review
```

### Phase 2b Day 1 (AI Intelligence added, KB empty)

```text
THE NINE QUESTIONS — PHASE 2b FRESH SYSTEM (Phase 2a feeds running)
═══════════════════════════════════════════════════════════════════

Q1  Why is it vulnerable?          ✅ CVE Summarizer works from day 1
Q2  Can it be exploited?           ⚠️ Needs Phase 2a feeds (EPSS/KEV/ExploitDB) synced
Q3  Is exploit public?             ✅ ExploitDB CSV synced by Phase 2a
Q4  Is it KEV-listed?              ✅ CISA KEV synced by Phase 2a
Q5  Is the code path reachable?    ❌ Needs Microservice registered with service description
Q8  What VEX status?               ⚠️ auto_apply=false — Context Analyzer confidence < 0.85
                                      all findings go to human review
Q9  Safest remediation?            ⚠️ Generic without GHSA fix versions; precise with GHSA

Blast-radius notifications:        ⚠️ Product-only (Microservice/Customer registration needed)
Auto-VEX (AI):                     ❌ Confidence always < 0.85 on day 1 (no KB, no context)
False positive savings:            ❌ KB empty on day 1
Score accuracy:                    ⚠️ Stale scores healed retroactively by ReEnrichJob [2a]
```

---

## Identified Gaps — Priority Order

| # | Gap | Severity | Affects | Status |
| --- | --- | --- | --- | --- |
| G1 | **VEX overlay not re-triggered after AI VEX generation** — AI VEX stored but effective_state stays DETECTED until re-ingest | High | Correctness | Decided — ReEnrichJob in usecase/vexgen/ after AI VEX creation [2c] |
| G2 | **EPSS/KEV sync does not retroactively update existing risk_context rows** — scores from before first sync are permanently stale | High | Correctness | Decided — adapter/epsskev/ enqueues ReEnrichJob for all DETECTED/IN_TRIAGE rows after each sync [2a] |
| G3 | **Group 16.4 open** — no image registration endpoint; admin must use SQL directly | High | Operability | Open (Group 16 prerequisite — blocks Phase 2 start) |
| G4 | **No "finding auto-suppressed" notification event** — AI silently suppresses findings with no team notification | Medium | UX | Decided — FINDING_AUTO_SUPPRESSED event type [2c] |
| G5 | **Context Analyzer has no service description on fresh system** — Q5 permanently low-confidence until Microservices registered | Medium | Intelligence quality | Expected — resolves when Microservices registered via Phase 2a API (OQ-9 resolved) |
| G6 | **NVD cold-start latency** — first upload per ecosystem: up to 40 sec without API key | Medium | Performance | Open — document SLA; warmup mode deferred |
| G7 | **Layer 3 batch size unbounded** — 200-component SBOM may trigger 350+ model calls in background | Medium | Performance | Open — priority queue (CRITICAL first) proposed, not decided [2b] |
| G8 | **pgvector extension not in setup docs** — migration 000015 fails if extension not pre-installed | Medium | Operability | Open — add to Phase 2b prerequisites doc [2b] |
| G9 | **No enrichment_status field in API response** — callers can't tell if AI enrichment is pending or complete | Low | UX | Decided — enrichment_status: pending\|complete in findings response [2b] |
| G10 | **PURL validation at ingest** — malformed PURLs degrade matching silently | Low | Data quality | Open — low priority |
| G11 | **PURL normalisation for upstream VEX** — Alpine build revisions, RPM namespace aliases, errata suffixes cause exact PURL match to fail silently; upstream VEX has zero effect | High | Correctness | Decided — four-phase algorithm in adapter/vexfeed/ (apk + RPM scope); Debian/Ubuntu follow-on [2a] |
| G12 | **Upstream VEX feed sync does not retroactively update risk_context** — new vex_assertions stored but existing findings stay DETECTED; same class as G2 | High | Correctness | Decided — ReEnrichJob per affected risk_context row after each feed sync [2a] |
| G13 | **No upstream VEX coverage visibility** — analyst cannot distinguish: matched/applied vs. no VEX published vs. PURL normalisation failed | Medium | UX | Decided — upstream_vex_coverage field on risk_context + /vex-coverage aggregate endpoint [2a] |
| G14 | **InProcessQueue does not survive restart** — AIEnrichmentJobs queued before a Themis restart are discarded; affected findings never receive AI enrichment unless the SBOM is re-uploaded | Low | Operability | Open — mitigated by Redis queue (Phase 3); document as known limitation in Phase 2b release notes [2b] |

---

## Day 1 vs. Day 30

```text
PHASE 2a DAY 1 (fresh system, deterministic only, no AI)
─────────────────────────────────────────────────────────
Risk scoring:       CVSS-only until EPSS/KEV syncs; then CVSS+EPSS+KEV
Graph depth:        Product only (Microservice entities not yet registered)
Upstream VEX:       EMPTY until first scheduler run (~02:00 UTC)
                    After first run: apk/RPM findings suppressed where
                    vendor says not_affected
AI enrichment:      None — Phase 2b not deployed
Auto-VEX:           None — Phase 2b not deployed
FP savings:         None — Phase 2b not deployed
Analyst load:       High — all findings except vendor VEX-covered go to human review

PHASE 2b DAY 1 (AI added, KB empty, 2a feeds running)
─────────────────────────────────────────────────────────
Risk scoring:       Full composite — CVSS + EPSS + KEV + AI exploitability + blast radius
Graph depth:        CVE → Microservice → Deployment → Customer (if entities registered)
Upstream VEX:       Running — apk/RPM findings with vendor not_affected suppressed;
                    retroactive ReEnrichJob fires on each scheduler run
AI enrichment:      Active but partial — low confidence (no KB, no service context)
Auto-VEX (AI):      Never fires — Context Analyzer confidence < 0.85 always on day 1
FP savings:         None — KB empty
Analyst load:       Maximum — every finding AI-annotated but all sent to human review

DAY 30 (graph populated, KB seeded ~500 decisions, Phase 2b+ running)
─────────────────────────────────────────────────────────
Risk scoring:       Full composite — CVSS + EPSS + KEV + exploit + blast radius
Graph depth:        Full traversal to Customer/Team nodes
Upstream VEX:       Matches correctly — Alpine/RHEL/Rocky findings suppressed where
                    vendor says not_affected; retroactive overlay fires on each sync
Auto-VEX (AI):      Fires for ~40% of findings (KB recognises recurring patterns)
FP savings:         Substantial — recurring patterns auto-dismissed
Analyst load:       Reduced to novel/ambiguous findings only
Coverage visible:   Per-finding upstream_vex_coverage shows covered / not_covered /
                    purl_mismatch — analyst knows exactly why each finding needs review
```

---

## Open Questions for Design Review

1. ✅ **G1 — VEX overlay re-trigger**: `usecase/vexgen/` enqueues a `ReEnrichJob`
   after AI VEX document creation. Same pattern as G2 and G12. [2c]

2. ✅ **G2 — retroactive score updates**: `adapter/epsskev/` updates ALL
   `DETECTED`/`IN_TRIAGE` `risk_context` rows on every sync, not just `NULL` rows. [2a]

3. **G7 — batch throttling** [2b]: should Layer 3 process at most N findings per
   ingestion, with the rest queued for next cycle? Or process all but log a warning
   if batch > threshold? Recommend: CRITICAL + HIGH findings first, remainder
   queued with TTL.

4. ✅ **OQ-9 — Microservice registration UX**: explicit API
   (`POST /api/v1/products/{id}/microservices`) is the Phase 2a starting point.
   Auto-discovery from SBOM metadata deferred. [2a]

5. **Sync ordering on fresh system**: should `cmd/themis/main.go` run
   EPSS/KEV/ExploitDB/GHSA/vendor VEX sync on startup before accepting ingestion,
   or accept immediately with a stale-score warning in responses?

6. ✅ **G11 — PURL normalisation scope**: four-phase fixed algorithm (exact →
   namespace alias → errata direction check → OSV range). Phase 2a scope: apk +
   RPM only. Debian/Ubuntu in post-2a follow-on. [2a]

7. ✅ **G12 — retroactive overlay trigger**: fine-grained `ReEnrichJob` per
   affected `risk_context` row (not one batch job per feed sync). [2a]

8. ✅ **G13 — coverage visibility placement**: per-finding `upstream_vex_coverage`
   field on `risk_context` + aggregate endpoint
   `GET /api/v1/products/{id}/versions/{v}/vex-coverage`. [2a]
