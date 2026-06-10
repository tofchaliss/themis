# Themis — Project Backlog

All deferred proposals and unimplemented items, organised by phase. Each entry records:
what it is, why it was deferred, which Phase 1 hooks or interfaces are already in place,
and the target phase.

---

## Phase decision log

The original `proposal-initial.md` defined:

- Phase 2 = Native React SPA (Web UI)
- Phase 3 = Full-Featured Platform (Docker, RBAC, HA)

**These boundaries were changed during Phase 1 design, then refined further before Phase 2
started.** The current plan:

- Phase 2 = AI enrichment, EPSS/KEV, upstream VEX feeds, VEX export — split into three
  sub-phases (2a, 2b, 2c) because the full scope is too large to implement reliably as one
  change and the AI layer depends on signals being healthy before meaningful testing is possible
- Phase 3 = Rate limiting + runtime observability + cosign/sigstore + CI/CD ingestion +
  deployment + UI + enterprise features

Rationale for sub-phase split: Phase 2a (signals + graph + VEX export) delivers standalone
value and validates the data foundation. Phase 2b (AI workers + RAG + pgvector) can only be
meaningfully tested after EPSS/KEV/ExploitDB are healthy. Phase 2c (auto-apply thresholds)
requires the KB to be seeded with real analyst decisions before confidence thresholds are
tunable. Splitting also lets each sub-phase be tagged as a release (v0.2.0, v0.3.0, v0.4.0).

---

## Phase 1 — Remaining hardening (Group 16)

These are post-completion tasks that close gaps found after the main Phase 1 build.
They must be done before Phase 1 is tagged as complete.

| # | Task | Status |
| - | ---- | ------ |
| 16.1 | OSV query: normalise Alpine package names before lookup (strip `so:` prefix, map `py3-foo` → `python3-foo`) | Open |
| 16.2 | Integration test: Alpine SBOM ingest with OSV-matched CVEs | Open |
| 16.3 | Integration test: rpm-based SBOM ingest with unsupported ecosystem skipped cleanly | Open |
| 16.4 | REST endpoint: `POST /api/v1/products/{id}/images` to register image before SBOM upload | Open |
| 16.5 | Upload helper script (curl-based) for local testing and CI pipelines | Open |
| 16.6 | `make check` run clean after all Group 16 items | Open |
| 16.7 | Coverage: `adapter/store/` reaches ≥90% | Open |
| 16.8 | Coverage: `adapter/osv/` reaches ≥90% | Open |
| 16.9 | Git tag `v0.1.0` and Phase 1 release notes | Open |

---

## Phase 2 backlog

Phase 2 is split into three sub-phases. Master architecture reference:
`openspec/changes/themis-phase-2/proposal.md` and `design.md`.
Current implementation status: `openspec/STATUS.md`.

---

### Phase 2a — Signal Foundation (`themis-phase-2a`) — Planned

**Gate:** Group 16 complete + `v0.1.0` tagged.
**Releases as:** v0.2.0
**OpenSpec change:** `openspec/changes/themis-phase-2a/` (to be created)

**What:**

- **EPSS/KEV sync** — daily CISA KEV + FIRST.org EPSS fetch; updates
  `intelligence_signals` with TTL; incorporates into risk score formula
- **ExploitDB CSV** — ingests `files_exploits.csv` from public GitHub mirror;
  CVE-to-EDB-ID lookup; feeds Layer 1 `ExploitPublic` rule
- **GHSA integration** — GitHub Security Advisories for ecosystem-precise fix
  versions (npm, Go, PyPI, Maven, etc.); extends the Phase 1 correlator
- **Upstream VEX feeds** — scheduled fetch from Red Hat, Alpine, Rocky Linux, Wolfi;
  applied as `vex_documents` with `source=upstream_vendor`; four-phase PURL normalisation
  for apk + RPM ecosystems (see Decision 15); Debian/Ubuntu deferred to follow-on (see below)
- **Layer 1 deterministic rules** — CVSS ≥ 9 ∧ KEV → Critical; CVSS ≥ 9 ∧
  ExploitPublic → High+; EPSS ≥ 0.5 ∧ CVSS ≥ 7 → Elevated; etc.
- **Microservice / Deployment / Customer entities** — new domain entities; registration
  APIs; resolves OQ-9 (registration workflow)
- **Layer 2 graph reasoning** — SQL traversal CVE → Package → Product → Microservice
  → Deployment → Customer; blast-radius scoring; team-level notifications
- **VEX export** — `GET /api/v1/products/{id}/versions/{v}/vex` CycloneDX or OpenVEX
- **System status API** — `GET /api/v1/status?top=N`: total components, CVE counts by
  severity/state, top-N components with most open vulnerabilities (name, product, CVE
  count, highest CVSS); answers "what is in Themis and what's most urgent?" in one call
- **SBOM management APIs** — `GET /api/v1/sboms`, `GET /api/v1/products/{id}/sboms`
  (paginated listings); `DELETE /api/v1/sboms/{id}` (soft-delete with force flag for
  latest SBOM; `deleted_at` tombstone; audit log entry)
- **Layman-friendly error responses** — three-field error envelope (`code`, `message`,
  `hint`) across all API endpoints; no raw DB errors or Go strings in responses
- **Cold-start fixes** — G2 (EPSS/KEV retroactive score update), G6 (NVD warmup)

**Why deferred from Phase 1:** risk score formula change and graph entity additions
are breaking changes that require the Phase 1 pipeline to be stable first.

**Phase 1 hooks:**

- `intelligence_signals` table has `signal_type`, `score`, `expires_at` columns
- `vex_documents.source` column distinguishes source tiers
- `watch/` scheduler pattern cloneable for EPSS/KEV + vendor VEX sync
- `JobQueue` interface for async tasks already in place
- `risk_context` has `epss_score`, `kev_listed` columns (populated NULL today)

**Database migrations:** 000014 (microservices, deployments, customers, exploit_records),
000017 (indexes)

**Post-2a follow-on — Debian/Ubuntu VEX feed matching:**

Debian (DSA format, dpkg version ordering with tilde rules and epochs) and Ubuntu
(USN format, per-series version ranges per `jammy`/`focal`/`noble`) are excluded from
Phase 2a scope because they use formats and version comparators that differ from
apk/RPM. The four-phase `Matcher` interface defined in Phase 2a supports adding
Debian/Ubuntu as new `Matcher` implementations with no changes to the shared matching
logic or VEX assertion storage. Implement after Phase 2a ships and the apk/RPM path
is validated in production.

---

### Phase 2b — AI Intelligence (`themis-phase-2b`) — Planned

**Gate:** Phase 2a complete and signal feeds confirmed healthy.
**Releases as:** v0.3.0
**OpenSpec change:** `openspec/changes/themis-phase-2b/` (to be created)

**Hardware prerequisites (operator must verify before deploying Phase 2b):**

- RAM: 16 GB minimum (Ollama model ~4.5 GB + PostgreSQL ~4 GB + pgvector + OS)
- GPU: strongly recommended — CPU-only inference is 60–180 s per model call
  (vs 1–8 s with GPU); CPU-only deployments set `ai.worker_concurrency=1`
- Disk: NVMe SSD; model weights ~4.5 GB; grow with pgvector KB size
- CyberPal-2.0 may not be in Ollama's public registry — most deployments will
  use the automatic Qwen2.5-7B fallback (see design.md Decision 3)
- PostgreSQL must have the `pgvector` extension installed before migration 000015

**What:**

- **Ollama integration** — HTTP client for CyberPal-2.0 / Qwen2.5-7B; model health check
- **pgvector + L1c Semantic Memory** — embedding table; HNSW index; nomic-embed-text model
- **KB-first optimisation** — pgvector similarity ≥ 0.92 → apply past decision, skip model
- **7 AI skill workers** — CWE Mapper, CVE Summarizer, Exploitability Analyzer, Context
  Analyzer, VEX Recommender, Remediation Advisor, False Positive Analyzer
- **Async JobQueue wiring** — AI enrichment jobs triggered for CVSS ≥ 7.0 OR KEV OR ExploitPublic
- **RAG context assembly** — per-finding context built from L0/L1/external sources + KB
- **Risk Explanation synthesis** — headline + narrative from all worker outputs
- **AI enrichment status in API** — `enrichment_status: pending|complete` in findings response
- **Cold-start fixes** — G1 (VEX overlay re-trigger), G7 (batch throttle), G9 (enrichment_status)

**Why deferred from 2a:** AI workers are only meaningfully testable when EPSS/KEV/ExploitDB
signals are present. Building 2b on an empty signal foundation makes it impossible to
distinguish AI errors from missing data errors.

**Phase 2a hooks:**

- Layer 1 + Layer 2 provide the deterministic signals AI workers consume
- Microservice/Deployment entities provide service descriptions for Context Analyzer
- `risk_context` has `ai_exploitability`, `ai_reachability_confidence` columns (NULL until 2b)

**Database migrations:** 000015 (pgvector extension + embeddings table),
000016 (ai_summaries, ai_cwe_mappings, ai_exploitability, ai_vex_recommendations,
ai_remediation_advice, ai_fp_analysis)

---

### Phase 2c — AI-Assisted VEX (`themis-phase-2c`) — Planned

**Gate:** Phase 2b running; KB has ≥ 50 seeded analyst decisions (threshold tunable).
**Releases as:** v0.4.0
**OpenSpec change:** `openspec/changes/themis-phase-2c/` (to be created)

**What:**

- **VEX auto-apply** — VEX Recommender confidence ≥ threshold auto-creates
  `vex_document(source=ai_generated)`; resolves OQ-5 (default 0.85)
- **FP auto-apply** — FP Analyzer confidence ≥ threshold auto-sets
  `effective_state=FALSE_POSITIVE`; resolves OQ-6 (default 0.90)
- **Four-eyes rule** — `trust_policy=strict` requires human confirmation before
  auto-apply fires; resolves OQ-10
- **FINDING_AUTO_SUPPRESSED notification** — new event type when AI suppresses a
  finding; fixes G4 (silent suppression)
- **Confidence threshold config** — `config.ai.vex_auto_apply_threshold`,
  `config.ai.fp_auto_apply_threshold` configurable per deployment
- **AI justification in VEX export** — enriches the 2a vex-export with AI-generated
  justification text and confidence scores

**Why after 2b:** Confidence thresholds (0.85, 0.90) are only meaningful when the KB
has real analyst decisions to retrieve. Tuning auto-apply against an empty KB
would result in under- or over-suppression — either missing real issues or drowning
analysts in false positives.

**Phase 2b hooks:**

- VEX Recommender + FP Analyzer workers already produce `auto_apply` bool and
  `confidence` float in their JSON output
- `vex_documents.source` enum already includes `ai_generated`
- `trust_policy` enum in domain already has `strict`, `standard`, `permissive`

---

## Phase 3 backlog

Phase 3 scope: Rate limiting, runtime observability, cosign/sigstore SBOM verification,
CI/CD ingestion (GitHub, GitLab, Bitbucket), deployment packaging, Redis queue, Web UI,
enterprise access control (RBAC/OIDC), high-availability deployment, admin CLI.

### Rate limiting

**What:** Per-API-key rate limiter on all ingestion endpoints. Configurable burst and
steady-state limits. Return `429 Too Many Requests` with a `Retry-After` header.

**Why deferred from Phase 2:** A single-tenant Phase 2 deployment has no rate-limiting
need. Rate limiting becomes important when multiple teams or CI pipelines share an
instance — a Phase 3 concern once CI/CD integration lands.

**Phase 1 hooks:**

- chi middleware stack in `infrastructure/http/` is the right injection point
- API key model already scopes keys to products; rate limits can be per-key or per-product

---

### Runtime observability

**What:** Structured log level configurable at runtime (no restart needed). Export OTel
traces to a configurable OTLP endpoint (Jaeger, Honeycomb, etc.). Add trace IDs to all
HTTP error responses.

**Why deferred from Phase 2:** `go.opentelemetry.io/otel` is already in `go.mod` and span
keys are defined in `domain/tracing.go`. The OTel exporter wiring is straightforward but
adds config surface area. Deferred to Phase 3 to keep Phase 2 config minimal.

**Phase 1 hooks:**

- OTel SDK and `domain/tracing.go` span key types already present
- `infrastructure/metrics/` has the OTel setup stub ready for the exporter wiring
- Zap logger already structured; adding `level` to config YAML is a 3-line change

---

### Real signature verification (CosignVerifier)

**What:** Replace `StubVerifier` in `adapter/trust/` with a real cosign/sigstore verifier.
Verify SBOM artifact signatures against the Rekor transparency log. Strict trust policy
enforcement gains real cryptographic teeth — unsigned or tampered SBOMs are rejected.

**Why deferred from Phase 2:** Cosign adds a significant external dependency
(`github.com/sigstore/cosign/v2` pulls in the sigstore ecosystem). Phase 2 already
introduces AI model integrations and a new risk score formula. Deferring cosign keeps Phase
2 self-contained and gives the trust gate logic another phase of real-world use before
cryptographic enforcement is turned on.

**Phase 1 hooks:**

- `SignatureVerifier` interface is defined in `internal/domain/`
- `StubVerifier` implements it and records `trust_status` correctly — no API or pipeline
  changes needed, only the implementation at the DI root changes
- Trust policies (`strict`, `standard`, `permissive`) already enforced by the gate

---

### CI/CD integration (GitHub, GitLab, Bitbucket)

**What:** SCM webhook receivers for GitHub (`push` / `release`), GitLab (`pipeline`), and
Bitbucket Cloud/Server (`repo:push`). Each webhook extracts or receives the committed SBOM
and submits it to the same `IngestionService.IngestSBOM` use case as manual upload. A new
`scm_webhook_configs` table stores per-product SCM configuration (provider, repo, SBOM path,
branch pattern). Git ref is recorded in `ingestion_jobs` metadata.

**Why deferred from Phase 2:** Phase 2 focuses on pure signal quality (AI enrichment,
EPSS/KEV, upstream VEX). CI/CD ingestion requires its own new infrastructure (SCM webhook
config table, branch-to-version mapping, SBOM discovery strategy) that is cleaner as a
focused Phase 3 workstream once the enriched risk signals are stable and the API contract
is settled.

**Phase 1 hooks:**

- `IngestionService.IngestSBOM` is format-agnostic — all ingestion sources call the same use case
- Webhook HMAC verification (`X-Themis-Signature`) middleware in `adapter/api/` is the pattern
- `ingestion_jobs` table can record the git ref as job metadata

---

### Docker Compose deployment

**What:** `docker-compose.yml` that starts `themis` + PostgreSQL in one command. Multi-stage
Dockerfile that produces a minimal image (~15 MB via Alpine or distroless).

**Why deferred:** Phase 1 and 2 target the binary-on-bare-metal deployment model. Docker
packaging is a packaging concern, not a functionality concern. Adding it before the feature
set is stable means the image will change frequently.

**Phase 1 hooks:**

- Config loading (`infrastructure/config/`) uses env vars — Docker-native
- Database URL, API port, and all config are already env-var driven

---

### Redis-backed job queue

**What:** Replace `InProcessQueue` with a Redis-backed queue. Workers can run in separate
processes. Supports horizontal scaling.

**Why deferred:** In-process queue with a goroutine pool handles Phase 1 and Phase 2 load.
Redis adds operational complexity (another service to deploy, monitor, and back up) that is
not justified until multi-instance deployment is needed (Phase 3).

**Phase 1 hooks:**

- `JobQueue` interface in `internal/domain/` is the swap point
- `InProcessQueue` in `internal/infrastructure/queue/` is one implementation
- Swap requires only a new struct implementing `JobQueue` + a DI root change in `cmd/themis/main.go`

---

### Web UI (React SPA)

**What:** Native React SPA providing: product / version / image inventory views, SBOM upload
drag-and-drop, vulnerability dashboard with filters (severity, state, component), triage
workflow (accept, dismiss, escalate), notification rule editor.

**Why deferred:** Originally Phase 2 in `proposal-initial.md`. Moved to Phase 3 so that
Phase 2 can focus on AI enrichment and threat intelligence — the signal quality that makes a
dashboard useful. A dashboard of unscored noise is not worth building.

**Phase 1 hooks:**

- REST API is the only data source the UI will need
- OpenAPI spec (`api/openapi.yaml`) can generate a typed TypeScript client
- All list endpoints are already paginated (cursor-based)

---

### RBAC + OIDC

**What:** Replace the Phase 1 `X-API-Key` auth with OIDC (OpenID Connect) tokens.
Role-based access control with roles: `reader`, `analyst`, `admin`. Integrate with
corporate identity providers (Okta, Azure AD, Google Workspace).

**Why deferred:** Single-tenant Phase 1/2 deployments don't need OIDC. Multi-tenant or
enterprise deployments do. Adding OIDC before the feature set is stable creates auth churn.

**Phase 1 hooks:**

- Auth middleware in `adapter/api/` is a single injection point
- API key auth and OIDC token auth can coexist via a middleware chain
- Product-scoped keys already establish the authorization model foundation

---

### High-availability deployment

**What:** Kubernetes Helm chart. Horizontal pod autoscaling on ingestion workers.
Leader election for scheduled watch/EPSS jobs (only one pod runs the scheduler at a time).
Health endpoints already exist (`/health`, `/ready`).

**Why deferred:** Requires Redis queue (Phase 3) and Docker packaging (Phase 3). Phase 1/2
are single-instance deployments.

**Phase 1 hooks:**

- `/health` and `/ready` HTTP endpoints are already implemented
- All config is env-var driven — K8s ConfigMap/Secret compatible

---

### Enhanced `themis-cli`

**What:** Expand the admin CLI (`infrastructure/cli/`) beyond `create-key` / `revoke-key`
to include: `list-products`, `trigger-rescan`, `export-vex`, `purge-stale-signals`. Package
as a standalone binary (`themis-cli`) distributed alongside the server.

**Why deferred:** Phase 1 admin CLI exists for key management only. Richer CLI operations
depend on Phase 2 features (EPSS, AI enrichment, VEX export) being available.

**Phase 1 hooks:**

- `infrastructure/cli/` package exists with the cobra/urfave command structure already in place
- DI root can expose the same use-case interfaces to CLI commands as to HTTP handlers

---

## Items from `proposal-initial.md` not yet assigned

These items appear in `proposal-initial.md` but were not included in Phase 1–3 planning.
They are captured here as unscheduled proposals.

| Item | Original location | Notes |
| ---- | ----------------- | ----- |
| Dependency graph visualisation | proposal ADR §7 | Requires UI (Phase 3 minimum) |
| SBOM diff (two versions of same image) | proposal ADR §8 | Data is available; API endpoint not planned |
| Policy-as-code (OPA integration) | proposal ADR §9 | Replaces or extends trust policies in Phase 3+ |
| Notification webhook outbound (POST to 3rd party) | proposal feature | Currently SMTP + Teams only |
| CSV/Excel vulnerability export | proposal feature | Low priority; VEX export (Phase 2) covers the main case |
| CVE comment / annotation by analyst | proposal feature | Triage note field exists; no dedicated annotation endpoint |
