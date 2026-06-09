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

- Phase 2 = AI enrichment, EPSS/KEV, upstream VEX feeds, VEX export — pure signal quality, no infra changes
- Phase 3 = Rate limiting + runtime observability + cosign/sigstore + CI/CD ingestion + deployment + UI + enterprise features

Rationale: Phase 2 is already significant domain work — AI enrichment introduces a new
external dependency and non-determinism, EPSS/KEV changes the risk score formula contract,
and upstream VEX feeds require precedence semantics. Rate limiting, observability wiring,
cosign, and CI/CD are all infrastructure concerns that are cleaner as a Phase 3 workstream
once the enriched risk signals are stable and the API contract is settled.

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

Phase 2 scope: AI enrichment, EPSS/KEV, upstream VEX feeds, VEX export.

### AI enrichment

**What:** Call an AI model (OpenAI, Claude, or local Ollama) to generate a contextual
exploitability assessment for findings with `effective_state=DETECTED` and high severity.
Store result as an `intelligence_signal` with `source=ai_enrichment`.

**Why deferred:** Phase 1 risk scoring is deterministic (`f(severity, vex_state)`). Adding
AI introduces external dependencies, latency, cost, and non-determinism — not appropriate
until the deterministic pipeline is stable and tested.

**Phase 1 hooks:**

- `EnrichmentResult` domain type is defined and has a `source` field
- `intelligence_signals` table (L3) exists with `source` column
- `JobQueue` interface means enrichment jobs can be submitted asynchronously without
  touching the ingestion use case

---

### EPSS / KEV scoring

**What:** Sync CISA KEV (Known Exploited Vulnerabilities) list and FIRST.org EPSS scores
on a daily schedule. Store each as an `intelligence_signal` (L3) with TTL. Incorporate
into `risk_context` score (Phase 1 score formula is `f(severity, vex_state)` only; Phase 2
adds `g(epss_score, kev_flag, vex_state, severity)`).

**Why deferred:** The L3 table and signal schema exist. Adding EPSS/KEV requires a
scheduler, HTTP fetch logic, and a score formula change — all are breaking changes to the
risk score contract, which must be stable before CI/CD consumers depend on it.

**Phase 1 hooks:**

- `intelligence_signals` table has `signal_type`, `score`, `expires_at` columns
- `risk_context` has `epss_score`, `kev_listed`, `ai_assessment` columns (populated NULL today)
- `watch/` use case scheduler pattern can be cloned for EPSS/KEV sync

---

### Upstream VEX feeds

**What:** Periodically fetch vendor VEX feeds and apply them as `vex_documents` with
`source=upstream_vendor`. Supported vendors: Red Hat, Ubuntu, Alpine, Debian, SUSE, Wolfi,
Rocky Linux. Match via PURL.

**Why deferred:** Requires a scheduled fetch job, PURL-to-vendor-package mapping, and a
de-duplication strategy (vendor VEX vs. user-supplied VEX — user VEX wins). These need
careful ordering semantics that Phase 1 has not yet defined.

**Phase 1 hooks:**

- `vex_documents.source` column distinguishes user-supplied vs. upstream
- PURL-based matching (`adapter/osv/` and `adapter/nvd/`) already handles ecosystem mapping
- `watch/` scheduler can be extended with a vendor-feed sync task

---

### VEX document export

**What:** `GET /api/v1/products/{id}/versions/{v}/vex` — export the computed risk context
for a product version as a standards-compliant VEX document (CycloneDX or OpenVEX format).

**Why deferred:** Export is the inverse of ingest; it requires the ingest path (and the
full risk_context population) to be complete and stable first.

**Phase 1 hooks:**

- All data needed for the export is already in `risk_context`, `vex_assertions`, `vex_documents`
- CycloneDX and SPDX structs are already known in `adapter/parser/`; export uses the same types

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
