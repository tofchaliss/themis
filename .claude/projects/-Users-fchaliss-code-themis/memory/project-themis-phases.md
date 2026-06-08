---
name: project-themis-phases
description: Themis project phase breakdown — what is in scope per phase, key decisions made
metadata:
  type: project
---

# Themis Phase Breakdown

Themis is an open-source Go backend security intelligence platform (vulnerability assessment and management). Full context in proposal-initial.md.

## Phase 1 — Core Intelligence Platform (current OpenSpec: themis-phase-1)

- Go REST API only, no UI
- PostgreSQL only (no SQLite)
- In-process job queue behind an interface (goroutine pool) — swappable to Redis in Phase 3
- Manual SBOM/VEX upload API + webhook endpoints defined (callable for testing, no CI automation)
- 8 capabilities: artifact-trust, sbom-parser, sbom-ingestion, sbom-store, intelligence-enrichment, cve-triage, cve-watch, notification-service
- intelligence-enrichment = VEX overlay on CycloneDX components only (no EPSS, KEV, AI)
- Phase 1 risk_score = raw severity + VEX effective state only
- API key auth, no RBAC
- No AI, no EPSS, no KEV in Phase 1
- cosign verification is a stub in Phase 1 (real verification in Phase 2)

## Phase 2 — AI Intelligence Layer + CI/CD Integration

- Predominantly AI interfacing — this is the defining theme of Phase 2
- New capabilities:
  - event-bus: async pub/sub for domain events — lands first, everything else publishes to it
  - ai-enrichment: LLM/Claude integration for exploitability reasoning, confidence scoring, remediation recommendations
  - vex-export: AI + human triage decisions → CycloneDX VEX documents (Themis becomes VEX authority)
  - upstream-vex-feed: scheduled fetch from Red Hat, Alpine, Ubuntu, SUSE, Wolfi, Rocky Linux vendor VEX feeds
  - epss-kev-sync: FIRST.org EPSS scores + CISA KEV list → intelligence_signals (L3)
  - git-ingestion: GitHub + GitLab webhook + polling; repo→product/project mapping via config; same artifact trust gate; CI/CD integration feeds richer data to AI layer
  - rate-limiting: per API key token-bucket rate limiting
  - product-component-api: GET /api/v1/products/{id}/components
  - runtime-observability: configurable log level (env/YAML), dev-friendly console output, OTel trace exporter for pipeline debugging
- Modified capabilities: artifact-trust (real cosign via sigstore), ci-webhook-api (E2E tests), sbom-ingestion (wired to event-bus)
- Deferred from Phase 2: Docker Compose, Bitbucket, UI, Redis, RBAC

## Phase 3 — Production Platform + UI

- Docker Compose full production stack (separate worker containers, Redis queue, Nginx TLS)
- UI / Dashboard (needs more design discussion before committing)
- Bitbucket git integration (same provider interface as Phase 2, new adapter)
- Full RBAC + OIDC/OAuth2
- Redis job queue (swap from in-process goroutine pool)
- HA / clustering (leader election for CVE watch scheduler)
- themis-cli companion CLI
- Compliance reports, audit exports
- Enterprise features

## Notes

**Why:** Phase 1 = standalone backend foundation. Phase 2 = AI intelligence + CI/CD feeds it. Phase 3 = infrastructure, UI, enterprise.

**How to apply:** When suggesting features or scope, check which phase they belong to. Never add Phase 2/3 features to Phase 1 specs.
