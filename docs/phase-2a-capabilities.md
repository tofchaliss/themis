# Phase 2a — Signal Foundation (`v0.2.0`)

Reference for what Themis **does** and **does not** include in Phase 2a.
Implementation status: **~132/140 tasks** (Groups 1–29 complete; Group 30 release gate open).
OpenSpec: `openspec/changes/themis-phase-2a/`.

---

## In scope (implemented)

### Carried from Phase 1

Single Go binary + PostgreSQL; SBOM/VEX ingestion; OSV/NVD correlation; VEX overlay;
human triage; CVE watch; notifications; API keys; in-process job queue.

### New in Phase 2a

| Area | Capability |
| ---- | ---------- |
| **Threat signals** | Daily EPSS, CISA KEV, ExploitDB CSV sync → retroactive `ReEnrichJob` |
| **Vendor VEX** | Red Hat CSAF + Alpine/Rocky/Wolfi OSV; four-phase PURL match (apk + RPM) |
| **Layer 1** | Deterministic rules → `deterministic_level` at ingest (sync, before `202`) |
| **Layer 2** | Blast-radius graph traversal → `blast_radius_score` at ingest (sync) |
| **Risk score V2** | EPSS +30%, KEV +15, blast multiplier 1.0–2.0×, Critical → 100 (**BREAKING**) |
| **Asset graph** | Microservice / Deployment / Customer registration APIs |
| **VEX export** | CycloneDX 1.5+ / OpenVEX 0.2+ per product version; coverage aggregate |
| **Status API** | `GET /api/v1/status?top=N` — live counts, top-N, `signals_stale` |
| **SBOM mgmt** | List + soft-delete (`deleted_at` tombstone); audit `SBOM_DELETED` |
| **Error UX** | `{error: {code, message, hint}}` on all endpoints; 12 catalogue codes |

### New API endpoints

- `GET /api/v1/status?top=N`
- `GET /api/v1/sboms`, `GET /api/v1/products/{id}/sboms`
- `DELETE /api/v1/sboms/{id}?force=true`
- `GET /api/v1/products/{id}/versions/{v}/vex`, `.../vex-coverage`
- `GET /api/v1/products/{id}/blast-radius`
- `POST /api/v1/products/{id}/microservices`
- `POST /api/v1/microservices/{id}/deployments`
- `POST /api/v1/customers`

---

## Out of scope (deferred)

| Phase | Items |
| ----- | ----- |
| **2b** | AI workers, Ollama, pgvector, GHSA adapter, Layer 3 async AI |
| **2c** | AI VEX auto-apply, false-positive automation, AI justification in export |
| **Post-2a** | Debian/Ubuntu VEX feeds; per-feed enable/disable flags |
| **Phase 1 gap** | `POST /api/v1/products/{id}/images` (Group 16) |
| **Phase 3+** | Redis queue, Docker stack, Web UI, RBAC/OIDC, real cosign, git ingestion |

---

## Known limitations

- Four vendor VEX feeds always registered; URLs configurable, no on/off per feed
- Graph must be registered manually — no SBOM metadata auto-discovery
- `THEMIS_GITHUB_TOKEN` wired but unused until Phase 2b
- Stub signature verification (no real cosign)
- Soft-delete hides SBOM from active queries; raw rows retained (not hard-deleted)

---

## Acceptance criteria

AC-16..AC-24 documented in [`acceptance-criteria.md`](acceptance-criteria.md).
Test name mapping enforced by `tests/acceptance/criteria_phase2a_test.go`.

---

## Next: Group 30

Coverage gates, Prometheus metrics wiring, doc sync, merge + tag `v0.2.0`.
See `openspec/changes/themis-phase-2a/tasks.md` §30.
