# Themis v0.2.0 — Phase 2a Signal Foundation

Release tag: `v0.2.0` (Phase 2a completion)

## Highlights

Phase 2a adds external threat signals, asset-graph blast radius, upstream vendor VEX matching, CycloneDX VEX export, management APIs, and a **breaking change** to the composite risk score formula.

## New capabilities

### Threat signals

- Scheduled EPSS/KEV sync with stale detection and batched `ReEnrichJob` follow-up
- ExploitDB CSV sync
- Vendor VEX feeds: RHEL (CSAF), Alpine/Rocky/Wolfi (OSV)
- Four-phase PURL matching (exact → namespace → errata → Alpine range) with always-logged PURL mismatch

### Enrichment (Layer 1–3)

- **Layer 1** deterministic rules (`deterministic_level`) applied synchronously before ingestion `202` returns
- **Layer 2** blast-radius multiplier from asset graph (Customer deduplication, 1.0–2.0× cap)
- **Layer 3** EPSS/KEV/exploit-public signals on `risk_context`
- Composite **risk score v2** (breaking — see below)

### Asset graph

- CRUD for microservices, customers, deployments
- Blast-radius query API

### Management APIs

- `GET /api/v1/status?top=N` — system status + top components
- `GET /api/v1/sboms`, `GET /api/v1/products/{id}/sboms`
- `DELETE /api/v1/sboms/{id}?force=true` — soft-delete with audit trail

### VEX export

- `GET /api/v1/products/{id}/versions/{version}/vex` — CycloneDX 1.5+ with `x-themis-*` extensions

### Error catalogue

- Structured `{error:{code,message,hint}}` envelope (12 codes); replaces RFC 7807 problem responses

## Breaking changes

**Risk score formula (Phase 2a):**

```text
base      = f(raw_severity, effective_state)     [Phase 1 formula]
layer1    = if deterministic_level=Critical → 100 else base
epss_adj  = base × (1 + epss_score × 0.3)
kev_adj   = if kev_listed → +15 else 0
blast_adj = base × blast_radius_score           [1.0–2.0×]
final     = min(100, layer1 + epss_adj + kev_adj + blast_adj)
```

Clients comparing numeric scores across Phase 1 and 2a builds will see different values for the same finding.

## New Prometheus metrics

- `themis_epsskev_sync_total`, `themis_epsskev_stale`, `themis_reenrichjob_batches_total`
- `themis_vexfeed_sync_total`, `themis_vexfeed_assertions_total`, `themis_vexfeed_purl_mismatch_total`
- `themis_layer1_rules_fired_total`, `themis_blast_radius_score` (histogram)

## Configuration (new env vars)

See `README.md` § Phase 2a configuration: `THEMIS_EPSS_*`, `THEMIS_KEV_*`, `THEMIS_EXPLOITDB_*`, `THEMIS_VEXFEED_*`, graph/feed poll intervals.

## Migrations

Schema version **19** — includes `deleted_at` on SBOMs, asset graph tables, vendor VEX tables, threat signals, and Phase 2a `risk_context` columns.

## Upgrade notes

1. Run migrations before starting the new binary.
2. Re-enrichment runs automatically after signal/feed sync; no manual step required.
3. Soft-deleted SBOMs are excluded from all read paths (status, lists, blast-radius, VEX export).
4. Idempotent SBOM uploads with `Idempotency-Key` return `200` with `duplicate: true` once the first ingestion is recorded.
