# Themis

Themis is an open-source Go backend security intelligence platform. It ingests SBOM and VEX
documents, correlates vulnerabilities against live CVE feeds, applies VEX overlay semantics,
and delivers actionable notifications — all without touching your build system.

A single binary backed by PostgreSQL. No agents. No daemons. No lock-in.

---

## What Themis Does

| Capability | Description |
| ---------- | ----------- |
| **Artifact trust** | Schema validation, SHA-256 integrity, deduplication, provenance checks on every SBOM and VEX document ingested |
| **SBOM parsing** | CycloneDX 1.4/1.5/1.6, SPDX 2.3/3.0, and Trivy JSON — all normalised to one internal canonical model |
| **SBOM ingestion** | REST upload endpoint and HMAC-verified webhook; async pipeline with idempotency and lifecycle tracking |
| **Vulnerability correlation** | Component catalog matched against NVD and OSV by PURL and version range |
| **VEX overlay** | VEX assertions applied as a contextual layer; raw findings are never deleted — safe to revoke at any time |
| **CVE watch** | Background scheduler polls NVD/OSV; new findings auto-created for matching catalog components |
| **Human triage** | Triage API records decisions; each decision auto-generates a VEX assertion that applies to future ingestions and survives rescans |
| **Notifications** | SMTP and Microsoft Teams delivery with configurable routing rules and digest aggregation |
| **Threat signals** | Daily EPSS/KEV, ExploitDB, and upstream vendor VEX sync; retroactive re-enrichment of open findings |
| **Deterministic prioritisation** | Layer 1 rules (CVSS, KEV, EPSS, public exploit) set `deterministic_level` at ingest time |
| **Blast radius** | Asset graph (Product → Microservice → Deployment → Customer) drives a score multiplier and team routing |
| **Upstream vendor VEX** | Red Hat, Alpine, Rocky, Wolfi feeds matched to SBOM PURLs; sets VEX overlay and `upstream_vex_coverage` |
| **VEX export** | CycloneDX 1.5+ and OpenVEX export per product version; coverage aggregate for upstream vendor VEX |
| **System status** | `GET /api/v1/status` — live component/vuln counts, severity/state breakdown, top-N ranking, `signals_stale` flag |
| **SBOM management** | List SBOMs system-wide or per product; soft-delete with tombstone (`deleted_at`); audit log on delete |
| **Error UX** | Layman-friendly `{error: {code, message, hint}}` envelope on all endpoints; 12 catalogue codes |

For architecture (Clean Architecture layers, the data model, VEX overlay semantics), technology
stack, roadmap, and quality gates, see [PROJECT_CONTEXT.md](docs/current-changes/PROJECT_CONTEXT.md). Deferred items are
tracked in [project-backlog.md](docs/current-changes/project-backlog.md).

> **Schema line:** the current schema is the `v0.3.0` core model (`sboms` + `scan_reports`, merged
> `artifacts`, identity-keyed `risk_context`). There is **no in-place upgrade** from a pre-`v0.3.0`
> database — drop and recreate (see [Full database reset](#resetting-ingested-data-local-dev-only)).

---

## Documentation

All project documentation lives under [`docs/`](docs/), organised by purpose:

| Area | Location | Contents |
| ---- | -------- | -------- |
| Architecture & context | [`docs/current-changes/`](docs/current-changes/) | [`PROJECT_CONTEXT.md`](docs/current-changes/PROJECT_CONTEXT.md) (data model, Clean Architecture, invariants, quality gates), [`project-backlog.md`](docs/current-changes/project-backlog.md) (deferred work), in-flight design discussion, the agent guide, and the verification checklist |
| Release notes | [`docs/release-notes/`](docs/release-notes/) | Per-version notes (`release-notes-v0.2.0` … `v0.3.11`) |
| Decision records | [`docs/architecture/`](docs/architecture/) | Architecture Decision Records (ADRs) |
| Historical | [`docs/archive/`](docs/archive/) | Original proposal (9 ADRs) and superseded material |

---

## Prerequisites

| Requirement | Version | Notes |
| ----------- | ------- | ----- |
| Go | 1.25+ | Must match `go` version in `go.mod` |
| PostgreSQL | 14+ | Running and reachable before you start Themis |
| golangci-lint | latest | Only needed for `make check` / contributing |

The binary itself needs no runtime dependencies beyond PostgreSQL.

---

## Getting Started

This is the **canonical end-to-end guide** — a single from-scratch path that takes you
from an empty machine to an ingested, verified SBOM. Run the steps in order; each later step
reuses the shell variables exported earlier. Deeper references: [Testing with your own
CycloneDX SBOM](#testing-with-your-own-cyclonedx-sbom) (SBOM generation + correlation
nuances), [End-to-end verification](#end-to-end-verification--cross-check-the-whole-pipeline)
(per-stage "what good looks like"), and [Resetting ingested data](#resetting-ingested-data-local-dev-only).

> **Re-running after a code change?** Always **rebuild the binary (Step 3) before resetting
> the database (Step 2b).** Running an old binary against a fresh DB re-creates stale data.
> There is **no in-place upgrade** from a pre-`v0.3.0` database — reset and re-ingest.

### 0. Set your variables once

Fill these in; every later command reuses them.

```sh
export BASE_URL="http://localhost:8080"
export THEMIS_DATABASE_DSN="postgres://themis:themis-dev-password@localhost:5432/themis?sslmode=disable"
export SBOM_FILE="./myapp.cyclonedx.json"        # your CycloneDX file
export IMAGE_REF="myregistry/myapp:1.2.3"        # the image it describes
```

Do **not** copy the placeholder password — use a value you control and create a matching
Postgres role (Step 2a).

### 1. Start PostgreSQL

Ensure PostgreSQL is listening (default `localhost:5432`). On macOS with Homebrew:

```sh
brew services start postgresql@16   # or your installed version
pg_isready -h localhost -p 5432
```

### 2a. Create the database and role (first-time setup)

```sh
psql -U postgres -c "CREATE USER themis WITH PASSWORD 'themis-dev-password';"
psql -U postgres -c "CREATE DATABASE themis OWNER themis;"
psql -U postgres -c "GRANT ALL PRIVILEGES ON DATABASE themis TO themis;"
```

Verify the DSN connects before continuing (Themis will fail the same way if it can't):

```sh
psql "$THEMIS_DATABASE_DSN" -c 'SELECT 1;'
```

### 2b. Reset an existing database (clean slate)

Skip on first-time setup. To start fresh on a database that already has data — **required**
when moving from a pre-`v0.3.0` schema, or to pick up correctness fixes that only apply to
newly ingested data — stop the server, then wipe the schema. This needs **no superuser**
(the `themis` role owns its objects) and clears `schema_migrations`, so the legacy
"no migration found for version N" error cannot recur:

```sh
psql "$THEMIS_DATABASE_DSN" -c "DROP SCHEMA public CASCADE; CREATE SCHEMA public;"
```

This destroys all ingested data and **prior triage decisions do not carry over**. To keep
products/keys and clear only ingestion data instead, see
[Resetting ingested data](#resetting-ingested-data-local-dev-only).

### 3. Build the binary

```sh
make build                  # produces ./bin/themis
```

### 4. Configure Themis

Themis reads `themis.yaml` (optional) and environment variables. Env vars override file
values. Put secrets (DSN, passwords, API keys) in the environment — never in committed
config files.

```sh
cp themis.yaml.example themis.yaml
```

`THEMIS_DATABASE_DSN` (Step 0) is **required** whether or not you use `themis.yaml`. Leave
`database.dsn` empty in the file when using the env var (recommended). Optional:
`export THEMIS_CONFIG_PATH=/path/to/themis.yaml` if the config file is not in the working directory.

### 5. Apply database migrations

Themis also runs pending migrations on startup, but applying them explicitly is useful for
CI and first-time setup. Both `make migrate-up` and `make migrate-down` require
`THEMIS_DATABASE_DSN` in the same shell:

```sh
make migrate-up
psql "$THEMIS_DATABASE_DSN" -c "SELECT version, dirty FROM schema_migrations;"   # → 1, f
```

### 6. Start the server

Run from the repo root (so `./migrations` and optional `./themis.yaml` resolve correctly):

```sh
./bin/themis
```

On success the HTTP server listens on port `8080` (or the port in `themis.yaml`).

### 7. Verify health

```sh
curl -s "$BASE_URL/healthz"          # liveness — {"status":"ok"}
curl -s "$BASE_URL/readyz" | jq .    # readiness — checks.database = "ok"
curl -s -o /dev/null -w "%{http_code}\n" "$BASE_URL/metrics"   # → 200
```

`/readyz` may report `cve_feed: no successful poll yet` immediately after startup; that is
normal until the first background NVD/OSV poll completes, and does not block ingestion.

### 8. Create an API key

```sh
# --admin for local testing (all endpoints); use --product-id <uuid> in production
./bin/themis admin create-key --admin --expires 90d
export API_KEY="<key from output>"
```

API calls then require `X-API-Key: $API_KEY`. Webhooks use HMAC-SHA256 (`X-Themis-Signature`).

### 9. Create a product (auto-creates a default project + `latest` version)

```sh
export PRODUCT_ID=$(curl -s -X POST "$BASE_URL/api/v1/products" \
  -H "X-API-Key: $API_KEY" -H "Content-Type: application/json" \
  -d '{"name":"my-app","description":"from my image"}' | jq -r .id)
echo "PRODUCT_ID=$PRODUCT_ID"
```

### 10. Register the artifact (must exist before upload)

The trust gate requires the `image_digest` to be registered first; the returned `id` is the
`artifact_id` you upload against (re-registering the same digest is idempotent — the digest
is globally unique).

```sh
export IMAGE_DIGEST=$(docker inspect "$IMAGE_REF" --format '{{.Id}}')   # or any sha256:<64hex> for testing

export ARTIFACT_ID=$(curl -s -X POST "$BASE_URL/api/v1/products/$PRODUCT_ID/artifacts" \
  -H "X-API-Key: $API_KEY" -H "Content-Type: application/json" \
  -d "$(jq -n --arg d "$IMAGE_DIGEST" --arg repo "$(echo "$IMAGE_REF" | cut -d: -f1)" \
    '{image_digest:$d, version:"latest", repository:$repo}')" | jq -r .id)
echo "ARTIFACT_ID=$ARTIFACT_ID"
```

### 11. Upload the SBOM (envelope, not the raw file)

```sh
export SPEC_VERSION=$(jq -r '.specVersion // "1.6"' "$SBOM_FILE")     # must be 1.4 / 1.5 / 1.6

export INGESTION_ID=$(curl -s -X POST "$BASE_URL/api/v1/sbom/upload" \
  -H "X-API-Key: $API_KEY" -H "Content-Type: application/json" \
  -H "Idempotency-Key: upload-$(date +%s)" \
  -d "$(jq -n \
    --slurpfile doc "$SBOM_FILE" \
    --arg spec "$SPEC_VERSION" \
    --arg artifact_id "$ARTIFACT_ID" \
    --arg digest "$IMAGE_DIGEST" \
    '{format:"cyclonedx", spec_version:$spec, document:$doc[0],
      artifact_id:$artifact_id, image_digest:$digest, ci_job_id:"getting-started"}')" \
  | jq -r .ingestion_id)
echo "INGESTION_ID=$INGESTION_ID"
```

Expect **202 Accepted** with an `ingestion_id`. A `202` means *queued*, not done — always
poll (Step 12). Re-uploading the **same bytes** is idempotent: it returns the existing scan
and does **not** re-correlate (so to re-run after a code change, reset first — Step 2b).

### 12. Poll until the pipeline reaches a terminal state

```sh
until S=$(curl -s "$BASE_URL/api/v1/ingestions/$INGESTION_ID" -H "X-API-Key: $API_KEY" | jq -r .status); \
  [[ "$S" =~ ^(NOTIFIED|COMPLETED|FAILED|REJECTED)$ ]]; do
  curl -s "$BASE_URL/api/v1/ingestions/$INGESTION_ID" -H "X-API-Key: $API_KEY" | jq '{status, stage_detail}'
  sleep 2
done
echo "final=$S"
```

On `FAILED`/`REJECTED`, `stage_detail` is the authoritative reason (trust gate, parse, OSV,
or DB constraint) — see [Troubleshooting](#troubleshooting).

### 13. Inspect and verify the results

```sh
export PROJECT_ID=$(curl -s "$BASE_URL/api/v1/products/$PRODUCT_ID/projects" -H "X-API-Key: $API_KEY" | jq -r '.items[0].id')
export SCAN_ID=$(curl -s "$BASE_URL/api/v1/projects/$PROJECT_ID/scans" -H "X-API-Key: $API_KEY" | jq -r '.items[0].id')

curl -s "$BASE_URL/api/v1/scans/$SCAN_ID/vulnerabilities" -H "X-API-Key: $API_KEY" | jq '.items | length'
curl -s "$BASE_URL/api/v1/status?top=10" -H "X-API-Key: $API_KEY" | jq .
```

Sanity checks (see [End-to-end verification](#end-to-end-verification--cross-check-the-whole-pipeline)
for the full per-stage criteria):

| Check | Command | Expected |
| ----- | ------- | -------- |
| Findings are sane (not over-matched) | `… /status?top=10 \| jq '.top_components[] \| {name, vulnerability_count}'` | Plausible counts; no long-fixed CVEs on modern versions |
| Component identity is a valid PURL | `psql "$THEMIS_DATABASE_DSN" -c "SELECT component_purl FROM component_vulnerabilities LIMIT 5;"` | A single `@version`, no doubled `…@v?...@v` |
| Risk scores discriminate | `… /scans/$SCAN_ID/vulnerabilities \| jq '[.items[].enrichment.risk_score] \| unique'` | A range of values, not all `100` |

### 14. Confirm feeds and enrichment (background tickers)

```sh
curl -s "$BASE_URL/metrics" | grep -E 'themis_(epsskev_sync_total|epsskev_stale|exploitdb_sync_total|vexfeed_sync_total|reenrichjob_batches_total)'
curl -s "$BASE_URL/api/v1/status?top=10" -H "X-API-Key: $API_KEY" | jq '{signals_stale}'   # want false once EPSS/KEV synced
```

Feeds sync on startup then on their interval; `ReEnrichJob` back-fills open findings — no
re-upload needed. For coverage of upstream vendor VEX, check
`GET /api/v1/products/$PRODUCT_ID/versions/latest/vex-coverage` (expect `covered > 0` for
apk/rpm SBOMs).

---

## Configuration

See [Getting Started](#getting-started) for the minimum setup. Copy [`themis.yaml.example`](themis.yaml.example)
to `themis.yaml` for non-secret defaults. **Secrets** (database DSN, SMTP password, API keys) must
be set via environment variables — never committed in `themis.yaml`. Environment variables use the
`THEMIS_` prefix and **override** YAML values.

### Core

| Variable | Required | Purpose |
| -------- | -------- | ------- |
| `THEMIS_DATABASE_DSN` | **Yes** | PostgreSQL connection URL |
| `THEMIS_CONFIG_PATH` | No | Path to YAML config (default: `./themis.yaml`) |
| `THEMIS_NVD_API_KEY` | No | NVD API key (higher rate limits for CVE watch) |
| `THEMIS_SMTP_*` | No | Outbound email for notifications (`HOST`, `PORT`, `USERNAME`, `PASSWORD`, `FROM`, `USE_TLS`) |
| `THEMIS_TEAMS_WEBHOOK_URL` | No | Microsoft Teams webhook |
| `THEMIS_WEBHOOK_SECRET` | No | HMAC secret for CI webhook ingestion |
| `THEMIS_TRUST_DEFAULT_POLICY` | No | Default artifact trust policy: `strict`, `standard`, or `permissive` |
| `THEMIS_LOG_LEVEL` | No | Structured log verbosity: `debug`, `info`, `warn`, `error` |

YAML keys for the above: `database.dsn`, `nvd.api_key`, `nvd.poll_interval`, `osv.*`, `smtp.*`,
`teams.webhook_url`, `trust.default_policy`, `webhook.secret`, `log.level` — see `themis.yaml.example`.

### Signal feeds and intelligence

These settings control **background schedulers** that fetch external data and **retroactively update**
open findings (`ReEnrichJob`) without re-uploading SBOMs. All poll intervals default to **24h** and
use a simple ticker (not cron expressions).

#### EPSS + KEV (`epsskev` / `THEMIS_EPSSKEV_*`)

| YAML key | Env override | Purpose |
| -------- | ------------ | ------- |
| `epsskev.epss_url` | `THEMIS_EPSSKEV_EPSS_URL` | FIRST.org EPSS scores (gzip CSV). Feeds `epss_score` and the risk formula (+30% max). |
| `epsskev.kev_url` | `THEMIS_EPSSKEV_KEV_URL` | CISA Known Exploited Vulnerabilities JSON. Sets `kev_listed` (+15 risk score, Layer 1 Critical rule). |
| `epsskev.poll_interval` | `THEMIS_EPSSKEV_POLL_INTERVAL` | How often to sync EPSS/KEV (e.g. `24h`, `12h`). |

#### ExploitDB (`exploitdb` / `THEMIS_EXPLOITDB_*`)

| YAML key | Env override | Purpose |
| -------- | ------------ | ------- |
| `exploitdb.csv_url` | `THEMIS_EXPLOITDB_CSV_URL` | ExploitDB `files_exploits.csv` mirror. Populates `exploit_records`; drives `exploit_public` and Layer 1 rules. |
| `exploitdb.poll_interval` | `THEMIS_EXPLOITDB_POLL_INTERVAL` | ExploitDB sync frequency. |

#### Upstream vendor feeds (`vexfeed` / `THEMIS_VEXFEED_*`)

Themis separates **true vendor VEX** (exploitability overlay) from **advisory / vulnerability-DB
feeds** (correlation), per the Layer-0 refactor (CR-4):

- **VEX overlay** — Red Hat CSAF **VEX** (`rhel_vex_url`) only. Adjusts `risk_context.effective_state`
  and `upstream_vex_coverage`; never creates findings.
- **Correlation sources** — Alpine / Rocky / Wolfi **OSV** and Red Hat CSAF **advisories**
  (`rhel_csaf_url`). These create/enrich findings (carrying severity + fixed version, with
  provenance `distro_osv`/`rhsa`) through the unified Correlator. Matching applies to **Alpine
  (`apk`) and RPM (`rpm`)** PURLs.

| YAML key | Env override | Purpose |
| -------- | ------------ | ------- |
| `vexfeed.rhel_vex_url` | `THEMIS_VEXFEED_RHEL_VEX_URL` | Red Hat CSAF **VEX** directory → VEX overlay. |
| `vexfeed.rhel_csaf_url` | `THEMIS_VEXFEED_RHEL_CSAF_URL` | Red Hat CSAF **advisories** directory → rpm correlation source (NEVRA fixed-version ranges). |
| `vexfeed.rhel_url` | `THEMIS_VEXFEED_RHEL_URL` | **Deprecated** alias for `rhel_csaf_url` (kept one release). |
| `vexfeed.alpine_osv_url` | `THEMIS_VEXFEED_ALPINE_OSV_URL` | Alpine OSV GCS zip (`all.zip`) → apk correlation source. |
| `vexfeed.rocky_osv_url` | `THEMIS_VEXFEED_ROCKY_OSV_URL` | Rocky Linux OSV GCS zip (`all.zip`) → rpm correlation source. |
| `vexfeed.wolfi_osv_url` | `THEMIS_VEXFEED_WOLFI_OSV_URL` | Wolfi OSV security feed → apk correlation source. |
| `vexfeed.poll_interval` | `THEMIS_VEXFEED_POLL_INTERVAL` | Sync frequency. After sync, the correlation index is rebuilt and affected artifacts get the VEX overlay re-applied. |

**Feed registry (`vexfeed.feeds`).** Beyond overriding the built-in URLs, a `feeds:` delta list
lets you **add, override, or disable** feeds. It is merged over the built-in defaults **by name**
(built-ins: `rhel-vex` [overlay]; `rhel-csaf`, `alpine`, `rocky`, `wolfi` [correlation]). Each entry
takes `type` (`url` | `zip-osv` | `csaf-dir`), `class` (`correlation` default, or `overlay`),
`url`, `kind` (for `type: url`), and `enabled` (set `false` to disable a built-in). See
[`themis.yaml.example`](themis.yaml.example).

```yaml
vexfeed:
  feeds:
    - name: rocky            # disable a built-in by name
      enabled: false
    - name: my-distro        # add a custom correlation feed
      type: zip-osv
      url: https://example.com/osv/all.zip
      ecosystem: mydistro
```

A failed feed logs a structured warning, records degraded health (surfaced as `degraded_feeds[]`
on `GET /api/v1/status`), and leaves cached data in place; other feeds continue.

#### Other tuning

| YAML key | Env override | Purpose |
| -------- | ------------ | ------- |
| `intelligence.blast_radius_cap` | `THEMIS_INTELLIGENCE_BLAST_RADIUS_CAP` | Unique-customer count at which the blast-radius multiplier stops increasing (default **10** → max **2.0×**). |
| *(none)* | `THEMIS_GITHUB_TOKEN` | GitHub API token for GHSA rate limits — **config wired; GHSA adapter not used yet** (ships with the AI layer). |

**Risk score** is a composite: severity baseline, EPSS (+30% max), KEV (+15), the blast-radius
multiplier (1.0–2.0×), and a Layer 1 Critical override (`score = 100`). Integrations that hard-code
severity-only thresholds should recalibrate.

### API surface beyond Phase 1

#### VEX export

| Endpoint | Purpose |
| -------- | ------- |
| `GET /api/v1/products/{id}/versions/{v}/vex?format=cyclonedx\|openvex` | Export computed VEX state for all findings in a product version (default: CycloneDX). Includes `x-themis-epss-score`, `x-themis-kev-listed`, `x-themis-blast-radius` extensions. |
| `GET /api/v1/products/{id}/versions/{v}/vex-coverage` | Count findings by `upstream_vex_coverage`: `covered`, `not_covered`, `purl_mismatch`. |

VEX precedence in export: `themis_generated` (human triage) > `manual`/`vendor` (user-supplied) >
`ai_generated` > `upstream_vendor`.

#### Asset graph

Register the Product → Microservice → Deployment → Customer graph manually (no auto-discovery from SBOM metadata).

| Endpoint | Purpose |
| -------- | ------- |
| `POST /api/v1/products/{id}/microservices` | Register a microservice under a product |
| `POST /api/v1/microservices/{id}/deployments` | Link a microservice to a customer deployment |
| `POST /api/v1/customers` | Register an internal team/owner (not a B2B customer) |
| `GET /api/v1/products/{id}/blast-radius` | Query blast-radius score and affected teams for a product |

Blast-radius runs synchronously at SBOM ingest; empty graph → baseline multiplier `1.0×`; cap at
`2.0×` for 10+ unique customers (configurable via `intelligence.blast_radius_cap`).

#### Registration and management

| Endpoint | Purpose |
| -------- | ------- |
| `POST /api/v1/products/{id}/artifacts` | Register an artifact by `image_digest` (returns the existing one for a duplicate digest — digest is globally unique). Auto-creates a default project + `latest` version. |
| `POST /api/v1/projects/{id}/versions` | Create a version under a project |
| `GET /api/v1/status?top=N` | System overview: component counts, vuln breakdown by severity/state, top-N components (default 10, max 50), `signals_stale` when EPSS/KEV sync is overdue |
| `GET /api/v1/products/{id}/vulnerabilities` | Findings across every artifact under a product (latest scan per artifact). Same shape/filters as the scan endpoint: `?severity=`, `?effective_state=`, `?cve_id=`, cursor `?limit=`/`?cursor=`. |
| `GET /api/v1/projects/{id}/vulnerabilities` | Findings across every artifact under a project |
| `GET /api/v1/products/{id}/versions/{v}/vulnerabilities` | Findings for one product version |
| `GET /api/v1/sboms` | Paginated SBOM inventory (cursor + `total`) |
| `GET /api/v1/products/{id}/sboms` | Product-scoped SBOM list |
| `DELETE /api/v1/sboms/{id}?force=true` | Soft-delete (`deleted_at` tombstone); `force=true` required when deleting the latest scan for an artifact; writes a `SBOM_DELETED` audit entry |

Deleted SBOMs are excluded from status counts, listings, blast-radius, VEX export, and findings
queries. Raw `component_vulnerabilities` rows are never hard-deleted via API.

#### Error responses

All API errors use a three-field envelope:

```json
{"error": {"code": "SBOM_NOT_FOUND", "message": "...", "hint": "..."}}
```

Twelve catalogue codes cover all domain errors (`SBOM_NOT_FOUND`, `PRODUCT_NOT_FOUND`,
`CANNOT_DELETE_LATEST_SBOM`, `INVALID_SBOM_FORMAT`, `INTERNAL_ERROR`, etc.). No raw PostgreSQL or
Go error strings appear in response bodies.

#### Not yet implemented

Deferred to later work (see [project-backlog.md](docs/current-changes/project-backlog.md)): AI workers + knowledge graph,
GHSA adapter, Debian/Ubuntu vendor VEX feeds, Redis queue, Docker stack,
Web UI, RBAC, real cosign verification.

---

## Database Migrations

```sh
make migrate-up      # apply all pending migrations (THEMIS_DATABASE_DSN must be exported)
make migrate-down    # roll back one migration
```

Migration SQL lives in `migrations/` as a single squashed `v0.3.0` baseline. On normal startup
`./bin/themis` applies pending migrations automatically after connecting. A startup **schema-skew
guard** refuses to start against a pre-`v0.3.0` database (legacy `sbom_documents`/`images` tables)
with a "re-initialise your database" message — there is no in-place upgrade; see
[Full database reset](#resetting-ingested-data-local-dev-only).

---

## Running

```sh
export THEMIS_DATABASE_DSN="postgres://themis:themis-dev-password@localhost:5432/themis?sslmode=disable"
./bin/themis
```

See [Getting Started](#getting-started) for Postgres setup, config, migrations, and health checks.

---

## Troubleshooting

| Symptom | Likely cause | Fix |
| ------- | ------------- | --- |
| `missing required configuration field: database.dsn` | `THEMIS_DATABASE_DSN` not exported | `export THEMIS_DATABASE_DSN="postgres://..."` |
| `password authentication failed for user "..."` | DSN uses README placeholders | Create a matching Postgres role or update the DSN |
| `THEMIS_DATABASE_DSN is required` from `make migrate-up` | Env var unset | Export `THEMIS_DATABASE_DSN` in the same shell session |
| `connection refused` on `:5432` | Postgres not running | Start Postgres; confirm with `pg_isready` |
| Startup refuses with "re-initialise your database" | Pre-`v0.3.0` schema present | Drop & recreate the DB, then `make migrate-up` ([Full database reset](#resetting-ingested-data-local-dev-only)) |
| Server starts but `/readyz` is 503 | DB down or CVE feed not polled yet | Check `checks` in the JSON body; wait for the first watch poll |
| Ingestion succeeds but no vulnerabilities | PURL ecosystem not mapped to OSV, or no version match | See [SBOM correlation and OSV](#sbom-correlation-osv-and-linux-distros); check component ecosystems |
| Upload returns `422 invalid JSON body` | Malformed JSON or empty/invalid `artifact_id` / `project_id` UUIDs | Build the envelope with `jq`; omit UUID fields rather than sending `""` |
| Ingestion `REJECTED` — `image not found` | `image_digest` not registered in `artifacts` | Register the artifact first via `POST /api/v1/products/{id}/artifacts`; digest must match exactly |
| Ingestion `FAILED` — artifact FK violation | `artifact_id` in the payload is not a registered `artifacts.id` | Use the `id` returned by `POST /api/v1/products/{id}/artifacts` |
| `unsupported cyclonedx spec version` | SBOM version not 1.4 / 1.5 / 1.6 | Regenerate or set `spec_version` accordingly |
| Want verbose / debug logs | Default `info` | Set `THEMIS_LOG_LEVEL=debug` or `log.level` in `themis.yaml` |

---

## API Key Management

```sh
# Create a product-scoped key
./bin/themis admin create-key --product-id <id> --expires 90d

# Revoke a key
./bin/themis admin revoke-key --key-id <id>
```

Requires the same `THEMIS_DATABASE_DSN` (and optional `themis.yaml`) as the server.
See [Getting Started § 8](#8-create-an-api-key).

---

## MCP Server (LLM access)

`themis-mcp` is a [Model Context Protocol](https://modelcontextprotocol.io) server that exposes Themis to
LLM clients (Claude Code / Claude Desktop and any MCP host) as tools. It is a standalone API client — it drives a
running Themis over `/api/v1` and needs no database access of its own. Full reference:
[`cmd/themis-mcp/README.md`](cmd/themis-mcp/README.md).

### Build

```sh
go build -o bin/themis-mcp ./cmd/themis-mcp
```

### Configure

A running server (see [Running](#running)) and an API key (see [API Key Management](#api-key-management)) are
required; only the `themis_health` tool works without a key.

| Setting | How | Default |
| ------- | --- | ------- |
| Themis base URL | `THEMIS_BASE_URL` / `--base-url` | `http://localhost:8080` |
| API key | `THEMIS_API_KEY` | *(required for `/api/v1` tools)* |
| Read-only mode | `THEMIS_MCP_READ_ONLY=1` / `--read-only` | off |
| Transport | `--http :9000` for HTTP; omit for stdio | stdio |
| HTTP timeout | `--timeout` | `60s` |

### Run

Stdio (a local client launches the binary):

```sh
claude mcp add themis \
  --env THEMIS_API_KEY=<key> \
  --env THEMIS_BASE_URL=http://localhost:8080 \
  -- /path/to/bin/themis-mcp
```

Streamable HTTP (networked / shared gateway — put your own auth in front of it):

```sh
THEMIS_API_KEY=<key> ./bin/themis-mcp --http :9000
```

### Tools

34 tools (21 in `--read-only`): status, products/projects/versions, artifacts, scans, findings, components,
CVE-watch, SBOM list/upload, ingestion polling (with a wait-for-terminal helper), blast radius, VEX
export/coverage, config, and the state-changing triage / VEX-upload / SBOM-delete / config-update paths. Read
tools are annotated `readOnlyHint`; tools that change finding state or remove data are annotated
`destructiveHint` so clients can prompt before calling them.

> **Advisory-only (D-WRITE-1).** Themis holds that a finding's state should change only with a human in the
> loop. The triage, VEX-upload, and SBOM-delete tools cross that line: they are enabled here but flagged
> `destructiveHint`, attributed to the server's own API key in `audit_log`, and disabled entirely by
> `--read-only`. Treat them as human-authorized actions.

---

## Testing

### Smoke tests

With Themis running:

```sh
curl -s http://localhost:8080/healthz
curl -s http://localhost:8080/readyz | jq .
curl -s -o /dev/null -w "%{http_code}\n" http://localhost:8080/api/v1/products   # expect 401
```

### Testing with your own CycloneDX SBOM

> The canonical end-to-end path (setup → upload → verify) is [Getting
> Started](#getting-started). This section is a **deep-dive reference** for generating an SBOM
> and understanding correlation — read it alongside Getting Started Steps 9–14, not instead of them.

Use this path when you already have a CycloneDX JSON file from your container image (e.g.
generated by [Syft](https://github.com/anchore/syft), [Trivy](https://github.com/aquasecurity/trivy),
or your CI pipeline).

#### What your file provides vs what you must supply

| From your CycloneDX file | You still provide to Themis |
| ------------------------ | --------------------------- |
| Component list (with `purl`) | `image_digest` (from the image you scanned) |
| `specVersion` (1.4 / 1.5 / 1.6) | `artifact_id` (from `POST /products/{id}/artifacts`) |
| Optional embedded `vulnerabilities` | `project_id` (from API) and `X-API-Key` |

Findings are created by matching SBOM **components** (by PURL) against the local `vulnerabilities`
catalog and, when needed, **live OSV queries** during ingestion — not from the embedded
`vulnerabilities` section inside your CycloneDX file. Components without `purl` are skipped. CVE
watch also polls NVD/OSV in the background and correlates against the full stored catalog. If you
see components but zero findings, check [SBOM correlation and OSV](#sbom-correlation-osv-and-linux-distros).

#### 0. Generate an SBOM from your image (if needed)

```sh
export IMAGE_REF="myregistry/myapp:1.2.3"
export SBOM_FILE="./myapp.cyclonedx.json"

# Syft
syft "$IMAGE_REF" -o cyclonedx-json="$SBOM_FILE"

# or Trivy
trivy image --format cyclonedx --output "$SBOM_FILE" "$IMAGE_REF"
```

#### 1. Inspect the file

```sh
jq -r '.specVersion' "$SBOM_FILE"    # must be 1.4, 1.5, or 1.6
jq '[.components[]? | select(.purl != null and .purl != "")] | length' "$SBOM_FILE"
```

#### 2. Get the image digest (same image you scanned)

```sh
export IMAGE_DIGEST=$(docker inspect "$IMAGE_REF" --format '{{.Id}}')
# or: docker image inspect "$IMAGE_REF" --format '{{index .RepoDigests 0}}'
```

#### 3. Create an API key, product, and project

```sh
export BASE_URL="http://localhost:8080"
export THEMIS_DATABASE_DSN="postgres://themis:themis-dev-password@localhost:5432/themis?sslmode=disable"

./bin/themis admin create-key --admin --expires 90d
export API_KEY="<api_key from output>"

export PRODUCT_ID=$(curl -s -X POST "$BASE_URL/api/v1/products" \
  -H "X-API-Key: $API_KEY" -H "Content-Type: application/json" \
  -d '{"name":"my-app","description":"from my image"}' | jq -r .id)

export PROJECT_ID=$(curl -s -X POST "$BASE_URL/api/v1/products/$PRODUCT_ID/projects" \
  -H "X-API-Key: $API_KEY" -H "Content-Type: application/json" \
  -d '{"name":"my-app-main"}' | jq -r .id)
```

#### 4. Register the artifact

`POST /api/v1/products/{id}/artifacts` registers an artifact by its `image_digest` under the
product's auto-created default project (a duplicate digest returns the existing artifact — the
digest is globally unique). Use the returned `id` as the `artifact_id` in the upload envelope.

```sh
export ARTIFACT_ID=$(curl -s -X POST "$BASE_URL/api/v1/products/$PRODUCT_ID/artifacts" \
  -H "X-API-Key: $API_KEY" -H "Content-Type: application/json" \
  -d "$(jq -n --arg d "$IMAGE_DIGEST" --arg repo "$(echo "$IMAGE_REF" | cut -d: -f1)" \
    '{image_digest: $d, version: "latest", repository: $repo}')" | jq -r .id)
```

#### 5. Upload your CycloneDX file

```sh
export SPEC_VERSION=$(jq -r '.specVersion // "1.6"' "$SBOM_FILE")

export INGESTION_ID=$(curl -s -X POST "$BASE_URL/api/v1/sbom/upload" \
  -H "X-API-Key: $API_KEY" \
  -H "Content-Type: application/json" \
  -H "Idempotency-Key: upload-$(basename "$SBOM_FILE")-$(date +%s)" \
  -d "$(jq -n \
    --slurpfile doc "$SBOM_FILE" \
    --arg spec "$SPEC_VERSION" \
    --arg artifact_id "$ARTIFACT_ID" \
    --arg project_id "$PROJECT_ID" \
    --arg digest "$IMAGE_DIGEST" \
    '{
      format: "cyclonedx",
      spec_version: $spec,
      document: $doc[0],
      artifact_id: $artifact_id,
      project_id: $project_id,
      image_digest: $digest,
      ci_job_id: "local-upload"
    }')" | jq -r .ingestion_id)
```

Expect **202 Accepted** with an `ingestion_id`.

**Upload body shape** — the request must be a JSON **envelope** (`format`, `document`, optional
`artifact_id`, `project_id`, `image_digest`), not the raw CycloneDX file alone. Do not send empty
strings for UUID fields (`""` causes `422 invalid JSON body`).

#### 6. Poll ingestion until complete

```sh
until STATUS=$(curl -s "$BASE_URL/api/v1/ingestions/$INGESTION_ID" \
  -H "X-API-Key: $API_KEY" | jq -r .status); \
  [[ "$STATUS" == "NOTIFIED" || "$STATUS" == "COMPLETED" ]]; do
  curl -s "$BASE_URL/api/v1/ingestions/$INGESTION_ID" \
    -H "X-API-Key: $API_KEY" | jq '{status, stage_detail, scan_id}'
  [[ "$STATUS" == "FAILED" || "$STATUS" == "REJECTED" ]] && break
  sleep 2
done
echo "final=$STATUS"
```

On failure, `stage_detail` is the authoritative message (trust gate, parse, OSV, or DB constraint).
You can also inspect Postgres:

```sh
psql "$THEMIS_DATABASE_DSN" -c "
SELECT status, error_message,
       payload->>'pipeline_status' AS pipeline_status,
       payload->>'stage_detail' AS stage_detail
FROM ingestion_jobs WHERE id = '$INGESTION_ID';"
```

#### 7. Inspect results

```sh
export SCAN_ID=$(curl -s "$BASE_URL/api/v1/projects/$PROJECT_ID/scans" \
  -H "X-API-Key: $API_KEY" | jq -r '.items[0].id')

curl -s "$BASE_URL/api/v1/scans/$SCAN_ID/vulnerabilities" -H "X-API-Key: $API_KEY" | jq .
curl -s "$BASE_URL/api/v1/components?limit=20" -H "X-API-Key: $API_KEY" | jq .
```

#### 8. Triage a finding (optional)

```sh
export FINDING_ID=$(curl -s "$BASE_URL/api/v1/scans/$SCAN_ID/vulnerabilities" \
  -H "X-API-Key: $API_KEY" | jq -r '.items[0].id')

curl -s -X POST "$BASE_URL/api/v1/vulnerabilities/$FINDING_ID/triage" \
  -H "X-API-Key: $API_KEY" -H "Content-Type: application/json" \
  -d '{"decision":"false_positive","justification":"demo triage"}' | jq .
```

A triage decision auto-generates a `themis_generated` VEX assertion and a durable
`risk_context` verdict keyed on `(artifact_id, component_purl, cve_id)` — it survives rescans and
re-applies to future ingestions of the same component/CVE.

API reference: [`api/openapi.yaml`](api/openapi.yaml). Sample fixture used in tests:
[`internal/adapter/parser/testdata/cyclonedx-1.6.json`](internal/adapter/parser/testdata/cyclonedx-1.6.json).

### End-to-end verification — cross-check the whole pipeline

After uploading an SBOM, use these checks to confirm **each stage actually worked**: the
artifact is registered, the SBOM ingested and split into `sboms` + `scan_reports`, findings
correlated, enrichment signals applied, the external feeds are syncing, and the system reports
ready. Each step pairs an API or SQL check with **what "good" looks like**, and reuses the
environment variables exported above (`BASE_URL`, `API_KEY`, `THEMIS_DATABASE_DSN`, `PRODUCT_ID`,
`PROJECT_ID`, `IMAGE_DIGEST`, `ARTIFACT_ID`, `INGESTION_ID`, `SCAN_ID`).

> A `202 Accepted` on upload only means the job was **queued** — it is not success. Always run
> steps 2–6 below before concluding the pipeline works.

#### Step 0 — Server is up and ready

```sh
curl -s "$BASE_URL/healthz"                       # → {"status":"ok"}
curl -s "$BASE_URL/readyz" | jq .                 # → checks.database = "ok"
curl -s -o /dev/null -w "%{http_code}\n" "$BASE_URL/metrics"   # → 200
```

`readyz.checks.cve_feed` is `"no successful poll yet"` until the first background NVD/OSV poll;
that is normal right after startup and does not block ingestion.

#### Step 1 — Is the artifact registered? (must exist before upload)

```sh
# API: re-registering the same digest is idempotent — it returns the SAME artifact id
curl -s -X POST "$BASE_URL/api/v1/products/$PRODUCT_ID/artifacts" \
  -H "X-API-Key: $API_KEY" -H "Content-Type: application/json" \
  -d "$(jq -n --arg d "$IMAGE_DIGEST" '{image_digest:$d}')" | jq '{id, version_id, image_digest}'

# SQL: confirm exactly one artifact row for the digest (image_digest is globally UNIQUE)
psql "$THEMIS_DATABASE_DSN" -c \
  "SELECT id, version_id, image_digest FROM artifacts WHERE image_digest = '$IMAGE_DIGEST';"
```

**Good:** one `artifacts` row; the returned `id` equals your `ARTIFACT_ID`. A missing row is why
ingestion later rejects with `image not found — ingest parent first`.

#### Step 2 — Did ingestion complete, and did it write the split model?

```sh
# Pipeline reached a terminal success state (NOT FAILED / REJECTED)
curl -s "$BASE_URL/api/v1/ingestions/$INGESTION_ID" -H "X-API-Key: $API_KEY" \
  | jq '{status, stage_detail, scan_id}'        # → status NOTIFIED or COMPLETED

# one composition (sboms) + one scan run (scan_reports) per ingest
psql "$THEMIS_DATABASE_DSN" -c "
SELECT
  (SELECT COUNT(*) FROM sboms        WHERE artifact_id = '$ARTIFACT_ID') AS sboms,
  (SELECT COUNT(*) FROM scan_reports WHERE artifact_id = '$ARTIFACT_ID') AS scan_reports;"
```

**Good:** `status` is `NOTIFIED`/`COMPLETED`; `sboms ≥ 1` and `scan_reports ≥ 1`. Re-uploading the
**same** bytes is idempotent — `scan_reports` does **not** grow. On failure, `stage_detail` is the
authoritative reason (trust gate, parse, OSV, or DB constraint).

#### Step 3 — Is the SBOM registered/listed, and were findings correlated?

```sh
# The SBOM appears in the inventory (system-wide and product-scoped)
curl -s "$BASE_URL/api/v1/sboms?limit=20" -H "X-API-Key: $API_KEY" | jq '.items[] | {id, image_digest, is_latest}'
curl -s "$BASE_URL/api/v1/products/$PRODUCT_ID/sboms" -H "X-API-Key: $API_KEY" | jq '.total'

# Findings for the latest scan
export SCAN_ID=$(curl -s "$BASE_URL/api/v1/projects/$PROJECT_ID/scans" -H "X-API-Key: $API_KEY" | jq -r '.items[0].id')
curl -s "$BASE_URL/api/v1/scans/$SCAN_ID/vulnerabilities" -H "X-API-Key: $API_KEY" | jq '.items | length'

# Raw counts in Postgres
psql "$THEMIS_DATABASE_DSN" -c "
SELECT
  (SELECT COUNT(*) FROM components) AS components,
  (SELECT COUNT(*) FROM vulnerabilities) AS cve_catalog,
  (SELECT COUNT(*) FROM component_vulnerabilities) AS findings;"
```

**Good:** the SBOM shows up in both listings (`is_latest:true` for the newest scan); the scan has
≥ 1 vulnerability. `findings < components` is **normal** (version ranges, unmapped `rpm`, no OSV
entry) — see [SBOM correlation, OSV, and Linux distros](#sbom-correlation-osv-and-linux-distros).

#### Step 4 — Are enrichment signals attached to findings?

```sh
curl -s "$BASE_URL/api/v1/scans/$SCAN_ID/vulnerabilities" -H "X-API-Key: $API_KEY" \
  | jq '.items[0].enrichment'
```

**Good:** an `enrichment` object with `epss_score`, `kev_listed`, `exploit_public`, `risk_score`,
`deterministic_level`, `blast_radius_score`, `upstream_vex_coverage`. EPSS/KEV/exploit fields stay
empty until the **first feed sync** runs and `ReEnrichJob` back-fills open findings (Step 5) — no
re-upload needed. `blast_radius_score` is `1.0` until you register the asset graph
(`POST /customers` → `/microservices` → `/deployments`).

#### Step 5 — Are the external feeds working?

Feeds run on background tickers (default **24h**). Verify both that a sync **succeeded** and that
it **wrote rows**.

```sh
# Sync counters (status="success" should be ≥ 1 once the first tick has run)
curl -s "$BASE_URL/metrics" | grep -E \
  'themis_(epsskev_sync_total|epsskev_stale|exploitdb_sync_total|vexfeed_sync_total|vexfeed_assertions_total|reenrichjob_batches_total)'

# Rows landed in the signal tables
psql "$THEMIS_DATABASE_DSN" -c "
SELECT
  (SELECT COUNT(*) FROM epss_kev_signals) AS epss_kev,
  (SELECT COUNT(*) FROM exploit_records)  AS exploitdb,
  (SELECT COUNT(*) FROM vex_assertions)   AS vendor_vex;"
```

**Good:** `themis_*_sync_total{status="success"} ≥ 1`, `themis_epsskev_stale 0`, and non-zero
row counts. If a feed is `0`: the ticker may not have fired yet (restart to force a sync at
startup, or wait for the interval), the source URL is unreachable (a failed feed logs a warning and
leaves cached data in place — see [Signal feeds and intelligence](#signal-feeds-and-intelligence)),
or `status="error"` is incrementing. Override URLs with `THEMIS_EPSSKEV_*` / `THEMIS_EXPLOITDB_*`
/ `THEMIS_VEXFEED_*` for mirrors or air-gapped copies.

#### Step 6 — Is everything ready? (single overview)

```sh
curl -s "$BASE_URL/api/v1/status?top=10" -H "X-API-Key: $API_KEY" | jq .
```

**Good — the whole pipeline is healthy when:**

| Field | Ready value |
| ----- | ----------- |
| `components.total_registered` | > 0 (your SBOM's components) |
| `vulnerabilities.total_findings` | > 0, with `by_severity` / `by_state` populated |
| `top_components` | lists your most-vulnerable components |
| `signals_stale` | **`false`** — EPSS/KEV synced within the freshness window |

`signals_stale: true` means no successful EPSS/KEV sync is recent — re-check Step 5. Counts here
reflect **only the latest scan** per artifact (not every historical rescan), via the shared
`v_latest_findings` filter.

### SBOM correlation, OSV, and Linux distros

Debugging lessons from real SBOM bring-up (e.g. Alpine `apk` SBOMs from Syft/Trivy). Use this
before assuming “ingestion worked but Themis is broken.”

#### How findings are created

1. **Parse** — CycloneDX components become canonical inventory keyed by **PURL** (`ecosystem`, `name`, `version`).
2. **Correlate (ingest)** — For each component: match the local `vulnerabilities` table;
   if no hit, query **OSV** and upsert matches into `component_vulnerabilities`.
3. **CVE watch** — Background NVD/OSV poll plus correlation against the **full** stored catalog and
   registered components.

The CycloneDX `vulnerabilities` array in your file is **not** ingested as findings. A large NVD
cache with zero overlap on package names is normal until OSV correlation runs.

#### OSV ecosystem mapping (PURL type ≠ OSV name)

Syft/Trivy PURL **types** are not always valid [OSV ecosystem](https://google.github.io/osv.dev/) names.
Themis maps supported types before calling OSV (`internal/adapter/osv/ecosystem.go`):

| PURL type (in SBOM) | OSV ecosystem | Typical image / SBOM source |
| ------------------- | ------------- | --------------------------- |
| `apk` | `Alpine` | Alpine Linux, many minimal/nginx images |
| `deb` | `Debian` | Debian-based images |
| `ubuntu` | `Ubuntu` | Ubuntu-based images |
| `npm` | `npm` | Node.js dependencies |
| `maven` | `Maven` | Java dependencies |
| `go` | `Go` | Go modules |
| `pypi` | `PyPI` | Python packages |
| `nuget` | `NuGet` | .NET packages |
| `cargo` | `crates.io` | Rust crates |
| `gem` | `RubyGems` | Ruby gems |

**Unsupported for OSV (skipped, no live lookup):** `rpm`, `generic`, `oci`, and other types without
a mapping. This affects **RHEL, Rocky Linux, AlmaLinux, Fedora RPM** SBOMs: components are stored,
but OSV is not called for `rpm`. Findings may still appear from the local NVD cache when
CPE/package metadata aligns — often sparse for distro packages. (Distro OSV + RHSA advisories also
correlate RPM/apk PURLs — see [Upstream vendor feeds](#upstream-vendor-feeds-vexfeed--themis_vexfeed_).)

#### Distro-specific expectations

| Base / scanner output | Dominant PURL types | Correlation |
| --------------------- | ------------------- | ----------- |
| **Alpine** (incl. many `nginx` images) | `apk` | OSV `Alpine` — good coverage; finding count < component count is normal |
| **Debian / Ubuntu** | `deb` / `ubuntu` | OSV `Debian` / `Ubuntu` |
| **Rocky / RHEL / Alma** | `rpm` | OSV skipped; expect fewer automatic findings until RPM/distro feed support |
| **Mixed** (app + OS packages) | `npm`, `apk`, `rpm`, … | Each ecosystem handled independently |

**Alpine naming:** PURLs are often `pkg:apk/alpine/openssl@3.x`. Themis may store the name as
`alpine/openssl` while OSV expects `openssl`. Ingest succeeds; some packages may not match until
name normalization improves. **Image name ≠ ecosystem** — an `nginx:alpine` image still yields
`apk` components from the OS layer; correlation follows PURL type, not the image tag.

#### Debugging checklist

Run in order when components exist but findings are missing or ingestion fails:

```sh
# 1. Component ecosystems (what PURL types dominate?)
curl -s "$BASE_URL/api/v1/components?limit=200" -H "X-API-Key: $API_KEY" \
  | jq '[.items[].ecosystem] | group_by(.) | map({ecosystem: .[0], count: length})'

# 2. Ingestion outcome
curl -s "$BASE_URL/api/v1/ingestions/$INGESTION_ID" -H "X-API-Key: $API_KEY" \
  | jq '{status, stage_detail, scan_id}'

# 3. Counts in Postgres
psql "$THEMIS_DATABASE_DSN" -c "
SELECT
  (SELECT COUNT(*) FROM components) AS components,
  (SELECT COUNT(*) FROM vulnerabilities) AS cve_catalog,
  (SELECT COUNT(*) FROM component_vulnerabilities) AS findings;"

# 4. Sanity-check OSV for a sample Alpine package (PURL type vs OSV name)
curl -s -X POST 'https://api.osv.dev/v1/querybatch' -H 'Content-Type: application/json' \
  -d '{"queries":[{"package":{"ecosystem":"apk","name":"openssl"}}]}' | jq .message
# → "Invalid ecosystem" — OSV wants "Alpine", not "apk"

curl -s -X POST 'https://api.osv.dev/v1/querybatch' -H 'Content-Type: application/json' \
  -d '{"queries":[{"package":{"ecosystem":"Alpine","name":"openssl"}}]}' \
  | jq '.results[0].vulns | length'
```

#### Learnings (avoid repeating the same mistakes)

1. **`202 Accepted` ≠ success** — poll `GET /api/v1/ingestions/{id}`; trust `stage_detail` and
   `pipeline_status` in `ingestion_jobs`.
2. **Register the artifact before upload** — the trust gate requires `image_digest` in `artifacts`;
   `artifact_id` in the payload must be that row's id (`POST /products/{id}/artifacts`).
3. **Upload envelope, not raw SBOM** — wrap CycloneDX in `format` + `document`; never send `artifact_id: ""`.
4. **PURL type ≠ OSV ecosystem** — `apk`→`Alpine`, `deb`→`Debian`; unmapped types are skipped, not
   sent raw to OSV.
5. **NVD cache size is misleading** — hundreds of CVE rows can still yield zero findings without
   package-level OSV correlation.
6. **Idempotent re-submission** — re-uploading the same SBOM bytes returns the existing scan (no
   new `scan_reports`). A divergent SBOM (new `sbom_checksum`) for the same artifact adds a new
   `sboms` row.
7. **Finding count < component count is normal** — version ranges, missing OSV entries, and
   unsupported `rpm` packages all reduce matches. (A 77-component Alpine SBOM producing ~50 findings
   is expected partial coverage, not a bug.)

### Resetting ingested data (local dev only)

Prefer **`DELETE /api/v1/sboms/{id}`** for soft-delete (sets `deleted_at`; data hidden from active
queries but not hard-deleted). Use `?force=true` when deleting the latest scan for an artifact.

```sh
curl -s -X DELETE "$BASE_URL/api/v1/sboms/$SCAN_ID?force=true" -H "X-API-Key: $API_KEY" | jq .
```

For direct SQL, each API “scan” is a `scan_reports` row (the deletable unit); composition lives in
`sboms`:

```sh
psql "$THEMIS_DATABASE_DSN" -c \
  "SELECT sr.id, sr.image_digest, sb.format, sr.scanned_at, sr.deleted_at
   FROM scan_reports sr JOIN sboms sb ON sb.id = sr.sbom_id
   ORDER BY sr.scanned_at DESC LIMIT 10;"
```

**Delete one scan** (replace `SCAN_ID` with a `scan_reports.id`). Durable judgments
(`risk_context`, `triage_history`, …) are keyed on `(artifact_id, component_purl, cve_id)` and
survive rescans by design, so this removes only the scan's raw findings — not the artifact-level
verdicts:

```sh
export SCAN_ID="<uuid>"

psql "$THEMIS_DATABASE_DSN" <<EOF
BEGIN;
DELETE FROM component_vulnerabilities WHERE scan_report_id = '$SCAN_ID';
DELETE FROM scan_reports WHERE id = '$SCAN_ID';
DELETE FROM ingestion_jobs WHERE payload->>'scan_id' = '$SCAN_ID';
COMMIT;
EOF
```

**Clear all ingestion data** (keep products, projects, versions, artifacts, API keys):

```sh
psql "$THEMIS_DATABASE_DSN" <<'EOF'
BEGIN;
TRUNCATE TABLE
  triage_history,
  intelligence_signals,
  runtime_exposures,
  remediation_actions,
  risk_context,
  vex_assertions,
  vex_documents,
  component_vulnerabilities,
  dependency_relationships,
  component_versions,
  scan_reports,
  sboms,
  ingestion_jobs
RESTART IDENTITY CASCADE;
COMMIT;
EOF
```

**Full database reset** — also the **required** path when upgrading from a pre-`v0.3.0` database
(there is no in-place migration; the startup schema-skew guard refuses to start against the old
`sbom_documents` schema):

```sh
dropdb themis && createdb themis
export THEMIS_DATABASE_DSN="postgres://themis:themis-dev-password@localhost:5432/themis?sslmode=disable"
make migrate-up
```

Then recreate your API key, product, project, and artifact registration from
[Getting Started](#getting-started). Do not use manual SQL deletes in production — prefer
`DELETE /api/v1/sboms/{id}`; hard SQL deletes bypass audit and immutability guarantees.

### Developer test suite

```sh
# Unit tests
make test

# Integration tests (embedded Postgres; or set THEMIS_TEST_DATABASE_DSN for external Postgres)
make test-integration

# Unit + integration with coverage report (enforces per-package thresholds)
make coverage
```

Integration tests use the `//go:build integration` tag. The coverage report is written to
`coverage.txt`.

### Property-based testing

Critical invariants are verified with property-based tests built on
[`pgregory.net/rapid`](https://github.com/flyingmutant/rapid) (a test-only dependency with
automatic shrinking and deterministic seed replay). They run as ordinary unit tests — counting
toward the coverage gates and `make check` — and can also be driven harder:

```sh
make test-property                 # defaults to 1000 examples per property
make test-property RAPID_CHECKS=20000
```

| Area | Example invariants |
| ---- | ------------------ |
| **Pure logic** | Risk score bounds `[0,100]` and monotonicity; PURL build/parse round-trips; version comparator laws; backoff bounds; redaction never leaks secrets; HMAC sign/verify round-trip |
| **Parser & trust** | Parsers never panic on arbitrary input and stay self-consistent; parsing is idempotent; checksum compare is case-insensitive; dedup keys are stable |
| **Stateful flows** | Triage history is append-only and never mutates raw findings (VEX-overlay invariant); ingestion follows only legal lifecycle transitions and is idempotent; the in-process queue loses no jobs and bounds retries |

Shared rapid generators live in `internal/testutil/gen/`. Property tests are named `*Property` and
discovered automatically. When a property fails, rapid prints a seed for deterministic replay;
capture the shrunk counterexample as a table-driven regression test. A nightly GitHub Actions
workflow (`.github/workflows/property-tests.yml`) runs the deep suite.

**Coverage targets:**

| Packages | Target |
| -------- | ------ |
| `internal/domain/`, `internal/usecase/*/`, `internal/adapter/parser/`, `internal/adapter/trust/`, `internal/adapter/notify/` | 100% |
| `internal/adapter/store/`, `internal/adapter/api/`, `internal/infrastructure/*/` | ≥ 90% |
| `cmd/`, generated OpenAPI stubs | Excluded |

---

## Code Quality

```sh
make lint         # golangci-lint + depguard
make clean-arch   # Clean Architecture import-direction check
make deadcode     # dead code detection (zero tolerance)
make check        # all gates in sequence
```

Every task group must pass the gate sequence before being considered complete:
build → unit tests → coverage → dead code → integration tests → clean architecture → verify-build.

---

## Code Structure

```text
themis/
├── cmd/themis/main.go            DI root — wires all layers together
├── cmd/themis-mcp/               MCP server — exposes the REST API to LLM clients
│
├── internal/
│   ├── domain/                   Layer 1: pure types + port interfaces (stdlib only)
│   │   ├── sbom.go               CanonicalSBOM, CanonicalComponent
│   │   ├── vulnerability.go      Vulnerability, CVE types
│   │   ├── vex.go                VEXAssertion, EffectiveState
│   │   ├── product.go            Product, Project, Version, Artifact
│   │   ├── risk.go               RiskContext, risk score types
│   │   └── ports.go              repository + service interfaces
│   │
│   ├── usecase/                  Layer 2: application business rules
│   │   ├── ingestion/            trust → parse → store (sboms + scan_reports) → enrich → notify
│   │   ├── enrichment/           VEX overlay, state machine, risk score, Layer 1/2 signals
│   │   ├── triage/               human triage decisions, VEX generation, history
│   │   └── watch/                CVE feed polling, catalog matching, new findings
│   │
│   ├── adapter/                  Layer 3: interface adapters
│   │   ├── parser/               CycloneDX, SPDX, Trivy → CanonicalSBOM
│   │   ├── store/                PostgreSQL implementations of domain repositories
│   │   ├── notify/               SMTP + Teams delivery, routing rules, digest
│   │   ├── trust/                StubVerifier, hash, schema validation, policy
│   │   ├── nvd/ · osv/           CVE feed clients + ecosystem mapping
│   │   ├── epsskev/ · exploitdb/ · vexfeed/   signal-feed adapters
│   │   ├── assetgraph/           blast-radius traversal
│   │   └── api/                  HTTP handlers, OpenAPI stubs, auth + HMAC middleware
│   │
│   ├── infrastructure/           Layer 4: frameworks and drivers
│   │   ├── db/                   pgx pool, migration runner, schema-skew guard
│   │   ├── queue/                InProcessQueue (goroutine pool)
│   │   ├── http/                 chi router, startup, schedulers
│   │   ├── config/               YAML + env var loading
│   │   ├── metrics/              Prometheus + OpenTelemetry
│   │   └── cli/                  admin CLI (create-key, revoke-key)
│   │
│   └── testutil/gen/             shared rapid generators for property-based tests
│
├── migrations/                   SQL migrations (single squashed v0.3.0 baseline)
├── api/openapi.yaml              OpenAPI 3.1 specification
├── scripts/check-coverage.sh     per-package coverage threshold enforcement
├── Makefile
└── docs/current-changes/PROJECT_CONTEXT.md   full design reference
```

---

## Contributing

1. Run `make check` before every commit — all gates must pass.
2. No `TODO:` / `FIXME:` comments may be left at the end of a task group.
3. Every new exported symbol needs a consumer (test or production caller) — `make deadcode` enforces this.
4. Keep domain and use case packages free of framework imports — `make clean-arch` enforces this.
5. Design decisions, specs, and implementation tasks live under `openspec/changes/`; see
   [`openspec/STATUS.md`](openspec/STATUS.md) for the active change.

---

## License

[MIT](LICENSE)
