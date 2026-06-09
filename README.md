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
| **CVE watch** | Background scheduler polls NVD/OSV every 6 hours; new findings auto-created for matching catalog components |
| **Human triage** | L4 triage API records decisions; each decision auto-generates a VEX assertion that applies to future ingestions |
| **Notifications** | SMTP and Microsoft Teams delivery with configurable routing rules and digest aggregation |

---

For architecture (Clean Architecture layers, three-layer data model, VEX overlay semantics),
technology stack, phase roadmap, and quality gates, see [PROJECT_CONTEXT.md](PROJECT_CONTEXT.md).
Deferred Phase 2 and Phase 3 items are tracked in [project-backlog.md](project-backlog.md).

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

End-to-end steps to build and run Themis locally.

### 1. Start PostgreSQL

Ensure PostgreSQL is listening (default `localhost:5432`). On macOS with Homebrew:

```sh
brew services start postgresql@16   # or your installed version
pg_isready -h localhost -p 5432
```

### 2. Create the database and role

Replace the username and password with values you control. The examples below use
`themis` / `themis-dev-password` — do **not** copy placeholder values from docs
without creating matching Postgres roles.

```sh
psql -U postgres -c "CREATE USER themis WITH PASSWORD 'themis-dev-password';"
psql -U postgres -c "CREATE DATABASE themis OWNER themis;"
psql -U postgres -c "GRANT ALL PRIVILEGES ON DATABASE themis TO themis;"
```

### 3. Build the binary

```sh
make build
```

### 4. Configure Themis

Themis reads `themis.yaml` (optional) and environment variables. Env vars override file
values. Put secrets (DSN, passwords, API keys) in the environment — never in committed
config files.

```sh
cp themis.yaml.example themis.yaml
export THEMIS_DATABASE_DSN="postgres://themis:themis-dev-password@localhost:5432/themis?sslmode=disable"
```

`THEMIS_DATABASE_DSN` is **required** whether or not you use `themis.yaml`. Leave
`database.dsn` empty in the file when using the env var (recommended).

Optional: `export THEMIS_CONFIG_PATH=/path/to/themis.yaml` if the config file is not in
the current working directory.

Verify the DSN before continuing:

```sh
psql "$THEMIS_DATABASE_DSN" -c 'SELECT 1'
```

If this fails with `password authentication failed`, fix the Postgres user/password in the
DSN — Themis will fail the same way.

### 5. Apply database migrations

Themis also runs pending migrations on startup, but applying them explicitly is useful
for CI and first-time setup:

```sh
make migrate-up
```

`make migrate-up` and `make migrate-down` require `THEMIS_DATABASE_DSN` to be exported in
the same shell (not a typo like `THEMIS_DTABASE_DSN`).

### 6. Start the server

Run from the repo root (so `./migrations` and optional `./themis.yaml` resolve correctly):

```sh
./bin/themis
```

On success you should see the HTTP server listening on port `8080` (or the port in
`themis.yaml`).

### 7. Verify health

```sh
curl http://localhost:8080/healthz   # liveness — should return {"status":"ok"}
curl http://localhost:8080/readyz    # readiness — DB + CVE feed checks
curl http://localhost:8080/metrics   # Prometheus metrics
```

`/readyz` may report `cve_feed: no successful poll yet` immediately after startup; that is
normal until the first background NVD/OSV poll completes.

### 8. Create an API key (optional)

Admin commands use the same config (`themis.yaml` and/or `THEMIS_DATABASE_DSN`):

```sh
# --admin for local testing (all endpoints); use --product-id <uuid> in production
./bin/themis admin create-key --admin --expires 90d
```

API calls then require `X-API-Key: <key>`. Webhooks use HMAC-SHA256 (`X-Themis-Signature`).

See [Testing with your own CycloneDX SBOM](#testing-with-your-own-cyclonedx-sbom) for the full
ingestion walkthrough.

---

## Configuration

See [Getting Started](#getting-started) for the minimum setup. Full non-secret defaults and
YAML field names are in [`themis.yaml.example`](themis.yaml.example).

| Variable | Required | Purpose |
| -------- | -------- | ------- |
| `THEMIS_DATABASE_DSN` | **Yes** | PostgreSQL connection URL |
| `THEMIS_CONFIG_PATH` | No | Path to YAML config (default: `./themis.yaml`) |
| `THEMIS_NVD_API_KEY` | No | NVD API key (higher rate limits) |
| `THEMIS_SMTP_*` | No | Outbound email for notifications |
| `THEMIS_TEAMS_WEBHOOK_URL` | No | Microsoft Teams webhook |
| `THEMIS_WEBHOOK_SECRET` | No | HMAC secret for CI webhook ingestion |

Environment variables use the `THEMIS_` prefix and override `themis.yaml` values.

---

## Database Migrations

```sh
# Apply all pending migrations (THEMIS_DATABASE_DSN must be exported)
make migrate-up

# Roll back one migration
make migrate-down
```

Migration SQL files live in `migrations/`. Themis refuses to start if the database schema
version is ahead of the binary version. On normal startup, `./bin/themis` applies pending
migrations automatically after connecting.

---

## Running

```sh
export THEMIS_DATABASE_DSN="postgres://themis:themis-dev-password@localhost:5432/themis?sslmode=disable"
./bin/themis
```

See [Getting Started](#getting-started) for Postgres setup, config, migrations, and health
checks.

---

## Troubleshooting

| Symptom | Likely cause | Fix |
| ------- | ------------- | --- |
| `missing required configuration field: database.dsn` | `THEMIS_DATABASE_DSN` not exported | `export THEMIS_DATABASE_DSN="postgres://..."` |
| `password authentication failed for user "user"` | DSN uses README placeholders | Create a matching Postgres role or update the DSN |
| `THEMIS_DATABASE_DSN is required` from `make migrate-up` | Env var unset or typo | Export `THEMIS_DATABASE_DSN` in the same shell session |
| `unknown driver postgres` from `make migrate-up` | Old Makefile without postgres build tag | Pull latest `main`; `make migrate-up` uses `-tags postgres` |
| `connection refused` on `:5432` | Postgres not running | Start Postgres; confirm with `pg_isready` |
| `failed to open database` / migrate errors | Wrong host, DB name, or SSL mode | Test with `psql "$THEMIS_DATABASE_DSN" -c 'SELECT 1'` |
| Server starts but `/readyz` is 503 | DB down or CVE feed not polled yet | Check `checks` in the JSON body; wait for first watch poll |
| Ingestion succeeds but no vulnerabilities | PURL ecosystem not mapped to OSV, or no version match | See [SBOM correlation and OSV](#sbom-correlation-osv-and-linux-distros); check component ecosystems |
| Upload returns `422 invalid JSON body` | Malformed JSON or empty/invalid `image_id` / `project_id` UUIDs | Build upload envelope with `jq`; omit UUID fields rather than sending `""` |
| Ingestion `REJECTED` — `image not found` | `image_digest` not in `images` table | Register image in Postgres (Testing step 4) before upload; digest must match exactly |
| Ingestion `FAILED` — `sbom_documents_image_id_fkey` | `image_id` in payload does not exist in `images` | Use `image_id` from `SELECT id FROM images WHERE digest = '...'` |
| Ingestion `FAILED` — `osv api status 400: Invalid ecosystem` | Old binary sent PURL type (e.g. `apk`) to OSV instead of OSV name (`Alpine`) | Pull latest, `make build`, restart; see [SBOM correlation and OSV](#sbom-correlation-osv-and-linux-distros) |
| `unsupported cyclonedx spec version` | SBOM version not 1.4 / 1.5 / 1.6 | Regenerate or set `spec_version` accordingly |
| `ingestion_id` is `00000000-0000-0000-0000-000000000000` | Known bug in older binaries (empty ID returned) | Pull latest `main`, rebuild; check `ingestion_jobs` table for the real job id |
| Need to remove a test upload | No delete API in Phase 1 | See [Resetting ingested data](#resetting-ingested-data-local-dev-only) (SQL, local dev only) |
| Want verbose / debug server logs | No log-level config in Phase 1 or 2 | Use `GET /api/v1/ingestions/{id}`, `/metrics`, and `ingestion_jobs` in Postgres; configurable logging and OTel trace export are planned for Phase 3 (`runtime-observability`) |

---

## API Key Management

```sh
# Create a product-scoped key
./bin/themis admin create-key --product-id <id> --expires 90d

# Revoke a key
./bin/themis admin revoke-key --key-id <id>
```

Requires the same `THEMIS_DATABASE_DSN` (and optional `themis.yaml`) as the server.
See [Getting Started § 8](#getting-started).

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

Use this path when you already have a CycloneDX JSON file from your container image (e.g.
generated by [Syft](https://github.com/anchore/syft), [Trivy](https://github.com/aquasecurity/trivy),
or your CI pipeline).

#### What your file provides vs what you must supply

| From your CycloneDX file | You still provide to Themis |
| ------------------------ | --------------------------- |
| Component list (with `purl`) | `image_digest` (from the image you scanned) |
| `specVersion` (1.4 / 1.5 / 1.6) | `image_id` (registered in Postgres — no REST API in Phase 1) |
| Optional embedded `vulnerabilities` | `project_id` (from API) and `X-API-Key` |

Findings are created by matching SBOM **components** (by PURL) against the local
`vulnerabilities` catalog and, when needed, **live OSV queries** during ingestion — not from the
embedded `vulnerabilities` section inside your CycloneDX file. Components without `purl` are
skipped.

CVE watch also polls NVD/OSV in the background and correlates against the full stored catalog.
If you see components but zero findings, check [SBOM correlation and OSV](#sbom-correlation-osv-and-linux-distros).

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

**2. Get the image digest** (same image you scanned)

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

**4. Register the image in Postgres** (required until an image API exists)

```sh
export IMAGE_ID=$(uuidgen | tr '[:upper:]' '[:lower:]')
export ARTIFACT_ID=$(uuidgen | tr '[:upper:]' '[:lower:]')

psql "$THEMIS_DATABASE_DSN" <<EOF
INSERT INTO artifacts (id, artifact_type) VALUES ('$ARTIFACT_ID', 'image');
INSERT INTO images (id, artifact_id, product_id, project_id, repository, digest)
VALUES (
  '$IMAGE_ID', '$ARTIFACT_ID', '$PRODUCT_ID', '$PROJECT_ID',
  '$(echo "$IMAGE_REF" | cut -d: -f1)', '$IMAGE_DIGEST'
);
EOF
```

#### 5. Upload your CycloneDX file

Prefer JSON upload (supports `image_id` and `project_id`):

```sh
export SPEC_VERSION=$(jq -r '.specVersion // "1.6"' "$SBOM_FILE")

curl -s -X POST "$BASE_URL/api/v1/sbom/upload" \
  -H "X-API-Key: $API_KEY" \
  -H "Content-Type: application/json" \
  -H "Idempotency-Key: upload-$(basename "$SBOM_FILE")-$(date +%s)" \
  -d "$(jq -n \
    --slurpfile doc "$SBOM_FILE" \
    --arg spec "$SPEC_VERSION" \
    --arg image_id "$IMAGE_ID" \
    --arg project_id "$PROJECT_ID" \
    --arg digest "$IMAGE_DIGEST" \
    '{
      format: "cyclonedx",
      spec_version: $spec,
      document: $doc[0],
      image_id: $image_id,
      project_id: $project_id,
      image_digest: $digest,
      ci_job_id: "local-upload"
    }')" | jq .
```

Expect **202 Accepted** with an `ingestion_id`.

#### 6. Poll ingestion until complete

```sh
export INGESTION_ID="<from upload response>"

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

**Upload body shape** — `-d @file.json` must be a JSON **envelope** (`format`, `document`, optional
`image_id`, `project_id`, `image_digest`), not the raw CycloneDX file alone. Build it with the
`jq` command in step 5; do not send empty strings for UUID fields (`""` causes `422 invalid JSON body`).

#### 7. Inspect results

```sh
curl -s "$BASE_URL/api/v1/projects/$PROJECT_ID/scans" -H "X-API-Key: $API_KEY" | jq .

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

API reference: [`api/openapi.yaml`](api/openapi.yaml). Sample fixture used in tests:
[`internal/adapter/parser/testdata/cyclonedx-1.6.json`](internal/adapter/parser/testdata/cyclonedx-1.6.json).

### SBOM correlation, OSV, and Linux distros

This section captures Phase 1 behaviour and debugging lessons from real SBOM bring-up (e.g. Alpine
`apk` SBOMs from Syft/Trivy). Use it before assuming “ingestion worked but Themis is broken.”

#### How findings are created

1. **Parse** — CycloneDX components become canonical inventory keyed by **PURL** (`ecosystem`, `name`, `version`).
2. **Correlate (ingest)** — For each component: match the local `vulnerabilities` table; if no hit, query **OSV** and upsert matches into `component_vulnerabilities`.
3. **CVE watch** — Background NVD/OSV poll plus correlation against the **full** stored catalog and registered components.

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
but Phase 1 does not call OSV for `rpm`. Findings may still appear from the local NVD cache when
CPE/package metadata aligns — often sparse for distro packages.

Sending an unmapped PURL type as-is to OSV (e.g. `apk` instead of `Alpine`) returns
`400 Invalid ecosystem` and fails ingestion on older binaries. Current code maps or skips.

#### Distro-specific expectations

| Base / scanner output | Dominant PURL types | Phase 1 correlation |
| --------------------- | ------------------- | ------------------- |
| **Alpine** (incl. many `nginx` images) | `apk` | OSV `Alpine` — good coverage; finding count < component count is normal |
| **Debian / Ubuntu** | `deb` / `ubuntu` | OSV `Debian` / `Ubuntu` |
| **Rocky / RHEL / Alma** | `rpm` | OSV skipped; expect fewer automatic findings until RPM/distro feed support |
| **Mixed** (app + OS packages) | `npm`, `apk`, `rpm`, … | Each ecosystem handled independently |

**Alpine naming:** PURLs are often `pkg:apk/alpine/openssl@3.x`. Themis may store the name as
`alpine/openssl` while OSV expects `openssl`. Ingest succeeds; some packages may not match until
name normalization is improved. Not every component has a CVE at your pinned version.

**Image name ≠ ecosystem** — an `nginx:alpine` image still yields `apk` components from the OS
layer; correlation follows PURL type, not the image tag.

#### Debugging checklist

Run in order when components exist but findings are missing or ingestion fails:

```sh
# 1. Component ecosystems (what PURL types dominate?)
curl -s "$BASE_URL/api/v1/components?limit=200" -H "X-API-Key: $API_KEY" \
  | jq '[.items[].ecosystem] | group_by(.) | map({ecosystem: .[0], count: length})'

# 2. Ingestion outcome (use latest ingestion_id)
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

1. **`202 Accepted` ≠ success** — poll `GET /api/v1/ingestions/{id}`; trust `stage_detail` and `pipeline_status` in `ingestion_jobs`.
2. **Register the image before upload** — trust gate requires `image_digest` in `images`; `image_id` in the payload must be that row’s UUID.
3. **Upload envelope, not raw SBOM** — wrap CycloneDX in `format` + `document`; never send `image_id: ""`.
4. **PURL type ≠ OSV ecosystem** — `apk`→`Alpine`, `deb`→`Debian`; unmapped types are skipped, not sent raw to OSV.
5. **NVD cache size is misleading** — hundreds of CVE rows can still yield zero findings without package-level OSV correlation.
6. **Re-upload needs a new checksum or delete** — duplicate `(image_digest, checksum_sha256)` skips re-correlation.
7. **Finding count < component count is normal** — version ranges, missing OSV entries, and unsupported `rpm` packages all reduce matches.

After fixes on branch `themis-phase-2`, a 77-component Alpine SBOM produced **50 findings** —
expected partial coverage, not 77/77.

### Resetting ingested data (local dev only)

Phase 1 has **no REST API to delete** uploaded SBOMs, scans, or raw findings — that is by design
(immutable audit evidence). For local testing you can remove rows directly in PostgreSQL.

**Find what to delete** — each API “scan” is a row in `sbom_documents`:

```sh
psql "$THEMIS_DATABASE_DSN" -c \
  "SELECT id, image_digest, format, is_latest, ingested_at
   FROM sbom_documents ORDER BY ingested_at DESC LIMIT 10;"
```

**Delete one upload** (replace `SBOM_ID` with the `id` from the query or from
`GET /api/v1/projects/{id}/scans`):

```sh
export SBOM_ID="<uuid>"

psql "$THEMIS_DATABASE_DSN" <<EOF
BEGIN;
UPDATE sbom_documents SET supersedes_id = NULL WHERE supersedes_id = '$SBOM_ID';
UPDATE sbom_documents SET supersedes_id = NULL WHERE id = '$SBOM_ID';
DELETE FROM triage_history WHERE component_vulnerability_id IN (
  SELECT id FROM component_vulnerabilities WHERE sbom_document_id = '$SBOM_ID');
DELETE FROM intelligence_signals WHERE component_vulnerability_id IN (
  SELECT id FROM component_vulnerabilities WHERE sbom_document_id = '$SBOM_ID');
DELETE FROM runtime_exposures WHERE component_vulnerability_id IN (
  SELECT id FROM component_vulnerabilities WHERE sbom_document_id = '$SBOM_ID');
DELETE FROM remediation_actions WHERE component_vulnerability_id IN (
  SELECT id FROM component_vulnerabilities WHERE sbom_document_id = '$SBOM_ID');
DELETE FROM risk_context WHERE component_vulnerability_id IN (
  SELECT id FROM component_vulnerabilities WHERE sbom_document_id = '$SBOM_ID');
DELETE FROM vex_assertions WHERE vex_document_id IN (
  SELECT id FROM vex_documents WHERE sbom_document_id = '$SBOM_ID');
DELETE FROM vex_assertions WHERE component_version_id IN (
  SELECT id FROM component_versions WHERE sbom_document_id = '$SBOM_ID');
DELETE FROM vex_documents WHERE sbom_document_id = '$SBOM_ID';
DELETE FROM component_vulnerabilities WHERE sbom_document_id = '$SBOM_ID';
DELETE FROM dependency_relationships WHERE sbom_document_id = '$SBOM_ID';
DELETE FROM component_versions WHERE sbom_document_id = '$SBOM_ID';
DELETE FROM sbom_documents WHERE id = '$SBOM_ID';
DELETE FROM ingestion_jobs WHERE payload->>'scan_id' = '$SBOM_ID';
COMMIT;
EOF
```

Shared `components` and `vulnerabilities` (CVE catalog) rows are left in place.

**Clear all ingestion data** (keep products, projects, images, API keys):

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
  sbom_documents,
  ingestion_jobs
RESTART IDENTITY CASCADE;
COMMIT;
EOF
```

**Full database reset:**

```sh
dropdb themis && createdb themis
export THEMIS_DATABASE_DSN="postgres://themis:themis-dev-password@localhost:5432/themis?sslmode=disable"
make migrate-up
```

Then recreate your API key, product, project, and image registration from [Getting Started](#getting-started).

Do not use manual SQL deletes in production — they bypass Themis immutability guarantees.

### Developer test suite

```sh
# Unit tests
make test

# Integration tests (requires PostgreSQL)
THEMIS_DATABASE_DSN="..." make test-integration

# Unit + integration with coverage report
THEMIS_DATABASE_DSN="..." make coverage
```

Integration tests use the `//go:build integration` tag and run against a real PostgreSQL
instance. The coverage report is written to `coverage.txt`.

### Property-Based Testing

Critical invariants are verified with property-based tests built on
[`pgregory.net/rapid`](https://github.com/flyingmutant/rapid) (a test-only dependency
with automatic shrinking and deterministic seed replay). They run as ordinary unit tests —
so they count toward the coverage gates and execute as part of `make test` and `make check` —
and can also be driven with a high example count for deep/nightly runs:

```sh
# Deep run: drives rapid with a high example count across all property-test packages
make test-property                 # defaults to 1000 examples per property
make test-property RAPID_CHECKS=20000
```

What the properties cover:

| Area | Example invariants |
| ---- | ------------------ |
| **Pure logic** | Risk score bounds `[0,100]` and monotonicity; PURL build/parse round-trips; version comparator laws; backoff bounds; redaction never leaks secrets; HMAC sign/verify round-trip |
| **Parser & trust** | Parsers never panic on arbitrary input and stay self-consistent; parsing is idempotent; checksum compare is case-insensitive; dedup keys are stable |
| **Stateful flows** | Triage history is append-only and never mutates raw findings (VEX-overlay invariant); ingestion only follows legal lifecycle transitions and is idempotent; the in-process queue loses no jobs and bounds retries |

Shared rapid generators live in `internal/testutil/gen/`. Property tests are named
`*Property` and discovered automatically by `make test-property`. When a property fails,
rapid prints a seed for deterministic replay; capture the shrunk counterexample as a
table-driven regression test. A nightly GitHub Actions workflow
(`.github/workflows/property-tests.yml`) runs the deep suite.

**Coverage targets:**

| Packages | Target |
| -------- | ------ |
| `internal/domain/`, `internal/usecase/*/`, `internal/adapter/parser/`, `internal/adapter/trust/`, `internal/adapter/notify/` | 100% |
| `internal/adapter/store/`, `internal/adapter/api/`, `internal/infrastructure/*/` | ≥ 90% |
| `cmd/`, generated OpenAPI stubs | Excluded |

---

## Code Quality

```sh
# Lint (golangci-lint + depguard)
make lint

# Clean Architecture import direction check
make clean-arch

# Dead code detection (zero tolerance)
make deadcode

# All gates in sequence
make check
```

Every task group must pass all six gates before being considered complete:
build → unit tests → coverage → dead code → integration tests → clean architecture.

---

## Code Structure

```text
themis/
├── cmd/
│   └── themis/
│       └── main.go              DI root — wires all layers together
│
├── internal/
│   ├── domain/                  Layer 1: pure types + port interfaces
│   │   ├── sbom.go              CanonicalSBOM, CanonicalComponent
│   │   ├── vulnerability.go     Vulnerability, CVE types
│   │   ├── vex.go               VEXAssertion, EffectiveState
│   │   ├── product.go           Product, ProductVersion, Image
│   │   ├── risk.go              RiskContext, risk score types
│   │   └── ports.go             SBOMRepository, JobQueue, NotificationSender, etc.
│   │
│   ├── usecase/                 Layer 2: application business rules
│   │   ├── ingestion/           Orchestrate trust → parse → store → enrich → notify
│   │   ├── enrichment/          VEX overlay, state machine, risk score computation
│   │   ├── triage/              Human triage decisions, VEX generation, history
│   │   └── watch/               CVE feed polling, catalog matching, new findings
│   │
│   ├── adapter/                 Layer 3: interface adapters
│   │   ├── parser/              CycloneDX, SPDX, Trivy → CanonicalSBOM
│   │   ├── store/               PostgreSQL implementations of domain repositories
│   │   ├── notify/              SMTP + Teams delivery, routing rules, digest
│   │   ├── trust/               StubVerifier (Phase 1 + 2); CosignVerifier (Phase 3)
│   │   └── api/                 HTTP handlers, OpenAPI stubs, auth middleware
│   │
│   ├── infrastructure/          Layer 4: frameworks and drivers
│   │   ├── db/                  pgx connection pool, migration runner
│   │   ├── queue/               InProcessQueue (goroutine pool)
│   │   ├── http/                chi router setup, middleware registration
│   │   ├── config/              YAML + env var config loading
│   │   └── metrics/             Prometheus registration, OpenTelemetry setup
│   │
│   └── testutil/
│       └── gen/                 Shared rapid generators for property-based tests
│
├── migrations/                  SQL migration files (golang-migrate)
├── api/                         openapi.yaml — OpenAPI 3.1 specification
├── scripts/
│   └── check-coverage.sh        Enforces per-package coverage thresholds
├── Makefile
└── PROJECT_CONTEXT.md           Full multi-phase design reference
```

---

## Contributing

1. Run `make check` before every commit — all six gates must pass
2. No `TODO:` or `FIXME:` comments may be left at the end of a task group
3. Every new exported symbol needs a consumer (test or production caller) — `make deadcode` enforces this
4. Keep domain and use case packages free of framework imports — `make clean-arch` enforces this
5. Detailed design decisions, specs, and implementation tasks are in `openspec/changes/themis-phase-1/`

---

## License

[MIT](LICENSE)
