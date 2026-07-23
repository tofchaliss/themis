# Themis — Testing Guide

How to exercise a running Themis manually, plus the developer test suite. Setup lives in
[INSTALLATION.md](INSTALLATION.md); the HTTP surface is in [API.md](API.md).

- [Part A — Phase-3 services](#part-a--phase-3-services) (incl. the Intelligence Gateway)
- [Part B — v0.3.x end-to-end SBOM flow](#part-b--v03x-end-to-end-sbom-flow)
- [Troubleshooting](#troubleshooting)
- [Developer test suite](#developer-test-suite)

---

## Part A — Phase-3 services

Each service serves under `/api/v1` on its own port ([API.md](API.md)). Health first:

```sh
curl -s localhost:8083/api/v1/findings?release=x\&faultline=y   # Governance up → 404 Problem (expected)
```

### Intelligence Gateway (reactive AI enrichment)

The Gateway grounds a Governance **Finding** (+ its Knowledge **Faultline**) and returns a validated
**advisory** Proposal — or `204` "no proposal" (a first-class safe outcome). It is stateless and optional.

**1. Fake-provider smoke test (no model, no dependencies).** Proves the service + 3-stage validation are
wired. It returns **`204`** because the fake's canned output doesn't match the subject — that's success:

```sh
THEMIS_INTELLIGENCE_PROVIDER=fake go run ./cmd/intelligence &     # :8086
curl -s -o /dev/null -w '%{http_code}\n' -X POST \
  localhost:8086/api/v1/capabilities/recommend_position/invoke \
  -H 'Content-Type: application/json' -d '{"finding_id":"any-id"}'   # → 204
```

**2. Real reactive invoke (Ollama + grounding).** For a `200` + Proposal the Gateway must reach the
Governance + Knowledge read APIs to assemble the Finding + Faultline, and the model output must pass
validation:

```sh
# native Ollama on macOS (Metal GPU); a Mac container is CPU-only
ollama serve & ; ollama pull llama3.1:8b
THEMIS_GOVERNANCE_URL=http://localhost:8083 \
THEMIS_KNOWLEDGE_URL=http://localhost:8085 \
THEMIS_OLLAMA_URL=http://localhost:11434 \
go run ./cmd/intelligence &

curl -s -X POST localhost:8086/api/v1/capabilities/recommend_position/invoke \
  -H 'Content-Type: application/json' -d '{"finding_id":"<a real finding id>"}' | jq .
# 200 + {capability, finding_id, stance, confidence, evidence[], reasoning, ...}, or 204 if it declines.
```

> **Grounding caveat (today):** the Knowledge standalone service wiring lands with the M5 event bus, so
> `THEMIS_KNOWLEDGE_URL` needs either a running Knowledge read API or a stub returning a `FaultlineView`
> ([API.md](API.md)). The **automated** grounding→validation→proposal path is fully proven without any of
> this — see `go test ./internal/intelligence/...` (`e2e_test.go` drives the whole stack over httptest).

**3. The human-triggered Governance seam.** A human asks Governance for an AI recommendation; Governance
(when AI is enabled) invokes the Gateway and records an **advisory AI proposal** — never auto-accepted:

```sh
# enable AI on the Governance service:
export THEMIS_GOVERNANCE_AI_ENABLED=1 THEMIS_INTELLIGENCE_URL=http://localhost:8086

# a Finding is born from a Knowledge ComponentMatched event; until the M5 bus lands, feed it over HTTP:
curl -s -X POST localhost:8083/internal/knowledge-events \
  -H 'Content-Type: application/json' \
  -d '{"type":"...","payload":{...}}'   # exact ComponentMatched shape: see internal/governance/adapters/inbound + seam_test.go

FINDING=$(curl -s "localhost:8083/api/v1/findings?release=<rel>&faultline=<fl>" | jq -r .id)
curl -s -o /dev/null -w '%{http_code}\n' -X POST localhost:8083/api/v1/findings/$FINDING/recommend
# 201 → an AI proposal was recorded (StatusProposed, actor=ai); 204 → AI off / unavailable / declined.
curl -s localhost:8083/api/v1/findings/$FINDING | jq '.proposals'   # inspect the advisory proposal
```

**4. Disable gate.** With `THEMIS_GOVERNANCE_AI_ENABLED` unset (or `cmd/intelligence` not running),
`POST /findings/{id}/recommend` returns `204`, no proposal is recorded, and Governance makes **zero**
outbound calls — the pipeline is unchanged. "Off", "down", and "declined" all collapse to the same `204`.

### Other services (per-context APIs)

Each context is testable in isolation via its own API ([API.md](API.md)) — e.g. register a Release
(`POST :8082/api/v1/releases`), register Evidence (`POST :8081/api/v1/evidence`), read a Finding's posture
(`GET :8083/api/v1/releases/{id}/posture`), preview a Publication (`POST :8084/api/v1/previews`). The one
wired **SBOM → published-VEX** cross-context run awaits the **M5 event bus**; until then, drive each hop
over its HTTP API.

---

## Part B — v0.3.x end-to-end SBOM flow

Exercises the frozen `cmd/themis` monolith (setup in [INSTALLATION.md § Part B](INSTALLATION.md#part-b--v03x-single-binary-cmdthemis)).
Reuse the shell variables across steps.

```sh
export BASE_URL="http://localhost:8080"
export API_KEY="<from: ./bin/themis admin create-key --admin --expires 90d>"
export SBOM_FILE="./myapp.cyclonedx.json"        # your CycloneDX 1.4/1.5/1.6 file
export IMAGE_REF="myregistry/myapp:1.2.3"
export IMAGE_DIGEST=$(docker inspect "$IMAGE_REF" --format '{{.Id}}')   # or any sha256:<64hex> for testing
```

**1. Product, artifact, upload.** The trust gate requires the digest be registered before upload; the
returned artifact `id` is the `artifact_id` you upload against (idempotent by digest):

```sh
export PRODUCT_ID=$(curl -s -X POST "$BASE_URL/api/v1/products" -H "X-API-Key: $API_KEY" \
  -H 'Content-Type: application/json' -d '{"name":"my-app"}' | jq -r .id)

export ARTIFACT_ID=$(curl -s -X POST "$BASE_URL/api/v1/products/$PRODUCT_ID/artifacts" \
  -H "X-API-Key: $API_KEY" -H 'Content-Type: application/json' \
  -d "$(jq -n --arg d "$IMAGE_DIGEST" --arg repo "${IMAGE_REF%%:*}" \
    '{image_digest:$d, version:"latest", repository:$repo}')" | jq -r .id)

export INGESTION_ID=$(curl -s -X POST "$BASE_URL/api/v1/sbom/upload" -H "X-API-Key: $API_KEY" \
  -H 'Content-Type: application/json' -H "Idempotency-Key: upload-$(date +%s)" \
  -d "$(jq -n --slurpfile doc "$SBOM_FILE" --arg spec "$(jq -r '.specVersion // "1.6"' "$SBOM_FILE")" \
    --arg aid "$ARTIFACT_ID" --arg dg "$IMAGE_DIGEST" \
    '{format:"cyclonedx", spec_version:$spec, document:$doc[0], artifact_id:$aid, image_digest:$dg, ci_job_id:"test"}')" \
  | jq -r .ingestion_id)
```

Expect **`202 Accepted`** (queued, not done). Re-uploading the **same bytes** is idempotent (no new scan).

**2. Poll to a terminal state, then inspect:**

```sh
until S=$(curl -s "$BASE_URL/api/v1/ingestions/$INGESTION_ID" -H "X-API-Key: $API_KEY" | jq -r .status); \
  [[ "$S" =~ ^(NOTIFIED|COMPLETED|FAILED|REJECTED)$ ]]; do
  curl -s "$BASE_URL/api/v1/ingestions/$INGESTION_ID" -H "X-API-Key: $API_KEY" | jq '{status, stage_detail}'; sleep 2
done; echo "final=$S"

export PROJECT_ID=$(curl -s "$BASE_URL/api/v1/products/$PRODUCT_ID/projects" -H "X-API-Key: $API_KEY" | jq -r '.items[0].id')
export SCAN_ID=$(curl -s "$BASE_URL/api/v1/projects/$PROJECT_ID/scans" -H "X-API-Key: $API_KEY" | jq -r '.items[0].id')
curl -s "$BASE_URL/api/v1/scans/$SCAN_ID/vulnerabilities" -H "X-API-Key: $API_KEY" | jq '.items | length'
curl -s "$BASE_URL/api/v1/status?top=10" -H "X-API-Key: $API_KEY" | jq .
```

On `FAILED`/`REJECTED`, `stage_detail` is the authoritative reason (trust gate, parse, OSV, or DB constraint).

> **Helper scripts** wrap this flow: [`scripts/upload-sbom.sh`](scripts/upload-sbom.sh) `-f <sbom> -i
> <artifact_id> -d <digest>` posts + reports the ingestion; [`scripts/list-open-vulns.sh`](scripts/list-open-vulns.sh)
> auto-discovers an API key + product ids and prints the **open** findings (filtered by `effective_state`) with a
> day-over-day snapshot diff. See [API.md](API.md#vulnerability-listing-filters--pagination) for the filters.

### What "good" looks like

| Field (`GET /status`) | Ready value |
| --------------------- | ----------- |
| `components.total_registered` | > 0 |
| `vulnerabilities.total_findings` | > 0, with `by_severity` / `by_state` populated |
| `signals_stale` | **`false`** once EPSS/KEV have synced |

`findings < components` is **normal** (version ranges, unmapped `rpm`, no OSV entry). Feeds run on background
tickers (default 24h) then back-fill open findings via `ReEnrichJob` — no re-upload needed.

### SBOM correlation & OSV (when components exist but findings don't)

Findings come from matching SBOM **components (by PURL)** against the local catalog + **live OSV** — not from
the CycloneDX `vulnerabilities` array in your file. PURL **type ≠ OSV ecosystem** (`apk`→`Alpine`,
`deb`→`Debian`); `rpm`/`generic`/`oci` are skipped (no live OSV lookup). Debug in order:

```sh
curl -s "$BASE_URL/api/v1/components?limit=200" -H "X-API-Key: $API_KEY" \
  | jq '[.items[].ecosystem] | group_by(.) | map({ecosystem: .[0], count: length})'
# sanity-check OSV: ecosystem must be "Alpine", not "apk"
curl -s -X POST 'https://api.osv.dev/v1/querybatch' -H 'Content-Type: application/json' \
  -d '{"queries":[{"package":{"ecosystem":"Alpine","name":"openssl"}}]}' | jq '.results[0].vulns | length'
```

### Resetting ingested data (local dev only)

Prefer soft-delete: `DELETE /api/v1/sboms/{id}?force=true`. For a full reset (also the **required** path from
a pre-`v0.3.0` schema — there is no in-place upgrade):

```sh
psql "$THEMIS_DATABASE_DSN" -c "DROP SCHEMA public CASCADE; CREATE SCHEMA public;" && make migrate-up
```

Durable judgments (`risk_context`, `triage_history`) are keyed on `(artifact_id, component_purl, cve_id)` and
survive rescans by design.

---

## Troubleshooting

| Symptom | Likely cause | Fix |
| ------- | ------------ | --- |
| `missing required configuration field: database.dsn` | `THEMIS_DATABASE_DSN` not exported | export it in the same shell |
| `password authentication failed` | DSN uses the placeholder password | create a matching role or fix the DSN |
| `connection refused` on `:5432` | Postgres not running | start it; `pg_isready` |
| Startup refuses "re-initialise your database" | pre-`v0.3.0` schema | drop & recreate, then `make migrate-up` |
| `/readyz` 503 | DB down or CVE feed not polled yet | check `checks` in the body; wait for first poll |
| Ingestion `REJECTED` — image not found | digest not registered | `POST /products/{id}/artifacts` first |
| Upload `422 invalid JSON body` | malformed JSON or empty UUID field | build with `jq`; omit UUID fields rather than `""` |
| Ingestion succeeds, no vulnerabilities | PURL ecosystem unmapped / no version match | see [SBOM correlation](#sbom-correlation--osv-when-components-exist-but-findings-dont) |
| Intelligence always `204` | fake provider, or grounding unreachable, or validation declined | use Ollama + real read APIs; check `THEMIS_GOVERNANCE_URL`/`THEMIS_KNOWLEDGE_URL` |
| `POST /findings/{id}/recommend` → `204` | AI disabled | set `THEMIS_GOVERNANCE_AI_ENABLED=1` + `THEMIS_INTELLIGENCE_URL`, run `cmd/intelligence` |
| Ollama slow / CPU-only on Mac | running Ollama in a container | run Ollama **natively** on macOS for Metal GPU |

---

## Developer test suite

```sh
make test               # unit tests
make test-integration   # embedded Postgres (no Docker); or set THEMIS_TEST_DATABASE_DSN
make coverage           # unit + integration with per-package coverage thresholds
make test-property      # property-based tests (1000 examples; RAPID_CHECKS=20000 to go deeper)
make check              # full gate: build · lint · clean-arch · arch-test · coverage(+integration) · deadcode
```

Every task group / PR must pass `make check`. Coverage tiers are enforced by `scripts/check-coverage.sh`
(domain/app 100%, adapters 90%, aggregate stores 80% pending fault injection). Property tests
(`pgregory.net/rapid`, `*Property`) verify critical invariants — risk-score bounds, reconciliation
precedence, the VEX-overlay append-only rule, materialization stance-equality — and print a replay seed on
failure. Integration tests use the `//go:build integration` tag and real embedded Postgres on distinct
per-context ports.
