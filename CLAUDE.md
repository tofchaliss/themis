# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What Themis is

Go backend security-intelligence platform: ingests SBOM (CycloneDX 1.4–1.6 / SPDX 2.3–3.0 / Trivy JSON) and VEX
documents, correlates vulnerabilities against NVD/OSV/distro feeds, applies VEX overlay semantics, watches for new
CVEs, and notifies (SMTP / MS Teams). Single binary + PostgreSQL 14+. Module `github.com/themis-project/themis`,
Go 1.25.

## Read these first

The repo carries its own agent documentation — this file is the index, not a replacement:

1. `openspec/STATUS.md` — **authoritative current status** (active change, release line). Maintained by the
   OpenSpec skills; do not hand-duplicate status into other docs.
2. `docs/current-changes/PROJECT_CONTEXT.md` — five-layer data model (L0–L3), Clean Architecture, invariants,
   quality gates, API conventions.
3. `docs/current-changes/AGENTS.md` — agent workflow and full context index.
4. `docs/current-changes/verification.md` — pre-completion checklist (Correctness C1–C14, Severity S1–S12,
   Observability O1–O14, Feed Resilience FR1–FR8). Work touching those paths ends with a `## Verification`
   block citing the rows and the commands/tests that prove them.
5. `openspec/specs/<capability>/spec.md` — 18 canonical capability specs, the source of truth for behavior.
   Check the relevant spec before implementing a capability.

Stale-path warning: `.cursor/rules/*.mdc` reference `PROJECT_CONTEXT.md`, `AGENTS.md`, and `verification.md` at
repo root — those files moved to `docs/current-changes/` (v0.3.11 docs consolidation). `architecture.mdc` is
Phase-1-era; where it conflicts with `AGENTS.md`/`STATUS.md`, the latter win. Deferred work lives in
`docs/current-changes/project-backlog.md` and `NEXT-STAGE.md`; ADRs in `docs/adr/`; the architecture book in
`docs/architecture/`.

## Commands

```sh
make build              # → ./bin/themis
make test               # unit tests
make test-integration   # go test -tags=integration -p 1 ./...  (-p 1 is mandatory — see Testing)
make lint               # golangci-lint (includes depguard layer rules)
make clean-arch         # go-cleanarch import-direction check
make deadcode           # dead-code check, zero tolerance
make coverage           # full-repo coverage + per-package threshold enforcement
make coverage-pkg PKG=usecase/enrichment   # scoped coverage gate (path under internal/ without prefix; list OK)
make check              # build + lint + clean-arch + coverage + deadcode
make verify-build       # clean + full rebuild — run after every task group
make test-property RAPID_CHECKS=10000      # deep property run (rapid; default 1000)
make migrate-up         # requires THEMIS_DATABASE_DSN exported; golang-migrate needs -tags postgres (Makefile handles it)
make generate-api       # regenerate internal/adapter/api/gen/ from api/openapi.yaml (oapi-codegen)
```

Single tests:

```sh
go test ./internal/usecase/enrichment/ -run TestName -v
go test -tags=integration -run TestAC17_AlpineVendorVEXNotAffected ./internal/adapter/store/   # one package: -p 1 not needed
go test ./internal/domain/ -run TestSomethingProperty -rapid.checks=5000
```

Run the server (from repo root — `./migrations` and `./themis.yaml` resolve by CWD):

```sh
export THEMIS_DATABASE_DSN="postgres://themis:<pw>@localhost:5432/themis?sslmode=disable"   # the only required setting
make build && ./bin/themis          # auto-runs migrations at boot
./bin/themis admin create-key --admin --expires 90d   # raw api_key printed once; X-API-Key on all /api/v1/*
./bin/themis admin revoke-key --key-id ID             # that's the entire CLI surface
```

`THEMIS_*` env vars override every `themis.yaml` key (full list: `internal/infrastructure/config/load.go`).
Secrets (DSN, SMTP password, NVD key, webhook secret) go in env vars only — never in `themis.yaml`.

## Architecture

### Clean Architecture — mechanically enforced

Imports point inward only, enforced twice (depguard in `.golangci.yml` + `make clean-arch`); violations fail
the gates:

```text
cmd/themis/main.go        DI entry — imports infrastructure/{cli,http}; depguard restricts cmd/** to infrastructure
internal/infrastructure/  L4: pgx, chi, config, queue, schedulers, metrics, CLI → may import all inner layers
internal/adapter/         L3: parser, store, api, notify, trust, nvd, osv, epsskev, exploitdb, redhat, vexfeed,
                          assetgraph → domain + usecase only
internal/usecase/         L2: ingestion, correlation, enrichment, triage, vexgen, watch → domain ONLY
                          (no HTTP/pgx/SMTP/Prometheus/OTel)
internal/domain/          L1: pure types + all port interfaces (ports.go) → stdlib ONLY
```

Format leakage is also policed: CycloneDX/SPDX/syft imports are allowed **only in `internal/adapter/parser/`** —
everything else sees `CanonicalSBOM` and domain types. `internal/testutil/{gen,findingset}` deliberately sits
outside the layers; import from `_test.go` files only.

### Request flow and DI

`cmd/themis/main.go` → `admin` subcommands go to `infrastructure/cli`, everything else to
`infrastructure/http.Run` → `Boot` (`startup.go`: config, pgxpool, auto-migrate, schema-version + schema-shape
guards) → `MountAPI` (`api_wiring.go` — the single DI composition root wiring every store, feed client,
scheduler, and the pipeline) → `api.Mount` (`internal/adapter/api/mount.go`) mounts `/api/v1` behind `X-API-Key`
auth. `/api/v1/webhooks/scan` uses HMAC (`X-Themis-Signature`) instead. `/healthz`, `/readyz`, `/metrics` live
outside `/api/v1`, unauthenticated.

**Two endpoint families** — decide which one a new endpoint joins:

- **Spec'd**: defined in `api/openapi.yaml`, served via the generated `gen.ServerInterface`. To add: edit
  `api/openapi.yaml` → `make generate-api` → implement the method on `*api.Handler` in a `handlers_*.go` file
  (compile breaks until you do) → if new deps, add a field to `api.Dependencies` and wire it in `MountAPI`.
- **Hand-mounted**: newer routes registered directly in `mount.go` (status, sboms, artifacts, blast-radius,
  versions, customers…) — not in the OpenAPI spec.

All error responses use the envelope `{"error":{code,message,hint}}` (14 catalogue codes,
`internal/adapter/api/errors.go`); never leak raw Postgres/Go error strings.

### Background work

One queue: `queue.InProcessQueue` (goroutine pool, Postgres-persisted jobs, retry with backoff). Job types are
constants in `domain/ports.go`; the handler switch is injected in `MountAPI`. Eight schedulers in
`internal/infrastructure/http/*_scheduler.go` (EPSS/KEV, ExploitDB, VEX feeds, correlation feeds, NVD/OSV CVE
watch, CVSS backfill, Red Hat VEX, triage expiry) — each feed scheduler runs once at startup then on a
`time.Ticker` (24h for signal feeds); triage expiry is the exception (first fires after its 1h interval).
There is **no admin endpoint to trigger a feed sync** — restart the server to force one. Feed failures must
never wipe previously synced data (abort + retain + WARN; see FR1–FR8).

The ingestion pipeline (`usecase/ingestion/service.go`) is transport-agnostic (upload, webhook → same use
case): trust gate → parse → correlate → enrich → notify, with per-stage status persisted. A `202 Accepted`
only means queued — poll `GET /api/v1/ingestions/{id}` until `NOTIFIED|COMPLETED|FAILED|REJECTED`. Layer 1
`deterministic_level` and `blast_radius_score` are computed inside the pipeline's enrichment stage, before
`risk_score` is written — but the whole pipeline runs in the async job, so they are not readable immediately
after the 202, and the signals re-enrich job refreshes them when feeds update. (AC-20's wording in
`acceptance-criteria.md` says "before the `202`" — the code disagrees; trust the code and
`openspec/specs/intelligence-enrichment/spec.md`.)

### Data model in one paragraph

L0 inventory tables (`products → projects → versions → artifacts`, `sboms` + `scan_reports`, `components`,
`vulnerabilities`, `component_vulnerabilities`, `vex_documents`/`vex_assertions`) are append-only and
content-addressed — never mutated or deleted. Durable judgments (`risk_context`, `triage_history`, …) key on
`(artifact_id, component_purl, cve_id)` so triage survives rescans. `risk_context.effective_state` is the sole
"current status" of a finding. "Latest scan" = `ORDER BY scanned_at DESC` — there is no `is_latest` column on
`scan_reports`. Correlation matches by PURL against the catalog + live OSV; the CycloneDX embedded
`vulnerabilities` array is **not** ingested, and distro feed verdicts outrank OSV.dev for apk/rpm.

Migrations: single squashed baseline `migrations/000001_v030_baseline` (no in-place upgrade from pre-v0.3.0 —
drop schema and re-migrate). Adding a migration requires bumping `store.BinarySchemaVersion`
(`internal/adapter/store/migrate.go`) or the boot-time schema guard misbehaves.

## Hard invariants (never violate)

1. **VEX overlay, never delete** — VEX changes `risk_context.effective_state` only; rows in
   `component_vulnerabilities` are preserved forever. Revoked VEX ⇒ the finding resurfaces.
2. **Transport ≠ domain** — SBOM format structs exist only in `adapter/parser/`.
3. **Idempotency** — same `(image_digest, checksum_sha256)` upload returns the existing scan without
   re-correlating; `Idempotency-Key` header supported on mutating endpoints.
4. **Triage generates VEX** — every human triage decision auto-creates a `source=themis_generated` VEX that
   re-applies on future ingestions. Precedence: `themis_generated` > manual/vendor > `ai_generated` >
   `upstream_vendor`.
5. **Vendor VEX is authoritative for backports** — after a vendor VEX match the upstream CVE version range
   must not be consulted.
6. **AI is advisory-only** (D-WRITE-1) — AI never writes `effective_state`; state changes require a human.
7. **SBOM delete is soft-only** — `deleted_at` tombstone via `DELETE /api/v1/sboms/{id}`; every deletion
   writes an `audit_log` row. No hard SQL deletes.
8. **Scope guardrail** — do not implement Phase 3 features (rate limiting, cosign, CI/CD ingestion, Docker,
   UI, Redis, RBAC) or anything beyond the active OpenSpec change without explicit user direction.

## Testing

- Integration tests are tagged `//go:build integration`. Each integration package's `TestMain` boots
  **embedded Postgres 16 on a fixed port** (store 15432, db 15438, http 15450, …) — that's why
  `make test-integration` uses `-p 1`; never drop it when running multiple packages. Set
  `THEMIS_TEST_DATABASE_DSN` to use an external Postgres instead. If embedded PG fails to start, tests
  **skip** (silent green) — check stderr.
- Property tests (`pgregory.net/rapid`, funcs matching `Property|Prop_`) double as unit tests; shared
  generators live in `internal/testutil/gen` — reuse them (they deliberately mix junk input). CI
  (`.github/workflows/property-tests.yml`) runs them on PR/push/nightly; CI does **not** run the full
  unit/integration/coverage suite — those are local gates.
- `tests/acceptance/criteria_test.go` + `criteria_phase2a_test.go` map AC-1..24 to named test funcs via
  `go test -list` — renaming a mapped integration test breaks the meta-test; update the mapping.
- There are **two independent `ComputeRiskScore` implementations by design** (`usecase/enrichment` and
  `usecase/triage`); `tests/acceptance/score_oracle_property_test.go` asserts they agree — change both.
- Golden finding-set harness: `internal/testutil/findingset` diffs correlation output against committed
  goldens (`internal/adapter/vexfeed/testdata/golden/`); regenerate with `UPDATE_GOLDEN=1 go test …`.
  Correlation-core changes are expected to surface here as reviewable drift, not silently.
- Coverage thresholds are enforced per package by `scripts/check-coverage.sh` (authoritative): 100% for
  `domain`, most `usecase/*`, `adapter/{parser,trust,notify}`; 90% for stores/infrastructure; named overrides
  (`usecase/enrichment` 90, `adapter/osv` 90, `adapter/{epsskev,exploitdb,redhat}` 85, `adapter/api` 80).
  Generated `gen/` dirs are excluded. **A new package must be registered in that script or it exits 2.**

## Task-group workflow

Feature work is driven by OpenSpec: `openspec/specs/` holds canonical capability specs;
`openspec/changes/<name>/` holds the active change (proposal/design/tasks/delta-specs); skills
`/opsx:propose|apply|sync|archive|explore` run the lifecycle and maintain `STATUS.md`. Note: the `openspec`
CLI the skills invoke is **not installed on this machine** — install it before running an opsx skill.
`openspec/changes/themis-phase-2/` is an architecture reference, not an implementation change — never archive
it.

Before marking a task group done, two separate checks in this order:

1. **Task-wise gates** for the touched packages only: unit tests, `make coverage-pkg PKG=…`, `make deadcode`,
   `go test -tags=integration ./internal/<pkg>/...`, `make clean-arch`.
2. **Full build, always last**: `make verify-build`.

Mark tasks complete only when the gates pass; no `TODO`/`FIXME` left behind (deadcode also forces every new
exported symbol to have a consumer).

## Gotchas

- **Rebuild the binary before resetting the database.** An old binary against a fresh DB re-creates stale
  data. Re-uploading identical SBOM bytes is idempotent and does not re-correlate — reset first to re-test a
  code change.
- DB reset without superuser: `psql "$THEMIS_DATABASE_DSN" -c "DROP SCHEMA public CASCADE; CREATE SCHEMA public;"`
  then `make migrate-up`. Durable judgments do not survive this, but they do survive scan deletion — by design.
- SBOM upload takes a JSON **envelope** `{format, spec_version, document, artifact_id, image_digest}`, not the
  raw SBOM file, and the artifact must be registered first (`POST /api/v1/products/{id}/artifacts`) or
  ingestion is `REJECTED`. Never send `""` for optional UUID fields — omit them (422 otherwise).
- `scripts/upload-sbom.sh` predates v0.3.0 (sends `image_id`, references the legacy `images` table) — prefer
  the README's curl envelope. `scripts/run-alpine-e2e-local.sh` hardcodes `/opt/homebrew/bin/go` (repo was
  developed on macOS; the Makefile's Homebrew PATH prefix is harmless here — don't "fix" it casually).
- NVD rate limits are load-bearing (`adapter/nvd` token bucket: ~1.5 rps with API key, 0.15 without);
  exceeding them trips Cloudflare 503s.
- PURL type → OSV ecosystem mapping (`adapter/osv/ecosystem.go`) skips unmapped types (`rpm`, `generic`,
  `oci`) — sparse findings for RHEL-family SBOMs are expected, and `findings < components` is normal, not a
  bug.
- Prometheus metrics are prefixed `themis_`; `THEMIS_LOG_LEVEL=debug` emits per-PURL correlation detail.
