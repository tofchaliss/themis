---
name: themis-release-test
description: Full end-to-end smoke test for a new Themis v0.3.x release/build — build, run, reset the database, upload the sample SBOM, verify components register and vulnerabilities correlate, then track CVE enrichment over time. Use when the user wants to test/validate a new Themis release or build.
disable-model-invocation: true
---

# Themis Release Test

Validate a new Themis v0.3.x build end-to-end: a clean instance ingests the sample SBOM, components
register, vulnerabilities correlate to findings, and CVE severities enrich over time.

**Destructive:** this **drops and recreates the `themis` database**. That is intended (a release test starts
clean). Confirm with the user before running if the current database holds data they care about.

## When to use

- Testing a new build/release of the v0.3.x monolith (`cmd/themis`).
- After a schema, feed, or correlation change — to confirm the ingest → correlate → enrich pipeline still works.

## Steps

### 1. Run the automated bring-up (in the background)

`scripts/release-smoke-test.sh` performs the deterministic pipeline: build → stop old instance →
**drop + recreate the DB** → migrate → run → provision an admin key → register product + artifact → upload
`scripts/oamp.json` → poll ingestion to terminal → verify components → list vulnerabilities (baseline
snapshot).

It takes ~1–3 min (build + correlation), so **run it in the background** and read the output when it finishes:

```sh
scripts/release-smoke-test.sh
```

Overridable via env: `THEMIS_SBOM=<path>` (default `scripts/oamp.json`), `THEMIS_DATABASE_DSN`,
`THEMIS_BASE_URL` (default `http://localhost:8080`).

On failure it prints `FAIL: <reason>` — inspect `themis-smoke.log` and the ingestion `stage_detail` to
diagnose (e.g. schema drift, a dead feed URL, a rejected SBOM).

### 2. Confirm the checkpoints (from the script output)

- **Components registered** — `components registered: N` (must be > 0; ~481 for the oamp SBOM).
- **Vulnerabilities correlated** — the open-vulnerability table has rows (findings > 0; ~228 for oamp), each
  with CVE, severity, component PURL, and installed→fixed.
- **Ingestion terminal state** — `COMPLETED` or `NOTIFIED` (not `FAILED` / `REJECTED`).
- **Baseline snapshot** — `list-open-vulns.sh` wrote one under `~/.themis-vuln-snapshots/`.

### 3. Track CVE enrichment over time

Right after ingest, some CVEs show `unknown` severity / `risk 0`; the background feeds (NVD CVSS backfill,
EPSS/KEV, vendor VEX) fill them in over minutes–hours. To verify enrichment is progressing:

- Leave themis running (the script does).
- Re-run `scripts/list-open-vulns.sh` after a delay (≈10–30 min). Its **snapshot diff** reports the change,
  e.g. `~ CHANGED CVE-2026-42013 … sev:unknown→high risk:0→70`, plus new/closed findings.
- A healthy release shows the `unknown`-severity count **dropping** and severities/EPSS populating across
  successive runs.
- To automate the re-check, use `/loop 15m scripts/list-open-vulns.sh`, or schedule a re-run and report the
  diff back to the user.

## Pass criteria

- Build + migrate succeed; `/healthz` returns OK.
- Components registered > 0 and findings > 0.
- Ingestion reaches `COMPLETED` / `NOTIFIED`.
- On a later re-run, the `unknown`-severity count decreases (enrichment is working).

## Notes

- Requires a reachable PostgreSQL with a `themis` role (see `INSTALLATION.md`); the default DSN is the local
  dev one (`themis` / `themis-dev-password`).
- The reusable primitives it orchestrates are committed: `scripts/release-smoke-test.sh`,
  `scripts/upload-sbom.sh`, `scripts/list-open-vulns.sh`. This skill wires them into the full release flow and
  owns the temporal "enrichment over time" judgement.
- The sample SBOM `scripts/oamp.json` is local test data. For a different image, point `THEMIS_SBOM` at its
  CycloneDX/SPDX export (or a Trivy `--format cyclonedx` output).
