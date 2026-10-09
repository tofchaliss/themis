# Proposal — phase3-report-intake (EDR-INTAKE-01)

## Why

Uploading a vulnerability report into Themis today takes **two scripts and four REST calls across two
services**, and the operator has to know which converter to run first. On 2026-10-05 one didn't —
their Cortex export was JSON and every documented JSON road assumed Trivy — so the raw vendor array
went up, `json.Valid` passed it, Evidence filed it immutably, and **Knowledge's evidence stream
halted for 31 hours** on the poison event (EDR-EVENTBUS-01 D8). The same export through the
maintained converter yields **427 of 427 findings**: the pipeline was never the problem.

Three gaps, all measured in that incident:

- **The border validates almost nothing.** `json.Valid` is the entire scanner-report check, so a
  document no consumer can read became immutable evidence. This is parity gap **E1**.
- **There is no JSON road for Cortex**, only CSV — GUI-16 predicted exactly this and left the
  question open ("whether Cortex can export scan results as JSON at all"). It does. **GUI-16b**.
- **The operator's only feedback was a renderer on another screen**, after the write. "Upload
  failed" and "upload succeeded and halted the pipeline" were indistinguishable.

## What changes

- **One REST door (D1).** `POST /api/v1/intake` on Evidence takes an SBOM or a vulnerability report,
  validates it, converts it if needed, and files it. `POST /api/v1/evidence` is unchanged and keeps
  working — intake is strictly additive.
- **CSV and JSON both accepted for vulnerability reports (D2, D5);** SPDX and CycloneDX JSON for
  SBOMs. A `text/csv` body is converted **server-side** and what is filed is the curated JSON, so
  Evidence's document stays a JSON string and CON-0007 is untouched: CSV becomes a *request
  encoding*, never an evidence document. This is the resolution of GUI-16's deferred option (c).
- **Validation as a closed taxonomy (D11).** Twelve named reasons, refused at the border before
  anything is filed — including `schema_invalid`, which is **E1** and which refuses the exact body
  that cost 31 hours. The same curated-shape check is added to `POST /evidence` so the poison class
  is unreachable through the old door too.
- **One converter per dialect (D4).** The Go registry becomes *the* implementation; the browser's
  D16 translators call intake instead, and `cortex-csv-to-scan-report.sh` becomes a thin wrapper that
  POSTs. Ported against the existing script's output as the oracle — closes **GUI-10**.
- **SBOM-before-report enforced (D6)** with `no_inventory_for_release` and an explicit
  `allow_without_sbom` override recorded in provenance.
- **Product/Project/Release resolved read-only (D7).** `release_id` or `{product, project, version}`;
  intake never creates Registry identity.
- **A receipt for every attempt (D9).** `202 + intake_id + status_url` when work exceeds the inline
  budget, so a slow upload is resumable; `GET /intake/{id}` reports
  `accepted → validating → converting → registering → filed` or `rejected`/`failed` with a
  two-field `reason` + `detail`. Terminal receipts carry `next_checks` for downstream completion
  (D10 — intake reports intake; correlation is answered by Knowledge and Governance).

## Impact

Evidence `domain`/`app`/`adapters` + one migration (receipts), the Evidence OpenAPI spec (additive),
a new `adapters/report` converter registry, `cmd/evidence` wiring, the dashboard upload path (D16
translators removed in favour of the endpoint), and two scripts rewired. **No change** to Knowledge,
Governance, Communication, the bus, or any event contract — a filed document is filed exactly as
today, so everything downstream is untouched.

**One behaviour change to call out (D6):** a vulnerability report uploaded *before* its SBOM
currently succeeds and silently under-matches; it will be refused unless the caller passes
`allow_without_sbom`.

## Milestones

Reviewable and shippable in three, in dependency order. **M1 alone closes the incident.**

| | scope | closes |
| --- | --- | --- |
| **M1** | intake endpoint, detection table, validation taxonomy, read-only release resolution, SBOM-first, synchronous only | E1 · GUI-16b · the 31-hour class |
| **M2** | receipts + the `202` slow path + `Idempotency-Key` + `next_checks` | D9/D10/D12 |
| **M3** | converter consolidation: Go registry as sole implementation, GUI and scripts rewired | D4 · GUI-10 |

M1 ships the CSV/JSON acceptance by calling the existing Python converter's **ported** Go
equivalent for Cortex; M3 is what retires the duplicates. If M3 slips, the duplicates persist and
TESTING.md's one-converter rule is enforced by review rather than by construction — acceptable for
one milestone, not indefinitely.
