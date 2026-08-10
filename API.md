# Themis — API Reference

Every Themis HTTP API is **spec-first**: the OpenAPI document under [`api/`](api/) is the source of
truth, and the Go handlers are generated from it (`make generate-api*`). All errors use a small JSON
envelope; no raw PostgreSQL or Go error strings appear in response bodies.

- **v0.3.x monolith** (`cmd/themis`) — one API, `api/openapi.yaml`, served at `/api/v1`.
- **Phase-3 greenfield** — one spec per bounded-context service, each served at `/api/v1` on its own port.

> **Phase-3 is the go-forward** (see [INSTALLATION.md](INSTALLATION.md)); the v0.3.x monolith API is frozen
> at v0.3.x and kept as reference.

---

## v0.3.x monolith API — [`api/openapi.yaml`](api/openapi.yaml)

Base path `/api/v1`; auth via `X-API-Key` (webhooks use HMAC-SHA256 `X-Themis-Signature`).

| Group | Key endpoints |
| ----- | ------------- |
| **Ingestion** | `POST /sbom/upload` (envelope, async → `202` + `ingestion_id`) · `GET /ingestions/{id}` (poll to terminal state) |
| **Findings** | `GET /scans/{id}/vulnerabilities` · `GET /products/{id}/vulnerabilities` · `GET /projects/{id}/vulnerabilities` · `GET /products/{id}/versions/{v}/vulnerabilities` |
| **Triage** | `POST /vulnerabilities/{id}/triage` (auto-generates a `themis_generated` VEX assertion + durable verdict) |
| **Registration** | `POST /products` · `POST /projects/{id}/versions` · `POST /products/{id}/artifacts` (idempotent by digest) |
| **SBOM management** | `GET /sboms` · `GET /products/{id}/sboms` · `DELETE /sboms/{id}?force=true` (soft-delete + audit) |
| **VEX export** | `GET /products/{id}/versions/{v}/vex?format=cyclonedx\|openvex` · `GET .../vex-coverage` |
| **Asset graph** | `POST /products/{id}/microservices` · `POST /microservices/{id}/deployments` · `POST /customers` · `GET /products/{id}/blast-radius` |
| **Status** | `GET /status?top=N` (component/vuln counts, severity/state breakdown, `signals_stale`) |
| **Health** | `GET /healthz` · `GET /readyz` · `GET /metrics` (no auth) |

### Vulnerability-listing filters & pagination

The four `.../vulnerabilities` endpoints share query parameters:

- `effective_state` — one of `detected`, `confirmed`, `in_triage`, `accepted_risk`, `false_positive`,
  `resolved`, `not_affected`, `suppressed`. Filter to the **open** set (`detected` / `confirmed` / `in_triage`)
  to list actionable findings.
- `severity` — `critical` | `high` | `medium` | `low` | `none` | `unknown`.
- `cve_id` — exact CVE match.
- `limit` + `cursor` — page size and opaque cursor; the response returns `next_cursor` when more remain.

Each item carries `cve_id`, `severity`, `effective_state`, `component_purl`, `installed_version`,
`fixed_version`, and an `enrichment` block (`risk_score`, `epss_score`, `kev_listed`, `exploit_public`,
`deterministic_level`, `blast_radius_score`, `upstream_vex_coverage`).

> **Helper scripts:** [`scripts/list-open-vulns.sh`](scripts/list-open-vulns.sh) auto-discovers an API key +
> product ids and prints the open findings (with a day-over-day snapshot diff);
> [`scripts/upload-sbom.sh`](scripts/upload-sbom.sh) uploads an SBOM against a registered artifact
> (`-i <artifact_id> -d <digest>`). See [TESTING.md](TESTING.md) for the full walkthrough.

### Error envelope

```json
{"error": {"code": "SBOM_NOT_FOUND", "message": "...", "hint": "..."}}
```

Twelve catalogue codes cover all domain errors (`SBOM_NOT_FOUND`, `PRODUCT_NOT_FOUND`,
`CANNOT_DELETE_LATEST_SBOM`, `INVALID_SBOM_FORMAT`, `INTERNAL_ERROR`, …).

---

## Phase-3 greenfield APIs

Each context is an independent service with its own spec, served at `/api/v1` on its own port. Contexts
collaborate only via events + read APIs — they never share a database. Errors use an RFC-7807-style
`{title, detail}` **Problem** envelope. Regenerate any handler with `make generate-api-<context>`.

| Context | Port | Spec |
| ------- | ---- | ---- |
| Registry | `:8082` | [`api/registry.openapi.yaml`](api/registry.openapi.yaml) |
| Evidence | `:8081` | [`api/evidence.openapi.yaml`](api/evidence.openapi.yaml) |
| Knowledge | `:8085`\* | [`api/knowledge.openapi.yaml`](api/knowledge.openapi.yaml) |
| Governance | `:8083` | [`api/governance.openapi.yaml`](api/governance.openapi.yaml) |
| Communication | `:8084` | [`api/communication.openapi.yaml`](api/communication.openapi.yaml) |
| Intelligence | `:8086` | [`api/intelligence.openapi.yaml`](api/intelligence.openapi.yaml) |

\* Knowledge's standalone service wiring lands with the M5 event bus; the read API + handler exist today.

### Registry — Product → Project → Release identity

| Method | Path | Operation |
| ------ | ---- | --------- |
| POST | `/products` | `registerProduct` |
| GET | `/products` | `listProducts` — the estate entry point (DASH-1): without it a caller had to already know a product id to read anything |
| GET | `/products/{id}/projects` | `listProjectsOfProduct` (DASH-1) |
| POST | `/projects` | `registerProject` |
| GET | `/projects/{id}/releases` | `listReleasesOfProject` (DASH-1) |
| POST | `/releases` | `registerRelease` |
| GET | `/releases` | `listReleases` |
| GET | `/releases/{id}` | `getRelease` (backs Evidence's `SubjectRef` / `ReleaseExists`) |

The **estate graph** (EDR-ESTATE-01, C1) hangs off the same identity spine. It is what turns a technical
severity into a business one: without it every Finding on every release ranks alike, because nothing knows
how many customers a release reaches.

| Method | Path | Operation |
| ------ | ---- | --------- |
| POST | `/products/{id}/microservices` | `registerMicroservice` |
| POST | `/microservices/{id}/deployments` | `registerDeployment` — binds a microservice to a customer in an environment (`customer_id` + `environment`) |
| POST | `/customers` | `registerCustomer` |
| GET | `/releases/{id}/blast-radius` | `getBlastRadius` — the unique-customer count behind Governance's blast multiplier (C2). Governance **fail-safes to 1.0×** when this is unreachable, so an outage here de-amplifies priority rather than blocking triage |

### Evidence — SBOM/VEX ingestion + immutable evidence

| Method | Path | Operation |
| ------ | ---- | --------- |
| POST | `/evidence` | `registerEvidence` (dedup by raw bytes → stable id) |
| GET | `/evidence` | `listEvidence` |
| GET | `/evidence/{id}` | `getEvidence` |
| GET | `/evidence/{id}/inventory` | `getEvidenceInventory` (raw + canonical inventory) |
| GET | `/evidence/{id}/document` | `getEvidenceDocument` — the stored bytes, verbatim. Knowledge reads uploaded VEX through this seam and parses it itself (EDR-VEX-01 Phase 1): Evidence serves evidence, it does not interpret it |

### Knowledge — Faultlines (one card per canonical CVE)

| Method | Path | Operation |
| ------ | ---- | --------- |
| GET | `/faultlines?cve=` | `getFaultlineByCVE` |
| GET | `/faultlines/{id}` | `getFaultlineById` (enrichment: severity, EPSS, KEV, exploit, fixed/affected versions) |
| GET | `/faultlines/{id}/releases` | `getFaultlineReleases` |
| GET | `/feeds` | `getFeedHealth` (B1) — per-feed poll outcomes plus `signals_stale` / `degraded_feeds`. The point is that a *silent* feed and a *healthy* one are otherwise identical from the outside: enrichment that quietly stopped looks exactly like an estate with no new signals |

### Governance — Findings + Enterprise Positions (the authority)

| Method | Path | Operation |
| ------ | ---- | --------- |
| GET | `/findings?release=&faultline=` | `getFindingByKey` |
| GET | `/findings/{id}` | `getFinding` |
| GET | `/findings/{id}/position` | `getPosition` |
| POST | `/findings/{id}/proposals` | `raiseProposal` |
| POST | `/findings/{id}/proposals/{proposalId}/accept` | `acceptProposal` (human/policy only) |
| POST | `/findings/{id}/proposals/{proposalId}/reject` | `rejectProposal` |
| POST | `/findings/{id}/resolve` · `/reopen` · `/archive` | `resolveFinding` · `reopenFinding` · `archiveFinding` — lifecycle transitions |
| POST | `/findings/{id}/recommend` | `recommendPosition` — **on-demand AI seam** (records an advisory AI proposal, never auto-accepted; `204` when AI is off/unavailable/declines) |
| GET | `/findings/{id}/proposals` (on the Finding read) | Each proposal now carries **`evidence_trust`** — `observed` \| `asserted` \| `inferred`. It is the field the constitutional check turns on (an `inferred` proposal can never be auto-accepted by any policy), and it is surfaced because a human exercising that check was otherwise shown an AI proposal and a system proposal rendered identically. |
| GET | `/findings/{id}/assessment` | `getFindingAssessment` — the **Domain Projection** (EDR-TRUST-01 T10): the release-scoped concern plus what Knowledge knows about the CVE, in one read. Named for the business view, not for a consumer — a dashboard, a report and the AI runtime all read this same shape, and the AI grounds its citations *against* it. Knowledge is best-effort: unreachable degrades to the Finding alone rather than failing. |
| GET | `/releases/{releaseId}/posture` | `getReleasePosture` — one row per Finding carrying `effective_priority`, `residual_priority`, the exploitability `band`, the matched `components` (with the source package a fix ships under, and each component's **`claim_class`**) and the `fixes` published for *those* components. The band/components/fixes are on the rollup so a release-scoped question costs **one** read rather than one per Finding (DASH-2). |
| GET | `/faultlines/{faultlineId}/blast-radius` | `getBlastRadius` |

### Communication — Publications (VEX / advisory / report)

| Method | Path | Operation |
| ------ | ---- | --------- |
| POST | `/publications` | `createPublication` (human-triggered materialization of a Position) |
| GET | `/publications?release=` | `listPublications` |
| GET | `/publications/{id}` | `getPublication` (payload regenerated if pruned) |
| POST | `/previews` | `previewPublication` (render without recording) |
| GET | `/publishable-positions` | `getPublishableQueue` |

### Intelligence — the AI Gateway (optional, advisory-only)

| Method | Path | Operation |
| ------ | ---- | --------- |
| POST | `/capabilities/{id}/invoke` | `invokeCapability` — reactive, synchronous; returns a validated advisory output (`200`) or `204` "no output" (a safe outcome, **never** an error). |

Two capabilities ship, and they differ in **output class** (EDR-TRUST-01 T7), which is the thing to
understand before calling either:

| Capability | Subject | Output class | What it is |
| --- | --- | --- | --- |
| `recommend_position` | one Finding | **Decision** | Proposes a stance. Goes to Governance as an advisory Proposal a human or policy must accept — it is never auto-applied. |
| `plan_remediation` | one Release | **Information** | Groups the release's Findings into upgrade actions ordered by risk removed. It proposes no stance and reaches no Position, so nothing needs to accept it. |

A `200` response carries **`precedents_used`** — how many past Enterprise Positions grounded the
answer, retrieved from the Operational Semantic Index (Δ3a) plus any exact-CVE fallback. Zero is
reported explicitly rather than omitted, because *"no precedent was found"* and *"nobody looked"* are
different answers and only one of them is a reason to distrust the result.

A `204` carries **`X-Themis-AI-Reason`** (and `X-Themis-AI-Detail`) explaining which gate declined:

| Reason | What it means | What an operator should do |
| --- | --- | --- |
| `disabled` | no AI wired on this node | nothing — the pipeline is unaffected |
| `unreachable` | provider transport failed or timed out | check the model runtime; check BOTH timeouts (see below) |
| `insufficient` | the model correctly declined, or a guard fired | nothing — this is the seam working |
| `schema_invalid` | the output was not valid against the capability's schema | usually an oversized prompt truncating the answer |
| `business_invalid` | the claim did not check out against our own truth | a prompt/gate disagreement — the citation form was refused |
| `budget_exhausted` | the capability's spend ceiling for this window is used up | nothing; it clears when the window rolls |
| `provider_error` | the provider failed | check the model runtime |

A caller that treats every `204` as "the AI had nothing to say" will misread a timeout, a budget
pause and a correct refusal as the same event.

See [TESTING.md](TESTING.md) for runnable request/response examples, and
[`docs/engineering/decisions/`](docs/engineering/decisions/) for the design rationale behind each context.
