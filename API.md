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
| POST | `/projects` | `registerProject` |
| POST | `/releases` | `registerRelease` |
| GET | `/releases` | `listReleases` |
| GET | `/releases/{id}` | `getRelease` (backs Evidence's `SubjectRef` / `ReleaseExists`) |

### Evidence — SBOM/VEX ingestion + immutable evidence

| Method | Path | Operation |
| ------ | ---- | --------- |
| POST | `/evidence` | `registerEvidence` (dedup by raw bytes → stable id) |
| GET | `/evidence` | `listEvidence` |
| GET | `/evidence/{id}` | `getEvidence` |
| GET | `/evidence/{id}/inventory` | `getEvidenceInventory` (raw + canonical inventory) |

### Knowledge — Faultlines (one card per canonical CVE)

| Method | Path | Operation |
| ------ | ---- | --------- |
| GET | `/faultlines?cve=` | `getFaultlineByCVE` |
| GET | `/faultlines/{id}` | `getFaultlineById` (enrichment: severity, EPSS, KEV, exploit, fixed/affected versions) |
| GET | `/faultlines/{id}/releases` | `getFaultlineReleases` |

### Governance — Findings + Enterprise Positions (the authority)

| Method | Path | Operation |
| ------ | ---- | --------- |
| GET | `/findings?release=&faultline=` | `getFindingByKey` |
| GET | `/findings/{id}` | `getFinding` |
| GET | `/findings/{id}/position` | `getPosition` |
| POST | `/findings/{id}/proposals` | `raiseProposal` |
| POST | `/findings/{id}/proposals/{proposalId}/accept` | `acceptProposal` (human/policy only) |
| POST | `/findings/{id}/proposals/{proposalId}/reject` | `rejectProposal` |
| POST | `/findings/{id}/resolve` · `/reopen` · `/archive` | lifecycle transitions |
| POST | `/findings/{id}/recommend` | `recommendPosition` — **on-demand AI seam** (records an advisory AI proposal, never auto-accepted; `204` when AI is off/unavailable/declines) |
| GET | `/releases/{releaseId}/posture` | `getReleasePosture` |
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
| POST | `/capabilities/{id}/invoke` | `invokeCapability` — reactive, synchronous; returns a validated advisory Proposal (`200`) or `204` "no proposal" (a safe outcome). Δ1 capability: `recommend_position`. |

See [TESTING.md](TESTING.md) for runnable request/response examples, and
[`docs/engineering/decisions/`](docs/engineering/decisions/) for the design rationale behind each context.
