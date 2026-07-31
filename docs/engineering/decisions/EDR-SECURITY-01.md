# EDR-SECURITY-01 — Inbound API Authentication, Authorization & Webhook Trust

Status: **Accepted — implementation in progress** (topology confirmed 2026-07-31: shared platform auth;
see "Realization notes" for the codegen-driven D4/D7 adaptation)
Date: 2026-07-31
Author: parity-closure session (gap cluster F1/F2/F3)

## Purpose

Engineering Decision Record for the greenfield's **inbound edge security** — API-key authentication,
scope-based authorization, and HMAC-verified CI webhook ingest — across the six independently-deployed context
services (Evidence, Knowledge, Governance, Communication, Intelligence, Registry).

It closes parity gaps **F1** (no inbound auth), **F2** (no HMAC webhook), **F3** (no admin key CLI) from
[`PARITY-GAP.md`](../PARITY-GAP.md). Today **every** greenfield service mounts only
`observability.RequestLogger` — every endpoint is open. The monolith had a full model (bcrypt `X-API-Key`
store, three-tier scopes, HMAC webhook, `themis admin` key CLI); this EDR carries that model forward, adapted
to the greenfield's database-per-context topology.

Ground rule: **ADR wins; the PoC (`internal/{domain,usecase,adapter,infrastructure}`) is reference only.**

## Why this is a NEW decision, not a realization of an existing ADR

A deliberate check of the ADR set (2026-07-31) found **no ADR — and no EDR — governs inbound REST
authentication.** The three "Enterprise Security Domain" ADRs (**BCK-0036**, **DOM-0034**, **DOM-0035**) are
about the *business* model (findings, positions, VEX, ownership) — not API auth. **ADR-INT-0069** is a real
Security-category ADR but is scoped to the **Intelligence Gateway's outbound** data governance (enforce
authn/authz/sanitization *before enterprise data leaves the platform*). The monolith implemented API-key auth
as an un-decided infrastructure detail. Inbound edge security is therefore a genuine architectural gap in the
decision record on **both** trees. This EDR establishes it. (Recommend backfilling a companion ADR if the ADR
corpus is meant to be complete; the mechanics below are the decision of record meanwhile.)

## Realizes (ADR traceability)

- **DOM-0035 / BCK-0036** — the Domain is the single authoritative business model; the backend *realizes* it
  and must not redefine business concepts. → **Auth is an implementation concern.** Principals, keys, and
  scopes live in the platform/adapter rings and the domain/app rings never import them (enforced, D1).
- **ADR-INT-0069** — "security enforcement precedes provider invocation; security is an architectural
  responsibility, not a per-component feature." → **Generalized from Intelligence's outbound edge to every
  context's inbound edge:** enforcement happens in shared platform middleware before any handler runs, not
  hand-rolled per service.
- **CON-0016** (complete traceability) — every authenticated request carries a resolvable principal
  (`KeyID`) alongside the existing `X-Correlation-ID`, so who-did-what is auditable.
- **Precedent:** `internal/platform/{observability,eventbus}` — the two existing shared platform concerns, and
  the already-accepted principle (EDR-EVENTBUS-01) that a **shared infrastructure database** (`bus`) does not
  violate context isolation because it carries no business-domain join.

## Grilled against (current-state slice)

Greenfield: every `cmd/<ctx>/main.go` router mounts only `observability.RequestLogger` (evidence:100,
knowledge:161, governance:125, communication:116, registry:76, intelligence:76); no `securitySchemes` in any
`api/*.openapi.yaml`. Monolith reference: `internal/adapter/api/middleware/{auth.go,webhook.go}`,
`internal/adapter/api/{auth.go,hmac.go,mount.go}`, `internal/domain/catalog.go:157-188` (`APIKeyRecord`,
scopes), `internal/infrastructure/cli/admin.go`, `api/openapi.yaml:509-517` (the two security schemes).

---

## Headline architectural invariant

**Inbound edge security is a shared platform capability that no bounded context owns.** Exactly as the
Platform owns message *transport* (eventbus) and *telemetry* (observability), it now owns *edge security*.
Contexts own business state; the Platform authenticates and authorizes the request before a context handler
sees it; **the domain and app rings never import auth** (a principal is passed in as data, if at all). One
credential, issued once, is honored by all six services.

## Governing principle — freeze the contract, mature the mechanism

| Decision | Contract (frozen now) | Implementation (matures later) |
| --- | --- | --- |
| D1/D2 | a shared `auth` port + middleware carrying an `AuthPrincipal`; one identity store | bcrypt key table now → OIDC/JWT/mTLS behind the same middleware later |
| D4 | three scope tiers (`admin`/`read`/`product:<id>`) as the authorization contract | per-route checks now → policy engine later, same scope vocabulary |
| D5 | HMAC-signed webhook ingest as a distinct trust path | shared-secret HMAC now → per-CI signing keys later |

---

## Decisions (proposed)

### D1 — Inbound auth is the third shared platform package

`internal/platform/auth` is created as a peer of `observability` and `eventbus`. It exports the middleware
(`RequireAPIKey`, `RequireScope`), the `AuthPrincipal` value, and the identity store port. **Only `adapters`
and the `cmd` composition root may import it** — enforced by a new depguard rule `platform-auth-infra-only`
(mirroring `platform-eventbus-infra-only`) and an arch test `TestPlatformAuthIsBusinessAgnostic` (auth imports
no bounded context and no registry — kernel + drivers only). The `domain` and `app` rings never see it.

### D2 — Identity lives in one shared `auth` database (the confirmed topology)

A small dedicated database `auth` holds a single `api_keys` table
(`id, name, key_hash, scopes text[], created_at, expires_at, revoked_at`). Every context's composition root
opens a read pool against it and mounts the same middleware. Justified exactly as the shared `bus` DB is:
it is **infrastructure identity, not business state**, so no cross-context *business* join is created and
database-per-context isolation for business data is preserved.

- Config switch **`THEMIS_AUTH_DATABASE_DSN`**, mirroring `THEMIS_BUS_DATABASE_DSN`. Set ⇒ auth enforced;
  unset ⇒ auth **disabled with a loud startup warning** (`AUTH DISABLED — dev only`), so local single-service
  dev stays frictionless (same ergonomics as the bus stub).
- **`THEMIS_AUTH_REQUIRED=1`** hard-fails startup if the DSN is unset — production (systemd) sets this, so a
  prod node can never silently boot open. (Fail-open is a *dev* affordance only, never the prod default.)

### D3 — Credential format & verification (ported from the monolith)

Opaque random bearer token presented in the **`X-API-Key`** header; stored **bcrypt-hashed** at rest
(`golang.org/x/crypto/bcrypt`, already in the tree). The middleware loads active keys, `bcrypt`-compares,
rejects expired/revoked, and attaches `AuthPrincipal{KeyID, Scopes}` to the request context. Failures return
RFC-7807 `problem+json 401` (the existing error envelope). Linear-scan-over-active-keys is retained from the
monolith (acceptable at expected key counts; a lookup index is a later mechanism change, not a contract one).

### D4 — Authorization: three scope tiers (ported)

`admin` (global), `read` (authenticated but blocked from mutating endpoints), `product:<id>` (scoped to one
product's resources). Middleware `RequireScope(...)` guards routes in the adapter layer. Product-scoped keys
authorize only routes carrying that product/release id (Registry, Evidence, Knowledge, Governance,
Communication); Intelligence exposes no product-scoped routes, so it honors `admin`/`read` only.

### D5 — HMAC-verified CI webhook ingest (F2) on Evidence

`POST /webhooks/scan` on the **Evidence** service (the ingest context). Header **`X-Themis-Signature`** = hex
`HMAC-SHA256(rawBody, secret)`, **constant-time** compared; secret from **`THEMIS_WEBHOOK_SECRET`**. This path
is **exempt from `X-API-Key`** (it has its own trust mechanism) and drives an Evidence register with
provenance `actor=webhook` + CI job/pipeline metadata. No secret ⇒ the route returns 401 (never open).

### D6 — Admin key CLI (F3)

A small `cmd/authadmin` binary (`create-key --name --scope ... --expires`, `revoke-key --id`) writes to the
shared `auth` DB: it generates the token, prints it **once**, and stores only the bcrypt hash. This is the
greenfield equivalent of the monolith's `themis admin create-key/revoke-key`.

### D7 — Spec-first: security schemes in every OpenAPI (API change)

Add `securitySchemes` (`ApiKeyAuth`: `apiKey`/header/`X-API-Key`; `WebhookSignature`: `apiKey`/header/
`X-Themis-Signature`) and the appropriate `security:` requirement to **every** `api/*.openapi.yaml`, then
`make generate-api-<context>`. The spec documents the contract; the D1 middleware enforces it. Handlers stay
generated, never hand-edited.

### D8 — Enforcement boundary

Middleware wraps all `/api/v1` business routes. **Exempt (always unauthenticated):** `/healthz`, `/readyz`
(parity gap F5, when added), `/metrics` (F4), and `POST /webhooks/scan` (its own HMAC trust). A future dev
`DELETE /dev/*` purge route stays gated behind its existing dev flag *and* `admin` scope.

### D9 — Quality gates

`internal/platform/auth` (middleware + store) sits in the adapters/infra coverage tier (**90%**); the key
store in the aggregate-store tier (**80%**). The `auth` DB owns an up/down-reversible migration under a
`migrations/` dir. Middleware unit tests cover: valid key, missing header, expired, revoked, wrong scope,
and (webhook) good/bad/missing signature. New package + new DB + new depguard rule + API change are all
"Must ask" items — **this EDR is that ask**, and its sign-off authorizes them.

## Realization notes (2026-07-31 — discovered during implementation)

A codegen constraint changed *how* D4/D7 are enforced (the contract — the scope vocabulary and the
"authenticate-then-authorize at the edge" invariant — is unchanged; only the mechanism moved, per the
governing principle):

- **oapi-codegen does not emit per-operation auth** from the OpenAPI `security` / `securitySchemes` blocks.
  Its generated chi handler applies `ChiServerOptions.Middlewares` uniformly to every operation. So
  per-route scope enforcement **cannot** come from the spec; it is applied at **mount time** in each
  `cmd/<ctx>/main.go`.
- **D4 is realized as method-based enforcement** (`auth.RequireWriteScope`): read methods (GET/HEAD/OPTIONS)
  pass for any authenticated principal (the `read` floor); mutating methods require a write-capable key
  (`AuthorizeWrite()` — admin or product-scoped, not read-only). The three-scope **vocabulary** is preserved
  and stored; only the enforcement granularity changed.
- **Product-scope *isolation* to a specific product is deferred.** Greenfield routes key on release / finding
  / faultline, not product, so restricting a `product:<id>` key to one product needs resource→product
  resolution — a follow-up. Product-scoped keys are currently treated as write-capable (BACKLOG follow-up).
- **D7 spec `securitySchemes` are documentation-only** under the current codegen (they annotate the API
  contract but do not generate enforcement). Still worth adding for accurate API docs; enforcement stays in
  the composition-root middleware.

## Not in scope (explicit non-goals)

OAuth2 / OIDC / JWT / SSO; per-human user identity (keys are service/tenant credentials, not users); mTLS;
automated secret rotation; inbound rate limiting (a separate concern, absent in both trees today); and
signature verification of SBOM/VEX *documents* (tracked separately; both trees only stub it).

## Implementation plan (post-sign-off — one PR per numbered step, `make check-ci` green each)

1. `internal/platform/auth` package: `AuthPrincipal`, store port + Postgres store, `RequireAPIKey` /
   `RequireScope` middleware, `auth` DB migration. Unit + store tests. depguard rule + arch test.
2. `cmd/authadmin` create-key/revoke-key.
3. Wire the middleware into all six `cmd/<ctx>/main.go` routers (behind `THEMIS_AUTH_DATABASE_DSN`);
   per-route `RequireScope`.
4. D5 webhook route on Evidence (spec + generated handler + HMAC verify).
5. D7 spec `securitySchemes` across all `api/*.openapi.yaml`; regenerate.
6. `deploy/node.env.example` + `INSTALLATION.md` + systemd env: document `THEMIS_AUTH_DATABASE_DSN`,
   `THEMIS_AUTH_REQUIRED`, `THEMIS_WEBHOOK_SECRET`, and the `auth` DB in the create-databases step.
