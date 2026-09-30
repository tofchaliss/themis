# Design — phase3-outward-actions

Source of truth: `docs/engineering/decisions/EDR-DELIVERY-01.md` (this file is the realization
map). Runtime-side alignment: `themis-ai-runtime/openspec/changes/outward-actions`, **D-N-6
locked** — Themis authorizes outward-action credentials explicitly and refuses a callback
credential every governance write; the runtime holds no governance authority.

| EDR decision | Realization |
|---|---|
| D1 Explicit per-route gate | `Handler.authorizeGovernanceWrite(w, r, findingID)` in `internal/governance/adapters/http/handler.go`; called first in all nine mutations (7 in `handler.go`, `CommissionFinding`/`WithdrawCommission` in `harness.go`) |
| D1 `AuthorizeWrite` retired for Governance | no Governance call site remains; `auth.RequireWriteScope` (method floor, other contexts) unchanged |
| D2 Callback refused on the scope | `Principal.IsDeliveryCallback()` checked FIRST, before the admin branch; `AuthorizeWrite` also skips `ScopeDeliveryCallback` |
| D3 Finding → Release → Product | `Handler.productOfFinding` (store hop via `read.GetFinding`) + `registry.Client.ProductOfRelease` (`GET /api/v1/releases/{id}` → `project_id`, `GET /api/v1/projects/{id}` → `product_id`) |
| D3 No cross-context import | `govhttp.ProductResolver` declared at the CONSUMER; `adapters/wiring` supplies the Registry client |
| D4 Fail closed | resolver nil / transport error / non-200 / blank hop ⇒ 403; `store.ErrNotFound` ⇒ 404; `admin` never resolves |
| D5 Closed vocabulary | `auth.ScopeDeliveryCallback`, `auth.KnownScope`; `validScopes` in `cmd/authadmin` refuses at mint time |
| D5 Explicit helpers | `Principal.HasScopeExact` (with `HasScope` delegating to it), `HasScopePrefix`, `HasProductScope`, `IsDeliveryCallback` — none of them fold in admin |
| D6 Edge-only, reads untouched | the check lives in the HTTP adapter; `domain`/`app` unchanged; no read route gated |
| D7 Per-route, not middleware | the decision needs the resource; the route knows it, a path-parsing middleware would duplicate the router |

## Why the interface is declared at the consumer

`govhttp.ProductResolver` (one method, `ProductOfRelease`) lives in the HTTP package, not in
`app`. The seam is adapter→adapter and carries no business rule: `app` has no use case that asks
"who owns this release", and adding a port there would put an authorization concern in a ring that
EDR-SECURITY-01 D1 keeps free of scopes. The composition root (`adapters/wiring`) builds ONE
Registry client and hands it to both seams — the fail-open blast-radius reader and the fail-closed
product resolver — so a deployment cannot have one without the other.

## Why one guard line per handler beats one middleware

A middleware would have to re-derive the Finding id from the path, which means a second routing
table that can silently disagree with the generated one. The chosen shape puts the check where the
id is already bound, and moves the completeness guarantee into the TEST: `governanceWriteRoutes()`
enumerates the write surface, and the matrix crosses it with every scope. A route added without a
guard fails the matrix, which is the only place completeness can be checked mechanically.

## What the tests pin

- **Matrix** (`handler_auth_test.go`): 9 routes × 5 principals — `read` 403, `delivery:callback`
  403, `product:<wrong>` 403, `product:<correct>` 2xx, `admin` 2xx.
- **Nothing recorded on refusal**: the aggregate carries no proposal and no commission after a
  refused write (a status-only assertion would pass even if it half-applied).
- **Callback beside admin**: still 403 — the refusal is on the scope.
- **Confinement**: one key, two Findings in two products; writes split, reads stay open.
- **Fail-closed**: Registry unreachable · release unknown · seam not wired ⇒ 403, while `admin`
  still writes. Unknown Finding ⇒ 404.
- **Unknown scope authorizes nothing** — the regression that `AuthorizeWrite` used to allow.
- `platform/auth`: the four helpers (admin implies nothing) and `KnownScope`'s closed list.
- `governance/adapters/registry`: both hops, and a blank hop returning an error rather than `""`.
- `cmd/authadmin`: `validScopes` accepts the vocabulary and names the offender otherwise; the
  usage text mentions `delivery:callback` and `product:<id>`.
