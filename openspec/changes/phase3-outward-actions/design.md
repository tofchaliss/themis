# Design — phase3-outward-actions

Source of truth: `docs/engineering/decisions/EDR-DELIVERY-01.md` (this file is the realization
map). Runtime-side alignment: `themis-ai-runtime/openspec/changes/outward-actions`, **D-N-6
locked** — Themis authorizes outward-action credentials explicitly and refuses a callback
credential every governance write; the runtime holds no governance authority.

| EDR decision | Realization |
|---|---|
| D1 Explicit per-route gate | `Handler.authorizeGovernanceWrite(w, r, findingID)` in `internal/governance/adapters/http/handler.go`; called first in all nine mutations (7 in `handler.go`, `CommissionFinding`/`WithdrawCommission` in `harness.go`) |
| D1 `AuthorizeWrite` retired for Governance | no Governance call site remains; `auth.RequireWriteScope` keeps its role (method floor, other contexts) |
| D2 Callback refused on the scope | `Principal.IsDeliveryCallback()` checked FIRST, before the admin branch; `AuthorizeWrite` excludes it too |
| D3 Finding → Release → Product | `Handler.productOfFinding` (store hop via `read.GetFinding`) + `registry.Client.ProductOfRelease` (`GET /api/v1/releases/{id}` → `project_id`, `GET /api/v1/projects/{id}` → `product_id`) |
| D3 No cross-context import | `govhttp.ProductResolver` declared at the CONSUMER; `adapters/wiring` supplies the Registry client and asserts `var _ govhttp.ProductResolver = (*registry.Client)(nil)` |
| D4 Fail closed | resolver nil / transport error / non-200 / blank hop ⇒ 403; `store.ErrNotFound` ⇒ 404; `admin` never resolves |
| D5 Closed vocabulary | `auth.ScopeDeliveryCallback`, `auth.KnownScope`; `validScopes` in `cmd/authadmin` refuses at mint time |
| D5 Explicit helpers | `Principal.HasScopeExact` (with `HasScope` delegating to it), `HasScopePrefix`, `HasProductScope`, `IsDeliveryCallback` — none of them fold in admin |
| D5 Closure at the READ end | `AuthorizeWrite() = IsAdmin() \|\| HasScopePrefix(ProductScopePrefix)` — every other scope, known or not, is refused by the floor in Knowledge/Evidence/Communication/Registry/Intelligence, not only at mint time |
| D5a Refusal withholds the estate | generic 403 details; `writeRefusal` + `Handler.logRefusal` send key id, Finding, release, owning product, rule, correlation id and the withheld error to `observability.Logger` (`WithLogger`; no-op by default) |
| D6 Edge-only, reads untouched | the check lives in the HTTP adapter; `domain`/`app` unchanged; no read route gated |
| D7 Per-route, not middleware | the decision needs the resource; the route knows it, a path-parsing middleware would duplicate the router |

## Why the interface is declared at the consumer

`govhttp.ProductResolver` (one method, `ProductOfRelease`) lives in the HTTP package, not in
`app`. The seam is adapter→adapter and carries no business rule: `app` has no use case that asks
"who owns this release", and adding a port there would put an authorization concern in a ring that
EDR-SECURITY-01 D1 keeps free of scopes. The composition root (`adapters/wiring`) builds ONE
Registry client and hands it to both seams — the fail-open blast-radius reader and the fail-closed
product resolver — so a deployment cannot have one without the other.

## Why the write floor had to close too

Governance's explicit gate does not protect Knowledge, Evidence, Communication, Registry or
Intelligence — those mount `RequireWriteScope`, whose whole decision is `AuthorizeWrite()`. Closing
the vocabulary only at MINT time would have left every already-minted key with an unrecognized
scope holding write access to all of them: the guarantee "these four scopes and nothing else" is
made by the code that READS scopes, not by the code that writes them. So the floor now answers
`admin ∪ product:<id>` and nothing else. It is a behaviour change outside this change's nominal
blast radius, in the only safe direction, and it is the one place where a typo could previously be
mistaken for authority.

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
- **A refusal leaks nothing, and logs everything**: the 403 body carries neither the owning
  product nor the transport error, while the captured log (zap observer) carries key id, Finding,
  release, owning product, rule, correlation id and the withheld cause.
- `platform/auth`: the four helpers (admin implies nothing), `KnownScope`'s closed list, and
  `AuthorizeWrite`'s closed write set — asserted both directly and through `RequireWriteScope`,
  the seam every non-Governance context mounts.
- `governance/adapters/registry`: both hops, and a blank hop returning an error rather than `""`.
- `cmd/authadmin`: `validScopes` accepts the vocabulary and names the offender otherwise; the
  usage text mentions `delivery:callback` and `product:<id>`.

## Acceptance as documented — Remediation Cycle (2026-10-01)

`EDR-DELIVERY-01` **Revision 2** (RC-1..RC-8), mirroring runtime-side **D-N-8..D-N-12**
(`themis-ai-runtime/openspec/changes/outward-actions/design.md`). **Documentation only** — no code,
API, schema or generated-handler realization exists for any row below, which is why this block is
"accepted as documented" and not a realization map.

| EDR Revision 2 decision | Accepted as documented |
|---|---|
| RC-1 Trigger | The cycle starts on **evaluation complete** ("release posture evaluated") for the Release, never on SBOM receipt; a Themis-owned pub/sub notification MAY carry that signal to the harness. Transport, event names, delivery semantics, subscriber auth and owning context are deferred to their own EDR + API change — until then `finding_opened` / the posture-evaluated path remains the effective trigger in code. |
| RC-2 Jira | One ticket **per Release**; severity counts for Critical/High/Medium/Low; **CVE ids listed for Critical and High only**; updates idempotent by intent id + attempt index; Jira stays a projection. |
| RC-3 `ci_rebuild` | New delivery kind, **approved, not implemented**. Policy-gated (no fresh proposal acceptance); snapshot = pipeline name, Product/Project/Release, prior SBOM id, targeted Finding set, attempt index, no credentials; callback MUST carry **new SBOM id + image digest**. `ci_build` unchanged (`proposal_accepted` path, carries the accepted artifact). |
| RC-4 Comparison | New SBOM vs previous SBOM for the same Product/Project/Release → closed vs still open; the only measure of progress; drives the Jira update. Baseline window open. |
| RC-5 Email | Plain text, **after the comparison** on each attempt, never from the build callback; governed audiences; idempotent per intent id; snapshot facts only. |
| RC-6 Loop control | **Default max-attempts = 2** per Release, operator-configurable (locus/name TBD); success = targeted set closed; exhaustion → stop + mail + Jira update; **never auto-resolve a Finding**. |
| RC-7 Ownership | Themis owns security truth, all outward effects and loop control; the harness is a subscriber only — networkless for Jira/CI/mail, no outward credential, no Governance act. Model output advisory; secrets excluded from intents; controls fail closed. |
| RC-8 N-M0 | **Unchanged.** Group 1 stands as implemented; no new scope, no relaxation, no new Governance write path. |

## Acceptance as documented — Revision 3 (N-M2) (2026-10-07)

The outward-actions plan's **Revision 3 — N-M2**, recorded in `EDR-DELIVERY-01` as the section
**Revision 5 (2026-10-07) — N-M2** (the EDR's own counter is at 4 because N-M1a and N-M1b each took
one; both names mean the same section). Decisions **M2-1..M2-9**, mirroring the runtime-side
subscriber-seam lock in `themis-ai-runtime/openspec/changes/outward-actions/design.md`.

**Documentation only** — no code, API spec, schema, migration or generated-handler realization
exists for any row below, which is why this is "accepted as documented" and not a realization map.
It closes every question Revision 2 deferred (RC-1's transport and owning context, RC-4's baseline
window, RC-6's knob name and locus) and supersedes M1a-3's `finding_opened` proxy.

| EDR N-M2 decision | Accepted as documented |
|---|---|
| M2-1 Trigger and ordering | Knowledge publishes `knowledge.release_correlation_completed.v1` once per SBOM, appended AFTER all its other events for that SBOM; the bus's per-`source_context` `seq` order makes "everything earlier is already processed" a transport property, not a wait. Governance consumes it and publishes the signal, because Governance owns the counts. |
| M2-2 `governance.release_evaluated.v1` | snake_case `product_id`, `project_id`, `release_id`, `sbom_id`, `severity_counts {critical, high, medium, low}` as integers, `cause` ∈ {`new_sbom`, `rediscovery`}. **Zero counts still emit both events and are the SUCCESS case**, never a skip. Buckets are M1b-5's `base_score` ladder; `Unknown` (score 0) is not `low`, so the counts need not sum to the Finding count. |
| M2-3 Re-discovery | Emits with `cause=rediscovery` and **never starts or advances the loop** — nothing was built, so there is no new side to compare and no attempt to spend. The cause is carried by the producer, never inferred by a consumer. |
| M2-4 Subscriber seam | `GET /api/v1/governance/events/release-evaluated?after=<sequence>&limit=<n>`; `X-API-Key` **read** scope; at-least-once; **dedupe by event id**; cursor is the **sequence**, not the id; `limit` default **100**, max **500** (clamped); rows stored in the new Governance table **`release_evaluated_events`**; no purge policy. **No SSE, no webhook, no long-lived connection.** The harness subscribes only. |
| M2-5 Baseline and target | Baseline = the **immediately-previous** SBOM of the same Release **by upload order** (no window, no knob — closes RC-4). Targeted set = Critical + High **at cycle start**; it **does not grow** mid-loop; later Critical/High appear in the ticket's counts and wait for the next cycle. |
| M2-6 `ci_rebuild` sender | Jenkins **`buildWithParameters`**, HTTP Basic auth (user + API token), `THEMIS_COMMUNICATION_JENKINS_{ENABLED,URL,USER,API_TOKEN,JOB}`; off by default and subordinate to `..._DELIVERY_ENABLED`. **`https` mandatory, refused at configure time** (loopback excepted) exactly as M1b-2 refuses it for Jira, with the fake sender kept and the variable named at ERROR. Snapshot unchanged from RC-3: no credential, no key, no model output. |
| M2-7 Callback | The job uploads the new SBOM under a **`product:<id>`**-scoped key, then `POST /api/v1/communication/callbacks/ci-rebuild` under **`delivery:callback` only** with `{intent_id, build_id, git_ref, image_digest, sbom_id}`. **No HMAC variant now.** The callback is governed-external evidence **on the intent** and changes no Finding, Position or posture. |
| M2-8 Loop and stop | Compare → update the one-per-Release Jira ticket (RC-2 / M1b-4) → mail, all **after** the evaluation and never from the callback. **`THEMIS_COMMUNICATION_REBUILD_MAX_ATTEMPTS`, default 2, no per-Release override** (closes RC-6). Stop on success (targeted set closed) or exhaustion (stop + mail + Jira update telling a person); no further `ci_rebuild` intent after a stop; **Findings are never auto-resolved**. |
| M2-9 N-M0 | **Unchanged.** The cursor route is a READ route under a read-scoped key; the callback is a Communication route under `delivery:callback`, still refused on every Governance write. No new scope, no relaxation, no Governance write path. `ci_build` keeps its `proposal_accepted` path. |
| Steps | **N-M2a..N-M2j**, each testable alone, in `tasks.md` Group 6. API/schema deltas are **N-M2d** (Governance events table + cursor read API, migration up/down) and **N-M2h** (the Communication callback route); **N-M2g** widens the intent-type CHECK constraint to admit `ci_rebuild`. **N-M2j** is the only step in `themis-ai-runtime`. |
