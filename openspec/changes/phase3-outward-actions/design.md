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
| D8 Record, never send | `inbound.Consumer.handleFindingOpened` / `handleProposalAccepted` → `app.DeliveryIntentService.Record*`; the consumer holds no `Sender`. `store.SaveIntent` joins the inbox unit of work on the context, so the row commits with the envelope claim |
| D9 Snapshot + freeze | `domain.NewDeliveryIntent` calls `MaterializeDeliveryPayload` + `MarshalDeliverySnapshot` itself and hashes the result; `snapshot` / `payload_bytes` / `payload_hash` columns |
| D10 Forward-only, append-only | `RecordSuccess` / `RecordFailure` / `Retry` / `Cancel` on the aggregate; `store.RecordAttempt` writes state + the `delivery_attempts` row in ONE transaction; the port has no Delete |
| D11 Envelope id as dedup key | `ux_delivery_intents_origin (origin_event_id, origin_event_type, kind, destination)`; `inbound.originID` supplies the dev-seam surrogate. Why not the bus `seq`: it is not on the wire `Envelope` |
| D12 Worker per kind, decides nothing | `delivery.IntentWorker` (kind-scoped `DueIntents`, its own ticker) reports outcomes to the aggregate; `next_attempt_at` IS the schedule, so there are no timers and no sleeps in the tests |
| D13 Fake senders | `delivery.Sender` port + `delivery.FakeSender` (success / fail / flaky, no network); `THEMIS_DELIVERY_FAKE_*_MODE`, unrecognized ⇒ success |
| D14 No credential on an intent | `destination` is a governed NAME (`app.DefaultIntentDestination`); no secret column exists |
| D15 Admin-only operator surface | `http.Handler.requireAdmin` on all four `/delivery/intents` routes — reads included, because `product:<id>` cannot be confined from an intent's lineage and the list is a cross-product view |
| D16 Retry/Cancel transitions | `domain.ErrIntentNotRetryable` / `ErrIntentNotCancellable` → 409; `app.ErrIntentNotFound` → 404; cancel on `CANCELLED` is a no-op success |
| D17 Disabled kind ⇒ no worker | `wiring.intentWorkers` skips a kind absent from `OutwardConfig.EnableFor`; `cmd/communication.logDeliveryState` states the enabled kinds beside the per-status counts |

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

## Acceptance criteria as BUILT (authoritative for N-M1a)

`phase3-*` changes carry no `specs/` deltas, so this section and the EDR are the system of record
for what N-M1a actually guarantees. Where the step's original wording and this section differ, the
difference is named here on purpose and the reason is cited — reading the original wording as still
current is the regression this section exists to prevent.

| # | Criterion, as built | Deviation from the step's wording |
|---|---|---|
| 1 | Migrations create **`delivery_intents`** and **`delivery_attempts`** in the `communication` DATABASE, default (`public`) schema, and reverse cleanly | The step writes `communication.delivery_intents`; that names the database, not a Postgres schema. This repo is database-per-context and no Communication table is schema-qualified (`publications`, `communication_outbox`, `publishable_positions`, `release_rollups`). Asserted by `TestDeliveryIntentMigrations_SchemaMatchesTheStore` |
| 2 | `delivery_intents` carries a UNIQUE index on **`(origin_event_id, origin_event_type, kind, destination)`** | **Named deviation.** The step says `origin_event_seq`. The kernel `Envelope` carries no seq; `event_log.envelope_id` is the bus's own `UNIQUE` dedup key and the publisher is idempotent on it. Reason of record EDR-DELIVERY-01 **D11**; approval pending as `tasks.md` 2.0b. There is no `origin_event_seq` column anywhere in the schema |
| 3 | `governance.finding_opened` ⇒ exactly one PENDING `jira_issue` intent, non-empty `payload_hash`, **no sender contacted** — structurally, since the consumer holds no sender | none |
| 4 | `governance.proposal_accepted` ⇒ `ci_build` + `email` with harness-execution evidence, `email` alone without | Structurally complete, **dormant on a real estate**: `governance.proposal_accepted.v1` is `additionalProperties: false` over four fields and states no evidence schema, and N-M1a changes no event schema. Tests stub the payload; M2 adds the field. Stated at startup by the node |
| 5 | Worker: `fail` + max_attempts=3 ⇒ DEAD_LETTER, `last_error` set, 3 history rows; `success` ⇒ DELIVERED, 1 row | none |
| 6 | Operator API: list by status/kind, retry a DEAD_LETTER to PENDING with attempts zeroed, cancel a PENDING, 403 for non-admin | **Named deviation: OFF BY DEFAULT.** `THEMIS_DELIVERY_OPERATOR_API=1` serves the routes; unset, they answer `501` naming the switch. The API addition is an unapproved must-ask (`tasks.md` 2.0a). Recording, sending, retry and dead-lettering are NOT gated |
| 7 | Coverage: `domain`/`app` 100%, adapters ≥90%, store ≥80% | none |
| 8 | `deploy/node.env.example` documents every `THEMIS_DELIVERY_*` knob inline (R2) | none |
| 9 | `scripts/vm-verify.sh` prints a delivery summary, non-fatal when the tables are absent | none |

### Verifying criterion 9 by hand

The line is `delivery: pending=… delivered=… dead_letter=… cancelled=…`, printed in the
"Pipeline" block with an `EDR-DELIVERY-01 N-M1a` comment above it. Graceful degradation is
structural rather than conditional: `q()` runs `psql … 2>/dev/null`, and the script sets
`-uo pipefail` but **not** `-e`, so a query against a missing table yields an empty string and the
run continues. All four counts empty ⇒ the `n/a (no delivery_intents table — node predates
outward actions N-M1a)` branch. To confirm on a live host:

```sh
# 1. Expect the n/a line: point the script at a database with no delivery_intents table.
psql "$PGBASE/communication?sslmode=disable" -c 'ALTER TABLE delivery_intents RENAME TO delivery_intents_x'
PGBASE="$PGBASE" ./scripts/vm-verify.sh | grep delivery:
# 2. Put it back, expect the counts line.
psql "$PGBASE/communication?sslmode=disable" -c 'ALTER TABLE delivery_intents_x RENAME TO delivery_intents'
PGBASE="$PGBASE" ./scripts/vm-verify.sh | grep delivery:
```

Step 1 is the only mutation in this procedure and it is reversible by step 2; do it on a dev
estate, never on the one being verified.

## What the N-M1a tests pin

- **The event path sends nothing** (`adapters/inbound`): a `finding_opened` envelope yields exactly
  one PENDING `jira_issue` intent with a non-empty payload hash, and the consumer's collaborator set
  contains no sender to call. A `proposal_accepted` yields `email` alone, or `ci_build` + `email`
  when the payload states `harness-execution/v1` evidence (stubbed — the frozen v1 payload cannot
  carry it yet; see the EDR's honest limits).
- **A redelivered envelope records no second intent** — the dedup, asserted through the consumer,
  and again in the store against the real unique index.
- **An envelope with no id still distinguishes facts** — the dev-seam surrogate (D11); without it
  every event of a type would collapse onto one intent.
- **The lifecycle, without a single sleep** (`adapters/delivery`): `fail` + max_attempts=3 ⇒
  DEAD_LETTER with `last_error` set and three failed history rows, and the dead letter is then OFF
  the queue; `success` ⇒ DELIVERED with one history row, and a later pass does not re-send it;
  `flaky` ⇒ DELIVERED with fail/fail/success on the record. Backoff is crossed by stepping an
  injected clock, so no test is timing-dependent.
- **Isolation between channels**: one kind's outage leaves another kind's queue untouched.
- **A store failure stops the pass** rather than sending the next intent unrecorded.
- **An operator retry puts a dead letter back on the queue** — and the failed attempts stay on the
  record.
- **Store integration** (embedded Postgres): round-trip, the unique constraint on
  (origin_event_id, origin_event_type, kind, destination), append-only history, due-queue scoping by
  kind AND due time, list/count, and migrations 000006/000007 down-then-up again.
- **HTTP** (`adapters/http`): admin-only on all four routes (non-admin ⇒ 403, no principal ⇒ open,
  matching every other route on an auth-disabled node), the status/kind filters, the history on the
  single read, retry 409 on PENDING and 200 on DEAD_LETTER with attempts zeroed, cancel 200 on
  PENDING and 409 on DELIVERED, 404 on an unknown id, 501 when the service is not wired.
