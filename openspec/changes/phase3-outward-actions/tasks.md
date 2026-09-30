# Tasks — phase3-outward-actions

Source of truth: `docs/engineering/decisions/EDR-DELIVERY-01.md`.

`phase3-*` changes carry no `specs/` deltas (proposal/design/tasks + the EDR are the source of
truth), so `openspec validate` reporting "no deltas" is expected; archive with
`openspec archive phase3-outward-actions --skip-specs -y`.

## Group 1 — N-M0 explicit write-scope authorization (D1–D7) — **implemented 2026-09-30**

- [x] 1.1 `internal/platform/auth/auth.go`: `ScopeDeliveryCallback`, `KnownScope` (closed
      vocabulary), `Principal.HasScopeExact` (+ `HasScope` delegating to it), `HasScopePrefix`,
      `HasProductScope`, `IsDeliveryCallback`. **`AuthorizeWrite` closed to `admin` ∪
      `product:<id>`** — the vocabulary is enforced at BOTH ends (D5), so an unknown or typo'd
      scope no longer grants write in Knowledge/Evidence/Communication/Registry/Intelligence
      either. Tests: the helpers fold in no admin; `KnownScope`'s accept/refuse lists;
      `AuthorizeWrite`'s write set; and the same refusals through `RequireWriteScope`
      (`middleware_test.go`), the seam every non-Governance context mounts.
      OPERATOR ACTION on deploy: audit `api_keys` for scopes outside the vocabulary — they lose
      write capability (query + remediation in EDR-DELIVERY-01 D5).
- [x] 1.2 `internal/governance/adapters/registry/client.go`: `ProductOfRelease` — release →
      project → product over the existing read API, failing closed on a blank hop. Tests: both
      hops asserted, four refusal paths, transport + decode errors.
- [x] 1.3 `internal/governance/adapters/http/handler.go`: `ProductResolver` (declared at the
      consumer), `WithProductResolver`, `WithLogger`, `authorizeGovernanceWrite`, `logRefusal`
      (D5a — generic 403 detail, the estate detail to the shared logger), `productOfFinding`; guard in
      `RaiseProposal`, `AcceptProposal`, `RejectProposal`, `ResolveFinding`, `ReopenFinding`,
      `ArchiveFinding`, `RecommendPosition`, and in `harness.go` `CommissionFinding`,
      `WithdrawCommission`. `AuthorizeWrite` no longer authorizes any Governance write.
- [x] 1.4 `internal/governance/adapters/wiring/wiring.go`: one Registry client feeding both seams
      (fail-open blast radius, fail-closed product resolver) + the compile-time assertion
      `var _ govhttp.ProductResolver = (*registry.Client)(nil)`; empty `THEMIS_REGISTRY_URL` ⇒ only
      `admin` may write. `Wire` takes the shared logger (nil ⇒ no-op); `cmd/governance` passes
      `logger.Component("api")`.
- [x] 1.5 `cmd/authadmin`: `validScopes` against `auth.KnownScope` (refuses at mint time), usage
      documenting `delivery:callback` and `product:<id>`. Tests: parse, validate, usage text.
- [x] 1.6 `internal/governance/adapters/http/handler_auth_test.go`: the matrix (9 write routes × 5
      principals), nothing-recorded-on-refusal, callback-beside-admin, cross-product confinement,
      the three fail-closed cases, unknown-Finding 404, unknown-scope-authorizes-nothing, and the
      refusal-withholds-the-estate-but-logs-it pair (zap observer).
      `harness_test.go`: `TestReadKeyCannotCommission` wires the product seam (the operator key is
      now confined, which is the point).
- [x] 1.7 `docs/engineering/decisions/EDR-DELIVERY-01.md` (N-M0 only; M1–M3 deliberately not
      pre-decided).
- [x] 1.8 Gates: `make check` green (build · vet-tags · test · lint · clean-arch · arch-test ·
      coverage · deadcode); coverage — `governance/adapters/http` 96.6%,
      `governance/adapters/registry` 92.9%, `platform/auth` 94.7% (all ≥90%). No package added, so
      `scripts/check-coverage.sh` needs no registration. `make vet-tags` caught the five
      integration/e2e `govwiring.Wire` callers when the logger parameter was added — exactly the
      defect class it exists for.

## Group 2 — N-M1a delivery intents (D8–D17) — **implemented 2026-09-30**

The record + the isolated workers + the operator surface. All of it in the Communication context;
senders are FAKES (D13) — real Jira/SMTP/CI are M2/M3.

- [ ] **2.0 MUST-ASK, OUTSTANDING — the API change is NOT approved.** CLAUDE.md puts "API change"
      on the must-ask list, and N-M1a adds four routes to `api/communication.openapi.yaml`:
      `GET /delivery/intents`, `GET /delivery/intents/{id}`, `POST /delivery/intents/{id}/retry`,
      `POST /delivery/intents/{id}/cancel`. They are implemented because the step's own requirement
      is that "a person can see failed requests, retry them or cancel them", and an API is the only
      surface this repository has for that (no GUI is in scope). **No approval has been recorded**,
      so this item stays open until the owner gives one. What is being asked for:
      - **Why:** a dead-lettered outward action is invisible and un-redrivable without it; the
        milestone ships the failures and the means to see them in the same step, deliberately.
      - **Alternatives considered:** (a) a read-only list with no retry/cancel — leaves an operator
        able to see a failure and unable to act on it, and a `psql` UPDATE then becomes the
        remediation path, which is a mutation outside the event stream; (b) a `scripts/` SQL report
        instead of routes — same objection, and it cannot mutate through the API either; (c) gating
        the routes behind an off-by-default flag — makes the deployed default a node where failures
        are invisible, which is the condition this step exists to remove.
      - **Impact:** additive only. Four new paths, two new schemas (`DeliveryIntent`,
        `DeliveryAttempt`); no existing path, schema or response shape changes; problem bodies use
        the existing `Problem` envelope. **Admin-only, reads included** (D15), so no new capability
        reaches a non-admin key. Unwired ⇒ `501`, so a node that does no outward delivery is
        unaffected.
      - **Files:** `api/communication.openapi.yaml`, `internal/communication/adapters/http/gen/…`
        (generated), `adapters/http/handler_delivery_intents.go` (+ its test).
      - **If refused:** revert the four paths and the two schemas, regenerate, and delete
        `handler_delivery_intents.go`; the record, the workers and the dead-lettering all keep
        working, and the operator's view falls back to `scripts/vm-verify.sh`'s counts with no way
        to retry or cancel.

- [x] 2.1 `internal/communication/domain/delivery_intent.go`: the `DeliveryIntent` aggregate —
      `DeliveryKind` (`jira_issue`/`email`/`ci_build`) and `IntentStatus`
      (`PENDING`/`DELIVERED`/`DEAD_LETTER`/`CANCELLED`) as closed vocabularies, `DeliveryOrigin`
      lineage, `MaterializeDeliveryPayload` + `MarshalDeliverySnapshot` (D9 — the freezing happens
      in the domain, so no caller can hand in bytes the hash would then certify as matching a
      lineage they do not match), `BackoffPolicy.Delay` (doubling that stops AT the cap, which is
      also what keeps it from overflowing into a negative duration), and the transitions
      `RecordSuccess` / `RecordFailure` / `Retry` / `Cancel` (D10, D16). Tests: 12, incl. payload
      determinism per kind, snapshot round-trip, and `Reconstitute` applying no rules.
- [x] 2.2 `internal/communication/app/delivery_intents.go`: `DeliveryIntentRepository` (no Delete
      method — intents are never deleted), `DeliveryIntentService` with the two halves that never
      meet: `RecordFindingOpened` / `RecordProposalAccepted` (recording) and `DueIntents` /
      `RecordOutcome` (sending). `RecordOutcome` RETURNS the updated intent — discarding it would
      make the worker log the pre-attempt state and announce a dead letter as an ordinary retry.
      A dedup skip is not an error (returning one would make the reader retry a fully applied
      envelope).
- [x] 2.3 Migrations `000006_delivery_intents` + `000007_delivery_attempts` (up/down, reversibility
      asserted by `TestDeliveryIntentMigrations_ReverseAndReapply`): the unique index
      `ux_delivery_intents_origin (origin_event_id, origin_event_type, kind, destination)` — D11
      records why the key is the envelope id and not the bus `seq` — plus the workers' due-queue
      index and the operator's status index. `Store.Purge` truncates both new tables.
- [x] 2.4 `internal/communication/adapters/store/delivery_intents.go`: `SaveIntent` dedups on the
      INDEX (`ON CONFLICT DO NOTHING`) and not on a prior SELECT — two readers draining the same
      replayed envelope would both see "absent"; it joins the inbox unit of work on the context so
      the intent commits with the envelope claim (D8). `RecordAttempt` writes state + history in one
      transaction (D10). `scanIntent` reads the lineage from the snapshot and falls back to the
      columns, so an intent whose JSON went bad is still retrievable.
- [x] 2.5 `internal/communication/adapters/inbound/consumer.go`: `governance.finding_opened` →
      one `jira_issue` intent; `governance.proposal_accepted` → `email` always, `ci_build` only on
      `harness-execution/v1` evidence. `WithDeliveryIntents` keeps it optional (nil ⇒ the lifecycle
      events are ignored, the right behaviour for a node that does no outward delivery). **No sender
      is reachable from the ACL** (D8) — asserted, not merely intended. The dormant-`ci_build` limit
      is recorded at the DTO, where the field looks load-bearing and is not yet.
- [x] 2.6 `internal/communication/adapters/delivery/`: the `Sender` port (takes the INTENT, not just
      the bytes — a real sender needs the kind, destination and lineage to address and de-duplicate
      its own call), `FakeSender` (`success|fail|flaky`, per-intent call counts, no network),
      `IntentWorker.Drain` / `Run` and `Workers` — one per enabled kind (D12, D17). No sleeps
      anywhere: the schedule is `next_attempt_at` on the row and the tests step an injected clock.
- [x] 2.7 `api/communication.openapi.yaml` + `make generate-api-communication`:
      `GET /delivery/intents` (status/kind/limit/offset), `GET /delivery/intents/{id}` (with the
      attempt history), `POST …/retry`, `POST …/cancel`. Handlers in
      `adapters/http/handler_delivery_intents.go`, **admin-only including the reads** (D15), 409 on a
      refused transition, 404 on an unknown intent, 501 when the service is not wired. Payload bytes
      are not exposed; the hash pins which bytes were decided on.
- [x] 2.8 Wiring + config (R2): `wiring.OutwardConfig` (isolated from the bus's own retry envelope
      even though the defaults mirror it — a slow mail relay must be givable more patience without
      making the governance stream more patient), `cmd/communication` parsing
      `THEMIS_DELIVERY_MAX_ATTEMPTS` · `_BACKOFF_BASE_MS` · `_BACKOFF_CAP_MS` ·
      `_WORKER_INTERVAL_MS` · `_ENABLE_{JIRA,EMAIL,CI}` · `_FAKE_{JIRA,EMAIL,CI}_MODE`, a startup
      line stating which kinds have a worker beside the per-status counts (D17), and all of it
      documented inline in `deploy/node.env.example`.
- [x] 2.9 `scripts/vm-verify.sh`: a `delivery: pending=… delivered=… dead_letter=… cancelled=…`
      line, degrading to `n/a` on a node predating the migrations (a verification script that dies
      on an absent table is a script people stop running) and pointing at the dead-letter query when
      the count is non-zero. Read-only, as the whole script is.
- [x] 2.10 Gates: `go build ./...`, `go vet -tags=integration` + `-tags=e2e`, unit + integration
      tests, `golangci-lint run` (0 issues), `go-cleanarch` on `internal/communication`,
      `tests/architecture`. Coverage — `communication/domain` **100%**, `communication/app`
      **100%**, `adapters/delivery` **100%**, `adapters/inbound` **100%**, `adapters/http` **97.1%**,
      `adapters/store` **82.9%** (tiers 100 / 90 / 80). No package added, so
      `scripts/check-coverage.sh` needed no registration (`communication/adapters/delivery` was
      already listed). `tests/pipeline` updated for `Wire`'s two new parameters — the caller class
      `vet-tags` exists to catch.
- [x] 2.11 `docs/engineering/decisions/EDR-DELIVERY-01.md` revision 2: D8–D17 + "Honest limits —
      N-M1a". M2/M3 still deliberately not pre-decided.
- [ ] 2.12 CARRIED from N-M0: the Governance → Registry read seam sends no API key, so on an
      auth-enabled estate a `product:<id>` key cannot resolve its product and therefore cannot
      write. Giving the read seam a credential is a security-model change; N-M1a did not need it
      (its own surface is admin-only — D15), so it stays with the milestone that does.
- [ ] 2.13 OPEN, by design: `delivery:callback` is still refused everywhere and has no capability.
      What an outward target may call BACK into is undecided; N-M1a is outbound only.

## Group 3 — M2 CI — NOT STARTED

Blocks on one thing Themis owns: `governance.proposal_accepted` does not state the accepted
proposal's evidence schema, so `ci_build` intents are structurally present and dormant
(EDR-DELIVERY-01 "Honest limits — N-M1a"). M2 is where that event grows the field and where the CI
payload gains its artifact members.

## Group 4 — M3 mail — NOT STARTED
