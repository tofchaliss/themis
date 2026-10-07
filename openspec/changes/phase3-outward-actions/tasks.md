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

## Group 2 — N-M1a delivery intents (EDR-DELIVERY-01 Revision 3) — **implemented 2026-10-02**

Half of M1: Themis RECORDS what must go out and SENDS it in a worker, against FAKE senders. Real
Jira/mail senders are N-M1b; the CI build and the rebuild loop are NOT in this step at all (M1a-9
— no `ci_build`, no `ci_rebuild`, no CI worker, no callback). Owner feedback shaped two things:
deduplicate on the ORIGINATING EVENT ID, and carry no CI-build content.

- [x] 2.1 `internal/communication/adapters/store/migrations/000006_delivery_intents.{up,down}.sql`:
      `delivery_intents` (+ `delivery_attempts`, append-only, FK-cascading). Idempotence is a
      PARTIAL UNIQUE INDEX on `origin_event_id WHERE origin_event_id IS NOT NULL` — worker-sourced
      intents store NULL and collide with nothing. Type and state are CHECK-closed
      (`jira_issue|email`, `pending|delivered|dead_letter|cancelled`), which is also what makes a
      CI kind impossible to add by accident. Foreign ids are TEXT, not UUID (other contexts'
      identities, carried verbatim — the D5 rule). Reversibility is covered by the existing
      `TestMigrationDownUp`.
- [x] 2.2 `internal/communication/adapters/store/delivery.go`: `CreateIntent` (idempotent,
      `ON CONFLICT (origin_event_id) WHERE … DO NOTHING RETURNING`, returning the existing row),
      `GetIntent`, `GetPendingForWork`, `RecordAttempt` (counters + ledger; NOT state),
      `MarkDelivered` / `MarkDeadLetter` / `CancelIntent` / `RetryIntent` (guarded transitions →
      `app.ErrIntentNotFound` on zero rows, so an operator never sees a silent success),
      `ListDeadLetters`. A new `q(ctx)` joins the ambient inbox transaction (the Exec-only
      `exec(ctx)` cannot: the idempotent insert needs `QueryRow`). `Purge` + the test `truncate`
      cover the new tables.
- [x] 2.3 `internal/communication/app/delivery_intent.go`: `Intent` / `Attempt` / `IntentLineage`,
      the closed `IntentType` + `IntentState` vocabularies, the `DeliveryIntents` port, and
      `DeliveryIntentService` with `EnqueueJiraForRelease` / `EnqueueDecisionMail` /
      `EnqueueDeadLetterMail`. The service is the ONLY way an intent is created, which puts three
      guarantees in one place: governed destination names, the identity facts stamped into the
      snapshot (a caller cannot omit them), and `ErrNoSubject` — nothing is enqueued for an
      indeterminate subject. `lineage` carries no `event_seq` (not in the kernel Envelope, EB-02).
- [x] 2.4 `internal/communication/adapters/inbound/consumer.go`: `governance.finding_opened` →
      one ticket intent for the Release, `governance.proposal_accepted` → one decision mail, both
      keyed on the envelope id; both added to `Subscription.Interest` (an undeclared type never
      reaches `Handle`). `WithIntents` keeps the mappings OPT-IN. The reader holds no Jira, mail or
      HTTP client — M1a-1, asserted by `TestConsumer_NeverDelivers`. The `finding_opened` trigger
      is a RECORDED TEMPORARY PROXY for "release posture evaluated" (RC-1 / D-N-8), and the
      consequence is recorded with it: one event → one intent, so RC-2's one-ticket-per-Release is
      not yet realized.
- [x] 2.5 `internal/communication/adapters/delivery/{delivery,worker}.go`: `IntentDeliverer` +
      `Result`, `FakeJiraDeliverer` / `FakeMailDeliverer` (log-only, programmable, NO network),
      `Config` + `ConfigFromEnv` (R2 — every knob documented, out-of-range falls back to its
      default), and `Worker` (one fetcher + N senders; exponential backoff capped; dead-letter on
      exhaustion → an operations mail INTENT, never an inline send; the notification chain stops at
      one; an already-exhausted pending intent is finished WITHOUT sending again). A failed
      delivery is an outcome — only a STORE failure is reported as an error.
- [x] 2.6 `internal/communication/adapters/wiring/wiring.go` `WireDelivery` + `cmd/communication`:
      ONE switch over BOTH halves (M1a-7) — `THEMIS_COMMUNICATION_DELIVERY_ENABLED=0` (default)
      wires no worker and leaves the consumer without the intake, so nothing is recorded and
      nothing is sent.
- [x] 2.7 `cmd/deliveryctl`: `list-deadletters` · `retry` · `cancel` over the Communication store,
      following `cmd/authadmin`. **No HTTP surface added.** An unknown or already-delivered id
      exits non-zero; `retry` clears the counters but never the attempt ledger.
- [x] 2.8 Tests: store integration (idempotence on the event id, due-time claim order, attempt
      ledger, terminal transitions refusing a delivered intent, dead-letter list + paging + window,
      retry/cancel, purge); inbound unit (one intent per event, replay creates no second, no
      Release ⇒ nothing, malformed ⇒ error, intake absent ⇒ inert, the reader never delivers);
      worker unit (fail-twice-then-succeed with the backoff asserted per attempt, the cap,
      exhaustion → dead_letter + an operations email intent, the chain stopping, no-deliverer, the
      store-failure matrix, the disabled toggle, the loop, logs carry the correlation ids and never
      the payload); CLI unit (list/retry/cancel, exit codes 0/1/2). Coverage: `communication/app`
      100%, `adapters/delivery` 98.1%, `adapters/inbound` 100%, `adapters/store` 81.8% (≥80),
      `cmd/deliveryctl` 90.6%. No package added under `internal/`, so
      `scripts/check-coverage.sh` needs no registration.
- [x] 2.9 `docs/engineering/decisions/EDR-DELIVERY-01.md` **Revision 3** (M1a-1..M1a-9 + honest
      limits) and `deploy/node.env.example` (the eight knobs + the operator CLI).
- [ ] 2.10 Carried limit from N-M0 (EDR-DELIVERY-01 "Honest limits"): the Governance → Registry
      read seam sends no API key, so on an auth-enabled estate a `product:<id>` key cannot resolve
      its product and therefore cannot write. Giving the read seam a credential is a security-model
      change and belongs to the milestone that needs it.
- [x] 2.11 N-M1b: the real Jira and mail senders behind `IntentDeliverer`, and payload
      materialization — **implemented 2026-10-02** (Group 2b below).
- [ ] 2.12 Open, for the owner: (a) confirm the `finding_opened` proxy stands until a
      valuation-complete signal exists, or pause the ticket mapping until then — the proxy means N
      intents per Release today; (b) fix the governed default destination names (the code defaults
      are `themis-remediation`, `security-decisions`, `operations`) and whether they are per-type
      or per-intent; (c) duplicate suppression when two Communication nodes drain one database —
      N-M1b NARROWS this (an update is idempotent, a mail carries a stable Message-ID) but two
      nodes racing before either has created the issue can still open it twice; closing it needs a
      store-level claim.

## Group 2b — N-M1b real Jira + mail senders (EDR-DELIVERY-01 Revision 4) — **implemented 2026-10-02**

The other half of M1: the same seam, two REAL channels. Both **OFF by default** and enabled
independently; every secret from the environment only; the payload snapshotted at enqueue. The CI
build and the rebuild loop are STILL not in this step (M1b-7 — no `ci_build`, no `ci_rebuild`, no
callback, no loop control, no API or OpenAPI edit).

- [x] 2b.1 `internal/communication/app/delivery_intent.go`: the **payload envelope**
      (`BuildPayload` / `SplitPayload` / `PayloadDigest` — one `Subject:` line, a blank line, the
      body, so BOTH halves of what goes out live inside the bytes the SHA-256 covers), the
      `IntentPayloadRenderer` port, the narrow `ReleaseSeverityReader` port +
      `ReleaseSeverityRow`, `WithPayloadRenderer`, and `create` — which materializes BEFORE
      persisting, so a render failure means NO intent (`ErrEmptyPayload` / the renderer's error)
      and the bus retries the event. A replay re-renders and discards: `CreateIntent` returns the
      stored row, payload included, so determinism is a property of the RECORD.
- [x] 2b.2 `adapters/serializer/outward.go`: `OutwardRenderer` (implements the app port) with
      `RenderJiraIssue` / `RenderDecisionEmail` / `RenderOpsDeadLetterEmail`. RC-2's rule is here:
      counts for Critical/High/Medium/Low, CVE ids for **Critical and High only**, sorted and
      deduplicated so two renders of one posture are byte-identical. The severity buckets invert
      Knowledge's own baseline ladder over Governance's `base_score` (90/70/40/>0) because the
      posture projection carries no severity word — and a score of 0 is `Unknown`, counted
      separately and only when non-empty, never folded into `Low`.
- [x] 2b.3 `adapters/governance/client.go`: `ReleaseSeverity` — a SECOND narrow view of the
      existing posture endpoint (CVE + `base_score`), not a widened `postureRow`: the rollup wants
      the decided half and the verdicts, a ticket wants an id and a number. Every failure is
      reported, never degraded to an empty posture — a ticket rendered from zero rows would claim a
      Release has nothing open, which is the one thing a failed read cannot know.
- [x] 2b.4 `adapters/delivery/jira.go`: `RealJiraDeliverer` over REST v3 + `net/http` (no client
      dependency). **One ticket per Release by exact LABEL** (`themis-release-<uuid>`), not by
      `summary ~ "<uuid>"` — a tokenization near-miss does not fail, it silently opens a second
      ticket. Update is a FULL REPLACE (idempotent by construction); the key lands on the intent
      result. ADF description (v3 requires it). The Authorization header is set in one place and
      no error, excerpt or log field carries the token. **A clear-text `http://` base URL is
      REFUSED at configure time** (loopback excepted), as is a non-http(s) scheme: Basic auth puts
      the token in EVERY request, so this is the same rule 2b.5 applies to a password without
      STARTTLS — one rule, both channels (EDR Revision 4 M1b-1).
- [x] 2b.5 `adapters/delivery/mail.go`: `RealMailDeliverer` over `net/smtp` + `crypto/tls`.
      The governed audience NAME becomes recipients here or nowhere — an unmapped audience is
      REFUSED, never redirected to a default. `Date` from the intent's creation time and
      `Message-ID` from its id, so a retry is byte-identical and a relay can collapse it (RC-5).
      A username without STARTTLS is refused at startup for a non-loopback relay (the password
      would cross the network in the clear; `net/smtp` refuses it one layer down anyway).
      **Every STEP of the conversation is bounded**, not just the dial (`deadlineConn` refreshes a
      per-operation deadline; the context closes the connection on shutdown) — a relay that accepts
      and then stops answering is not unreachable, so a dial timeout never fires and the worker
      goroutine would block forever. **Header values are folded** (CR/LF → space) at the boundary,
      because a newline in a header value adds HEADERS rather than breaking one; an ADDRESS is
      refused (`From`) or dropped (a recipient, leaving its audience unmapped and loudly refused),
      since a silently repaired address mails security content somewhere nobody chose. The
      Governance read seam is bounded too (`NewClient` with a nil client no longer means
      `http.DefaultClient`, which has no timeout) — it runs inside the inbox transaction now.
- [x] 2b.6 `adapters/delivery/delivery.go`: `JiraConfig` + `MailConfig` on `Config`,
      `jiraFromEnv` / `mailFromEnv` / `ParseAudiences`, and `NewDeliverers` — the selection:
      real when enabled AND complete, else the fake with an **ERROR naming the unset knobs**. Both
      `String()`s report `set`/`unset` for a credential and never a value (and the mail one prints
      audience NAMES only — an address list is estate detail).
- [x] 2b.7 `adapters/wiring/wiring.go`: the posture read seam carried on the `Communication`
      bundle, the renderer wired whenever it is present (materialization is a property of the
      record, not of the channel — a node on the fakes still stores the exact bytes), and
      `NewDeliverers` replacing the hard-wired fakes. `WireDelivery`'s signature is unchanged, so
      M1a-7's one switch over both halves still reads as one switch.
- [x] 2b.8 Tests: serializer (the content rule, determinism under reordering, the Unknown bucket,
      the three fail-closed refusals, both mails, the dispatcher); app (materialization on all
      three enqueue paths incl. the STORED row, fail-closed on a render error and on empty bytes,
      the replay keeping the first payload, the envelope round trip); governance client
      (`ReleaseSeverity` + three failure modes); delivery (**httptest** Jira create/update paths
      asserting JQL, labels, ADF content and the recorded key; the update's idempotence under
      retry; five Jira refusals as OUTCOMES; an **in-process SMTP server** asserting MAIL FROM,
      the resolved RCPT TOs, every header and that the body IS the payload body; byte-identical
      retry; PLAIN auth; three SMTP refusals; the unmapped audience; `ErrNoPayload` on both
      senders; the selection matrix incl. the loud incomplete-config fallback and
      configured-but-disabled making no call; `ConfigFromEnv`) and store integration (the payload
      round-trips and the CLAIM carries it — the N-M1a emptiness assertion is gone).
      **Secrecy is asserted, not assumed**: a zap observer plus the attempt ledger are checked for
      the token and the password on every path, including the failures. The hardening has its own
      negative paths: the clear-text/`no-scheme`/wrong-scheme Jira refusals **and** the selection
      keeping the fake for a clear-text site; a relay that stalls on DATA timing out instead of
      hanging; context cancellation ending a conversation in flight; a payload whose subject carries
      `CRLF + Bcc:` producing NO extra header; a `From` and a recipient with control characters
      refused and dropped; and a stalled Governance read honouring its deadline.
      Coverage: `communication/app` 100%, `adapters/serializer` 98.7%, `adapters/delivery` 96.3%,
      `adapters/governance` 95.7% (all ≥90), `adapters/store` ≥80. No package added, so
      `scripts/check-coverage.sh` needs no registration.
- [x] 2b.8a **Field defect, enterprise VM 2026-10-05 — the read seam was unauthenticated.** With
      Governance and Registry under `THEMIS_AUTH_REQUIRED=1`, Communication's posture read got **401**,
      so the ticket payload could not be rendered, so (correctly, per 2b.1) NO intent was recorded and
      the `finding_opened` envelope retried forever — the pipeline stopped at the first Finding.
      Owner decision: **both read clients send `X-API-Key` from `THEMIS_API_KEY` when set; unset means
      no key, as before.** Same variable the Dashboard proxy and Intelligence use; a READ-scoped key is
      enough and is what the docs tell an operator to mint. Implemented as `WithAPIKey` on
      `adapters/governance` + `adapters/registry` (every read of both goes through one request builder,
      so "does this seam authenticate" has ONE answer), threaded through `wiring.Wire` from
      `cmd/communication` — which logs only WHETHER a key is set. Keys are trimmed (a pasted key
      arrives with a newline the operator cannot see). A 401/403 now says whether the read sent **no**
      key or one that was **refused** — two different places to look — and never quotes the key.
      Tests: the auth-on matrix on both clients (all three Governance reads and all three Registry
      hops carry it; a padded key still authenticates; absent and stale keys refuse with the right
      sentence and no credential in the error; a refused `GetPosition` is an ERROR, never "no Position
      yet"), plus the defect itself at the reader — with a key the Jira intent IS recorded and its
      payload reflects the authenticated posture; without one NOTHING is recorded and `Handle` returns
      an error naming `THEMIS_API_KEY`. `deploy/node.env.example` and the systemd installer's
      communication stanza document it. Recorded as EDR-DELIVERY-01 **M1b-8**; closes the N-M0 limit
      for Communication only (2.10's Governance→Registry half is a separate decision).
- [x] 2b.8b **Field defect, enterprise VM 2026-10-06 — the estate's Jira is self-hosted DATA CENTER**
      (`https://almsbx.radisys.com/jira`), not Cloud. The first cut was wrong three ways at once: HTTP
      Basic where Data Center issues a **Personal Access Token** for `Authorization: Bearer`,
      `/rest/api/3` where it serves **v2**, and an ADF description where v2 wants **plain text**.
      Owner decision: two knobs, **defaulting to Cloud** so an existing deployment sets neither —
      `THEMIS_COMMUNICATION_JIRA_AUTH` (`basic` | `bearer`) and `THEMIS_COMMUNICATION_JIRA_API_VERSION`
      (`3` | `2`). The version knob selects the path prefix AND the description encoding together,
      because they are not independent; neither vocabulary falls back (a typo'd `bearer` sending a PAT
      as a password is a 401 that reads as "the token is wrong", so it is refused at startup with the
      variable named and both options spelled out); and the USER is required only under `basic`,
      because a PAT identifies its own owner. The base URL may carry a **path** — every endpoint
      APPENDS to it, so `/jira` is preserved with no second code path, and a bare `host/path` with no
      scheme is refused as the likeliest paste. Everything else is SHARED: the JQL label search, the
      labels, the summary, the full-replace update, the content rule. Tests run **both flavours**
      through one table over create, update, path addressing (the stub 404s outside
      `<basePath>/rest/api/<v>`, so a mis-addressed call fails rather than passing quietly) and the
      whole posture-to-ticket path — plus the closed-vocabulary refusals and
      "bearer needs no user / basic still does / the Cloud defaults need no new variable".
      Recorded as EDR-DELIVERY-01 **M1b-3a**; `deploy/node.env.example` documents both flavours and
      carries a complete, commented Data Center stanza.
- [x] 2b.8c **Field defect, enterprise VM 2026-10-07 — project ME forbids labels on its create screen**
      (`Field 'labels' cannot be set`), and Jira refuses the WHOLE create over that one field, so every
      ticket failed. Three owner-directed changes, all implemented:
      **(a) create without labels, add them afterwards, and stop depending on the label to find the
      ticket.** The lookup order is now Themis's OWN RECORD (`jira_issue_key` on an earlier delivered
      intent for that Release) → the label search as FALLBACK → create. If labels can fail to apply then
      a label search can fail to find, so the rule could not keep resting on it. The labels arrive by a
      follow-up `update` edit that is BEST EFFORT: on failure the ticket stands, the key is recorded, and
      the next update retries (`add` is idempotent, so no state tracks it). A failed label edit must
      never fail the delivery — a retried delivery retries the CREATE, on an intent whose key is not yet
      in the store, which is exactly how a Release gets two tickets. Work on one Release is serialized
      in-process by a lock held across lookup AND create, with a process-local memo beside it because the
      durable key only lands when the worker marks the intent delivered, after the sender has returned.
      New store read `JiraIssueKeyForRelease` (delivered intents only; a blank key is not an answer);
      `jira_found_by` and `jira_labels` are recorded so an operator can see which mechanism is carrying
      the rule. **(b)** `THEMIS_COMMUNICATION_JIRA_ISSUE_TYPE_ID` (sent by id, and then the name is not
      sent at all) and `THEMIS_COMMUNICATION_JIRA_EXTRA_FIELDS` (a JSON object merged into every CREATE's
      fields, verbatim; it can never override project/issuetype/summary/description/labels — a reserved
      key is dropped and logged; invalid JSON refuses the sender at startup and keeps the fake; create
      only, so Themis never overwrites what a human changed). **(c)** fixed the issue-type NAME
      defaulting in only one half of the node — the sender applied `Task` internally while
      `ConfigFromEnv` left it empty, so the startup line read `issue_type=""` and disagreed with the
      request it described. Tests: the stub now REFUSES a create carrying labels (Jira's own wording) and
      counts content edits apart from label edits, so "no labels on create" is a regression test rather
      than a restatement; create-then-label on both flavours; a label edit that fails → key recorded,
      `jira_labels=pending`, and a second intent UPDATES that ticket with no second create; record
      preferred over search (the search is not even called); the search still used when there is no
      record AND when the record read FAILS; **eight intents for one Release across four worker
      goroutines → exactly one create** (passes under `-race`); issue type by id with no name; the ME
      project's five extra fields reaching a create and NOT an update; every reserved key dropped with
      the non-reserved one kept and the warning naming them; invalid JSON refused at four shapes and the
      selection keeping the fake; empty/`{}` accepted; the effective issue type in both the config and
      the startup line. `deploy/node.env.example` carries the complete, commented **ME** stanza.
      Recorded as EDR-DELIVERY-01 **M1b-4a/4b**, with two honest limits restated: two NODES can still
      open two tickets, and a create whose outcome never gets recorded can be repeated.
- [x] 2b.9 `docs/engineering/decisions/EDR-DELIVERY-01.md` **Revision 4** (M1b-1..M1b-8 + honest
      limits) and `deploy/node.env.example` (the two switches, every knob commented, both secrets
      documented as environment-only and left valueless, the N-M1a-payload consequence, and
      `THEMIS_API_KEY` for the two read seams).
- [ ] 2b.10 Open, for the owner: (a) ~~confirm the Jira flavour~~ — **settled 2026-10-06 by 2b.8b**:
      both Cloud and Data Center are supported, the estate is Data Center; the ISSUE TYPE is settled
      too (2b.8c — ME uses id 10501 with five required fields); (b) the ticket currently counts
      EVERY Finding of the Release, including those a Position has suppressed — filtering by
      disposition is a policy decision nobody has taken; (c) a central governed audience registry
      (the env map is the registry until one exists); (d) Jira credential needs
      BROWSE/SEARCH, or first-run idempotence degrades to a duplicate ticket.
- [ ] 2b.11 **Owner sign-off wanted on one deliberate deviation from the M1b draft design.** The
      draft allowed a real sender to render ONCE from current facts when an intent carries no
      payload (back-compat for N-M1a rows) and store the result. This implementation **refuses**
      instead (`ErrNoPayload`), because that fallback is render-at-send with extra steps and is the
      determinism hole the plan's own Risks section asks a reviewer to look for. Consequence: an
      estate upgraded from N-M1a dead-letters its already-queued intents, visibly, for an operator
      to `deliveryctl cancel` or retry after re-triggering. Recorded in EDR-DELIVERY-01 Revision 4
      M1b-3 and `deploy/node.env.example`. If the upgrade cost is unacceptable, the alternative is a
      one-time render path behind its own knob — a knob, so the default stays strict.

## Group 3 — M2 CI (`ci_build`, the `proposal_accepted` artifact path) — NOT STARTED

Unchanged and still unstarted. The REBUILD path (`ci_rebuild`, policy-gated, no artifact) is a
different kind and is designed in Group 6 — the two must not be conflated (RC-3).

## Group 4 — M3 mail — NOT STARTED

## Group 5 — Remediation cycle — **documentation only, 2026-10-01**

No code, API spec, schema, migration or generated handler changes in this group. Runtime-side
source: `themis-ai-runtime/openspec/changes/outward-actions` **D-N-8..D-N-12**.

- [x] 5.1 `docs/engineering/decisions/EDR-DELIVERY-01.md`: **Revision 2 (2026-10-01)** with
      RC-1..RC-8 — evaluation-complete trigger + the Themis-owned pub/sub notification (transport
      deferred to its own EDR); Jira one ticket per Release with CVE ids for Critical/High only;
      `ci_rebuild` approved (policy-gated, callback carries new SBOM id + image digest, `ci_build`
      unchanged); new-vs-previous SBOM comparison; mail after the comparison; default
      max-attempts 2; ownership and invariants; **N-M0 unchanged**. Status line updated.
- [x] 5.2 `design.md`: "Acceptance as documented — Remediation Cycle" block mirroring RC-1..RC-8,
      marked as documentation rather than a realization map.
- [x] 5.3 `proposal.md`: the owner's loop restated, doc-only scope, `ci_build` semantics and N-M0
      explicitly preserved. The operator-configurable **max-attempts default = 2** knob is recorded
      as documentation — its configuration locus and name are NOT fixed here — and the Jira content
      rule (CVE ids listed only for Critical and High; Medium/Low by count) is recorded with it.
- [x] 5.4 Gates: `make check` green (build · vet-tags · test · lint · clean-arch · arch-test ·
      coverage · deadcode), proving no code drift from a documentation-only change.
- [x] 5.5 **Settled 2026-10-07 by Group 6** — the notification seam is designed in
      `EDR-DELIVERY-01` **Revision 3 — N-M2** (M2-1/M2-2/M2-4): event names
      `knowledge.release_correlation_completed.v1` + `governance.release_evaluated.v1`,
      at-least-once with dedupe by event id, transport = polling a Governance cursor read API,
      subscriber auth = `X-API-Key` read scope, owning context = **Governance**. The API change
      itself is N-M2d (task 6.4) and is not in this documentation-only group.
- [x] 5.6 **Settled 2026-10-07 by Group 6** (M2-8):
      `THEMIS_COMMUNICATION_REBUILD_MAX_ATTEMPTS`, default **2**, Communication-side, **no
      per-Release override**.
- [x] 5.7 **Settled 2026-10-07 by Group 6** (M2-5): strictly the **immediately-previous SBOM of
      the same Release by upload order**. No configured baseline window.

## Group 6 — N-M2 the release-evaluated trigger, polling subscriber, `ci_rebuild` and the loop (EDR-DELIVERY-01 **Revision 3 — N-M2**) — **designed 2026-10-07, documentation only**

No code, API spec, schema, migration or generated handler changes in the DESIGN step (6.0); the
steps **N-M2a..N-M2j** below are the build plan, each small and testable alone. API/schema deltas:
**N-M2d** (events table + cursor read API), **N-M2h** (the callback route) and **N-M2g** (a
constraint migration only — the intent-type CHECK widened to admit `ci_rebuild`). Runtime-side
source: `themis-ai-runtime/openspec/changes/outward-actions` (D-N-8..D-N-13). Owner decisions
recorded in `proposal.md` and accepted in `design.md`.

- [x] 6.0 Design recorded: `docs/engineering/decisions/EDR-DELIVERY-01.md`, the appended section
      **Revision 3 — N-M2** (M2-1..M2-9, the supersession of M1a-3's `finding_opened` proxy stated
      inside that section, the N-M2a..N-M2j step table, the closed-questions table, honest limits).
      The EDR is **append-only**: no earlier section and no status line is amended. Plus `design.md`
      ("Acceptance as documented — Revision 3 (N-M2)") and `proposal.md` (owner decisions 1–6 plus
      the shape decisions that leave nothing to an implementer). Gates: `make check` green, proving
      no code drift from a documentation-only change.
- [ ] 6.1 **N-M2a** (`themis`; no API, no schema) — Knowledge publishes
      `knowledge.release_correlation_completed.v1` **once per SBOM**, appended to the outbox AFTER
      every other Knowledge event for that SBOM, carrying the discovery cause. Test:
      `TestEventSchema_Knowledge_ReleaseCorrelationCompletedV1` (`internal/knowledge/adapters/store`)
      — schema, the ordering proof (its `seq` exceeds every other event for that SBOM), and the
      zero-match case.
- [ ] 6.2 **N-M2b** (`themis`; no API, no schema) — Governance consumes it and publishes
      `governance.release_evaluated.v1`: snake_case `product_id` / `project_id` / `release_id` /
      `sbom_id`, integer `severity_counts {critical, high, medium, low}` off M1b-5's `base_score`
      ladder, `cause` mapped verbatim. Test:
      `TestReleaseEvaluatedEvent_ZeroCounts_AndCauseMapping` — zero counts emitted as the success
      case, both causes mapped, no third cause accepted.
- [ ] 6.3 **N-M2c** (`themis`; no API, no schema) — Communication switches triggers: retire the
      `governance.finding_opened` → ticket mapping (M1a-3's proxy) and create a ticket intent only on
      `governance.release_evaluated` with `cause=new_sbom`, product and project now populated. This
      is what finally realizes RC-2's one-ticket-per-Release, because one Release evaluation is one
      event and dedup is per origin event id (M1a-2). Tests:
      `TestReleaseEvaluatedMapping_OnlyNewSBOM_CreatesIntents` and
      `TestFindingOpenedAndRediscovery_CreateNoIntents`
      (`internal/communication/adapters/inbound`).
- [ ] 6.4 **N-M2d** (`themis`; **API CHANGE + SCHEMA CHANGE**) — Governance table
      `release_evaluated_events` (migration **up/down**, reversibility a gate) and the cursor read
      API `GET /api/v1/governance/events/release-evaluated?after=<sequence>&limit=<n>` in
      `api/governance.openapi.yaml` (spec-first, `make generate-api-governance`). Cursor is the
      **sequence**; `limit` default **100**, max **500** (clamped, not refused); response
      `items: [{seq, event_id, name, occurred_at, body}]` with the next cursor being the last item's
      `seq`; `X-API-Key` **read** scope; standard error mapping. Tests:
      `TestReleaseEvaluatedEventsCursorRead_AfterLimit_AuthMatrix` (handler table test: auth matrix,
      paging bounds, clamped limit, empty page) + migration up/down reversibility. Coverage: register
      the store/handler packages in `scripts/check-coverage.sh` if new.
- [ ] 6.5 **N-M2e** (`themis`; no API, no schema) — the comparison baseline: select the
      **immediately-previous SBOM of the Release by upload order** and detect closure of the targeted
      set. Tests: `TestSelectPreviousSBOM_ByUploadOrder` and
      `TestTargetedSetClosure_DoesNotGrowMidLoop`.
- [ ] 6.6 **N-M2f** (`themis`; no API, no schema) — Jira update and mail emitted **after the
      comparison only**, never from the callback. Tests (worker level):
      `TestPostEvaluationOnly_ProducesTicketAndMail` and `TestCallbackAlone_NoSideEffects`; the
      ticket update stays a full-replace and therefore idempotent (M1b-4).
- [ ] 6.7 **N-M2g** (`themis`; no API; **widens the intent-type CHECK constraint** to admit
      `ci_rebuild` — a constraint migration, up/down) — the `ci_rebuild` kind, the Jenkins
      `buildWithParameters` sender (Basic auth, user + API token,
      `THEMIS_COMMUNICATION_JENKINS_{ENABLED,URL,USER,API_TOKEN,JOB}`, off by default and subordinate
      to `..._DELIVERY_ENABLED`), **`https` enforced at configure time** with the loopback exception
      and the fake kept + ERROR naming the variable (M1b-1/M1b-2), and
      `THEMIS_COMMUNICATION_REBUILD_MAX_ATTEMPTS` (default 2). Tests:
      `TestCIBuildSender_BasicAuth_Params_HTTPSRefusal` (`httptest`: parameters, Basic auth header,
      `http://` refused), config defaulting/override for the knob, and the per-call timeout
      (M1b-6a). `deploy/node.env.example` gains the six commented, valueless knobs (R2).
- [ ] 6.8 **N-M2h** (`themis`; **API CHANGE**) — `POST /api/v1/communication/callbacks/ci-rebuild`
      in `api/communication.openapi.yaml` (spec-first), **`delivery:callback` only**, payload
      `{intent_id, build_id, git_ref, image_digest, sbom_id}` schema-enforced with `image_digest` and
      `sbom_id` required. Recorded as governed-external evidence **on the intent**. Tests:
      `TestCIRebuildCallback_AuthAndBodySchema` (every other scope refused, missing members refused)
      and `TestCallback_NoFindingMutation`.
- [ ] 6.9 **N-M2i** (`themis`; no API, no schema) — stop conditions: success (targeted set closed)
      and exhaustion (stop + mail + Jira update telling a person); **no further `ci_rebuild` intent
      after a stop**; **no Finding is ever auto-resolved**. Tests:
      `TestStopOnSuccessOrExhaustion_NoFurtherIntents` and `TestNotifyPersonOnExhaustion` (ticket and
      mail wording).
- [ ] 6.10 **N-M2j** (`themis-ai-runtime`; no API, no schema) — the harness poller: poll with
      `after=<sequence>` and `limit`, at-least-once, dedupe by **event id**, filter
      `cause=new_sbom`, persist a local high-water mark. Subscribes only — no Jira, no CI, no mail.
      Test: `TestHarnessPoller_PollingWithCursor_AtLeastOnce_DedupeAndFilterNewSBOM` (`httptest`
      Governance stub: paging, a redelivered page proving dedupe is harmless, a `rediscovery` event
      ignored).
- [ ] 6.11 Gates for each build step: `make check` green, and `make vet-tags` as the last act of the
      group (a tagged caller of a changed seam is invisible otherwise).
