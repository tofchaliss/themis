# Tasks — phase3-trust-model (evidence trust, deterministic inference, capability surface)

> Scope: the cross-context trust model per `proposal.md` / `design.md`; every decision traces to
> **`docs/engineering/decisions/EDR-TRUST-01.md` (T1–T12)**. Each group ends green on **`make check-ci`**.
> **Group order is load-bearing** — it is the migration order that keeps `recommend_position` behaviourally
> identical throughout (design.md §Migration order). Do not reorder groups 6 and 7.

## 1. Trust vocabulary in the kernel (T2 · T3)

- [x] 1.1 `internal/kernel/value/trust.go`: `TrustClass` (`Observed` < `Asserted` < `Inferred`), `Valid()`,
  ordering, and a monotonic `Max(...)` that returns the highest-risk class. Stdlib-only. — named
  **`MaxTrust`**, not `Max`: every top-level func in this package names its concept (`ParseSeverity`,
  `CompareVersions`), and `value.Max(…)` would say nothing about trust at the call site. Two safety choices:
  the signature is `MaxTrust(first, rest...)` so an **empty** argument list is impossible — a variadic-only
  form would return the *most trusted* class for no evidence, the exact failure T3 exists to prevent — and an
  unrecognized class **ranks highest** and normalizes to `TrustInferred`, so a malformed value can never be
  mistaken for a trusted one.
- [x] 1.2 Document the criterion **on the type**: *derivable vs declared* — can this be re-derived, or must
  someone be believed? Include the SBOM and vendor-`not_affected` cases as the two calibrating examples. —
  both examples are on the type doc, with the "self-assertion is not observation" corollary.
- [x] 1.3 Property test (`rapid`): `Max` is commutative, associative, idempotent, and **never returns a
  lower class than any input** (monotonicity is the invariant the whole model rests on). —
  `trust_property_test.go`, five properties (the four above plus *always returns a valid class*), and the
  generator **includes malformed values** because that is where a silent downgrade would hide. Plus a
  worked unit test of the laundering case: one Inferred input among three Observed still yields Inferred.
- [x] 1.4 Register the package in `scripts/check-coverage.sh` (**kernel tier = 100%**). — **no change
  needed**: `kernel/value` is already registered in `domain_pkgs` at the 100% tier, and this adds a file to
  that existing package rather than a new one.
- [x] 1.5 Gate: `make check-ci` green. **No behaviour change** — this group is pure addition. — exit 0;
  `kernel/value` **100.0%** (`trust.go` 100% per-func); 51 packages over threshold. One lint fix on the way:
  staticcheck `QF1001` on a negated conjunction in the test.

## 2. Source → class mapping in Knowledge (T2)

- [x] 2.1 A single reviewable registry mapping each feed/source id to its `TrustClass`, per design.md's
  table. Adding a source must force answering one question: *reproducible, declared, or reasoned?* —
  `adapters/wiring/trust_sources.go`, beside `NewPrecedence` in the composition root: the domain owns the
  mechanism, the composition root owns the table (the same split `Precedence` already uses).
- [x] 2.2 `knowledge/domain`: `Proposal` exposes a **derived** `TrustClass()` from its existing `source` —
  **no new persisted field**, no migration. — realized as `domain.TrustPolicy.ClassOf(source)` rather than a
  method on `Proposal`: a Proposal should not know the global policy, and injecting the table matches
  `Precedence`. Confirmed **no migration** — the class is derived from the `source` already stored.
- [x] 2.3 An unknown source must **fail closed** to `Asserted` (never `Observed`) and be logged once. —
  fails closed to `Asserted`. **Not logged**: `domain` may not log (depguard, R1), and a runtime log is the
  wrong instrument anyway — an unclassified source is a config gap, so it is a **build failure** instead
  (`TestEveryKnownSourceIsClassified`). Asserted rather than Inferred is deliberate and documented: Inferred
  means "a model produced this", so labelling an unknown feed Inferred would be a lie that corrupts the
  vocabulary for the sake of a risk level.
- [x] 2.4 Reconciliation carries the class through to the enterprise view, using `Max` across contributing
  proposals (T3). — **per field-group, not per view**: `HeadlineTrust` (the winner's class — the headline is
  winner-take-all) · `RangeTrust` · `SignalTrust` (folded across contributors). A single view-level class
  would be **actively wrong**: one vendor VEX statement would drag the whole card down and bar a
  version-range verdict computed purely from Observed ranges — the group-6 rule. Unset groups stay empty,
  which is safe because `MaxTrust` reads an unset class as Inferred. Trust is now part of `equal()`, so a
  trust change correctly fires `FaultlineEnriched`.
- [x] 2.5 Unit tests incl. the calibration cases: OSV range → Observed; Red Hat `not_affected` → Asserted;
  an AI-sourced proposal → Inferred. — asserted twice: against a fixture (`trustpolicy_test.go`) and against
  the **table we actually ship** (`trust_sources_test.go`). Plus the test that justifies the whole
  field-group design: an Asserted applicability on a card does **not** contaminate Observed ranges.
- [x] 2.6 Gate: `make check-ci` green; `knowledge/domain` still 100%. — exit 0; `knowledge/domain` **100%**,
  `knowledge/app` **100%**. **Caught a real regression on the way:** the store's `viewDTO` has an explicit
  field list and silently dropped the three new fields, so the view decoded empty on every reload, was
  recomputed, and fired a duplicate `FaultlineEnriched` on **every** fold. `TestViewChangeEmitsOneEvent`
  caught it. Fixed in `adapters/store/codec.go`; jsonb, so backward-compatible with no migration.
  Three deferrals filed as **TRUST-1/2/3** in `docs/BACKLOG.md`.

## 3. Trust across the Knowledge → Governance seam (T3)

- [x] 3.1 Decide per event whether the class must ride the wire or is re-derivable downstream. Prefer
  re-derivation — it keeps the frozen v1 payloads untouched. — **the preference does not survive contact: it
  must ride the wire.** Re-deriving downstream would require Governance to hold a **second copy of the
  source→class policy**, and two copies of a trust policy will eventually disagree — worse than a wire
  change. Knowledge owns the table, so Knowledge ships the verdict. Applied to
  **`knowledge.faultline_enriched`** only; `component_matched` opens a Finding and raises no proposal, so it
  needs no class yet.
- [x] 3.2 Where it must ride: mint `<event>.v2.schema.json` + a new `schema_ref`. **Never edit a frozen v1
  schema.** Keep v1 readable for in-flight events. — **no v2 was minted, and that is the correct call.** The
  house pattern for additive fields is an **optional property on v1** with `required` unchanged and
  `omitempty` on the struct — used twice already, for `Score` (BUG-3) and `Applicabilities` (EDR-VEX-01 D5),
  whose schema comment states the intent: *"keeps the frozen v1 wire byte-identical (EVENTBUS D9 — additive,
  non-breaking)"*. Minting a v2 would have forced a `schema_ref` change nothing needs and broken consistency
  with those two. The v1 schema was **extended, not edited** — no existing constraint changed.
- [x] 3.3 Consumer tests drive the exact wire JSON for both versions. — both shapes covered on both sides.
  Knowledge: `TestIntegrationContractV1_FaultlineEnrichedTrustIsAdditive` asserts a trust-less card marshals
  **byte-identically** to the pre-change wire (keys absent) *and* a trust-bearing card still validates v1 —
  the two conditions that make "additive, not v2" legitimate. Plus
  `TestIntegrationContractV1_RejectsUnknownTrustClass` (the schema pins the vocabulary via `enum`, so a typo
  fails the contract instead of reaching Governance as an unrecognized string). Governance: DTO decode tests
  for both shapes, asserted on the **decode itself** — nothing consumes trust until group 4, so there is no
  Finding change to assert against yet.
- [x] 3.4 Gate: `make check-ci` + `make e2e-pipeline` green. — both exit 0. `knowledge/domain` 100%,
  `governance/app` 100%, `governance/adapters/inbound` 100%. **Filed TRUST-4:** the CVE-withdrawal path
  carries no class, and unset reads as `Inferred` — which would make group 4's constitutional bar block a
  policy auto-accept that works today. A live regression waiting; the site is marked in
  `coordinator.go` and it is a **must-do before group 4 consumes trust**.

## 4. Governance — the constitutional stage (T4 · T6)

- [ ] 4.1 `governance/domain`: a **pure, non-configurable** constitutional check evaluated **before**
  `PolicyRule`. Chiefly: a proposal whose class is `Inferred` is **never** auto-acceptable.
- [ ] 4.2 Wire it ahead of policy in the aggregate's decision path. A proposal failing stage 1 is ineligible
  for **any** automatic acceptance.
- [ ] 4.3 Stop branching on producer identity (T1): the `Proposer().Kind != ActorSystem` gate is replaced by
  the trust class. **Land 4.1–4.2 first** so the `Inferred` bar is never momentarily absent.
- [ ] 4.4 Regression test proving the laundering path is closed: a **deterministic** rule consuming
  AI-derived evidence yields an `Inferred` conclusion and is **not** auto-accepted — the case producer-based
  classification could not see.
- [ ] 4.5 Test that no policy configuration can enable auto-acceptance of `Inferred`.
- [ ] 4.6 Confirm outcomes stay **Accepted / Rejected**, with open (`StatusProposed`) as the absence of an
  automatic outcome. **No new status is added.**
- [ ] 4.7 Gate: `make check-ci` green; `governance/domain` + `app` 100%.

## 5. Reservations — derived, never stored (T12)

- [ ] 5.1 Derive a **Reservation** from a Position's immutable `PositionInputs` when its evidence included
  `Asserted` (or lower) facts. **No new column, no new state.**
- [ ] 5.2 Surface it in the read models — beside `stance` and `effective_priority` on the posture rollup, and
  on the Position in the read API. *Derived must not mean invisible; this is part of the decision.*
- [ ] 5.3 Test: an acceptance resting on a vendor `not_affected` surfaces a reservation naming the declarer;
  one resting only on Observed evidence surfaces none.
- [ ] 5.4 Test the lifting path: a later Position version resting on Observed evidence carries **no**
  reservation, with **no migration or backfill** — history simply shows it lift.
- [ ] 5.5 Gate: `make check-ci` green.

## 6. Deterministic Inference — add the version-range rule to the backend, prove equivalence (T5 · T11)

> **This group must be complete and green before Group 7.** A window with the rule in neither place is a
> window where a deterministic verdict silently disappears.

- [ ] 6.1 Implement the version-range rule as a stage **inside the context that owns its evidence**,
  alongside the existing `reactToApplicability` precedent. No new context, no new deployable.
- [ ] 6.2 **Precision requirement:** it must evaluate the **reconciled, backport-aware** range, not a feed's
  query-time filter. Add a distro-backport test — upstream flags the version, the distribution's build is not
  vulnerable — as the explicit guard.
- [ ] 6.3 A provable verdict raises a **system proposal** on the covered Finding, travelling the same road as
  the vendor-VEX suppression proposal. Its class is `Observed`, so policy may auto-accept it.
- [ ] 6.4 **Equivalence test:** the backend rule returns the *same* verdict as the Intelligence rule for the
  same inputs — table-driven, reusing the existing `domain/rule_test.go` cases as the oracle.
- [ ] 6.5 Prove the D13 repair: with AI **disabled**, the version-range verdict is still produced.
- [ ] 6.6 Gate: `make check-ci` + `make e2e-pipeline` green.

## 7. Remove the version-range rule from the AI runtime (T5)

- [ ] 7.1 Delete `intelligence/domain/rule.go` + its wiring; `recommend_position`'s plan becomes
  `[Knowledge → LLM]`.
- [ ] 7.2 Remove the now-unused `EngineRule` dispatch path and its kernel version-range import.
- [ ] 7.3 `demo_e2e_test.go` + `llm_e2e_test.go` stay green **unchanged in behaviour** — the semantic
  precedent still flips a recommendation.
- [ ] 7.4 `make deadcode` reports nothing orphaned.
- [ ] 7.5 Gate: `make check-ci` green.

## 8. Selection replaces the bare finding id (T9)

- [ ] 8.1 `intelligence/domain`: `Selection{Type, IDs}` with `SelectionType` ∈ {`finding`, `release`};
  `Capability` declares its supported type and **min/max cardinality** (which subsumes any fan-out limit).
- [ ] 8.2 `Gateway.Invoke(ctx, capabilityID, Selection, correlationID)`; a type or cardinality mismatch is a
  new `ReasonSelectionMismatch`, rejected **before** any projection or provider call.
- [ ] 8.3 Spec-first API change: `subject{type, ids}` in `InvokeRequest`, with **`finding_id` accepted as a
  deprecated alias** for one release. Regenerate; never hand-edit `gen/`.
- [ ] 8.4 Governance's `adapters/intelligence` client constructs the Selection; its `app` port is
  **unchanged**.
- [ ] 8.5 Tests: cardinality boundaries, type mismatch, the deprecated alias.
- [ ] 8.6 Gate: `make check-ci` green; `intelligence/domain` + `app` 100%.

## 9. Domain Projections; the runtime stops gathering (T10)

- [ ] 9.1 Recognize `ReleasePosture` as the first **Domain Projection**; document the naming rule (business
  view, never a consumer) beside it.
- [ ] 9.2 Add the projection(s) `recommend_position` needs, owned by the context owning the Selection Type,
  assembled **only** from events and read-only APIs. **Serve them before 9.3.**
- [ ] 9.3 Delete `intelligence/app/context.go` (`AssembleContext`) — closing backlog **G-AI-6**, the dead
  `NeedFinding`, with it. The runtime issues **no business reads**.
- [ ] 9.4 Implement the four rules: no orchestration · information-preserving shaping (nothing introduced
  that the projection did not contain) · full provenance · **Grounding Verification anchors to the received
  Domain Projection, never solely to a shaped view**.
- [ ] 9.5 Test that a shaped view cannot launder an invented identifier past Grounding Verification.
- [ ] 9.6 Replayability test: a capability runs end-to-end from a **recorded projection fixture**, no live
  database.
- [ ] 9.7 Gate: `make check-ci` + `make e2e-pipeline` green.

## 10. Capability classes and the verification split (T7 · T8)

- [ ] 10.1 `Capability` declares its **output class**: `Information` or `Decision`.
- [ ] 10.2 An **Information** capability returns an ephemeral response; **nothing is recorded**, and it never
  reaches Governance. Grounding Verification still applies — for Information it is the **only** gate.
- [ ] 10.3 A **Decision** capability's proposal is **Business-Verified** by Governance against current truth
  **before** it is recorded, and carries its trust class.
- [ ] 10.4 Arch/unit test asserting an Information Response has **no** path to enterprise truth.
- [ ] 10.5 `recommend_position` is registered as a `Decision` capability — behaviour unchanged.
- [ ] 10.6 Gate: `make check-ci` green.

## 11. Documentation + close-out

- [ ] 11.1 `TESTING.md`: how to exercise trust classes, the constitutional bar, and the projection fixtures.
- [ ] 11.2 `deploy/node.env.example` + `INSTALLATION.md` if any knob is added (R2 — self-documented config).
- [ ] 11.3 `PHASE3-STATUS.md` resume point; `PARITY-GAP.md` if any gap closes; **close `G-AI-6`** in
  `docs/BACKLOG.md`.
- [ ] 11.4 Record the answers to `EDR-TRUST-01`'s remaining open questions if implementation settles them.
- [ ] 11.5 Final gate: **`make check`** (whole repo, macOS) **and** `make check-ci`, plus `make e2e-pipeline`
  and `make e2e-evidence`.
- [ ] 11.6 Archive: `openspec archive phase3-trust-model --skip-specs -y` (phase3 changes carry no
  `specs/` deltas — "no deltas" is expected).
