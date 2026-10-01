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

## Group 2 — M1 delivery — NOT STARTED

- [ ] 2.1 Awaiting the runtime-side grilling of the delivery milestone. `delivery:callback` exists
      and is refused on every Governance write; what it may DO is undecided.
- [ ] 2.2 Carried limit from N-M0 (EDR-DELIVERY-01 "Honest limits"): the Governance → Registry
      read seam sends no API key, so on an auth-enabled estate a `product:<id>` key cannot resolve
      its product and therefore cannot write. Giving the read seam a credential is a security-model
      change and belongs to the milestone that needs it.

## Group 3 — M2 CI — NOT STARTED

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
- [ ] 5.5 Dedicated EDR + API change for the Themis→harness notification seam before any
      implementation: event name(s), at-least-once semantics, transport, subscriber
      authentication, owning context (Communication or Governance). Class 4 — owner approval first.
- [ ] 5.6 Fix the configuration locus and name of the max-attempts knob, and whether per-Release
      overrides are supported.
- [ ] 5.7 Confirm the comparison baseline: strictly the immediately-previous SBOM id for the
      Release, or a configured baseline window.
