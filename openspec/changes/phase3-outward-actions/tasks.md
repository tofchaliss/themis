# Tasks — phase3-outward-actions

Source of truth: `docs/engineering/decisions/EDR-DELIVERY-01.md`.

`phase3-*` changes carry no `specs/` deltas (proposal/design/tasks + the EDR are the source of
truth), so `openspec validate` reporting "no deltas" is expected; archive with
`openspec archive phase3-outward-actions --skip-specs -y`.

## Group 1 — N-M0 explicit write-scope authorization (D1–D7) — **implemented 2026-09-30**

- [x] 1.1 `internal/platform/auth/auth.go`: `ScopeDeliveryCallback`, `KnownScope` (closed
      vocabulary), `Principal.HasScopeExact` (+ `HasScope` delegating to it), `HasScopePrefix`,
      `HasProductScope`, `IsDeliveryCallback`; `AuthorizeWrite` excludes the callback scope so
      minting it grants nothing in the other contexts. Tests: the helpers fold in no admin, and
      `KnownScope`'s accept/refuse lists.
- [x] 1.2 `internal/governance/adapters/registry/client.go`: `ProductOfRelease` — release →
      project → product over the existing read API, failing closed on a blank hop. Tests: both
      hops asserted, four refusal paths, transport + decode errors.
- [x] 1.3 `internal/governance/adapters/http/handler.go`: `ProductResolver` (declared at the
      consumer), `WithProductResolver`, `authorizeGovernanceWrite`, `productOfFinding`; guard in
      `RaiseProposal`, `AcceptProposal`, `RejectProposal`, `ResolveFinding`, `ReopenFinding`,
      `ArchiveFinding`, `RecommendPosition`, and in `harness.go` `CommissionFinding`,
      `WithdrawCommission`. `AuthorizeWrite` no longer authorizes any Governance write.
- [x] 1.4 `internal/governance/adapters/wiring/wiring.go`: one Registry client feeding both seams
      (fail-open blast radius, fail-closed product resolver); empty `THEMIS_REGISTRY_URL` ⇒ only
      `admin` may write.
- [x] 1.5 `cmd/authadmin`: `validScopes` against `auth.KnownScope` (refuses at mint time), usage
      documenting `delivery:callback` and `product:<id>`. Tests: parse, validate, usage text.
- [x] 1.6 `internal/governance/adapters/http/handler_auth_test.go`: the matrix (9 write routes × 5
      principals), nothing-recorded-on-refusal, callback-beside-admin, cross-product confinement,
      the three fail-closed cases, unknown-Finding 404, unknown-scope-authorizes-nothing.
      `harness_test.go`: `TestReadKeyCannotCommission` wires the product seam (the operator key is
      now confined, which is the point).
- [x] 1.7 `docs/engineering/decisions/EDR-DELIVERY-01.md` (N-M0 only; M1–M3 deliberately not
      pre-decided).
- [x] 1.8 Gates: `go build ./...`, `go test ./...`, `make vet-tags`, `make lint`,
      `make clean-arch`, `make arch-test`; coverage — `governance/adapters/http` 96.3%,
      `governance/adapters/registry` 92.9%, `platform/auth` 94.9% (all ≥90%). No package added, so
      `scripts/check-coverage.sh` needs no registration.

## Group 2 — M1 delivery — NOT STARTED

- [ ] 2.1 Awaiting the runtime-side grilling of the delivery milestone. `delivery:callback` exists
      and is refused on every Governance write; what it may DO is undecided.
- [ ] 2.2 Carried limit from N-M0 (EDR-DELIVERY-01 "Honest limits"): the Governance → Registry
      read seam sends no API key, so on an auth-enabled estate a `product:<id>` key cannot resolve
      its product and therefore cannot write. Giving the read seam a credential is a security-model
      change and belongs to the milestone that needs it.

## Group 3 — M2 CI — NOT STARTED

## Group 4 — M3 mail — NOT STARTED
