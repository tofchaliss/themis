# Tasks — phase3-knowledge (Knowledge / Faultline bounded context)

> Scope: the Knowledge context per `proposal.md` / `design.md`; all decisions trace to
> `docs/engineering/decisions/EDR-KNOWLEDGE-01.md` (D1–D12). Each group ends with the six Themis gates
> (`make check`), extended to `internal/knowledge/`. Task IDs map to the EDR issue table (KNOW-01…13).
> Depends on `phase3-evidence` (`EvidenceRegistered` + `GetInventory`).

## 1. Context scaffold + architecture enforcement (KNOW-01 · D12)

- [x] 1.1 Create `internal/knowledge/{domain,app,adapters}` with a `doc.go` per package stating the ring.
- [x] 1.2 Extend `go-cleanarch` + depguard; architecture test asserting inward-only + no cross-context
  imports. — `knowledge` added to `boundedContexts` + `GREENFIELD_CONTEXTS`; `knowledge-{domain-inner,
  app-domain-only,no-cross-context}` depguard rules (deny evidence/governance/communication/intelligence).
- [x] 1.3 Gate: build green; clean-architecture check green.

## 2. Faultline domain — aggregate, Proposal, reconciliation, events (KNOW-02, KNOW-03, KNOW-04 · D1/D2/D6/D7/D8/D9)

- [x] 2.1 `Faultline` aggregate: own identity, CVE alias (via kernel `CVEID` normalization), append-only
  Proposals, materialized enterprise view, forward-only lifecycle ladder + invariants; optimistic version.
- [x] 2.2 `Proposal` value object + kinds (`vuln-facts` / `exploit-signal` / `applicability`) with typed
  payloads + defensive copies.
- [x] 2.3 Reconciliation / precedence rule (pure, deterministic) — source-precedence headline via a strict
  total-order comparator; sorted-union ranges/fixes; OR exploit signals; latest EPSS; held applicabilities.
  Order-independence proven by a `rapid` property test (which caught + fixed a real same-source tie bug).
- [x] 2.4 Knowledge events (`FaultlineCreated/Enriched/Matured/Superseded`, `ComponentMatched`) as
  completed facts, thin payloads.
- [x] 2.5 Unit tests: identity/alias, append-only, lifecycle transitions, precedence outcomes, event shape.
  — 100% coverage (incl. rapid order-independence property).
- [x] 2.6 Gate: build + unit tests + coverage green; clean-architecture green. — lint + arch-test + 100%.

## 3. Feed ACLs → common Proposal (KNOW-05 · D6)

- [x] 3.1 One ACL per feed (nvd/osv/redhat/epsskev/exploitdb/vexfeed) → common Proposal envelope, typed by
  kind; extensible registry; helpful rejection. — `internal/knowledge/adapters/feed`: `ACL` interface +
  `Registry` (`Translate(source, raw)`), `*UnsupportedSourceError`. nvd/osv/redhat→vuln-facts,
  epsskev/exploitdb→exploit-signal, vexfeed→applicability; CVE bound via kernel `NewCVEID` (folds distro
  aliases, OSV alias search).
- [x] 3.2 Golden-file tests per feed (dialect → Proposal). — `testdata/<feed>.json` + assertions; plus a
  helpful-rejection table (bad json / no CVE / bad time / bad CVSS / EPSS range / empty VEX).
- [x] 3.3 Gate: six Themis gates green. — build, lint, clean-arch, arch-test; feed 94.3% (90% infra tier —
  remaining lines are defensive constructor-error branches unreachable given sanitized inputs).

## 4. Fold-Proposal / Enrich + persistence + outbox (KNOW-06, KNOW-09 · D2/D8/D9)

- [x] 4.1 `app`: Fold-Proposal / Enrich use case — attach Proposal, reconcile view, advance lifecycle,
  publish on view-change via outbox; optimistic concurrency. — `FaultlineService.FoldProposal` with a
  retry-on-conflict loop; events carried as `OutboxNote`s (created + enriched-on-view-change). 100%.
- [x] 4.2 `adapters/store`: Postgres aggregate (card + append-only Proposals + view + lifecycle + version),
  with outbox; aggregate-root load/store. — `faultlines`/`faultline_proposals`/`knowledge_outbox`; codec for
  view + per-kind proposal payloads; optimistic UPDATE-WHERE-version; duplicate-CVE insert → ErrConcurrent;
  `Relay` + `Publisher`. (Projections deferred to G6.)
- [x] 4.3 Integration tests: concurrent enrich → converge (no lost update); view-change → exactly one
  event; migration up/down. — plus all-3-kinds codec round-trip, duplicate-create, malformed-row branches,
  relay retry. store 83.9% (80% tier).
- [x] 4.4 Gate: six Themis gates green.

## 5. Correlation + lazy discovery + coordinator (KNOW-07, KNOW-08, KNOW-12 · D3/D4/D5/D11)

- [x] 5.1 Correlation worker: on `EvidenceRegistered(SBOM)` read `GetInventory`, match components →
  Faultlines, emit `ComponentMatched` (idempotent). — `CorrelationService` + real `adapters/evidence`
  read-API HTTP client (the seam); `store.RecordMatch` inserts a `faultline_matches` row idempotently,
  advances the card to Correlated, and emits ComponentMatched in one tx.
- [x] 5.2 Lazy discovery: SBOM-time OSV query-by-package + scheduled NVD modified-since watch (+ watermark
  `knowledge_watch_state`) creating/enriching cards. — `PackageVulnSource` + `ChangedVulnSource` +
  `WatchState` ports + `WatchService.Poll`; the **feed-fetch HTTP clients are ports** (fakeable) awaiting
  real OSV/NVD adapters (follow-up; the ACLs from G3 do the translation).
- [x] 5.3 Non-owning coordinator sequencing new-SBOM → correlate → enrich → emit via app services only. —
  `Coordinator.OnEvidenceRegistered` (SBOM-only), calls services, owns nothing.
- [x] 5.4 Integration tests: SBOM → matches; watch discovers new cards; re-run idempotent. — correlate +
  watch app tests (fakes), Evidence client httptest, store RecordMatch idempotency + watch watermark.
- [x] 5.5 Gate: six Themis gates green. — app 100%, evidence client 95.2%, store 83.4%.

## 6. Read side + recovery (KNOW-10, KNOW-13, KNOW-11 · D10/D11)

- [x] 6.1 `app`: `GetFaultline` (view + provenance) from aggregate; disposable event-built projection
  (affected-releases). — `ReadService` (GetByID/GetByCVE + AffectedReleases over the `faultline_matches`
  projection).
- [x] 6.2 `adapters/http`: read API — GET faultline by id / CVE + rollup (releases); error-UX envelope. —
  spec-first oapi-codegen (`api/knowledge.openapi.yaml`, `make generate-api-knowledge`) + `wiring`; 97.6%.
- [x] 6.3 Recovery: idempotent re-run from durable inputs + first-class reconciler (state-based, no
  replay); crash/resume tests. — `ReconcileService` + `store.ReconcileStuckStages` (advances cards that
  have matches but never reached Correlated); crash-then-reconcile integration test.
- [x] 6.4 Gate: six Themis gates green; `markdownlint-cli2` clean.
