# Tasks — phase3-evidence (Evidence bounded context)

> Scope: the Evidence context per `proposal.md` / `design.md`; all decisions trace to
> `docs/engineering/decisions/EDR-EVIDENCE-01.md` (D1–D9). Each group ends with the six Themis gates
> (`make check`), extended to `internal/evidence/`. Task IDs map to the EDR issue table (EVID-01…13).
> Depends on `phase3-shared-kernel` (SubjectRef → registry `ReleaseExists`).

## 1. Context scaffold + architecture enforcement (EVID-01 · D9)

- [x] 1.1 Create `internal/evidence/{domain,app,adapters}` with a `doc.go` per package stating the ring.
- [x] 1.2 Extend `go-cleanarch` + depguard: `domain` imports nothing; `app` imports `domain`; `adapters`
  import `app` + `domain`; no imports across bounded contexts. (per-context go-cleanarch via
  `GREENFIELD_CONTEXTS` loop + depguard ring/`no-cross-context` rules)
- [x] 1.3 Architecture test asserting the inward-only direction and the no-cross-context-imports rule.
  (`tests/architecture/architecture_test.go`, wired as `make arch-test` in `check`)
- [x] 1.4 Gate: build green; clean-architecture check green.

## 2. Evidence domain — aggregate, inventory, event (EVID-02, EVID-03 · D2/D3/D4/D5/D6)

- [x] 2.0 Minimal shared kernel value objects Evidence's domain depends on:
  `internal/kernel/value/{ContentFingerprint (SHA-256), PURL}` (final per EDR-KERNEL-01 D3; built here to
  avoid inline-and-refactor churn). depguard `kernel-stdlib-only`; 100% coverage.
- [x] 2.1 `Evidence` aggregate root: kind label, stable ID, byte-fingerprint identity, subject reference,
  provenance + trust value objects; immutability invariant (construct-once, no setters).
- [x] 2.2 Canonical component-inventory value object (components + dependency edges; defensive copies).
- [x] 2.3 `EvidenceRegistered` domain event — thin (id, kind, subject ref, fingerprint).
- [x] 2.4 Unit tests: immutability/copy-semantics, identity stability, fingerprint equality, all validation
  branches, event shape.
- [x] 2.5 Gate: build + unit tests + coverage (100%) green; lint/clean-arch/arch-test green; no deadcode.

## 3. Border adapters — parser + trust (EVID-04, EVID-05 · D4/D2)

- [x] 3.1 Parser ACL (`internal/evidence/adapters/parser`): CycloneDX + SPDX → canonical inventory;
  extensible registry (`NewRegistry`+`Option`); **standards only** (Trivy dropped — producer, not format).
- [x] 3.2 Unsupported format → helpful rejection (`*UnsupportedFormatError` carrying the supported list).
- [x] 3.3 Trust-gate (`internal/evidence/adapters/trust`): SHA-256 fingerprint (kernel `ContentFingerprint`),
  expected-checksum verify, well-formed-JSON validation, provenance capture. (Per-format JSON-schema
  validation left to the parser ACL; noted in package doc.)
- [x] 3.4 Golden-file tests (`testdata/{cyclonedx,spdx}.json`) + rejection/edge tests; purl-helper unit tests.
- [x] 3.5 Gate: build + lint + clean-arch + arch-test green; coverage 100%/100%; no deadcode.

## 4. Persistence — repository + outbox + relay (EVID-06, EVID-07 · D2/D3/D7)

- [x] 4.1 Migration in a **context-owned** dir (`internal/evidence/adapters/store/migrations/`, separate
  from the legacy tree — Book III §3.5): `evidence` (TEXT opaque id, UNIQUE fingerprint, raw BYTEA +
  canonical JSONB, provenance, subject ref, kind, filed_at) + `evidence_outbox`.
- [x] 4.2 Aggregate-root repository (`Store`): load/store whole Evidence; **fingerprint-idempotent** insert
  (`ON CONFLICT (fingerprint) DO NOTHING` → returns existing id, `Created=false`).
- [x] 4.3 Transactional outbox: Evidence record + `EvidenceRegistered` note in one local transaction.
- [x] 4.4 Outbox relay (`Relay.DeliverPending`): delivers unsent notes via a `Publisher` port (reusable M5
  seed), marks sent, increments attempts + retries on failure without aborting the batch.
- [x] 4.5 Read paths: `GetByID`, `GetInventory`, `ListByRelease` (separate read paths).
- [x] 4.6 Integration tests (embedded-postgres, Evidence-owned harness): concurrent duplicate → same id +
  one event; outbox fail-then-retry → exactly-once; migration down/up reversible; malformed-row read errors.
- [x] 4.7 Gate: build/lint/clean-arch/arch-test green; store coverage 84.2% (≥80% DB-adapter tier;
  error-branch fault-injection via an injectable pool interface is a documented follow-up). deadcode flags
  the store methods until Group 5 wires them (informational; exit 0).

## 5. Application — register + read use cases + subject-ref port (EVID-08, EVID-09, EVID-12 · D1/D5/D6/D8)

- [x] 5.1 Ports (`app/ports.go`): `Repository`, `Parser`, `TrustGate`, `SubjectRefValidator`, `IDGenerator`,
  `Clock` (domain-typed; outbox is internal to `Repository.Save`, not a separate port).
- [x] 5.2 `EvidenceService.Register`: validate subject → trust → parse → build aggregate → `Save`(+outbox);
  returns id + Created; rejects unknown subject (`ErrUnknownSubject`) + trust rejection (`ErrRejected`);
  idempotent via the store.
- [x] 5.3 `SubjectRefValidator` port + **stub adapter** (`adapters/subjectref`, allow-set; rejects unknown).
  The real registry `ReleaseExists` adapter + image-digest provenance wiring land with `phase3-shared-kernel`.
- [x] 5.4 Read use cases: `GetEvidence`, `GetInventory`, `ListByRelease`.
- [x] 5.5 Unit tests with fakes — happy SBOM, non-SBOM skips parser, and every failure branch.
- [x] 5.6 Gate: build/lint/clean-arch/arch-test green; app + subjectref coverage **100%**. (Concrete
  parser/trust/store → port bridges are wired in cmd in Group 6, which also clears the store deadcode.)

## 6. HTTP counter + dev-only purge (EVID-10, EVID-11 · D8)

- [x] 6.1 REST via **spec-first oapi-codegen** — `api/evidence.openapi.yaml`,
  `api/evidence.oapi-codegen.yaml`, `make generate-api-evidence` → `adapters/http/gen`; handler implements
  the generated `ServerInterface` (POST register / GET by-id / GET inventory / GET list).
- [x] 6.2 Problem error envelope + helpful rejections (unsupported-format carries `supported_formats`;
  unknown-subject / trust-rejection → 422; not-found → 404).
- [x] 6.3 Dev-only purge: `Store.Purge` + `DELETE /dev/evidence` **env-gated** in `cmd/evidence`
  (`THEMIS_EVIDENCE_DEV_PURGE=1`); off by default. Purge behavior integration-tested.
- [x] 6.4 Handler tests (httptest + in-memory fakes): register/idempotent/get/inventory/list, every
  rejection branch, and server-error paths — 95.7% coverage.
- [x] 6.5 Gate: build/lint/clean-arch/arch-test green; http 95.7% / store 84.5%. **`cmd/evidence` wiring
  (concrete adapters → app ports) cleared the store deadcode.**

## 7. Blueprints from the exemplar (EVID-13 · D9)

- [x] 7.1 `implementation-blueprint/01-repository-layout.md` — the context-first Evidence tree.
- [x] 7.2 `02-package-rules.md` + `03-dependency-rules.md` — the ring rules + 3-layer enforcement.
- [x] 7.3 `04-bounded-context-template.md` — `evidence/` as the reusable template (+ gotchas learned).
- [x] 7.4 `05-service-template.md` (`EvidenceService.Register`) + `06-event-template.md`
  (`EvidenceRegistered` + transactional outbox + relay).
- [x] 7.5 Gate: `markdownlint-cli2` clean (0 errors); blueprints cross-reference EDR-EVIDENCE-01.
