# Tasks — phase3-evidence (Evidence bounded context)

> Scope: the Evidence context per `proposal.md` / `design.md`; all decisions trace to
> `docs/engineering/decisions/EDR-EVIDENCE-01.md` (D1–D9). Each group ends with the six Themis gates
> (`make check`), extended to `internal/evidence/`. Task IDs map to the EDR issue table (EVID-01…13).

## 1. Context scaffold + architecture enforcement (EVID-01 · D9)

- [ ] 1.1 Create `internal/evidence/{domain,app,adapters}` with a `doc.go` per package stating the ring.
- [ ] 1.2 Extend `go-cleanarch` + depguard: `domain` imports nothing; `app` imports `domain`; `adapters`
  import `app` + `domain`; no imports across bounded contexts.
- [ ] 1.3 Architecture test (in `docs/engineering/architecture-tests` / test package) asserting the
  inward-only direction and the no-cross-context-imports rule.
- [ ] 1.4 Gate: build green; clean-architecture check green.

## 2. Evidence domain — aggregate, inventory, event (EVID-02, EVID-03 · D2/D3/D4/D5/D6)

- [ ] 2.1 `Evidence` aggregate root: kind label, stable ID, byte-fingerprint identity, subject reference,
  provenance + trust value objects; immutability invariant (construct-once, no setters).
- [ ] 2.2 Canonical component-inventory value object (components + dependency edges).
- [ ] 2.3 `EvidenceRegistered` domain event — thin (id, kind, subject ref, fingerprint).
- [ ] 2.4 Unit tests: immutability, identity stability, fingerprint equality, event shape.
- [ ] 2.5 Gate: build + unit tests + coverage green; clean-architecture green.

## 3. Border adapters — parser + trust (EVID-04, EVID-05 · D4/D2)

- [ ] 3.1 Parser ACL: CycloneDX + SPDX → canonical inventory; extensible registry; **standards only**.
- [ ] 3.2 Unsupported format → helpful rejection (error-UX envelope with hint).
- [ ] 3.3 Trust-gate: SHA-256 fingerprint, schema validation, signature/provenance capture.
- [ ] 3.4 Golden-file tests (CycloneDX + SPDX fixtures) + rejection tests.
- [ ] 3.5 Gate: six Themis gates green.

## 4. Persistence — repository + outbox + relay (EVID-06, EVID-07 · D2/D3/D7)

- [ ] 4.1 Migration: `evidence` table (unique fingerprint, raw + canonical JSONB, provenance, subject
  ref, kind, filed_at) + `evidence_outbox` table.
- [ ] 4.2 Aggregate-root repository: load/store whole Evidence; idempotent insert returns the existing ID
  on fingerprint clash (optimistic concurrency).
- [ ] 4.3 Transactional outbox: write Evidence record + outbox note in one local transaction.
- [ ] 4.4 Outbox relay: background sender delivers un-sent notes, marks done, retries on failure.
- [ ] 4.5 Read views: canonical inventory + list-by-software (separate read paths).
- [ ] 4.6 Integration tests: concurrent duplicate upload → same ID; outbox crash/retry →
  exactly-once-eventually; migration up/down reversible.
- [ ] 4.7 Gate: six Themis gates green.

## 5. Application — register + read use cases + subject-ref port (EVID-08, EVID-09, EVID-12 · D1/D5/D6/D8)

- [ ] 5.1 Ports: `Repository`, `Parser`, `TrustGate`, `Outbox`, `SubjectRefValidator`.
- [ ] 5.2 `RegisterEvidence` use case: trust → parse → store (+ outbox) in one transaction; return ID;
  reject unknown subject; idempotent replay.
- [ ] 5.3 `SubjectRef` validation port + stub adapter (rejects unknown; forward-linked to Shared Kernel
  M2).
- [ ] 5.4 Read use cases: `GetEvidence`, `GetInventory`, `ListBySoftware`.
- [ ] 5.5 Unit tests (use cases with fakes).
- [ ] 5.6 Gate: six Themis gates green.

## 6. HTTP counter + dev-only purge (EVID-10, EVID-11 · D8)

- [ ] 6.1 REST: `POST` register (returns ID), `GET` by-id (facts), `GET` inventory, `GET` list; OpenAPI
  schema + `make generate-api`.
- [ ] 6.2 Error-UX envelope + helpful rejection messages.
- [ ] 6.3 Dev-only purge: environment/build-gated; disabled in production; guard test.
- [ ] 6.4 Handler tests (register, get, list, rejection, purge gating).
- [ ] 6.5 Gate: six Themis gates green.

## 7. Blueprints from the exemplar (EVID-13 · D9)

- [ ] 7.1 `implementation-blueprint/01-repository-layout.md` — the Evidence tree.
- [ ] 7.2 `02-package-rules.md` + `03-dependency-rules.md` — the ring rules.
- [ ] 7.3 `04-bounded-context-template.md` — `evidence/` as the reusable template.
- [ ] 7.4 `05-service-template.md` (`RegisterEvidence`) + `06-event-template.md` (`EvidenceRegistered` +
  outbox).
- [ ] 7.5 Gate: `markdownlint-cli2` clean; blueprints cross-referenced from EDR-EVIDENCE-01.
