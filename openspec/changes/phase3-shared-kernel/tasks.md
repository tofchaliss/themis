# Tasks — phase3-shared-kernel (Shared Kernel, M2)

> Scope: the M2 Shared Kernel per `proposal.md` / `design.md`; all decisions trace to
> `docs/engineering/decisions/EDR-KERNEL-01.md` (D1–D4). Each group ends with the six Themis gates
> (`make check`), extended to `internal/kernel/` + `internal/registry/`. Task IDs map to the EDR issue
> table (KERN-01…06). Build this change **before** `phase3-evidence`.

## 1. Kernel scaffold + admission enforcement (KERN-01 · D3)

- [x] 1.1 Create `internal/kernel/{value,id,event}` with a `doc.go` stating the 4-part admission rule.
- [x] 1.2 Architecture test + depguard: `internal/kernel/` imports nothing from any context or from
  `registry/` (it is the leaf); everyone may import it. — `TestKernelIsLeaf` + `kernel-{value,id,event}`
  depguard rules.
- [x] 1.3 Gate: build green; clean-architecture check green.

## 2. Universal value objects + base primitives (KERN-02, KERN-03 · D3)

- [x] 2.1 Value objects: `CVEID` (canonical/normalized — port the PoC `NormalizeCVEID` semantics),
  `PURL`, `ContentFingerprint` (SHA-256), `CVSS` (score + vector), `Severity`; construction + validation.
  — `PURL`/`ContentFingerprint` pre-existed from Evidence; added `CVEID`, `CVSS`, `Severity`.
- [x] 2.2 Base primitives: typed-ID / UUID helper, `Clock`. — `internal/kernel/id` (`New`, `Clock`,
  `SystemClock`).
- [x] 2.3 Unit tests: validation, equality, normalization, round-trips.
- [x] 2.4 Gate: build + unit tests + coverage green (100% value + id); clean-architecture green.

## 3. Registry domain — Product/Project/Release (KERN-04 · D1)

- [x] 3.1 `registry/domain`: `Product`, `Project`, `Release` aggregates — identity + structure only
  (names, versions, membership); **no security state**.
- [x] 3.2 Invariants: every Project ∈ one Product; every Release ∈ one Project; stable identity.
- [x] 3.3 Unit tests for invariants. — 100% coverage.
- [x] 3.4 Gate: six Themis gates green. — build, lint, clean-arch (per-context loop + registry),
  arch-test (`TestRegistrySupportingContext`), coverage 100%.

## 4. Registry persistence + API (KERN-05 · D1)

- [x] 4.1 Migration: `products` / `projects` / `releases` tables (structure/identity only). — context-owned
  `internal/registry/adapters/store/migrations`; FKs enforce membership.
- [x] 4.2 `registry/app`: register + lookup use cases; `ReleaseExists(releaseID)` query backing Evidence
  `SubjectRef`. — 100% coverage.
- [x] 4.3 `registry/adapters`: Postgres repository + HTTP (register/list/lookup); error-UX envelope. —
  spec-first oapi-codegen (`api/registry.openapi.yaml`, `make generate-api-registry`); Store implements the
  app Repository directly; `wiring` + `cmd/registry` composition root.
- [x] 4.4 Integration tests: register + lookup; `ReleaseExists` true/false; migration up/down. — plus FK
  membership + malformed-row branches; store 89.2% (80% DB-adapter tier), http 92.7%.
- [x] 4.5 Gate: six Themis gates green.

## 5. Integration-event envelope contract (KERN-06 · D4)

- [x] 5.1 `internal/kernel/event`: envelope value shape (id, type, occurred-at, source context,
  subject/aggregate ref, payload schema ref, correlation-id) + JSON schema. — `Envelope` + `NewEnvelope`
  validation + embedded `envelope.schema.json` (Draft 2020-12) via `Schema()`.
- [x] 5.2 Unit tests: envelope construction + schema validation of golden fixtures. — 100%; golden fixtures
  validated with `jsonschema/v6` (valid thin + marshaled-envelope pass; missing/empty/additional-property
  fail).
- [x] 5.3 Note: the outbox runner + bus that *carry* envelopes are **Event Infrastructure (M5)**, seeded
  by `phase3-evidence` D7 — not in this change. — stated in `event/doc.go` + `kernel/doc.go`.
- [x] 5.4 Gate: six Themis gates green; `markdownlint-cli2` clean.
