# Tasks — phase3-shared-kernel (Shared Kernel, M2)

> Scope: the M2 Shared Kernel per `proposal.md` / `design.md`; all decisions trace to
> `docs/engineering/decisions/EDR-KERNEL-01.md` (D1–D4). Each group ends with the six Themis gates
> (`make check`), extended to `internal/kernel/` + `internal/registry/`. Task IDs map to the EDR issue
> table (KERN-01…06). Build this change **before** `phase3-evidence`.

## 1. Kernel scaffold + admission enforcement (KERN-01 · D3)

- [ ] 1.1 Create `internal/kernel/{value,id,event}` with a `doc.go` stating the 4-part admission rule.
- [ ] 1.2 Architecture test + depguard: `internal/kernel/` imports nothing from any context or from
  `registry/` (it is the leaf); everyone may import it.
- [ ] 1.3 Gate: build green; clean-architecture check green.

## 2. Universal value objects + base primitives (KERN-02, KERN-03 · D3)

- [ ] 2.1 Value objects: `CVEID` (canonical/normalized — port the PoC `NormalizeCVEID` semantics),
  `PURL`, `ContentFingerprint` (SHA-256), `CVSS` (score + vector), `Severity`; construction + validation.
- [ ] 2.2 Base primitives: typed-ID / UUID helper, `Clock`.
- [ ] 2.3 Unit tests: validation, equality, normalization, round-trips.
- [ ] 2.4 Gate: build + unit tests + coverage green; clean-architecture green.

## 3. Registry domain — Product/Project/Release (KERN-04 · D1)

- [ ] 3.1 `registry/domain`: `Product`, `Project`, `Release` aggregates — identity + structure only
  (names, versions, membership); **no security state**.
- [ ] 3.2 Invariants: every Project ∈ one Product; every Release ∈ one Project; stable identity.
- [ ] 3.3 Unit tests for invariants.
- [ ] 3.4 Gate: six Themis gates green.

## 4. Registry persistence + API (KERN-05 · D1)

- [ ] 4.1 Migration: `products` / `projects` / `releases` tables (structure/identity only).
- [ ] 4.2 `registry/app`: register + lookup use cases; `ReleaseExists(releaseID)` query backing Evidence
  `SubjectRef`.
- [ ] 4.3 `registry/adapters`: Postgres repository + HTTP (register/list/lookup); error-UX envelope.
- [ ] 4.4 Integration tests: register + lookup; `ReleaseExists` true/false; migration up/down.
- [ ] 4.5 Gate: six Themis gates green.

## 5. Integration-event envelope contract (KERN-06 · D4)

- [ ] 5.1 `internal/kernel/event`: envelope value shape (id, type, occurred-at, source context,
  subject/aggregate ref, payload schema ref, correlation-id) + JSON schema.
- [ ] 5.2 Unit tests: envelope construction + schema validation of golden fixtures.
- [ ] 5.3 Note: the outbox runner + bus that *carry* envelopes are **Event Infrastructure (M5)**, seeded
  by `phase3-evidence` D7 — not in this change.
- [ ] 5.4 Gate: six Themis gates green; `markdownlint-cli2` clean.
