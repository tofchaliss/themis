# Blueprint 02 — Package Rules (the three rings)

Every context has three rings; each package states its ring in a `doc.go`.

## `domain/` — the pure core

- Aggregate roots, value objects, domain events, invariants. Aggregates are **immutable**
  (construct-once, no setters; defensive copies for slices).
- Imports **nothing** but the standard library and `internal/kernel`.
- Exemplar: `evidence/domain` — the `Evidence` aggregate, `Inventory`, `EvidenceRegistered`.

## `app/` — the use cases + ports

- Application services orchestrating the domain, plus **ports** (interfaces) the adapters implement, typed
  in domain/kernel terms.
- Imports `domain` (+ kernel + stdlib) only. **Never** imports adapters.
- Exemplar: `evidence/app` — `EvidenceService.Register` and the `Repository` / `Parser` / `TrustGate` /
  `SubjectRefValidator` / `IDGenerator` / `Clock` ports.

## `adapters/` — the plumbing

- Implement the app ports (store, parser, trust, http, …). May import `app` + `domain` + kernel + any
  third-party library.
- Never imported by domain or app; never import another bounded context.
- The composition root (`cmd/<context>`) bridges concrete adapters onto the app ports.
