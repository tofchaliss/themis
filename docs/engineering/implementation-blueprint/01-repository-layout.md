# Blueprint 01 — Repository Layout

The Phase-3 greenfield is **context-first**: each bounded context is a self-contained tree under
`internal/<context>/`, beside a shared value kernel and a per-context entrypoint. Realized exemplar: the
**Evidence** context.

## Layout

```text
internal/
├── kernel/
│   └── value/            behavior-free shared value objects (ContentFingerprint, PURL, …)
├── evidence/             a bounded context — copy this shape per context
│   ├── domain/           pure core: aggregate, value objects, events, invariants
│   ├── app/              use cases + ports (interfaces the adapters implement)
│   └── adapters/
│       ├── parser/       border ACL (CycloneDX/SPDX → canonical inventory)
│       ├── trust/        trust gate (fingerprint + validate)
│       ├── store/        Postgres aggregate repo + outbox relay
│       │   └── migrations/   context-owned migrations (golang-migrate)
│       ├── subjectref/   stub for a cross-context read (until the owning context lands)
│       └── http/         REST adapter
│           └── gen/      oapi-codegen output
cmd/
└── evidence/             composition root: bridges adapters → ports; serves HTTP + relay loop
api/
├── evidence.openapi.yaml         spec-first API contract
└── evidence.oapi-codegen.yaml    codegen config
tests/
└── architecture/         module-wide arch test (ring direction + no cross-context imports)
```

## Rules

- One Go module; each context is a top-level folder under `internal/`.
- Each context **owns its own migrations** (`adapters/store/migrations/`), never the top-level
  `migrations/` (Book III §3.5).
- Each context is **independently deployable** via its own `cmd/<context>` entrypoint.
- The value kernel (`internal/kernel`) is the only shared code a context's domain may import.
