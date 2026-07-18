# Blueprint 04 — Bounded-Context Template

To add a context `X`, copy the Evidence shape (`internal/evidence/` + `cmd/evidence`):

1. Create `internal/X/{domain,app,adapters}/doc.go` stating each ring.
2. Register `X` in three enforcement points: the Makefile `GREENFIELD_CONTEXTS` var, the
   `tests/architecture` `boundedContexts` slice, and `.golangci.yml` depguard rules (`X-domain-inner`,
   `X-app-domain-only`, `X-no-cross-context`).
3. Register coverage: add `./internal/X/...` to `COVERAGE_PKGS` and each package in
   `scripts/check-coverage.sh` (domain/app → 100%; store → 80%; http → 90%).
4. Build inward-out: `domain` → `app` (ports + use cases) → `adapters` (store/http/…) → `cmd/X`
   composition root that bridges concrete adapters onto the ports.
5. Own your migrations under `internal/X/adapters/store/migrations/`.
6. Spec-first API: `api/X.openapi.yaml` + `api/X.oapi-codegen.yaml` + a `generate-api-X` Make target.

Gate **every task group** with the six Themis gates (`make check`): build, lint, clean-arch, arch-test,
coverage, deadcode. Realized reference: the entire `internal/evidence/` tree + `cmd/evidence`.

## Gotchas (learned building Evidence)

- pgx encodes `[]byte` as `bytea`; pass JSON to `jsonb` columns as `string(...)`.
- Aggregate ids are **opaque TEXT** columns (the domain does not mandate UUID; the app assigns them).
- depguard `allow`-lists do not block third-party imports (only `deny` rules do); `_test.go` is excluded
  from depguard. `make deadcode` is informational (exit 0); a store's methods read as unreachable until the
  `cmd/<ctx>` composition root wires them.
