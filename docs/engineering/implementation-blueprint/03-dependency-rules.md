# Blueprint 03 — Dependency Rules & Enforcement

## The rules

- Dependencies point **inward only**: `adapters → app → domain`; `domain` depends on nothing but the
  standard library and `internal/kernel`.
- **No cross-context imports.** Contexts collaborate solely via **events + read APIs**, never by importing
  another context or sharing its database (Book III §3.5).
- The shared kernel (and a supporting registry) are the only shared foundations any context may import.

## Enforcement (three layers)

1. **go-cleanarch, per context** — `make clean-arch` runs, for each `GREENFIELD_CONTEXTS`,
   `go-cleanarch -domain domain -application app -interfaces adapters ./internal/<ctx>` (the legacy flat
   config cannot express the context-first layout, so each context tree is checked on its own).
2. **depguard** (`.golangci.yml`) — per-context rules: `<ctx>-domain-inner` (allow stdlib + kernel),
   `<ctx>-app-domain-only` (+ `<ctx>/domain`), and a `<ctx>-no-cross-context` **deny** listing the other
   contexts.
3. **Architecture test** (`tests/architecture/`, `make arch-test`, wired into `make check`) — loads each
   context's packages and asserts inward-only ring direction + no cross-context imports. Add a context to
   its `boundedContexts` slice.
