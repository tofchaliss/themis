# Themis v0.4.0 — the greenfield bounded-context platform (first release)

Release tag: `v0.4.0` — the **first release of the Phase-3 greenfield rebuild**: Themis re-architected from
the single v0.3.x monolith into independently-deployable **bounded-context services** that collaborate over a
Postgres event bus and read-only HTTP APIs. This is a new go-forward line; the v0.3.x monolith is **frozen and
reference-only** (its last tag is `v0.3.11`).

Validated **end-to-end on a live deployment** before tagging — a real SBOM driven from registration through
correlation, enrichment, governed VEX suppression, blast-radius scoring, and an AI recommendation.

## The architecture

Six services, each its own binary (`cmd/<context>`), its own database, and inward-only Clean-Architecture
rings (`domain ← app ← adapters`). Contexts collaborate **only** via domain events (transactional outbox →
relay → a dedicated `bus` database) and read-only HTTP read APIs — **no cross-context imports, no shared
tables** (enforced by `go-cleanarch`, an architecture test, and import guards).

**Pipeline:** Kernel/Registry → Evidence → Knowledge → Governance → Communication, with the **Intelligence**
AI gateway beside it.

- **Kernel / Registry** — shared value objects + Product→Project→Release identity, plus the enterprise
  **estate graph** (Product→Microservice→Deployment→Customer) and a `GET /releases/{id}/blast-radius`
  traversal (C1).
- **Evidence** — immutable, content-addressed SBOM/VEX intake (CycloneDX/SPDX in) + canonical inventory.
- **Knowledge** — the **Faultline** aggregate (one enterprise card per canonical CVE), order-independent
  reconciliation by source precedence, feed ACLs, and component→CVE correlation.
- **Governance** — **Findings** + append-only **Enterprise Positions** (AI proposes, humans/policy decide;
  never auto-decide), with a release-scoped blast-radius priority.
- **Communication** — deterministic Publication materialization + a serializer registry (OpenVEX,
  CycloneDX-VEX, CSAF, markdown, JSON, text out).
- **Intelligence** — a reactive AI gateway (`recommend_position` over Ollama); advisory-only, disable-able,
  never auto-decides; all provider/LLM code confined behind a provider port.

## Capabilities in this release

- **SBOM → correlation → Finding → Position → published VEX**, the whole pipeline over the event bus.
- **Correlation:** OSV query-by-package (language + distro) always on. Distro advisories for
  **RHEL / Rocky / Alma** correlate via OSV's `upstream` CVEs. Opt-in, relevance-bounded feeds (never a
  full-feed mirror): **NVD** (authoritative CVSS), **EPSS / KEV / ExploitDB** (exploit signals), **Red Hat**
  (vendor severity + `not_affected` + RPM fixed builds), and a **generic CSAF-VEX** feed.
- **Governed vendor-VEX suppression (EDR-VEX-01):** an uploaded or fed `not_affected` statement raises a
  **system Proposal** on the covered Finding that policy auto-accepts or a human decides — it never
  auto-suppresses ("Gathering Is Not Knowing"). Package-precise matching prevents over-suppression.
- **RPM stream-scoped fixed verdict:** a `pkg:rpm/…` component at/above its same-EL-stream fix records no
  match — version-aware, so an already-patched build opens no Finding while an unpatched one still does.
- **Enterprise estate + blast radius (C1/C2):** triage priority is `base_score × blast_multiplier`, the
  multiplier derived from the unique customers a release reaches (fail-safe to 1.0× when Registry is
  unreachable; saturation cap configurable via `THEMIS_BLAST_RADIUS_CAP`).
- **Inbound-edge API-key auth (EDR-SECURITY-01):** per-node `X-API-Key` with `admin`/`read` scopes; a
  production guard (`THEMIS_AUTH_REQUIRED=1`) so a node can never boot open.
- **Standards-only formats:** CycloneDX / SPDX in; CycloneDX-VEX / OpenVEX / CSAF out.

## Live validation (pre-tag)

A from-scratch deployment validated: CVE capture end-to-end, API-key auth (401/200), Red Hat + EPSS/KEV
enrichment (idempotent, convergent), governed VEX suppression (proposal → human accept → suppressed),
blast-radius amplification (×1.2), distro rpm correlation (RHEL/Rocky/Alma via `upstream`), the RPM
fixed-verdict discrimination (a fixed build drops the patched CVEs and keeps the unpatched one), and the AI
recommend path (advisory, honest-insufficient invariants intact).

## What's next — v0.4.x (AI-capability expansion)

- **GOV-14 (EDR-GOVERNANCE-01 D14):** a disposition-aware `residual_priority` on the posture, plus a
  deterministic **disposition re-evaluation watcher** (KEV / EPSS-threshold / new exploit / reversing VEX →
  re-surface a suppressed or accepted Finding) — with an optional AI-judge upgrade. Decided in this release,
  implemented next.
- Further AI-gateway capabilities and LLMOps (weight tuning, richer grounding), and the remaining
  monolith→greenfield parity items tracked in `docs/engineering/PARITY-GAP.md` / `docs/BACKLOG.md`.

## Running it

See [`INSTALLATION.md`](../../INSTALLATION.md) Part A for the operator runbook (install Postgres → create the
six databases → `go build -o bin/ ./cmd/...` → run each node → drive an SBOM). `TESTING.md` covers exercising
a running system, including the vendor-VEX and AI flows.

> The v0.3.x monolith (`cmd/themis`) remains in-tree, **frozen and reference-only** — do not build on it.
