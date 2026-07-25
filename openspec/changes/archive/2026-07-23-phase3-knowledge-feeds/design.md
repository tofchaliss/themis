# Design — phase3-knowledge-feeds (Knowledge feed layer)

## Source of truth

Engineering decisions live in **`docs/engineering/decisions/EDR-KNOWLEDGE-01.md`** (D5/D6 — feed-fetch +
scanner-report Proposals) and **EDR-EVIDENCE-01 D4** (scanner = producer, standards-only). The gaps this
change closes are documented in **`docs/current-changes/FEED-E2E-VERIFICATION.md`** and the **D-NVD-2** /
**D-FEED-2** defects in **`docs/current-changes/project-backlog.md`**. This document states layout, import
rules, seams, and gates only.

## Scope

Additive to the implemented **`phase3-knowledge`** (M7). The only domain-model touches are a `Reconcile`
precedence **extension** (CVSS v4.0) and a feed-registry `tier` **attribute**; everything else slots behind
the existing ports (`PackageVulnSource`, `ChangedVulnSource`, the feed ACL `Registry`). No new context.

## Layout

```text
internal/knowledge/
├── domain/reconcile.go        + CVSS v4.0 in the vuln-facts headline precedence (v3.1 -> v3.0 -> v4.0 -> v2)
├── adapters/feed/
│   ├── osv_client.go          real OSV query-by-package  (PackageVulnSource)
│   ├── nvd_client.go          real NVD modified-since watch (ChangedVulnSource) + watermark
│   ├── scanner.go             scanner-report ACL -> vuln-facts Proposals (EDR-KNOWLEDGE-01 D6)
│   └── registry.go            + per-feed tier metadata (openspec/intel-source-tiers.md)
└── app/ (or adapters)         tier-aware feed health + staleness
```

## Import rules (ADR-BCK-0037/0038/0039; Book III §3.5)

Unchanged from M7: `domain/` imports nothing; `app/` imports `domain/`; `adapters/` import `app/` +
`domain/`. **No cross-context imports** — Knowledge collaborates only via events + read APIs. HTTP/provider
specifics stay in `adapters/`. Enforced by `go-cleanarch` + depguard + the architecture test.

## Cross-context seams

- **Evidence (dependency):** the `scanner-report` Evidence kind (EDR-EVIDENCE-01) must be **registrable +
  readable** via Evidence's read API; Knowledge reads it like an SBOM inventory but routes it through the
  scanner ACL. If Evidence does not yet accept `scanner-report`, that Evidence task is a **prerequisite** for
  group 4.
- **Governance (unchanged):** scanner-derived matches still emit `ComponentMatched` → Findings; no new
  downstream contract.

## Stack

Canonical stack + rationale: **`docs/engineering/STACK.md`**. Feed-specific: OSV / NVD **HTTP clients**
behind the existing ports; **`jsonschema/v6`** for scanner-report validation; CVSS parsing **in-domain**
(pure, `rapid`-covered); feed-tier **config** per **R2** (self-documented); **OpenTelemetry** for tier-aware
feed health.

## Quality gates

The six Themis gates (`make check`) — build, unit tests, coverage, dead-code, integration, clean-arch —
extended to the new `internal/knowledge/` code. Markdown passes `markdownlint-cli2`.
