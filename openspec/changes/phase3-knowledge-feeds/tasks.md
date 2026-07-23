# Tasks — phase3-knowledge-feeds (Knowledge feed layer)

> Scope: make the Knowledge feed layer production-real + close the go-forward feed gaps, per `proposal.md` /
> `design.md`. **Additive** to the implemented `phase3-knowledge` (M7); decisions trace to
> `docs/engineering/decisions/EDR-KNOWLEDGE-01.md` (D5/D6) + EDR-EVIDENCE-01 D4, and close the go-forward
> equivalents of **D-NVD-2** / **D-FEED-2** (`docs/current-changes/project-backlog.md`). Each group ends with
> the six Themis gates (`make check`), extended to `internal/knowledge/`. Depends on `phase3-knowledge`
> (ports + ACL registry + `Reconcile`) and — for group 4 — Evidence accepting a `scanner-report` kind.

## 1. Real feed-fetch HTTP clients (PHASE3-BACKLOG §C · EDR-KNOWLEDGE-01 D5)

- [ ] 1.1 OSV **query-by-package** client implementing `PackageVulnSource` (SBOM-time lazy discovery) behind
  the existing port; feeds the M7 OSV ACL. Config-driven endpoint (R2).
- [ ] 1.2 NVD **modified-since** client implementing `ChangedVulnSource` (scheduled watch) + the
  `knowledge_watch_state` watermark; feeds the M7 NVD ACL. Rate-limit-aware (NVD 50/30s with a key).
- [ ] 1.3 Tests: httptest fixtures per client → discovered Proposals; watermark advance + resume; helpful
  rejection on malformed responses.
- [ ] 1.4 Gate: six Themis gates green.

## 2. CVSS v4.0 in the vuln-facts ACL + Reconcile (go-forward D-NVD-2 · D6/D2)

- [ ] 2.1 Parse **CVSS v4.0** — NVD `cvssMetricV40` (computed base score + severity) and OSV `CVSS:4.0`
  vectors — in the `vuln-facts` ACL, so a v4.0-only CVE is not dropped to score 0 / `unknown`.
- [ ] 2.2 Extend `Reconcile` headline precedence to **`v3.1 → v3.0 → v4.0 → v2`**, preferring **Primary**
  over **Secondary** within a version; order-independence preserved (the `rapid` property still holds).
- [ ] 2.3 Tests: a CVE scored **only** under v4.0 (fixture mirroring `CVE-2025-8869`) reconciles to a real
  severity/score; a CVE with **both** v3.1 + v4.0 keeps the v3.1 headline; rapid order-independence green.
- [ ] 2.4 Gate: six Themis gates green.

## 3. Source-tier taxonomy → tier-aware feed health (go-forward D-FEED-2 · BCK-0051)

- [ ] 3.1 Add a **tier** attribute to each feed in the ACL registry, sourced from
  `openspec/intel-source-tiers.md` (tier 1 critical … tier 4 planned); self-documented config (R2).
- [ ] 3.2 Make feed health + staleness **tier-aware**: a tier-1 feed failure escalates (stale + signal), a
  tier-3 "gold" feed failure stays informational — no longer one-size-fits-all "degraded".
- [ ] 3.3 Tests: tier-1 failure → stale/escalated; tier-3 failure → informational; all-healthy → no signal.
- [ ] 3.4 Gate: six Themis gates green.

## 4. Scanner reports as source Proposals (EDR-KNOWLEDGE-01 D5/D6 — the deferred item)

- [ ] 4.1 A **scanner-report ACL** translating a `scanner-report` Evidence kind (read via Evidence's read
  API) into `vuln-facts` Proposals (source = the scanner; **advisory** — CON-0002), reconciled by the same
  precedence as NVD/OSV/distro. Prereq: Evidence registers + serves the `scanner-report` kind.
- [ ] 4.2 Wire it into the correlation/fold path so a scanner report enriches cards + emits `ComponentMatched`
  like any other source; a scanner **never** sets truth (governed downstream).
- [ ] 4.3 Tests: a scanner report → advisory Proposals folded into the card; reconciliation grants the
  scanner **no special authority**; conflicting distro-authoritative data still wins by precedence.
- [ ] 4.4 Gate: six Themis gates green.

## 5. Seam e2e + docs

- [ ] 5.1 Per-context e2e: real feed clients (httptest) → discovered/enriched cards → CVSS-4.0 severity
  present → tier-aware health; scanner-report → advisory Proposal folded.
- [ ] 5.2 Update `PHASE3-STATUS.md` + `PHASE3-BACKLOG.md` (close the §C feed items) + `openspec/STATUS.md`;
  record the go-forward D-NVD-2 / D-FEED-2 resolutions.
- [ ] 5.3 Gate: six Themis gates green; `markdownlint-cli2` clean.
