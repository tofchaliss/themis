# Monolith → Greenfield — Capability Parity Gap

**Updated:** 2026-07-31 (full two-tree code audit). Tracks which v0.3.x monolith capabilities have (and have
not) carried over to the Phase-3 greenfield rebuild. The monolith (`internal/{domain,usecase,adapter,
infrastructure}`, `cmd/themis`) is **frozen/reference-only**; this is the go-forward closure list. Companion
to [`PHASE3-STATUS.md`](PHASE3-STATUS.md) (status) and [`../BACKLOG.md`](../BACKLOG.md) (open work).

## How to read this

Each gap has a stable **ID** (e.g. `A2`, `F1`) so we can reference it in discussion, a **severity**
(HIGH / MED / LOW), and a **status**:

- 🆕 **new** — found in the 2026-07-31 audit; was not in this doc before.
- 📋 **tracked** — already recorded here (or in BACKLOG §C) and confirmed accurate.
- ⚠️ **understated** — was in this doc, but the audit shows the gap is deeper than the one-line entry implied.
- 🎨 **by-design** — a deliberate architectural divergence, not a defect; listed so nobody re-discovers it as a
  "bug." May still deserve a compensating capability.

**Correction to the previous version of this doc.** The prior "§A Correlation & enrichment — ✅ CLOSED" was
accurate *for the specific features shipped in PRs #60–#63* (NVD modified-since watch, EPSS/KEV/ExploitDB
sweep, distro-via-OSV correlation, CVE-intrinsic priority+score). The full audit shows that cluster has
**depth gaps** (the ported version-range engine is not wired into the correlation path; NVD only *enriches*,
never *matches*) and that **whole adjacent subsystems remain missing** (feed-health, Red Hat VEX engine,
vendor-VEX crawler). "Closed" was too strong; the shipped slice is real, the cluster is not done.

---

## Progress since this audit (2026-07-31)

Nine PRs (all off `main`, CI-green, awaiting merge; see [`PHASE3-STATUS.md`](PHASE3-STATUS.md) for per-PR
detail) closed or advanced these gaps. The tables below keep the original audit findings unchanged; the rows
named here are now addressed in-flight.

| Gap(s) | PR | What landed |
| --- | --- | --- |
| **F1 / F2 / F3** | #65 | inbound `X-API-Key` auth + method-based scopes + HMAC webhook seam + `cmd/authadmin` (opt-in via `THEMIS_AUTH_DATABASE_DSN`) |
| **B1** | #66 | feed-health wired end-to-end (`feed_health` store + `GET /feeds` with `signals_stale` / `degraded_feeds`) |
| **A1** | #68 | reconciled version-range gate wired into correlation (realizes EDR-KNOWLEDGE-01 D3) |
| **A2** | #69 (stacked on #68) | NVD as a bounded, opt-in discovery source (keyword + CPE-product + version triple-gate) |
| **C6** | #71 | Knowledge base score threaded to the Governance Finding |
| **C1** | #71 | Registry estate graph (Product→Microservice→Deployment→Customer) + `GET /releases/{id}/blast-radius` |
| **C2** | #71 | blast multiplier on Finding priority (`base × 1.0–2.0×`; fail-safe 1.0×) |
| **VEX-ingest (→ B3/B4)** | #73 | uploaded OpenVEX → applicability Proposals on the card (EDR-VEX-01 **Phase 1**) |
| **VEX-suppress (Phase 2)** | (local) | applicability carried on `FaultlineEnriched` (v1-additive) → Governance raises a **system `not_affected` Proposal** on the covered Findings (policy/human accepts → suppressed). EDR-VEX-01 **Phase 2 DONE** 2026-08-01. Red Hat/generic **feeds = Phase 3** (B3/B4, open) |

Also shipped: a deterministic no-AI **SBOM→VEX CI gate** (#67, now a PR gate) and four decision records
(`EDR-SECURITY-01`, `EDR-ESTATE-01`, `EDR-VEX-01`, + realization notes on `EDR-KNOWLEDGE-01`). **Remaining
tail:** A3–A6, B2/B5/B6, C3–C5, the D-series notifications, E1–E11 input-integrity, F5/F7/F8 observability
(F4 metrics and F6 traces closed 2026-08-06/07).

## A. Correlation & version matching

The version-range engine **was ported** (`internal/kernel/value/versionrange.go` — a faithful copy of the
monolith's `version_engine.go` + `version_match.go`, rpm/apk/generic classes, `rpmvercmp`, epoch, 3-state
verdict) — but it is wired **only into the Intelligence advisory rule** (`intelligence/domain/rule.go`), not
into Knowledge correlation. `knowledge/app/correlate.go` does no local version matching at all; it records
whatever OSV's server-side `version` filter returns.

| ID | Capability | Monolith | Greenfield | Sev | Status |
| --- | --- | --- | --- | --- | --- |
| **A1** | Local version-range gate in correlation | `version_match.go:100` `VersionMatches`, invoked as the correlation gate | delegated to OSV server; ported engine runs only in Intelligence's reactive rule | MED | 🆕 |
| **A2** | NVD as a **correlation source** (CPE ranges drive a match) | NVD CPE ranges matched locally (`nvd/client.go:430` → `store/vulnerability.go:120`) | NVD is **enrich-only** (`enriching_source.go:14`); a CVE covered only by NVD CPE yields **no match** | MED-HIGH | 🆕 |
| **A3** | Distro-authoritative identity guard | `version_match.go:57` `PackageIdentityMatch` (rejects el8-openssl-style upstream over-match) | no local guard; protection only implicit via OSV per-distro ecosystem+source+epoch scoping | LOW-MED | 🆕 |
| **A4** | Ubuntu ecosystem mapping | `MapEcosystem` handles ubuntu→Ubuntu | `osvDistroEcosystem` has no ubuntu case (returns "") | LOW | ⚠️ (§C named it as a future-add, not a lost capability) |
| **A5** | Alpine package-name normalization | `osv/package_name.go` (`so:` / `py3-` → `python3-`) | absent | LOW | 🆕 |
| **A6** | CVE alias breadth | `resolveCVEID` scans `aliases` + `upstream` + `related` | greenfield OSV ACL reads `id` + `aliases` only (`feed/osv.go`) | LOW | 🆕 |

## B. Enrichment & feeds

Shipped and confirmed: **NVD watch (#61)**, **EPSS/KEV/ExploitDB sweep (#62)** — both opt-in, relevance-bounded
(EDR-KNOWLEDGE-01 D5), matching the code.

| ID | Capability | Monolith | Greenfield | Sev | Status |
| --- | --- | --- | --- | --- | --- |
| **B1** | Feed-health / status tracking + `degraded_feeds` API | full recorder + `PostgresFeedHealthStore` + `GET /status` | **fully unwired** — a *richer* `domain/feedtier.go` policy exists but has no recorder, store, `signals_stale`, or status route; schedulers record nothing | HIGH | 🆕 |
| **B2** | Periodic OSV/distro re-correlation of existing inventory | re-queries OSV for the whole catalog every watch cycle (+ distro re-run) | correlation is **event-driven only**; a new OSV/distro CVE for an already-ingested component isn't found until fresh evidence arrives | MED | 🆕 |
| **B3** | Red Hat VEX / CSAF applicability | full subsystem — fetch client + per-EL-stream verdict + epoch rpm compare + scheduler | **✅ CLOSED 2026-08-01.** `RedHatClient` per-CVE Hydra fetch → vendor vuln-facts + `not_affected` applicability + **main-stream `affected_release` fix NEVRAs**; relevance-bounded (`THEMIS_REDHAT_ENABLED`); precedence ranks `redhat` distro-authoritative; **stream-scoped epoch-rpm fixed verdict** in correlation (`value.RPMFixedByStream`, conservative — no false-fixed); covers RHEL/Rocky/Alma. (PRs: Phase-2 suppression #76, feed #77, verdict local.) | HIGH→**done** | ✅ |
| **B4** | Generic vendor-VEX feed | full subsystem — CSAF parser + fetch + scheduler | **✅ CLOSED 2026-08-01.** `feed.CSAFVexClient` — a **per-CVE** (relevance-bounded, D5 — NOT a bulk crawler) multi-base fetch of `<base>/<year>/cve-<id>.json` from any CSAF trusted provider; real CSAF 2.0 parser (`parseCSAFVEX`, resolves `product_tree` PURLs → package names) → `not_affected` applicability → Phase-2 suppression. `THEMIS_VEXFEED_ENABLED`/`_URLS`/`_POLL_INTERVAL`. (Bulk CSAF-dir/zip crawl deliberately rejected — it would transiently mirror the feed, violating D5, exactly where the legacy crawler failed.) | MED-HIGH→**done** | ✅ |
| **B5** | NVD by-CVE backfill (cards outside the 120-day window) | `cvss_backfill.go` `FetchByCVEID` + scheduler | absent; a card whose CVE last changed >120 days ago never gets NVD CVSS | MED | 📋 (§C) |
| **B6** | `feed.Registry` + per-record ACLs wired | n/a | `NewRegistry()` has **no production caller**; redhat/vex/epsskev/exploitdb per-record ACLs are dead on the prod path | LOW | 📋 (§C, but broader than the EPSS/KEV note) |

## C. Triage / positions / risk / blast-radius

| ID | Capability | Monolith | Greenfield | Sev | Status |
| --- | --- | --- | --- | --- | --- |
| **C1** | Org asset graph (Product→Microservice→Deployment→Customer, team routing) | full subsystem — typed nodes/edges, recursive-CTE traversal, CRUD API | **absent in every context**; Registry holds Product→Project→Release *identity* only | HIGH | 📋 (§ prior B) |
| **C2** | Per-Finding blast multiplier (`base × 1.0–2.0×`) | `risk_phase2a.go:73` customer-count multiplier applied per-Finding (`score.go:52`) | absent; `priority.go` is CVE-intrinsic and Governance computes no per-Finding score | HIGH | 📋 (§C) |
| **C3** | Effective-state / VEX score modifier | score scaled by outcome (FP ×0.1, confirmed ×1.2, resolved 0 — `state.go:46`) | absent; a not-affected/accepted finding is **not de-ranked** | MED | 🆕 |
| **C4** | Accepted-risk TTL / auto-expiry | `accepted_until` required + `ProcessExpiredAcceptedRisk` reverts on expiry | stance exists, but **no timer/TTL/auto-revert**; time-boxed acceptance silently becomes permanent | MED | 🆕 |
| **C5** | Assignee / team field on a Finding | `AssignedTo` on triage history + risk-context | Finding/Proposal/Position have no assignee — can't route/assign to a person or team | LOW-MED | 🆕 |
| **C6** | Knowledge score consumed by Governance | n/a | **ADDRESSED 2026-08-05:** the score reaches Findings via BOTH `FaultlineEnriched`→`SetBaseScore` and (BUG-3, PR #87) the score riding `ComponentMatched` so a Finding is stamped at open; Governance materializes `base_score` and ranks by `effective_priority = base × blast` (C2). Deeper `residual_priority`/re-eval is GOV-14. | LOW | ✅ |

## D. Export / VEX / notifications

Export formats: greenfield is **ahead** (6 serializers vs 2; no monolith export format is missing — SPDX is
input-only in both). The gaps are in notifications and in VEX content fidelity.

| ID | Capability | Monolith | Greenfield | Sev | Status |
| --- | --- | --- | --- | --- | --- |
| **D1** | Real delivery — SMTP/email + Teams | `adapter/notify/{smtp,teams}.go` (TLS, Adaptive Cards) | **`LogDeliverer` stub only** — logs, delivers nothing | HIGH | 📋 (§ prior B) |
| **D2** | Notification trigger breadth | 6 event types: ingestion done/rejected, CVE-watch finding, triage decision, VEX updated, blast-radius team | only Governance **Position** events materialize a Publication; the other five have **no home** even with a real deliverer | MED-HIGH | 🆕 |
| **D3** | Digest batching | `notify/digest.go` (BatchKey accumulate + flush + severity breakdown) | absent | MED | 🆕 |
| **D4** | Routing rules + config API (`GET/PUT /config/notifications`) | `notify/routing.go` (event/product/min-severity → channel) | absent (publishable-queue is a worklist, not channel routing) | MED-HIGH | ⚠️ |
| **D5** | Redaction (SMTP pw / webhook-URL scrubbing) | `notify/redact.go` | no-op `PassThroughRedactor` | MED | 📋 (§ prior B) |
| **D6** | CycloneDX-VEX content fidelity | carries `x-themis-epss/kev/blast-radius/vex-source` + CVSS ratings | drops all extension fields + ratings; emits `id + analysis + affects` only | LOW-MED | 🆕 |
| **D7** | VEX coverage summary (`ExportCoverage` + endpoint) | Covered / NotCovered / PURLMismatch counts | absent | LOW | 🆕 |

## E. Ingestion / evidence / trust

| ID | Capability | Monolith | Greenfield | Sev | Status |
| --- | --- | --- | --- | --- | --- |
| **E1** | JSON-schema document validation | validates every upload against embedded CycloneDX/SPDX/OpenVEX/CSAF schemas (`trust/schema.go`) | only `json.Valid` well-formedness; schema-invalid-but-well-formed docs are **accepted** | MED | 🆕 |
| **E2** | Trust policy + provenance/supplier enforcement | strict/standard/permissive; requires CI provenance fields, supplier allow-list, unsigned-reject-under-strict (`trust/gate.go`, `policy.go`) | provenance captured as data, **never enforced**; no policy concept | MED | 🆕 |
| **E3** | Trust audit trail | accept/reject/warning audit records | none | LOW | 🆕 |
| **E4** | Trivy-native JSON input | `parser/trivy.go` | CycloneDX + SPDX only | LOW | 📋 (§ prior B) |
| **E5** | Parse timeout | 5-min timeout wrapper (`parser/registry.go:61`) | max-components only, no timeout | LOW | 🆕 |
| **E6** | SBOM management read surface | list/version/counts/`is_latest`/soft-delete (`sbom_management.go`) | `ListByRelease` summaries only | LOW | 🆕 / partly 🎨 (Evidence is immutable) |
| **E7** | Artifact / image-digest registration entity | `RegisterArtifact` (globally-unique digest, repo/tag) | image digest is provenance-only; SBOM bytes are the dedup key | LOW | 🎨 (EDR-KERNEL-01 D2) |
| **E8** | Ingestion status entity + idempotency-key + `GET /ingestions/{id}` | lifecycle RECEIVED→…→NOTIFIED + status endpoint | synchronous content-addressed register; no observable status entity | LOW | 🎨 (dedup is structural) |
| **E9** | VEX→parent-SBOM integrity linkage | "ingest parent first"; VEX linked by SBOM checksum | VEX references a Release (`SubjectRef`), not a parent SBOM; not parsed | LOW | 🎨 |
| **E10** | SPDX 3.0 | supports 2.3 + **3.0** | supports **2.2** + 2.3 (dropped 3.0, added 2.2) | LOW | 🆕 |
| **E11** | `scanner-report` kind produces an inventory | Trivy handled as a format | `kind: scanner-report` accepted but not parsed → stored with **empty inventory** | LOW | 🆕 |

## F. Security & platform (cross-cutting)

| ID | Capability | Monolith | Greenfield | Sev | Status |
| --- | --- | --- | --- | --- | --- |
| **F1** | Inbound API auth (API keys + scopes) | `X-API-Key` bcrypt key store, 3-tier scopes (admin/read/product), product-authz, expiry/revocation | **zero** — every service mounts only `RequestLogger`; no `securitySchemes` in any spec | HIGH | ⚠️ (doc rated "M"; there is literally no auth surface) |
| **F2** | HMAC-verified CI-scan webhook | `POST /webhooks/scan`, `X-Themis-Signature` HMAC-SHA256, constant-time compare | absent | HIGH | 📋 (§ prior B, rated "S") |
| **F3** | Admin key-management CLI (`create-key`/`revoke-key`) | `infrastructure/cli/admin.go` | absent (nothing to manage — no auth) | MED-HIGH | 🆕 (subsumed by F1, distinct work) |
| **F4** | Prometheus `/metrics` + metric catalog | promhttp + 8 metrics (ingestion/queue/watch/notify) | **CLOSED 2026-08-06** — `observability.Metrics` (promhttp registry on `/metrics`, feed-poll/record + HTTP counters) | MED | ✅ |
| **F5** | `/healthz` + `/readyz` probes | both, per service | absent in all 6 services (k8s liveness/readiness gap) | MED | 🆕 |
| **F6** | OTel tracing spans | pipeline-stage spans (`domain/tracing.go`) | **CLOSED 2026-08-07** — OTLP `TracerProvider` + a server span per request, named by **route pattern** (renamed post-handler, since chi only fills its RouteContext during routing) and carrying `themis.correlation_id` so traces join their logs. **CONVENTIONS R1 is now complete: logs + metrics + traces.** | MED | ✅ |
| **F7** | Job isolation on failure | in-process pool: one poison job fails in isolation, pool keeps draining | eventbus **poison-halt stops the whole consumer stream** — no dead-letter, no per-subject isolation | MED | 🆕 (deliberate D8, but an availability regression) |
| **F8** | Inbound body-size (MaxBytes) limit | MaxBytes middleware | absent | LOW | 🆕 |

**Not a gap (verified):** CONVENTIONS R2 "self-documented example config" — **satisfied** by
`deploy/node.env.example` (inline-commented env template). Inbound HTTP rate limiting — absent in **both**
trees (parity). Signature verification — stub in monolith, fingerprint-only in greenfield (parity; both lack
real signing).

---

## Priority recommendation (for discussion)

Ranked by "blocks real production use" first, then coverage-correctness, then completeness:

1. **F1 + F2 + F3 — auth/webhook/admin CLI.** Every greenfield endpoint is open. This is the single biggest
   production blocker and a prerequisite for exposing the system beyond a trusted VM.
2. **B1 — feed-health/status.** Ops can't tell if a feeder is broken; the policy (`feedtier.go`) is already
   written and *richer* than the monolith — this is mostly wiring (recorder + store + `/status`).
3. **A2 + A1 — NVD-as-correlation-source + local range gate.** Coverage correctness: today a CVE only NVD
   knows about is never surfaced, and correlation trusts OSV's server for all version logic despite owning a
   verified local engine.
4. **B3 + B4 — Red Hat VEX engine + vendor-VEX crawler.** Distro accuracy; larger builds (a fetch client and
   a verdict engine, not just wiring).
5. **D1 + D2 — real delivery + trigger breadth.** Outbound value; note D2 means "wire a deliverer" is
   necessary but not sufficient.
6. **C1 + C2 + C3 + C4 — asset graph, blast multiplier, VEX/state score modifier, accepted-risk TTL.** Risk
   fidelity; C1 is the large one (a new asset-graph model, likely its own context).
7. **E1 + E2 — schema validation + trust policy.** Input-integrity hardening.
8. **F5 + F7 — probes, dead-letter.** Operability; each is self-contained. (F4 metrics and F6 traces are
   done — see the table.)
9. Long tail: A3–A6, B5–B6, C5–C6, D3–D7, E3–E11, F8.

## Where greenfield is *ahead* (no action)

Event bus + exactly-once consumer inbox; database-per-context isolation; the reactive **Intelligence AI
Gateway** (rule→LLM, grounding, 3-stage validation — the monolith only had a no-op AI slot); **6 export
formats** (CSAF, markdown, json-report, text beyond CycloneDX-VEX + OpenVEX); a **reconciliation aggregate**
(order-independent by construction, rapid property-proven, append-only audit) vs the monolith's flat
precedence map; immutable **versioned Enterprise Positions** with full Proposal history + an ADR-fixed
authority line (AI/System propose, Human/Policy decide); a **3-state range verdict** (`RangeUndecidable`) for
honest deferral; a **tier-differentiated feed-health policy** (`feedtier.go`, once wired); and
**content-addressed immutable Evidence** as a single dedup primitive.
