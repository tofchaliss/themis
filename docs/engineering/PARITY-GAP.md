# Monolith → Greenfield — Capability Parity Gap

**Updated:** 2026-07-30. Tracks which v0.3.x monolith capabilities have (and have not) carried over to the
Phase-3 greenfield rebuild. The monolith (`internal/{domain,usecase,adapter,infrastructure}`, `cmd/themis`)
is **frozen/reference-only**; this is the go-forward closure list. Companion to
[`PHASE3-STATUS.md`](PHASE3-STATUS.md) (status) and [`../BACKLOG.md`](../BACKLOG.md) (open work).

The greenfield is **architecturally ahead** (event bus + exactly-once inbox, DB-per-context isolation, a
reactive AI Gateway, a 6-format serializer registry) but was **feature-incomplete on the
intelligence/enrichment half**. Most gaps are "the ACL exists but nothing wires it" — i.e. wiring, not
building. The first (intelligence/enrichment) cluster is now **closed**.

## A. Correlation & enrichment — ✅ CLOSED (2026-07-30, PRs #60–#63)

| Capability | Monolith | Greenfield | Status |
| --- | --- | --- | --- |
| OSV language ecosystems | ✅ | ✅ wired | done (pre-existing) |
| **Distro correlation** (Alpine/Rocky/Wolfi + Red Hat via OSV distro DBs; source-name keying; epoch) | ✅ full subsystem | ✅ via OSV distro ecosystems, format-agnostic | **#60** |
| **NVD** CVSS/severity enrichment | ✅ | ✅ modified-since watch, relevance-bounded, opt-in | **#61** |
| **EPSS / KEV / ExploitDB** signals | ✅ feeds + schedulers | ✅ bulk-snapshot sweep of existing cards, opt-in | **#62** |
| **Deterministic priority + composite score** (Layer-1 rules + severity×EPSS×KEV) | ✅ | ✅ CVE-intrinsic on the Faultline (`domain/priority.go`) | **#63** |
| Retroactive re-enrichment | ✅ (re-score on feed sync) | ⚠️ partial — the scheduled sweeps re-fold on each poll (idempotent); no on-event re-score | mostly covered by the sweeps |

**Design rule applied:** all greenfield enrichment is **relevance-bounded (EDR-KNOWLEDGE-01 D5)** — feeds
enrich *existing* cards, never mirror the full feed — and **opt-in** (`THEMIS_NVD_ENABLED`,
`THEMIS_EPSSKEV_ENABLED`; off by default, no silent outbound calls).

## B. Remaining gaps (delivery / blast-radius / security cluster)

| Capability | Monolith | Greenfield | Effort |
| --- | --- | --- | --- |
| **Notifications** (SMTP/Teams, digests, routing, redaction) | ✅ | ❌ `LogDeliverer` + no-op redactor stubs | M |
| **Blast-radius graph** (Product→Microservice→Deployment→Customer, 1.0–2.0× multiplier, team routing) | ✅ | 🟡 release-set blast radius only (no org graph, no multiplier, no routing) | L |
| **API auth** (API keys, scopes, HMAC webhooks) | ✅ | ❌ no auth on any greenfield endpoint | M |
| **Trivy JSON** input format | ✅ | ❌ CycloneDX + SPDX only | S |
| **CI scan webhook** (HMAC ingest) | ✅ | ❌ | S |
| Signature verification | 🟡 stub | 🟡 fingerprint-only | parity (both lack signing) |

## C. Tracked follow-ups on the closed cluster (BACKLOG §C)

- **NVD by-CVE backfill** — enrich cards whose CVE is *outside* the 120-day modified-since window.
- **Per-Finding blast multiplier** — Governance-side `priority = Faultline base × blast` (needs the org
  asset graph; affected-release count is a usable proxy meanwhile).
- **Distro ecosystem map** — extend beyond rocky/alma/rhel/debian/alpine (ubuntu/suse) once verified on OSV.
- **Per-record ACL tidy-up** — the bulk EPSS/KEV/ExploitDB client bypasses the pre-existing per-record
  `epsskev.go`/`exploitdb.go` ACLs; reconcile or remove.
- **Vendor-VEX / Red Hat CSAF applicability** — the ACL exists but is unwired (a distinct correlation path).

## Where greenfield is *ahead* (no action)

Event bus + exactly-once inbox; database-per-context isolation; the reactive **Intelligence AI Gateway**
(rule→LLM, grounding, 3-stage validation — the monolith only had a no-op AI slot); and **4 extra export
formats** (CSAF, markdown, json-report, text) beyond the monolith's CycloneDX-VEX + OpenVEX.
