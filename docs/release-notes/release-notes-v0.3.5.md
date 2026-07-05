# Themis v0.3.5 — Red Hat VEX overlay (on-demand Security Data API)

Release tag: `v0.3.5` (**non-breaking** — no schema change; rebuild + restart, optionally set an
NVD key). A new capability on the v0.3.x correlation-accuracy line: Red Hat's authoritative
per-CVE, per-stream verdicts finally reach RPM findings.

## Why

The Red Hat CSAF VEX overlay was specced in Phase 2a but **never had data**: the
`CSAFDirectoryFeedSource` crawler looks for top-level `*.json` links, while Red Hat's CSAF repo
serves year subdirectories — so `vex_assertions` stayed empty and `upstream_vex_coverage` was
`not_covered` on every finding. Vendor verdicts (e.g. Red Hat marking ncurses **Not affected** on
RHEL-8 because the vulnerable code is the build-time `tic`, not the runtime library) never reached
findings, leaving back-port false positives in the active queue.

## What

**Option B — on-demand Red Hat Security Data API**, modeled on the CVSS backfill. For each open
RPM-family CVE, Themis fetches
`access.redhat.com/hydra/rest/securitydata/cve/{CVE}.json`, resolves the verdict for the
component's **exact EL stream** (from the product CPE, `enterprise_linux:8` → stream 8), and writes
a VEX-overlay assertion **keyed to the finding's own PURL** so the existing matcher applies it by
exact match:

- **`fix_state: "Not affected"`** for the component's stream → `effective_state=not_affected` and
  `upstream_vex_coverage=covered`. The ncurses CVE-2022-29458 case is suppressed from the active
  queue — as a **visible, human-overridable signal**, not an irreversible deletion.
- **`affected_release`** for the stream → the vendor's **back-ported fixed NEVRA**.
- **`threat_severity` + statement** → carried in the assertion **justification** (visible in the
  VEX export) so the analyst can confirm a likely back-port false positive.

**Themis surfaces every signal; the human decides.** Severity is **context only** — Themis never
auto-rescopes it. Human triage overrides the vendor verdict via the existing VEX precedence
(`themis_generated` > `manual`/`vendor` > `ai_generated` > `upstream_vendor`).

Scope: **RPM only** (Rocky / AlmaLinux / RHEL). Because each assertion is keyed to the finding's
exact PURL, the `rocky/alma → redhat` namespace alias was unnecessary (no over-suppression risk).
The verdict is **exact-stream**: an el8 build is only suppressed by a RHEL-8 "Not affected", never a
RHEL-9 one.

## Additions

- `feat(vex)` — Red Hat VEX overlay via the on-demand Security Data API (`adapter/redhat`,
  `domain.RedHatCVEReport.VerdictForStream`, `usecase/enrichment.RedHatVEXService`), wired with a
  `redhat_vex` scheduler, the `themis_redhat_vex_total` metric, and `feed_health` reporting.

## Upgrade

No schema change — **rebuild and restart**. The Red Hat scheduler runs at startup and on the
`vexfeed.poll_interval`, iterating the open RPM findings (bounded by distinct-CVE count, polite
rate, in-memory back-off). No new config required; an `THEMIS_NVD_API_KEY` is unrelated but
recommended for the parallel CVSS backfill.

```sh
git checkout main && git pull --ff-only && make clean && make build   # restart the service
```

## Verification

```sh
# vendor verdicts now land as overlay assertions
psql "$THEMIS_DATABASE_DSN" -c "SELECT status, COUNT(*) FROM vex_assertions va
  JOIN vex_documents vd ON vd.id = va.vex_document_id
  WHERE vd.source = 'upstream_vendor' GROUP BY status;"

# the ncurses back-port false positive is suppressed (visible, not deleted)
psql "$THEMIS_DATABASE_DSN" -c "SELECT cve_id, effective_state FROM risk_context
  WHERE cve_id = 'CVE-2022-29458' AND component_purl LIKE '%ncurses%';"   # → not_affected

# overlay outcomes + coverage
curl -s "$BASE_URL/metrics" | grep themis_redhat_vex_total
curl -s "$BASE_URL/api/v1/products/$PRODUCT_ID/versions/latest/vex-coverage" -H "X-API-Key: $API_KEY" | jq .
```

The vendor rationale (fix state, threat severity, statement, fixed NEVRA) is carried in the
assertion justification and surfaced in the VEX export; the finding shows `effective_state` +
`upstream_vex_coverage` so an analyst can review and override.

## Known gaps (tracked in `project-backlog.md`)

- Surfacing the vendor justification **inline on the findings API** (today it's on the VEX export);
  small additive enhancement.
- OSV.dev app-ecosystem version-range quirks (GIT-range over-match; major-line crossing) — separate
  from this RPM-focused work.
