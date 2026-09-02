# Proposal — phase3-occurrence-verdicts (KN-VERDICT-1: per-occurrence verdicts + the ownership bridge)

## Why

A vendor-backported fix that Themis had **fully ingested** could not clear a live finding
(CVE-2025-47273 on MRF, measured live 2026-09-02): the card held the exact Red Hat bound
(`python-setuptools 0:39.2.0-9.el8_10`), every feed was honestly healthy, the image carried the patched
RPM — and the finding stayed open because its component is the Python-package shadow
(`setuptools@39.2.0`, pypi, empty source) of files the RPM owns, and no bridge exists between the two
vocabularies. The same case exposed three more structural gaps: scanner-path matches take no verdict at
all; matches are append-only with the verdict firing exactly once at recording time; and one Finding held
two copies of the same package with **opposite truth values** (the patched distro copy and a
pip-installed 70.3.0 below the upstream fix), which a single all-or-nothing Position cannot describe
honestly.

Grounded in **`docs/engineering/decisions/EDR-VERDICT-01.md`** (D1–D9, grilled + confirmed 2026-09-02),
which is the source of truth for every decision, rejected alternative, and honest limit. Tracked as
**KN-VERDICT-1** in `docs/BACKLOG.md`; evidence case file published (artifact
b57b9622-c500-4a8e-9e10-6503bdb91210).

## What changes

- **Occurrence verdict state (D1/D2/D5)** — match records gain state + evidence grade + reason + a
  checked-against-card-version stamp; discovery and scanner intake unify into one record-then-judge path
  (no more silent drops, no more unverdicted scanner matches); Governance mirrors state on
  `finding_components` over the existing event seam and re-derives queue membership.
- **The ownership bridge (D3/D4)** — an rpm fix clears a language-package occurrence only via an
  owning-RPM connection: Observed grade (explicit SBOM ownership edge) or Inferred grade (same-inventory
  source-package + exact-upstream-version match), always labeled, strict-mode switch to disable Inferred.
- **Re-verdict (D6)** — immediate on a fold that actually changes a card's fix set + a bounded,
  self-targeting catch-up sweep over stale stamps (heals pre-existing rows — the motivating finding is
  history until this runs).
- **Queue semantics (D7)** — priority computed from open carrier occurrences only, full value, no
  proportional discount; a finding leaves the queue only when nothing real remains open.
- **Per-occurrence remediation + GUI (D8/D9)** — fix advice selected by the occurrence's own ecosystem;
  `plan_remediation` grouping becomes (package, world); the drawer shows each occurrence with state,
  grade label, reason, and its own fix.

## Impact

- **Knowledge**: migrations (match-record state columns + stamp), unified intake in app ring, bridge
  resolver, re-verdict trigger + sweep, read API additions. **Governance**: migration (mirror columns),
  consumer + queue derivation, read API additions. **Dashboard**: drawer occurrence view. **Intelligence**:
  plan grouping input change (deterministic pre-prompt only). Event contract: additive fields/one new
  event type. All "must-ask" categories were approved via the 2026-09-02 grill; per phase, `make check`
  green gates completion.
- **No new feeds, no new services, no new dependencies.** Every verdict input already lives on the card
  or in the inventory.
- `phase3-*` change: proposal/design/tasks + EDR are the source of truth, **no `specs/` deltas**;
  archive with `--skip-specs`.
