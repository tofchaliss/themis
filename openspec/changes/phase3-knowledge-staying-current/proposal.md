# Proposal: phase3-knowledge-staying-current — KN-SCAN-1 + KN-RECOR-1

## Why

A Q&A walkthrough (2026-08-13) measured both halves of the static-estate story missing: a CVE
published after a release's last upload is invisible until the next upload (KN-RECOR-1 — no
re-discovery), and the documented mitigation — upload an image-scan report — is accepted by
Evidence and then silently no-op'd by Knowledge (KN-SCAN-1 — the service and ACL exist, the seam
between them was never built). Together they mean an estate that registers once and stops
uploading reports a permanently green posture while going blind.

## What

1. **KN-SCAN-1 — wire scanner-report ingestion end-to-end.** An Evidence document-read source
   behind the existing `app.ScannerReportSource` port (reusing the same `GetDocument` client the
   VEX door uses), a curated report document schema that finally carries the component each
   finding names, a `scanner-report` branch in the coordinator with the D7 read/write split, and
   wiring. Scanner facts stay Asserted-trust advisory Proposals — a scanner never sets truth.
2. **KN-RECOR-1 — a scheduled re-discovery sweep.** Knowledge remembers which (release,
   evidence) pairs it has correlated (a small ledger written in the same transaction as the
   correlation itself) and re-runs the existing, idempotent discovery fan-out for the stalest
   ones on a rolling cadence — so new CVEs reach months-old inventory with nobody uploading
   anything. D5-compliant by construction: per-component queries against the estate, never a
   feed mirror.

## Source of truth

The two backlog filings (this branch) carry the measured defects + fix shapes; EDR-KNOWLEDGE-01
D5 (relevance bound), EDR-EVENTBUS-01 D7 (read/write split), and EDR-EVIDENCE-01 D4
(normalized-at-the-border producers) constrain the design. No `specs/` deltas (phase3
convention).

## Impact

- Knowledge context only (app + adapters + one new migration + cmd loop); Evidence, Governance,
  the bus, and every API are untouched — the scan path rides the existing `EvidenceRegistered`
  event and document endpoint.
- New env (all optional): `THEMIS_REDISCOVERY_ENABLED` (default on) / `_INTERVAL` /
  `_STALE_AFTER` / `_LIMIT`.
- Docs: TESTING.md (how to produce/upload a report; how to watch a sweep), node.env.example,
  CLAUDE.md enrichment notes; backlog entries closed.
