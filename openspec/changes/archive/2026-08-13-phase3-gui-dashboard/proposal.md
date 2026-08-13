# Proposal: phase3-gui-dashboard — productize the dashboard (GUI-6)

## Why

The `gui/dashboard-spike` evaluation (2026-08-10 → 2026-08-12) ended with a full-pass live test
round by its intended user and settled the visual style, the posture-first navigation, the
drawer-as-decision-surface, and the proxy pattern — but a spike is disposable by mandate: no
tests, no auth on its edge, `nohup` lifecycle, assets on disk. This change rebuilds it as a
production deployable.

## What

The **production Themis dashboard**: a single static-SPA + reverse-proxy binary (`cmd/dashboard`)
— a **view, never a context** (no database, no domain ring, no truth) — with an authenticated
browser edge (named API-key-backed operators, server-side sessions), proxy-enforced operator
scopes and identity validation, the spike's AI-honesty surfaces, embedded assets, tests +
coverage registration, and a systemd unit.

## Source of truth

**EDR-GUI-01 (Accepted, grilled 2026-08-13) — decisions D1–D13.** This change carries no
`specs/` deltas (phase3 convention); proposal/design/tasks + the EDR are the record.
The spike's wiring table (`DASHBOARD-SPIKE.md`) is the normative endpoint-per-view contract (D5);
the spike branch itself is reference only and never merges.

## Impact

- New deployable `cmd/dashboard` + its adapters; no bounded context is modified.
- The six read APIs are consumed as-is; anything missing is a read-API change in the owning
  context FIRST (the D5 discipline).
- `deploy/systemd/` gains a seventh unit; INSTALLATION.md Part A gains a step (Phase 4).
- The spike branch is deleted at the end (Phase 4), after Phase 1 moves its normative docs to
  `main`.
