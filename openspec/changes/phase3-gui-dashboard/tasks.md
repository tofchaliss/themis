# Tasks: phase3-gui-dashboard

Each group is its own PR off `main`, `make check-ci` green, and ends with `make vet-tags` green.

## 1. Phase 1 — the keeper skeleton (D1, D5, D7, D8)

- [x] 1.1 `cmd/dashboard` composition root: env/flags, `go:embed` static assets,
      `THEMIS_DASHBOARD_ASSETS` dev override
- [x] 1.2 `internal/dashboard/proxy`: route table from the DASHBOARD-SPIKE wiring contract,
      node-key injection, `X-Themis-AI-Reason` pass-through
- [x] 1.3 Port estate/posture/drawer views behaviour-for-behaviour from the spike (theme
      toggle, band colors, mono identifiers). *Build note:* the static assets rode WHOLESALE —
      carving the AI/publication sections out of the live-tested app.js would have created a
      third, untested behaviour; Phase 3 keeps the D9 preview and the AI-surface test plumbing.
- [x] 1.4 Startup honesty: `AUTH DISABLED` log line; `THEMIS_AUTH_REQUIRED=1` refuses to boot
      (guard wired before login exists — grill amendment)
- [x] 1.5 Move `DASHBOARD-SPIKE.md` + `GUI-UPGRADE-PLAN.md` onto `main` in this PR (they are
      the normative contract and evidence base — grill amendment)
- [x] 1.6 Proxy/handler tests (capability-id route class included) + coverage registration
      (adapter tier 90%) + `node --check` JS gate; `make vet-tags` green

## 2. Phase 2 — the authenticated edge (D2, D3, D4, D11, D12, D13)

- [ ] 2.1 `internal/dashboard/session`: login form (key paste), key verification via
      `internal/platform/auth`, in-memory session store, HttpOnly + SameSite=Strict cookie,
      `Secure` flag when TLS, ~8h idle expiry
- [ ] 2.2 `/whoami`: operator name + scopes from the session; SPA greys write controls from it
- [ ] 2.3 D11 scope gate at the proxy: read scope → GETs + the two Information invokes;
      writes (incl. `recommend_position` invoke) → admin, else 403
- [ ] 2.4 D12 write-time re-verification: every mutation re-checks the operator key is active
- [ ] 2.5 D13 identity validation: body `proposer_id`/`actor_id` must match the session
      operator on mutation routes, else 403; SPA threads `WHO` from `/whoami`
- [ ] 2.6 `THEMIS_AUTH_REQUIRED=1` now unlocks (boots WITH auth); TLS-fronting expectation
      documented in `deploy/node.env.example`
- [ ] 2.7 The full D11/D13 route-class test matrix; `make vet-tags` green

## 3. Phase 3 — AI surfaces + publish loop (D6, D9)

- [ ] 3.1 AI honesty surfaces: reason-taxonomy panels (persistent, labeled), `decided_by` +
      `precedents_used` chips, local-only mark, `[UNVERIFIED MENTIONS …]` highlighting
- [ ] 3.2 Explain (GUI-1) auto-run on drawer open: session cache, non-blocking, enabled-only
- [ ] 3.3 Publication document viewer (read + download) ported from the spike
- [ ] 3.4 D9 publishable-queue preview: `POST /previews` on queue rows
- [ ] 3.5 Tests for the new proxy routes + panels' data plumbing; `make vet-tags` green

## 4. Phase 4 — ship (D10)

- [ ] 4.1 `deploy/systemd/` seventh unit + generator entry; `nohup` lifecycle retired
- [ ] 4.2 INSTALLATION.md Part A step + `deploy/node.env.example` dashboard block
- [ ] 4.3 Delete `gui/dashboard-spike` (safe — 1.5 moved everything normative to `main`)
- [ ] 4.4 Archive this change: `openspec archive phase3-gui-dashboard --skip-specs -y`;
      `make vet-tags` green
