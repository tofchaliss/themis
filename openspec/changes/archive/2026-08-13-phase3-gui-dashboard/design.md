# Design: phase3-gui-dashboard

**EDR-GUI-01 D1–D13 is the design of record.** This file only maps decisions to build shape.

## Shape

```
cmd/dashboard/            composition root: flags/env, embed, wiring
  static/                 SPA assets (go:embed; THEMIS_DASHBOARD_ASSETS dev override — D8)
internal/dashboard/       adapters-only ring (D1: a view, never a context)
  proxy/                  reverse proxy: route table (D5), node-key injection (D4),
                          scope gate (D11), identity validation (D13)
  session/                dashboard-local sessions (D12): login, in-memory store,
                          write-time key re-verification, /whoami
```

The binary may import `internal/platform/*` (auth for key verification, observability) and no
bounded context. Enforced like every node: depguard + arch test.

## The request path (one picture)

```
browser ──cookie──▶ session (D12) ──▶ scope gate (D11) ──▶ identity check (D13)
                                                            │ mutation? re-verify key (D12)
                                                            ▼
                                              proxy + X-API-Key inject (D4) ──▶ node
```

Reads: session only. Writes: session + scope + identity match + key-still-active, then forward.
Every refusal is a `403` at the proxy; nothing invalid ever reaches a node.

## Write-route table (D11/D13)

The proxy owns an explicit route classification (the same table drives both checks):

| Class | Routes | read scope | admin scope |
| --- | --- | --- | --- |
| read | all `GET`s | ✓ | ✓ |
| info-invoke | `POST …/capabilities/{plan_remediation,explain_vulnerability}/invoke` | ✓ | ✓ |
| write | raise/accept/reject proposals, publications, `recommend_position` invoke | 403 | ✓ (identity-checked) |

`recommend_position` is a write because its invoke records an advisory Proposal in Governance.

## Test seams (D7)

Proxy and session are plain `http.Handler`s over injected fakes (auth store, node backends), so
the D11/D13 matrix, the reason-header pass-through, and the key-injection tests run without
Postgres. Adapter tier, 90%, registered in `scripts/check-coverage.sh`; a `node --check` JS
syntax gate rides CI.
