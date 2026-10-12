# EDR-GUI-01 — The Themis dashboard: productize the spike (GUI-6)

Status: **Accepted — grilled 2026-08-13; D3 amended 2026-10-12** (drafted 2026-08-12 from the
spike evaluation; decisions D1–D13 below — D11–D13 and the D3/Phase amendments are the grill's
outcomes; the 2026-10-12 D3 amendment adds username/password sign-in and the Admin tab at
owner request)
Date: 2026-08-12 (grilled 2026-08-13; amended 2026-10-12)
Author: GUI-productization session

## Purpose

Engineering Decision Record for the **production Themis dashboard** — the keeper rebuilt from the
`gui/dashboard-spike` evaluation (2026-08-10 → 2026-08-12, `docs/engineering/DASHBOARD-SPIKE.md` +
`GUI-UPGRADE-PLAN.md`). The spike's mandate was to settle the visual style and learn what the read
surface is missing; it ends with a **full-pass live test round by its intended user** and a set of
decisions this EDR fixes so the rebuild does not re-litigate them.

Ground rule: **ADR/EDR wins; the spike is reference only.** The spike branch never merges; every
behaviour that survives is re-implemented here with tests.

## What the spike settled (evidence, not intuition)

1. **Posture-first navigation is right.** Estate cascade → release posture → finding drawer
   survived three days of live use by a security engineer with zero navigation complaints.
2. **The drawer is the decision surface.** The whole governed loop (raise → accept/reject →
   publish → read the document) lives in one place and was exercised end-to-end live.
3. **The proxy pattern is structural, not stylistic.** Nodes set no CORS (correctly), and the
   API key must never reach the browser — a same-origin reverse proxy is the only shape that
   satisfies both.
4. **Two themes, fixed status colors, mono identifiers.** Enterprise ☀ / Midnight ☾ behind one
   toggle; band colors never themed; every CVE/PURL/version is a mono chip.
5. **AI transparency is a feature.** The six-reason no-answer taxonomy, `decided_by`,
   `precedents_used`, and the local-only mark all changed user behaviour when surfaced (GUI-9);
   the production version keeps them first-class.

## Decisions

### D1 — One deployable, a view, never a context

`cmd/dashboard` stays a single static-SPA + reverse-proxy binary: no database, no domain ring, no
truth. Every number on screen is fetched live from the six read APIs. It is a **view**, so Clean
Architecture applies as "adapters only": the binary may import `internal/platform/*` and nothing
from any bounded context.

*Narrowed 2026-10-12 by the D3 amendment:* the binary now owns exactly **one** table — its own
sign-in directory (`dashboard_users`, in the shared `auth` database). "No truth" is unchanged:
nothing a node could answer is stored there, and the GUI's own password is not a fact about any
bounded context. The rest of D1 stands as written.

### D2 — Identity: named API-key-backed operators (v1)

Decided by the user 2026-08-12 (GUI-UPGRADE-PLAN D5): v1 identity is a **small set of named
operators, each backed by an `internal/platform/auth` API key** (`authadmin create-key --name
alice`). The dashboard authenticates the BROWSER session (D3), resolves the operator name from
the presented key, and stamps it as `proposer_id` / `actor_id` on every decision. No user
management, no roles beyond the existing key scopes (admin=read+write, read=read-only), no SSO in
v1 — the seam (one `/whoami` answered by auth) is where SSO lands later without moving anything.

### D3 — The dashboard's own inbound edge is authenticated

The spike's `:8090` was open (acceptable behind the VM firewall; unacceptable beyond it). The
production dashboard wires `internal/platform/auth` like every node: a browser presents a key
once (login form → server-side session cookie, HttpOnly + SameSite=Strict); the SPA never sees
either the session's key or the node key. `THEMIS_AUTH_REQUIRED=1` hard-fails startup with no
auth DSN, same as the other nodes.

*Amended in the grill 2026-08-13:* the login paste is the one moment the operator's long-lived
key transits the wire, and no cookie flag protects a paste. **Production deployments front the
dashboard with TLS** (a reverse proxy terminating HTTPS; HTTP inside a firewalled network is an
acknowledged exception, the same class as the Phase-1 open port). The session cookie sets the
**`Secure` flag automatically when the request arrived over TLS**. Key-paste stays the v1 login
on purpose: the keys already exist, password infrastructure for a handful of named operators
would be waste, and SSO is the v2 answer behind the D2 seam.

*Amended 2026-10-12 (owner decision, approved as a security-model change): **username and
password sign-in is added, and key-paste becomes the secondary door.*** The paragraph above
called password infrastructure waste. It was wrong about what operators would ask for: they
asked for a GUI password they can change themselves, from the GUI, without an `authadmin`
invocation on the VM. A key is minted by someone with shell access on the host, and nothing
in the GUI could rotate it — so the one credential the GUI owned, the operator did not.

What this adds, and nothing more:

- **A dashboard-local `dashboard_users` table** (username, bcrypt hash, `is_default_password`,
  `updated_at`) in the shared `auth` database, owned by `internal/dashboard/userstore`, NOT by
  `internal/platform/auth` — D12's rule unchanged: a browser password is a concern no other
  node has. It carries its own `dashboard_schema_migrations` bookkeeping table, the way
  Registry does in the `evidence` database, and `cmd/dashboard` applies it under
  `THEMIS_DASHBOARD_MIGRATE=1`.
- **One seeded account**, `admin`, created with the shipped default password on first start
  and flagged as default. An existing row is never overwritten, so a restart cannot undo a
  password somebody changed. The plaintext default lives in exactly two places: the seed
  constant and `INSTALLATION.md`. It is never logged and never embedded in a served asset.
- **An Admin tab**, visible only to admin-scope sessions, holding the change-password form
  (current / new / confirm). While the default is in use, the tab and the topbar say so
  plainly. There are **deliberately no complexity rules** (owner decision): a rule nobody
  agreed to is a rule operators work around, and a shared GUI behind TLS on a firewalled
  estate is not where password entropy is the binding constraint.
- **Two dashboard-local routes** — `GET /api/dashboard/admin/status` and
  `POST /api/dashboard/admin/password` — mounted BEFORE the `/api/*` proxy and answered by the
  dashboard itself. This is the one exception to D5's "the GUI adds no private endpoints", and
  it is not really one: no node owns the GUI's login table, so there is nothing to add an
  endpoint to. Mounting order is load-bearing and is covered by a test with a proxy spy.
- **D12 extended, not reinterpreted.** A password login mints the same server-side session a
  key login does, and the mutation re-verify asks the same question in the password dialect:
  the user row still exists and its `updated_at` still equals the stamp captured at login. A
  password change therefore ends that user's other sessions on their next write — the same
  damage bound a revoked key gets.
- **D13 unchanged in rule, explicit in content:** the username is the operator id, so the
  body's `proposer_id` / `actor_id` must read `admin`.

**The trade-off, recorded because it is real:** `admin` is a SHARED account, and every decision
taken through it is stamped `admin` in an append-only audit trail. A GUI password that several
people know cannot answer "who accepted this". D2's named-operator identity is still the
honest answer, which is exactly why key-paste stays on the login page rather than being
replaced — an operator who needs their own name on a record signs in with their own key. SSO
(D2's seam) remains the v2 answer for named identity at the browser edge; this amendment buys
a self-serviceable credential, not an identity model.

### D4 — Node credentials stay server-side (unchanged from the spike)

The proxy injects `X-API-Key` from `THEMIS_API_KEY` toward the six nodes. Two keys exist on
purpose: the operator's key states who is deciding; the node key states the dashboard may act.
*(Clarified 2026-08-13, caught writing the deploy steps: the node key must be **write-capable**
— the governed loop's accepts and publishes are forwarded under it, so a read-scoped node key
would 403 every accept at the node edge. That is safe precisely because D11 enforces the
OPERATOR'S scope at the proxy before the node key is ever attached.)*
Per-operator pass-through (the operator's own key forwarded to the nodes, so node-side audit sees
the human) is the v2 upgrade and only needs the proxy to swap which key it injects.

### D5 — The endpoint-per-view wiring is the contract

The spike's wiring table (DASHBOARD-SPIKE.md) is normative: DASH-1 traversal, DASH-2 posture,
T10 assessment, similar/`plan_remediation`/`explain_vulnerability` invokes, publications +
document read, feeds. The GUI adds **no** private endpoints; anything the GUI needs that the
read surface lacks is a read-API change in the owning context first (that discipline produced
DASH-1/DASH-2 and is why the spike worked).

### D6 — AI surfaces keep the spike's honesty contract

The `X-Themis-AI-Reason` taxonomy renders as persistent labeled panels (never a transient toast);
`decided_by` + `precedents_used` chips render wherever the wire carries them; AI text is always
labeled, ephemeral, and never a stored fact; explain (GUI-1) auto-runs on drawer open with an
in-memory session cache, non-blocking, enabled-only (GUI-UPGRADE-PLAN D1); "Raise & accept" stays
two recorded audit steps; an `inferred` proposal keeps its "policy cannot auto-accept this; you
can" label.

### D7 — Tests and coverage, spike debt paid

The rebuild registers in `scripts/check-coverage.sh` (adapter tier, 90%): handler/proxy tests
(auth on the edge, key injection, reason-header pass-through, document read), plus a
`node --check`-equivalent JS syntax gate in CI. The capability-id 404 the spike hit on first VM
contact is exactly the class a proxy test kills.

### D8 — Assets embedded, dev override kept

`go:embed` static assets (one binary, like every node); `THEMIS_DASHBOARD_ASSETS` keeps the
edit-and-refresh loop for development.

### D9 — Publishable-queue preview joins the publication viewer

The spike shipped read-the-published-document; the rebuild adds `POST /previews` on queue rows
("what WOULD this position render as") — the API exists, the spike deliberately skipped the flow.

### D10 — Systemd unit like every node

`deploy/systemd/` gains the dashboard as a seventh templated unit; the `nohup` lifecycle dies
with the spike.

### D11 — The proxy is the v1 scope-enforcement point (grilled 2026-08-13)

D2 promises "read = read-only" and D4 injects the **admin** node key toward the nodes for every
request — so without a proxy-side gate, a read-scoped operator's restriction is enforced
NOWHERE (the nodes only ever see the node key until v2 pass-through). The proxy is the one
place that knows both who is asking (the session) and what they ask (the route), so it enforces:

- **read scope** passes `GET`s and the two Information-capability invokes
  (`plan_remediation`, `explain_vulnerability` — `POST` in shape, but they write nothing and
  propose no stance, T7);
- **everything else is a write and requires admin**: raise, accept/reject, publish — and
  notably the `recommend_position` invoke, because it writes an advisory Proposal into
  Governance. A non-admin write is refused with `403` at the proxy and never forwarded.
- The SPA greys write controls from `/whoami`'s scope answer; the proxy check is the
  enforcement, the greying is courtesy.

### D12 — Sessions are dashboard-local; mutations re-verify the key (grilled 2026-08-13)

Session machinery lives in the **dashboard binary's adapters**, not in `internal/platform/auth`:
browser sessions are a concern no other node has, and growing the shared platform package for
one consumer is how platform packages rot. The dashboard *uses* platform/auth to verify the
pasted key at login. Sessions are **in-memory** (a restart logs everyone out — acceptable for a
small named-operator set), idle expiry ~8h — and **every mutating request re-verifies the
operator's key is still active** before the proxy forwards it. Reads ride the session cheaply;
writes pay one auth-DB lookup; a key revoked with `authadmin revoke-key` can read until session
expiry but can decide **nothing** from the moment of revocation. The damage-bounding check sits
on the mutation path, the same fail-safe direction as the rest of Themis.

### D13 — The proxy validates identity claims; a mismatch is a 403 (grilled 2026-08-13)

The SPA sends `proposer_id`/`actor_id` in mutation bodies (the wire already carries them —
Governance requires `actor_id` on accept/reject). A client that can send JSON can lie, and a lie
lands in an append-only audit trail. The proxy therefore **validates the body's identity fields
against the session's operator on the known mutation routes and refuses a mismatch with `403`**
— never forwarding it. Validate-and-refuse over silent rewriting, deliberately: rewriting means
parsing and re-serializing every mutation body (a transparent proxy turns opaque), and refusing
a lie loudly is the Themis direction. A well-behaved SPA never notices the check exists.

## Not in scope (explicit non-goals)

SSO/OIDC (v2 — lands behind the D2 seam); per-operator key pass-through to nodes (v2 — D4);
Evidence raw-document browsing and Faultline-centric navigation (unproven demand — the spike
deliberately skipped them and nobody asked); write operations beyond the governed loop the read
APIs already expose; mobile layout.

## Phased implementation (each its own PR, `make check-ci` green)

1. **Phase 1 — the keeper skeleton.** New `cmd/dashboard` (fresh branch off `main`): proxy +
   embed + theme/token contract + estate/posture/drawer views ported behaviour-for-behaviour
   from the spike, WITH handler/proxy tests + coverage registration (D1, D5, D7, D8).
   *Grill amendments:* Phase 1 already logs **`AUTH DISABLED`** at startup and honors
   **`THEMIS_AUTH_REQUIRED=1`** — which, login not existing yet, means such a binary refuses to
   boot at all; that is the guard working, making the Phase-1 exposure window an explicit
   operator choice rather than a silent default. The Phase-1 PR also **carries
   `DASHBOARD-SPIKE.md` + `GUI-UPGRADE-PLAN.md` onto `main`** — they are the normative wiring
   contract (D5) and the evidence base of this EDR, they exist only on the spike branch, and
   the Phase-1 tests are written against them.
2. **Phase 2 — the authenticated edge.** D2 + D3 + D4 + **D11 + D12 + D13**: login, session,
   `/whoami` from the key, scope enforcement at the proxy, write-time key re-verification,
   identity validation, proposer/actor stamping, `THEMIS_AUTH_REQUIRED` unlock.
3. **Phase 3 — the AI surfaces + publish loop.** D6 (panels, chips, explain auto-run) + D9
   (queue preview) + the publication document viewer.
4. **Phase 4 — ship.** D10 systemd unit + INSTALLATION.md Part A step + spike branch deleted —
   safe now, because Phase 1 moved everything normative onto `main`; the spike dies as pure
   code history, which is what "reference only" always meant.
