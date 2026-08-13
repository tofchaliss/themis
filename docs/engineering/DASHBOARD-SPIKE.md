# Dashboard spike — the Themis GUI (branch `gui/dashboard-spike`)

**Status: SPIKE — this branch does not merge to `main`.** It exists to put a GUI in front of the
live VM deployment for a few days, settle the visual style, and learn what the read
surface is missing. Whatever survives gets rebuilt properly (EDR + OpenSpec change) on a fresh
branch; whatever doesn't gets deleted with the branch.

## What it is

One new deployable, `cmd/dashboard` (default `:8090`): a static single-page app plus a
same-origin reverse proxy to the six node read APIs. It is a **view, not a context** — no
database, no domain, no writes except the two explicitly-advisory actions the APIs already
expose. Every number on screen is fetched live; close the tab and nothing was stored.

```text
browser ── :8090 ──► cmd/dashboard ──┬── /api/registry/*      ──► :8082 /api/v1/*
   (one origin,      (static assets  ├── /api/evidence/*      ──► :8081 /api/v1/*
    no CORS,          + proxy +      ├── /api/knowledge/*     ──► :8085 /api/v1/*
    no key in JS)     X-API-Key)     ├── /api/governance/*    ──► :8083 /api/v1/*
                                     ├── /api/communication/* ──► :8084 /api/v1/*
                                     └── /api/intelligence/*  ──► :8086 /api/v1/*
```

**Why a proxy at all.** Two reasons, both structural: the nodes set no CORS headers (correctly —
they serve services, not browsers), so a page cannot call six ports directly; and with auth
enabled (F1) the `X-API-Key` must not live in browser JavaScript — the proxy injects it
server-side from `THEMIS_API_KEY`, so the credential never reaches the page.

## Wiring — endpoint per view

Everything rides the DASH-1/DASH-2 surface that `scripts/release-posture.sh` proved out; the
script was the working spec, this is the GUI it predicted.

| View | Endpoint(s) |
| --- | --- |
| Overview tiles + estate donut | `registry GET /products` · `knowledge GET /feeds` · the DASH-1 walk + one posture read per release (the estate sweep) |
| SBOM manager | DASH-1 selects · `evidence POST /evidence` (201 new / 200 dedup) · `GET /evidence?release=` |
| Who am I | the dashboard's own `GET /whoami` — `THEMIS_DASHBOARD_USER` until real auth answers it |
| Estate cascade | `GET /products` → `/products/{id}/projects` → `/projects/{id}/releases` (DASH-1) |
| Release posture | `governance GET /releases/{id}/posture` (DASH-2 — band, components+claim_class, fixes, priorities in ONE read) · `registry GET /releases/{id}/blast-radius` |
| Publications section | `communication GET /publications?release=` · `GET /publishable-positions` |
| Finding drawer | `governance GET /findings/{id}/assessment` (T10 projection: finding + knowledge, proposals with `evidence_trust`) |
| What it means here | `intelligence POST /capabilities/explain_vulnerability/invoke` — GUI-1, **auto-runs on drawer open** (D1): session-cached, non-blocking, enabled-only (a disabled/unreachable AI plane leaves no dead placeholder); ephemeral Information (T7), the stored summary above it stays the evidence |
| Similar decisions | `intelligence GET /findings/{id}/similar?k=5` — semantic precedent, **no model runs** |
| Ask the AI | `governance POST /findings/{id}/recommend` — records an ADVISORY proposal; on 201 the drawer reloads and highlights it (GUI-7); every 204's `X-Themis-AI-Reason` renders as a persistent labeled panel (GUI-9) |
| Remediation plan | `intelligence POST /capabilities/plan_remediation@v1/invoke` with `{subject:{type:release}}` — ephemeral Information (T7), rendered with `decided_by` + `precedents_used` chips and marked `[UNVERIFIED MENTIONS …]` caveats; never stored (GUI-8) |
| Decide (human) | `POST /findings/{id}/proposals` (proposer = the /whoami user) · `POST …/proposals/{pid}/accept` / `reject` (actor = the /whoami user; `review_by` offered on suppressing stances — GOV-14b) |
| Publish (human) | `communication POST /publications` (`finding_id` + artifact `vex` + chosen format) |

**The authority-line buttons landed 2026-08-11 on user direction** (they were initially held back
as "designed, not spiked"). The drawer now carries the whole governed loop: raise a proposal
(stance + rationale), accept/reject pending ones — including the AI's and the system's — and
publish an established Position. Guardrails preserved in the UI itself: "Raise & accept" is two
recorded audit steps, never one; a suppressing stance offers the `review_by` date the disposition
watcher enforces; an `inferred` proposal is labeled "policy cannot auto-accept this; you can" —
the buttons ARE the human decision T4 reserves. The `/whoami` identity is the recorded
proposer/actor, which is one more reason real authentication (GUI-6) must precede any deployment
where "who decided" matters.

## The two styles (decided on the VM, first round)

First VM review narrowed four candidates to two, switched by a **single toggle** in the topbar
(☀ Enterprise ↔ ☾ Midnight; persists in `localStorage`). Verdigris and Terminal were retired —
their deletion was one CSS block each, which is what the token contract was for.

| Theme | Character |
| --- | --- |
| **Enterprise** | Light. White cards on pale gray, blue primary, pastel stat tiles — the `gui-example.jpeg` language. |
| **Midnight** | Dark slate, brighter blue — the same layout for a dark-preferring ops room. |

Two things are the same in both, on purpose: the **status/band colors are fixed** (dataviz
rule — status is never themed) and **every identifier (CVE, PURL, version) is a mono chip**.

**Signature element:** the priority bar-in-cell. Track = `effective_priority`, fill =
`residual_priority`. A suppressed Finding keeps its full track with an empty fill — GOV-14's
"dispositioned, not deleted" drawn as a mark.

## First VM round — what changed (2026-08-11)

Eight items of live feedback, all landed the same day: themes 4 → 2 behind a toggle · CVE cells
never wrap (`white-space: nowrap`; the table scrolls instead) · an **estate-wide donut** on the
overview (every release's posture, aggregated by exploitability band — one DASH-2 read per
release, fanned out in parallel) · the topbar node-status dots removed · quick links cut to
Releases + Feed health · a **user chip** top-right fed by `/whoami` (`THEMIS_DASHBOARD_USER`,
default `operator` — the seam real authentication will answer through, which is deferred to its
own change) · an **SBOM manager** tab: cascading product/project/release selects, format
auto-detect (CycloneDX/SPDX), upload with the dedup answer said out loud (byte-identical →
"already registered"), and the release's evidence list.

Vocabulary note on the donut: the request said criticals/high/medium/low/informational; the
platform's own severity vocabulary is the exploitability **band** (critical · high+ · high ·
elevated · informational), which the posture rollup already carries — raw CVSS severity would
cost one Knowledge read per finding. The donut therefore shows bands; swapping to CVSS severity
is possible if wanted, at that read cost.

Also fixed on first contact: the finding drawer rendered permanently open (author `display:flex`
beats the `hidden` attribute — fixed with the standard `[hidden]{display:none !important}`
reset), which had been covering the theme controls.

## Second round — the AI×GUI batch (2026-08-12)

Planned and decided in [`GUI-UPGRADE-PLAN.md`](GUI-UPGRADE-PLAN.md) (D1–D6), shipped the same
day: **GUI-7** (an AI recommendation appears without a second click — reload + one-shot
highlight + an honest "may take a minute" progress label), **GUI-8** (the remediation-plan
card on the posture view), **GUI-9** (AI transparency — the six-reason no-answer taxonomy as a
persistent panel, `local-only` chips, `decided_by`/`precedents_used` provenance chips). The
principle behind all three: the harness was built honest, and the GUI must not launder that
honesty into a spinner and a vanishing toast.

## Data-viz compliance notes

One chart (the exploitability-band distribution bar) + stat tiles; the posture table is the
table view. Band → color: critical `#d03b3b` · high+ `#ec835a` · high `#fab219` (the fixed
status palette) · elevated = sequential blue · informational = neutral gray.

`validate_palette.js` was run against the light (`#ffffff`) and dark (`#131a29`) card surfaces.
It reports FAILs — **expected and dispositioned**: the validator's scope is *categorical*
palettes, and this is the fixed *status* scale, which the palette doc exempts from re-stepping
and mitigates by icon+label pairing. What the run still surfaced and what was fixed because of
it: white text on the amber/orange segments was near-invisible (→ dark ink on those fills), and
serious↔warning sit adjacent below the normal-vision floor (→ segments carry the band **name**,
not just a count, whenever the width allows; 2px gaps; legend chips; hover tooltips). Identity
never rides on hue alone.

## Run it — locally

```sh
go build -o bin/dashboard ./cmd/dashboard
./bin/dashboard
# open http://localhost:8090 — node URLs default to the runbook ports
```

`THEMIS_DASHBOARD_ASSETS=cmd/dashboard/static` serves assets from disk instead of the embedded
copy — edit-and-refresh while iterating on a theme.

## Run it — on the VM (paste-safe)

```sh
# on the VM, from the repo root, after git fetch + checkout gui/dashboard-spike:
git fetch origin
git checkout gui/dashboard-spike
go build -o bin/dashboard ./cmd/dashboard

# same env file the other nodes use; the dashboard needs only the URLs (+ key if auth is on).
# THEMIS_API_KEY is the token authadmin printed — the proxy injects it, the browser never sees it.
THEMIS_DASHBOARD_ADDR=:8090 \
THEMIS_REGISTRY_URL=http://localhost:8082 \
THEMIS_EVIDENCE_URL=http://localhost:8081 \
THEMIS_KNOWLEDGE_URL=http://localhost:8085 \
THEMIS_GOVERNANCE_URL=http://localhost:8083 \
THEMIS_COMMUNICATION_URL=http://localhost:8084 \
THEMIS_INTELLIGENCE_URL=http://localhost:8086 \
  nohup ./bin/dashboard > logs/dashboard.log 2>&1 &

# verify from the VM shell:
curl -s -o /dev/null -w "%{http_code}\n" localhost:8090/
curl -s localhost:8090/api/knowledge/feeds | head -c 200; echo
```

Reaching it from a workstation browser (the VM is firewalled): either open a firewall port for
8090, or tunnel it:

```sh
# from the WORKSTATION (replace user/host):
ssh -L 8090:localhost:8090 user@vm-host
# then browse http://localhost:8090
```

## What this spike is deliberately missing

- **Auth on the dashboard's own inbound edge** — the proxy holds the node key, but `:8090`
  itself is open; on the VM that is acceptable behind the firewall/tunnel, and a real version
  wires `internal/platform/auth` like every other node.
- **Evidence views** (raw SBOM/VEX browsing) and **Faultline-centric navigation** — posture-first
  was the bet; testing will say if it was right.
- **Tests** — `cmd/*` is outside the coverage gate like the other six cmds; a real version gets
  a handler/proxy test and a registered package.

File anything the VM days surface in `docs/BACKLOG.md` under a `GUI-` prefix.
