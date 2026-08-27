# EDR-ENHANCE-T3 — Enhancement Tier 3: enterprise & platform capabilities

**Status: PROPOSED (2026-08-21) — no implementation until the user confirms.**
Capability work that makes Themis consumable by an enterprise around it — delivery, integration,
scale. Enters the queue after T2 correctness per the board's standing rule; within the tier, the
R-table order (R2 → R3) governs.

## Scope

| Item | Tracking | What |
| --- | --- | --- |
| Structured AI-proposal fields | **R2** | An AI proposal records confidence/model/basis as prose in `rationale`; a confidence-threshold policy has nothing machine-readable to read. Add typed fields (additive) to the Governance proposal |
| Delivery channels | **R3** | Communication's delivery mechanics (exactly-once, idempotent, outcome-recorded) are done; the only channel is a log line. Add **SMTP** and **webhook** deliverers behind the existing port; Slack/Teams ride the webhook shape |
| **F2** | parity | The HMAC webhook verifier shipped in `internal/platform/auth` but no route mounts it — mount it on the webhook intake when R3's webhook channel lands (they pair naturally) |
| **GUI-15** *(new, filed with this roadmap)* | — | Second in-browser scanner translator — **Grype first** (closest shape to Trivy), Xray/Black Duck by demand. Each is a pure function + detector registration per EDR-GUI-01 D16; GUI-10's harness (T1) is the prerequisite quality gate |
| GUI-3 ✅ · GUI-5 ✅ | — | ✅ SHIPPED 2026-08-27 (EDR-VEX-01 D10/D11, with the distro-feed cluster) — Red Hat `changes.csv` modified-since gate; Rocky RXSA errata feed |
| Kafka transport swap | M5 maturation | A real broker behind the same kernel `Envelope` + ports — the bus database was built as its stand-in. Tracked as a maturation, **not proposed for this pass**: no current scale signal demands it, and doing it without one is résumé-driven engineering |

## Decisions to confirm before code

1. **R2 field set**: minimum viable = `confidence` (0–1), `model_id`, `decided_by` (already
   threaded), `grounding_refs`. Additive columns + additive API — but it is a Governance domain
   change, so it earns its own numbered decision in EDR-GOVERNANCE-01 when confirmed.
2. **R3 channel order**: SMTP first (universally consumable, zero receiver work) then webhook
   (composes with F2's verifier). Config per channel via env (R2 conventions); a failed delivery
   already records its outcome — no new failure semantics.
3. **GUI-15 timing**: only after GUI-10's harness (T1) so the second translator is born tested.
4. **Feed items** (GUI-3/GUI-5) are self-contained ACL work under EDR-VEX-01's existing decisions —
   confirmation is scheduling, not design.

## Delivery order

R2 → R3 (SMTP → webhook + F2) → GUI-15 → GUI-3/GUI-5. Kafka swap stays parked until a measured
scale signal exists.

## Impact

`internal/governance` (proposal fields + migration + API additive), `internal/communication/adapters`
(two deliverers + wiring + env), `internal/platform/auth` route mount, `cmd/dashboard/static/app.js`
(GUI-15), `internal/knowledge/adapters` feeds. R2 and R3 both touch API surfaces ⇒ each needs its
spec-first pass and its own EDR entries when confirmed.
