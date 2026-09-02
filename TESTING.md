# Themis — Testing Guide

How to exercise a running Themis manually, plus the developer test suite. Setup lives in
[INSTALLATION.md](INSTALLATION.md); the HTTP surface is in [API.md](API.md).

- [Part A — Phase-3 services](#part-a--phase-3-services) (incl. the Intelligence Gateway)
- [Part B — v0.3.x end-to-end SBOM flow](#part-b--v03x-end-to-end-sbom-flow)
- [Troubleshooting](#troubleshooting)
- [Developer test suite](#developer-test-suite)

---

## Part A — Phase-3 services

Each service serves under `/api/v1` on its own port ([API.md](API.md)). Health first:

```sh
curl -s localhost:8083/api/v1/findings?release=x\&faultline=y   # Governance up → 404 Problem (expected)
```

### Intelligence Gateway (reactive AI enrichment)

The Gateway grounds a Governance **Finding** (+ its Knowledge **Faultline**) and returns a validated
**advisory** Proposal — or `204` "no proposal" (a first-class safe outcome). It is stateless and optional.

**1. Fake-provider smoke test (no model, no dependencies).** Proves the service + 3-stage validation are
wired. It returns **`204`** because the fake's canned output doesn't match the subject — that's success:

```sh
THEMIS_INTELLIGENCE_PROVIDER=fake go run ./cmd/intelligence &     # :8086
curl -s -o /dev/null -w '%{http_code}\n' -X POST \
  localhost:8086/api/v1/capabilities/recommend_position/invoke \
  -H 'Content-Type: application/json' -d '{"finding_id":"any-id"}'   # → 204
```

**2. Real reactive invoke (Ollama + grounding).** For a `200` + Proposal the Gateway must reach the
Governance + Knowledge read APIs to assemble the Finding + Faultline, and the model output must pass
validation:

```sh
# native Ollama on macOS (Metal GPU); a Mac container is CPU-only
ollama serve & ; ollama pull llama3.1:8b
THEMIS_GOVERNANCE_URL=http://localhost:8083 \
THEMIS_KNOWLEDGE_URL=http://localhost:8085 \
THEMIS_OLLAMA_URL=http://localhost:11434 \
go run ./cmd/intelligence &

curl -s -X POST localhost:8086/api/v1/capabilities/recommend_position/invoke \
  -H 'Content-Type: application/json' -d '{"finding_id":"<a real finding id>"}' | jq .
# 200 + {capability, finding_id, stance, confidence, evidence[], reasoning, ...}, or 204 if it declines.
```

> **Grounding caveat (today):** the Knowledge standalone service wiring lands with the M5 event bus, so
> `THEMIS_KNOWLEDGE_URL` needs either a running Knowledge read API or a stub returning a `FaultlineView`
> ([API.md](API.md)). The **automated** grounding→validation→proposal path is fully proven without any of
> this — see `go test ./internal/intelligence/...` (`e2e_test.go` drives the whole stack over httptest).

**Automated real-model check.** `make e2e-llm` runs the shipped capabilities —
`recommend_position` (Decision, one Finding), `plan_remediation` (Information, one Release) and
`explain_vulnerability` (Information, one Finding — GUI-1) — over a **real** OpenAI-compatible server and
asserts the output passes validation (`200` with an `llm:<stance>` provenance for a Decision, `200`
carrying `information` for a plan/explanation, or an honest `204`).

**Why a real model and not a fake.** The prompt and the Grounding Verification gate are an interface with
**no compiler between them**, and a fake provider returns whatever the test author already believed — so a
fake can never surface a disagreement between the two. Measured 2026-08-07: every fake-provider test passed
while the live `plan_remediation` capability was refused **three times running**, each for a citation form
the prompt had invited and the gate rejected. A `204` whose reason is `business_invalid` therefore **fails**
this test: a declined recommendation is the seam working as designed, an ungrounded citation is our own two
halves disagreeing.
The provider is a pure OpenAI-compatible client, so it works with **Ollama**, **LM Studio**, or **vLLM** — but
they differ on two knobs the provider now supports: an optional bearer token (`THEMIS_LLM_API_KEY`) and the
structured-output mode (`THEMIS_LLM_RESPONSE_FORMAT`: empty `json_object` for Ollama; `json_schema` for LM
Studio / OpenAI; `text`; `none`). It **skips** when no server is up, so it never blocks CI:

```sh
# Ollama:
THEMIS_LLM_URL=http://localhost:11434 THEMIS_LLM_MODEL=llama3.1:8b make e2e-llm
# LM Studio (Require-API-Key ON; bind may be a LAN IP, not localhost; needs json_schema):
THEMIS_LLM_URL=http://<host>:1234 THEMIS_LLM_MODEL=<model> \
  THEMIS_LLM_API_KEY=<key> THEMIS_LLM_RESPONSE_FORMAT=json_schema make e2e-llm
```

Verified 2026-07-25 against LM Studio (WhiteRabbitNeo-V3-7B) → a validated `affected` proposal in ~16s.
Re-verified 2026-08-07 against Ollama (cyberpal20b) → a grounded remediation plan in ~73s.

**Router tiers (phase3-intelligence-router).** To exercise escalation live, pull a second model
(`ollama pull <bigger-model>`), set `THEMIS_INTELLIGENCE_MODEL_ESCALATION=<bigger-model:tag>` on the
Intelligence node, restart, and invoke `recommend_position` against a Finding known to decline (the
all-`scope` carrier cases are reliable decliners). The journal's `capability invoked` line then carries
`tier=escalation` — either with a produced proposal (the bigger model extracted more from the same
grounding) or with `reason=insufficient` ("the bigger model could not tell either", the telemetry
G-AI-2b exists for). Degrade-not-fail is the same shape with `_MODEL_ECONOMY` plus a small
`THEMIS_INTELLIGENCE_BUDGET_TOKENS`/`_WINDOW`: near-exhausted invocations log `tier=economy`; fully
exhausted ones still answer `budget_exhausted`.

> **This file did not compile for several days** (until 2026-08-07), because a refactor renamed the read
> seam it used and **no gate ever set `-tags=llm`**. A tagged file is invisible to `go build`, `go vet` and
> the test run unless its tag is set. `make vet-tags` — now part of `check` and `check-ci` — type-checks
> `integration`, `e2e`, `llm` and `postgres` in seconds, which is the difference between a tagged test being
> opt-in and being abandoned.

**Timeouts: raise BOTH sides.** Three deadlines govern one recommendation and the shortest decides —
`THEMIS_INTELLIGENCE_TIMEOUT` on Governance, and `THEMIS_LLM_TIMEOUT` on Intelligence (which drives the
provider client *and* the Gateway's runaway guard). Both default to `60s`. Raising only the Intelligence
side leaves Governance hanging up first, and the Gateway then logs `provider_error` for what is really a
caller-side timeout.

**3. The human-triggered Governance seam.** A human asks Governance for an AI recommendation; Governance
(when AI is enabled) invokes the Gateway and records an **advisory AI proposal** — never auto-accepted:

```sh
# enable AI on the Governance service:
export THEMIS_GOVERNANCE_AI_ENABLED=1 THEMIS_INTELLIGENCE_URL=http://localhost:8086

# A Finding is born when an SBOM component matches a card and the ComponentMatched event crosses the M5 bus
# to Governance. Drive one end-to-end (INSTALLATION.md § 5), then grab a Finding id from the release posture:
FID=$(curl -s "localhost:8083/api/v1/releases/$RID/posture" | jq -r '.[0].finding_id')
curl -s -o /dev/null -w '%{http_code}\n' -X POST localhost:8083/api/v1/findings/$FID/recommend
# an advisory AI proposal is recorded (actor=ai); 204 → AI off / unavailable / declined.
curl -s localhost:8083/api/v1/findings/$FID | jq '.proposals'   # inspect the advisory proposal
```

**4. Disable gate.** With `THEMIS_GOVERNANCE_AI_ENABLED` unset (or `cmd/intelligence` not running),
`POST /findings/{id}/recommend` returns `204`, no proposal is recorded, and Governance makes **zero**
outbound calls — the pipeline is unchanged. "Off", "down", and "declined" all collapse to the same `204`.

**5. Δ2 — the two-step `[Rule → LLM]` recommendation (deterministic-first).** `recommend_position` now runs a
**version-range rule first** and calls the model only when the rule can't decide:

- **Provably out of range → deterministic `not_affected`; the model is never called.** The response carries
  `"decided_by":"rule:not_affected"`. Fastest proof — no model, no services:

  ```sh
  go test ./internal/kernel/value/ ./internal/intelligence/...   # version-range engine + the whole Δ2 flow
  ```

  Over the wire, this needs grounding where the installed component version is **outside** the Faultline's
  `affected_ranges` (e.g. component `pkg:golang/x@2.0.0` vs range `<1.2`). The model may return `affected` and
  the Gateway still answers `not_affected` — the rule wins. `internal/intelligence/adapters/http/e2e_test.go`
  (`TestE2ERuleShortCircuitsOverTheWire`) drives exactly this over httptest.
- **In range / unknown ecosystem / no range → the model runs** (item 2); the response carries
  `"decided_by":"llm:<stance>"`.
- **Honest "can't determine".** When the model declines (`recommended_stance:"insufficient"`) or the facts are
  too thin, the Gateway returns **`204`** — a first-class **non-error** "no recommendation", distinct from AI
  being off. The recorded Governance rationale keeps the provenance, e.g. `AI recommendation [llm:affected] …`.
- **Richer grounding (precedent).** On the model path the Gateway also pulls our **own past Positions on the
  same CVE** from other releases (composed from Governance's `blast-radius` + `find-by-key`) and labels them
  into the prompt as *context, not instruction*. A rule short-circuit pulls **no** precedent (no wasted read).
- **Admission gate.** Before the model is called the prompt is **secret/PII-redacted**, the path is marked
  **local-only**, and a **runaway-prompt / timeout guard** turns an oversize prompt or a hung provider into a
  safe `insufficient` (never a hang). The per-call cost (`InputBytes`, tokens, duration) is metered on the
  telemetry record. Budget *enforcement* + data-classification are deliberately deferred (see
  `docs/BACKLOG.md` G-AI-4 / G-AI-5).

**6. Δ3a — semantic precedent (RC-1): a prior decision changes the recommendation.** With a store configured,
`recommend_position` runs `[Rule → Knowledge → LLM]`: the Knowledge step embeds the Finding and retrieves
semantically similar **past** Positions (a *different* CVE on the same component/bug-class) from the
Operational Semantic Index, labeled into the prompt with a similarity score. Fastest proof — no DB, no model:

  ```sh
  go test -run TestDemoSemanticPrecedentChangesRecommendation ./internal/intelligence/adapters/wiring/
  ```

  It asserts the demo directly: a cold index recommends `affected`; after a similar `not_affected` precedent is
  indexed, the retrieved precedent flips the recommendation to `not_affected` (and `PrecedentsUsed` on the
  telemetry rises 0 → 1). The store + exactly-once bus population is proven under `embedded-postgres`
  (`go test -tags=integration ./internal/intelligence/adapters/store/`). To run it live, set
  `THEMIS_DATABASE_DSN` + `THEMIS_BUS_DATABASE_DSN` on the Intelligence node (INSTALLATION.md); the index is
  **cold-start-safe** — until it warms up, the Gateway falls back to exact-CVE precedent, so behavior degrades
  gracefully, never breaks. After changing `THEMIS_INTELLIGENCE_EMBED_MODEL`, restart once with
  `THEMIS_INTELLIGENCE_REBUILD=1` to re-embed the whole index.

**Choosing the embedding model (R5).** `make e2e-embed` runs an opt-in retrieval-quality eval: it embeds a
labeled corpus (findings grouped by shared component) with each candidate model + text composition and prints
recall@1/@3 + MRR + embed latency, so you pick the best `THEMIS_INTELLIGENCE_EMBED_MODEL`. Needs a live Ollama
(or any OpenAI-compatible embedding server); SKIPS otherwise; not part of `make check`:

```sh
THEMIS_EMBED_MODELS=nomic-embed-text,mxbai-embed-large make e2e-embed

# point it at a non-default embedding server (default http://localhost:11434):
THEMIS_EMBED_URL=http://ollama-box:11434 THEMIS_EMBED_MODELS=nomic-embed-text make e2e-embed
```

**Run 2026-08-05 on the VM Ollama:** `nomic-embed-text` with the `components+severity` composition scored
recall@1 = 1.00, MRR = 1.00 at ~46 ms. Adding the CVE id was neutral; adding the description **hurt**
(recall@1 = 0.83) — a longer text is not a better embedding when the discriminating signal is the component
set. No model change was needed; detail in `docs/engineering/RAG-SESSION-2-SPIKE.md` §4.

#### Precedent without a model — `GET /findings/{id}/similar`

The retrieval half of Δ3a, served directly to a human. **No model runs**, so this is the fastest way to
tell whether the semantic index is working — and it isolates a retrieval problem from a generation one,
which a `204` from `recommend_position` cannot.

```sh
# what have we already decided that looks like this Finding?
curl -s "localhost:8086/api/v1/findings/$FID/similar?k=5" | jq .

# widen to the subject's own release ("what else did we decide here?")
curl -s "localhost:8086/api/v1/findings/$FID/similar?include_same_release=true" | jq .
```

Reading the result:

- `precedents: []` — the index is reachable and nothing resembles this Finding. Normal on a young
  deployment: the index holds only decisions that have actually been made.
- **`score: 0`** — an exact-CVE match, found by lookup rather than similarity. It is not "least similar";
  it means the semantic index returned nothing and the fallback answered.
- **`source_cve` differing from the subject's CVE is the point**, not a bug. Matching across CVEs on a
  shared component is what RC-1 exists to do.
- **Contradictory stances in one result set** are informative here and are also the exact condition under
  which `recommend_position` returns `204 insufficient` — the model declines rather than guessing between
  two of your own past decisions. Seeing both is how you confirm that is what happened.
- `404` — either no such Finding, or this node has no retrieval plane (no `THEMIS_DATABASE_DSN` on the
  Intelligence node). A node that cannot look says so instead of returning an empty list.

To prove the seam is shared, invoke `recommend_position` on the same Finding: its `precedents_used` count
must equal the number of items this endpoint returns.

### Other services (per-context APIs)

Each context is testable in isolation via its own API ([API.md](API.md)) — e.g. register a Release
(`POST :8082/api/v1/releases`), register Evidence (`POST :8081/api/v1/evidence`), read a Finding's posture
(`GET :8083/api/v1/releases/{id}/posture`), preview a Publication (`POST :8084/api/v1/previews`).

### Composed pipeline end-to-end (`make e2e-pipeline`)

The **M5 event bus** now carries the whole flow. `make e2e-pipeline` runs the in-process composed runner
(`tests/pipeline`, build tag `e2e`): it starts one embedded Postgres, creates a database per context plus the
`bus` database, wires all four contexts, and drives them **only over the bus** — no Docker, no external infra.

```sh
make e2e-pipeline
```

`TestPipeline_SBOMToPublishedVEX` pushes an SBOM into Evidence and asserts, purely over the read/triage/publish
HTTP APIs (no internal-state peeking), that a **published OpenVEX** artifact with the expected stance comes out
the other end: Evidence → (bus) → Knowledge correlates a Faultline → (bus) → Governance opens a Finding → a
human governs an **affected** Position → (bus) → Communication publishes the OpenVEX. It skips cleanly if
embedded Postgres is unavailable, and is **not** part of `make check` (e2e is slow; it runs post-merge in CI
alongside `make e2e-evidence`).

### Vendor-VEX capabilities (EDR-VEX-01: suppression + Red Hat + CSAF-VEX + fixed verdict)

The full manual walkthrough is [INSTALLATION.md § 5a](INSTALLATION.md#5a-test-vendor-vex-suppression--the-fixed-verdict-edr-vex-01); enable the feeds per [§ 4b](INSTALLATION.md#4b-enable-enrichment-feeds-optional). What each capability should show:

- **Uploaded-VEX suppression (Phase 2).** Upload an OpenVEX `not_affected` for a carded CVE's package → the
  card's `applicabilities` gains the statement (`GET :8085/api/v1/faultlines?cve=<CVE>`), Governance raises a
  **system `not_affected` Proposal** on the affected Finding (`GET :8083/api/v1/findings/<FID>` → a
  `proposer_kind:"system"`, `stance:"not_affected"`, `status:"proposed"` proposal), and accepting it flips the
  Position → the Finding drops from `GET :8083/api/v1/releases/<RID>/posture`. It is **never auto-suppressed**.
- **Red Hat feed (B3).** With `THEMIS_REDHAT_ENABLED=1`, a carded CVE Red Hat rates gains authoritative
  severity, and a Red Hat `not_affected` folds the same applicability automatically (no upload). Confirm the
  feed is live via `GET :8085/api/v1/feeds` → `redhat` healthy (tier 2). Covers RHEL and its 1:1 rebuilds
  (Rocky, Alma).
- **CSAF-VEX feed (B4).** With `THEMIS_VEXFEED_ENABLED=1` + `THEMIS_VEXFEED_URLS=<bases>`, generic vendor
  `not_affected` statements fold per carded CVE; `GET :8085/api/v1/feeds` → `vexfeed` (tier 3).
- **Stream-scoped fixed verdict (B3/PR3).** An SBOM whose `pkg:rpm/...` component is **at or above** its
  same-EL-stream Red Hat fix produces **no Finding** for that occurrence (already patched). A cross-stream
  fix (an el9 fix vs an el8 install) is deliberately never applied — verify a genuinely-vulnerable el8 build
  below its el8 fix **does** still open a Finding (the conservative direction never hides a live vuln).

---

### Scanner reports + the re-discovery sweep (KN-SCAN-1 / KN-RECOR-1)

**Upload an image-scan report** (kept current between SBOM uploads — the scanner is a second
detection engine at Asserted trust; it never sets truth). The curated document is
`{"findings":[…]}` where each finding carries the scanner-ACL record fields **plus the component
it names**. Convert Trivy JSON with jq, then POST it as evidence:

```sh
trivy image --format json --output trivy.json <image:tag>
jq '{findings:[.Results[] as $r | $r.Vulnerabilities[]? | {cve:.VulnerabilityID,
     observed_at:(now|todate), scanner:"trivy", severity:.Severity,
     cvss_score:(.CVSS.nvd.V3Score // 0), cvss_vector:(.CVSS.nvd.V3Vector // ""),
     affected:[], fixed:(if .FixedVersion then [.FixedVersion] else [] end),
     component:{purl:(.PkgIdentifier.PURL // ""), name:.PkgName,
                version:.InstalledVersion,
                ecosystem:(($r.Type // "") | {"python-pkg":"pypi","node-pkg":"npm","gobinary":"golang",
                           "gomod":"golang","jar":"maven","pom":"maven","gemspec":"gem"}[.] // .),
                source:""}}]}'   trivy.json > scan-report.json
# POST like an SBOM but kind=scanner-report (see gf-upload-sbom.sh for the envelope shape)
```

Findings the translation cannot use are skipped and counted, never fatal — one malformed
finding must not void a 400-finding report.

**Or skip the jq entirely:** the dashboard's SBOM-manager form accepts **raw Trivy JSON**
directly — the same translation runs in the browser (EDR-GUI-01 D16; the server only ever
sees the curated document), the Kind selector flips to "Scanner report" automatically, and
the file note shows the finding count plus how many were skipped. Either road, the release
posture's **Scans** card (D15) then lists the report with its per-scan view: every claim
the tool asserted joined by CVE to the enterprise posture, with asserted / matched /
decided / no-Finding counts.

**Verify a fix build** (IDEA-1's operator half): the dashboard's **Compare** tab diffs two
releases of the same project by CVE — **fixed** (Finding on the baseline, none on the
candidate: absence proven by new evidence), **new**, and **persisting**, each row deep-linking
to its Finding. It refuses to diff against a release with no evidence filed — a missing SBOM
would wrongly read as "everything fixed". Client-side over the two posture reads; no endpoint.

The `ecosystem` mapping exists because Trivy speaks its own vocabulary (`python-pkg`,
`node-pkg`, …) where the pipeline speaks purl types (`pypi`, `npm`) — measured live
2026-08-14: a Trivy setuptools finding landed as ecosystem `python-pkg` beside discovery's
`pypi` for the same package. Harmless (an unknown ecosystem never filters and never hides —
the KN-FIX-3 fail-safe), but mapped here so the two roads read as one ecosystem; the durable
in-code canonicalization is KN-SCAN-3.

**Occurrence verdicts + the ownership bridge (EDR-VERDICT-01, KN-VERDICT-1).** Every examined
component is now recorded WITH a verdict — `open` or `cleared_vendor_fix` — instead of a fixed
occurrence being silently dropped (discovery) or recorded unjudged (scanner). A clearance
carries an evidence grade and a plain-language reason on the Governance posture
(`verdict_state` / `verdict_grade` / `verdict_reason` per component, `open_carriers` per
entry): `observed` = direct evidence (the component's own build vs the vendor bound, or an
explicit SBOM ownership edge — Syft SPDX `ownership-by-file-overlap`), `inferred` = a labeled
same-inventory match (the rpm whose fix-attribution key and exact upstream version match the
language row — the CVE-2025-47273 `setuptools@39.2.0`-shadow-of-a-patched-rpm shape).
`THEMIS_VERDICT_INFERRED_BRIDGE=0` is strict mode (guess grade off). A finding leaves the
ranked queue only when EVERY carrier occurrence is cleared (`open_carriers=0` ⇒
effective/residual read 0); one live carrier keeps full urgency. To verify: check the posture
entry for a CVE whose distro copy is patched — the shadow row reads cleared-with-reason while
a pip-installed copy below the upstream fix stays open, and the finding stays queued.

**Watch a re-discovery sweep** (default ON): `journalctl -u themis@knowledge | grep re-discovery`
— every sweep logs `releases` and `new_matches`, including zeros ("nothing was stale" and "the
sweep stopped working" must not look alike). A non-zero `new_matches` is the headline event: a
CVE reached inventory nobody re-uploaded. To force one, set `THEMIS_REDISCOVERY_STALE_AFTER=1m`
temporarily and restart — every correlated release becomes due on the next tick.

### Trust model (EDR-TRUST-01)

The trust model is exercised entirely by the unit/integration suite — no live stack needed.

```sh
# Evidence trust classes + monotonic propagation (the invariant everything else rests on)
go test ./internal/kernel/value/ -run 'Trust|MaxTrust' -v

# Source classification, and the guard that fails the BUILD when a shipped source is unclassified
go test ./internal/knowledge/domain/ -run 'TrustPolicy|Reconcile.*Trust' -v
go test ./internal/knowledge/adapters/wiring/ -v

# The constitutional bar: Inferred evidence is never auto-accepted, under any policy
go test ./internal/governance/domain/ -run 'Constitutional|Inferred|Launder' -v
go test ./internal/governance/app/  -run 'InferredEvidence|ObservedEvidence' -v

# Deterministic version-range inference, incl. the distro-backport precision guard
go test ./internal/governance/domain/ -run ProvablyOutOfRange -v

# Reservations: derived from immutable Position inputs, never stored — and the LIFTING path
go test ./internal/governance/domain/ -run Reservation -v

# The trust class must survive persistence (integration; embedded Postgres)
go test -tags=integration -run 'TrustRoundTrips|PostureSurfacesReservation' \
  ./internal/governance/adapters/store/ -v
```

**What to look for.** `TestMaxTrust_DeterministicRuleCannotLaunderInferredEvidence` is the one that
justifies the whole model: a *deterministic* rule consuming one AI-derived fact still yields an
`Inferred` conclusion. Producer-based classification cannot see that case, because it asks who spoke
last. `TestProposalEvidenceTrustRoundTrips` asserts the constitutional **verdict** is identical either
side of a save/reload — not merely that the string survived.

### Domain Projections and the AI Runtime contract (T10)

```sh
# The runtime gathers nothing: one business-named projection, no composition
go test ./internal/intelligence/adapters/readapi/ -run Assessment -v

# Grounding Verification anchors to the AUTHORITATIVE projection, not to a shaped view
go test ./internal/intelligence/domain/ -run GroundsAnchors -v

# Replayability: the whole capability runs from a recorded JSON fixture — no DB, no services
go test ./internal/intelligence/adapters/http/ -run Replays -v

# Capability classes: an Information Response has no path to enterprise truth
go test ./internal/intelligence/app/ -run 'Information|Decision' -v

# Business Verification: Governance refuses a claim it cannot vouch for
go test ./internal/governance/app/ -run BusinessVerification -v
```

**Replaying a projection by hand.** A Domain Projection is deterministic and self-contained, so
reproducing a reasoning failure means capturing one document rather than two services' states:

```sh
curl -s localhost:8083/api/v1/findings/<finding-id>/assessment | tee /tmp/projection.json
```

Serve that file from any static endpoint, point `THEMIS_GOVERNANCE_URL` at it, and the capability
replays exactly.

## Part B — v0.3.x end-to-end SBOM flow

Exercises the frozen `cmd/themis` monolith (setup in [INSTALLATION.md § Part B](INSTALLATION.md#part-b--v03x-single-binary-cmdthemis)).
Reuse the shell variables across steps.

> **One-command release smoke test:** [`scripts/release-smoke-test.sh`](scripts/release-smoke-test.sh) runs
> this whole flow automatically — build → **fresh DB** → run → register + upload `scripts/oamp.json` → poll
> ingestion → verify components → list vulnerabilities (baseline snapshot). It is destructive (drops the
> database) and long-running (~1–3 min); run it in the background. Then re-run
> [`scripts/list-open-vulns.sh`](scripts/list-open-vulns.sh) after a delay to watch CVE severities enrich over
> time via its snapshot diff. The manual steps below are the same flow, unrolled.

```sh
export BASE_URL="http://localhost:8080"
export API_KEY="<from: ./bin/themis admin create-key --admin --expires 90d>"
export SBOM_FILE="./myapp.cyclonedx.json"        # your CycloneDX 1.4/1.5/1.6 file
export IMAGE_REF="myregistry/myapp:1.2.3"
export IMAGE_DIGEST=$(docker inspect "$IMAGE_REF" --format '{{.Id}}')   # or any sha256:<64hex> for testing
```

**1. Product, artifact, upload.** The trust gate requires the digest be registered before upload; the
returned artifact `id` is the `artifact_id` you upload against (idempotent by digest):

```sh
export PRODUCT_ID=$(curl -s -X POST "$BASE_URL/api/v1/products" -H "X-API-Key: $API_KEY" \
  -H 'Content-Type: application/json' -d '{"name":"my-app"}' | jq -r .id)

export ARTIFACT_ID=$(curl -s -X POST "$BASE_URL/api/v1/products/$PRODUCT_ID/artifacts" \
  -H "X-API-Key: $API_KEY" -H 'Content-Type: application/json' \
  -d "$(jq -n --arg d "$IMAGE_DIGEST" --arg repo "${IMAGE_REF%%:*}" \
    '{image_digest:$d, version:"latest", repository:$repo}')" | jq -r .id)

export INGESTION_ID=$(curl -s -X POST "$BASE_URL/api/v1/sbom/upload" -H "X-API-Key: $API_KEY" \
  -H 'Content-Type: application/json' -H "Idempotency-Key: upload-$(date +%s)" \
  -d "$(jq -n --slurpfile doc "$SBOM_FILE" --arg spec "$(jq -r '.specVersion // "1.6"' "$SBOM_FILE")" \
    --arg aid "$ARTIFACT_ID" --arg dg "$IMAGE_DIGEST" \
    '{format:"cyclonedx", spec_version:$spec, document:$doc[0], artifact_id:$aid, image_digest:$dg, ci_job_id:"test"}')" \
  | jq -r .ingestion_id)
```

Expect **`202 Accepted`** (queued, not done). Re-uploading the **same bytes** is idempotent (no new scan).

**2. Poll to a terminal state, then inspect:**

```sh
until S=$(curl -s "$BASE_URL/api/v1/ingestions/$INGESTION_ID" -H "X-API-Key: $API_KEY" | jq -r .status); \
  [[ "$S" =~ ^(NOTIFIED|COMPLETED|FAILED|REJECTED)$ ]]; do
  curl -s "$BASE_URL/api/v1/ingestions/$INGESTION_ID" -H "X-API-Key: $API_KEY" | jq '{status, stage_detail}'; sleep 2
done; echo "final=$S"

export PROJECT_ID=$(curl -s "$BASE_URL/api/v1/products/$PRODUCT_ID/projects" -H "X-API-Key: $API_KEY" | jq -r '.items[0].id')
export SCAN_ID=$(curl -s "$BASE_URL/api/v1/projects/$PROJECT_ID/scans" -H "X-API-Key: $API_KEY" | jq -r '.items[0].id')
curl -s "$BASE_URL/api/v1/scans/$SCAN_ID/vulnerabilities" -H "X-API-Key: $API_KEY" | jq '.items | length'
curl -s "$BASE_URL/api/v1/status?top=10" -H "X-API-Key: $API_KEY" | jq .
```

On `FAILED`/`REJECTED`, `stage_detail` is the authoritative reason (trust gate, parse, OSV, or DB constraint).

> **Helper scripts** wrap this flow: [`scripts/upload-sbom.sh`](scripts/upload-sbom.sh) `-f <sbom> -i
> <artifact_id> -d <digest>` posts + reports the ingestion; [`scripts/list-open-vulns.sh`](scripts/list-open-vulns.sh)
> auto-discovers an API key + product ids and prints the **open** findings (filtered by `effective_state`) with a
> day-over-day snapshot diff. See [API.md](API.md#vulnerability-listing-filters--pagination) for the filters.

### What "good" looks like

| Field (`GET /status`) | Ready value |
| --------------------- | ----------- |
| `components.total_registered` | > 0 |
| `vulnerabilities.total_findings` | > 0, with `by_severity` / `by_state` populated |
| `signals_stale` | **`false`** once EPSS/KEV have synced |

`findings < components` is **normal** (version ranges, unmapped `rpm`, no OSV entry). Feeds run on background
tickers (default 24h) then back-fill open findings via `ReEnrichJob` — no re-upload needed.

### SBOM correlation & OSV (when components exist but findings don't)

Findings come from matching SBOM **components (by PURL)** against the local catalog + **live OSV** — not from
the CycloneDX `vulnerabilities` array in your file. PURL **type ≠ OSV ecosystem** (`apk`→`Alpine`,
`deb`→`Debian`); `rpm`/`generic`/`oci` are skipped (no live OSV lookup). Debug in order:

```sh
curl -s "$BASE_URL/api/v1/components?limit=200" -H "X-API-Key: $API_KEY" \
  | jq '[.items[].ecosystem] | group_by(.) | map({ecosystem: .[0], count: length})'
# sanity-check OSV: ecosystem must be "Alpine", not "apk"
curl -s -X POST 'https://api.osv.dev/v1/querybatch' -H 'Content-Type: application/json' \
  -d '{"queries":[{"package":{"ecosystem":"Alpine","name":"openssl"}}]}' | jq '.results[0].vulns | length'
```

### Resetting ingested data (local dev only)

Prefer soft-delete: `DELETE /api/v1/sboms/{id}?force=true`. For a full reset (also the **required** path from
a pre-`v0.3.0` schema — there is no in-place upgrade):

```sh
psql "$THEMIS_DATABASE_DSN" -c "DROP SCHEMA public CASCADE; CREATE SCHEMA public;" && make migrate-up
```

Durable judgments (`risk_context`, `triage_history`) are keyed on `(artifact_id, component_purl, cve_id)` and
survive rescans by design.

---

## Troubleshooting

| Symptom | Likely cause | Fix |
| ------- | ------------ | --- |
| `missing required configuration field: database.dsn` | `THEMIS_DATABASE_DSN` not exported | export it in the same shell |
| `password authentication failed` | DSN uses the placeholder password | create a matching role or fix the DSN |
| `connection refused` on `:5432` | Postgres not running | start it; `pg_isready` |
| Startup refuses "re-initialise your database" | pre-`v0.3.0` schema | drop & recreate, then `make migrate-up` |
| `/readyz` 503 | DB down or CVE feed not polled yet | check `checks` in the body; wait for first poll |
| Ingestion `REJECTED` — image not found | digest not registered | `POST /products/{id}/artifacts` first |
| Upload `422 invalid JSON body` | malformed JSON or empty UUID field | build with `jq`; omit UUID fields rather than `""` |
| Ingestion succeeds, no vulnerabilities | PURL ecosystem unmapped / no version match | see [SBOM correlation](#sbom-correlation--osv-when-components-exist-but-findings-dont) |
| Intelligence always `204` | fake provider, or grounding unreachable, or validation declined | use Ollama + real read APIs; check `THEMIS_GOVERNANCE_URL`/`THEMIS_KNOWLEDGE_URL` |
| `POST /findings/{id}/recommend` → `204` | AI disabled | set `THEMIS_GOVERNANCE_AI_ENABLED=1` + `THEMIS_INTELLIGENCE_URL`, run `cmd/intelligence` |
| Ollama slow / CPU-only on Mac | running Ollama in a container | run Ollama **natively** on macOS for Metal GPU |

---

## Developer test suite

```sh
make test               # unit tests
make test-integration   # embedded Postgres (no Docker); or set THEMIS_TEST_DATABASE_DSN
make coverage           # unit + integration with per-package coverage thresholds
make test-property      # property-based tests (1000 examples; RAPID_CHECKS=20000 to go deeper)
make check              # full gate: build · test · lint · clean-arch · arch-test · coverage(+integration) · deadcode
```

Every task group / PR must pass `make check`. Coverage tiers are enforced by `scripts/check-coverage.sh`
(domain/app 100%, adapters 90%, aggregate stores 80% pending fault injection). Property tests
(`pgregory.net/rapid`, `*Property`) verify critical invariants — risk-score bounds, reconciliation
precedence, the VEX-overlay append-only rule, materialization stance-equality — and print a replay seed on
failure. Integration tests use the `//go:build integration` tag and real embedded Postgres on distinct
per-context ports.

## compare_releases@v1 — narrate a fix-verification diff (AI-CMP-1)

The fourth capability: an **Information** narration over Governance's deterministic comparison
read (EDR-GOVERNANCE-01 D16). The Selection is **ordered** — `[baseline, candidate]`, exactly two
releases — and the model is handed the `{fixed,new,persisting}` buckets verbatim (capped at 15
rows per bucket, worst-first, with omissions counted in the prompt).

```sh
curl -s -X POST -H "X-API-Key: $KEY" -H "content-type: application/json" \
  "http://localhost:8086/api/v1/capabilities/compare_releases/invoke" \
  -d '{"subject":{"type":"release","ids":["<BASELINE_ID>","<CANDIDATE_ID>"]}}'
```

`200` returns an `InformationResponse` (prose + provenance; nothing enters Governance). `204`
states its cause on `X-Themis-AI-Reason`: `no_grounding` covers Governance's honesty guard too —
an evidence-less side (422 upstream) or Evidence unreachable (502 upstream) refuses rather than
narrating a diff that proves nothing. Both releases empty ⇒ a deterministic
`rule:empty-comparison` answer, zero tokens. In the GUI: Compare tab → "Ask the advisor".

## On-demand CVE gather (G-AI-1 half a)

When a brand-new CVE has no card yet (`recommend_position` declines with
`decline_class=thin_grounding` — "no version evidence"), gather its facts explicitly:

```sh
curl -s -X POST -H "X-API-Key: $KEY" -H "content-type: application/json" \
  "http://localhost:8085/api/v1/faultlines/gather" -d '{"cve":"CVE-2026-12345"}'
```

Each wired per-CVE source (NVD today) reports `found` / `recorded` / `withdrawn` / `error`
independently; everything folds as ordinary source Proposals (same precedence as the scheduled
sweeps). No enable flag: the authenticated write-scoped POST is the opt-in. Uses
`THEMIS_NVD_URL` / `THEMIS_NVD_API_KEY` when set, NVD defaults otherwise.

## Δ4a LLMOps eval harness (`make eval-llm`)

The offline, live-model replay harness (EDR-INTELLIGENCE-01 § Δ4a). Build it, then run it by hand
against a node's store — after a deploy, or before promoting a model.

```sh
make eval-llm   # builds bin/intelligence-eval

# curate: promote a real logged invocation into the durable golden set (a case worth guarding)
THEMIS_DATABASE_DSN=<intelligence-dsn> \
  ./bin/intelligence-eval promote <correlation_id> --label "merged-module-stream plan"

# evaluate: replay the golden set through the live model, score, store + print a report
THEMIS_DATABASE_DSN=<intelligence-dsn> THEMIS_LLM_URL=http://localhost:11434 \
  THEMIS_LLM_MODEL=cyberpal20b:latest ./bin/intelligence-eval run
```

**Three honest limits, by design (D-Δ4a-2/4/6):**
- **Information capabilities** (`plan_remediation`, `explain_vulnerability`, `compare_releases`)
  score **groundedness / well-formedness, NOT answer quality** — prose has no single correct
  answer. "PASS" means it stayed grounded and well-formed, never "it was a good explanation".
- **Promotion is human-gated.** The report groups pass-rates by `(capability, prompt_version,
  model)` and ADVISES; nothing but a human reading it blocks deploying a worse-scoring model.
- **Run-it-yourself, no CI net.** The eval needs a live model and CI has none, so a
  prompt-contract or gate change that would reject previously-good outputs ships silently unless
  someone runs this. Make it a release-gate habit.

## Δ4b autonomous plane (default OFF)

The autonomous cross-release-consistency analyst raises advisory proposals no request would ask
for — when the same CVE was decided on a similar release but is undecided here. Enable it by
giving the pool a budget (its existence is the switch):

```sh
# on the intelligence node's env, then restart:
THEMIS_INTELLIGENCE_AUTO_BUDGET_TOKENS=500
THEMIS_INTELLIGENCE_AUTO_CADENCE=5m        # short cadence for a live test
THEMIS_REGISTRY_URL=http://localhost:8082
THEMIS_API_KEY=<a write-scoped key>
```

Within one cadence, advisory `ai` proposals appear on undecided Findings that have a decided
precedent elsewhere — visible in a release posture / the finding drawer. **Honest properties:**
- **Quiet by default** — it proposes ONCE per (finding, precedent) and stays silent until the
  precedent changes (D-Δ4b-5). It will not re-spam a Finding every tick.
- **Never authority** — an `ai` proposal can NEVER be auto-accepted, regardless of stance/evidence
  (constitutional, guarded by `TestAIProposalNeverAutoAccepts`). It advises; a human decides.
- **Bounded** — it spends from a SEPARATE capped pool (a hard isolation wall from reactive), and
  pauses (drain-then-stop) when the pool is spent, resuming next window. It can never starve
  reactive triage.
