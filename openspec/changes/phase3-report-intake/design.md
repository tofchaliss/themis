# Design — phase3-report-intake

Source of truth: `docs/engineering/decisions/EDR-INTAKE-01.md`. This file is the realization map
plus **the wire contract** — the curl commands an operator actually runs.

## Realization map

| EDR decision | Realization |
| --- | --- |
| D1 one intake door | `POST /api/v1/intake` on Evidence; `adapters/http/intake.go`; `app.IntakeService`. `POST /evidence` untouched |
| D2 CSV is a request encoding | `adapters/report` converts; `app.Intake` files the **curated JSON**; `domain.Provenance` gains `SourceDigest`, `ConvertedBy` |
| D3 deterministic conversion | `report.Converter.Convert(bytes, observedAt)` is pure; `observedAt` derived or supplied; `ErrObservedAtUnderivable` |
| D4 one converter per dialect | `adapters/report/{cortex,trivy,curated}.go` + `registry.go`; equivalence tests vs `scripts/` fixtures; D16 translators deleted in M3 |
| D5 detection | `report.Detect(contentType, body) (Kind, Dialect, error)`; closed table; echoed as `detected_kind`/`detected_format` |
| D6 SBOM first | `app.Intake` calls `inventoryExists(releaseID)` before filing a report; `ErrNoInventory`; `allow_without_sbom` → `Provenance.WithoutSBOM` |
| D7 read-only resolution | `app.ReleaseResolver` port; `cmd/evidence` wires it onto the registry store (same pool, the `SubjectRef` precedent at `main.go:103`) |
| D8 multi-report identity | unchanged Evidence content addressing; intake maps `200`/`409` to `created=false` / `duplicate_other_release` |
| D9 receipts | `domain.Receipt` + migration `000003_intake_receipts`; `GET /api/v1/intake/{id}`; `THEMIS_INTAKE_INLINE_BUDGET` |
| D10 next_checks | `ReceiptView.next_checks[]` built from `THEMIS_KNOWLEDGE_URL` / `THEMIS_GOVERNANCE_URL` |
| D11 taxonomy | `domain.RejectReason` closed enum; `TestIntakeReasonTaxonomyIsClosed` guard; `trust.Gate` gains the curated-shape check for `kind=scanner-report` |
| D12 idempotency | `Idempotency-Key` → `receipts.idempotency_key` UNIQUE; replay returns the original receipt |

## The wire contract

Ports: Registry `:8082`, Evidence `:8081`, Knowledge `:8085`, Governance `:8083`.
`X-API-Key` is required when the node has `THEMIS_AUTH_DATABASE_DSN` set (EDR-SECURITY-01 F1); omit
it on a dev estate that logs `AUTH DISABLED`.

### Step 0 — register identity, once per release (unchanged, idempotent)

Intake resolves but never creates (D7). First time only:

```sh
# a release is Product -> Project -> Release; capture the release id
PID=$(curl -sf -X POST localhost:8082/api/v1/products \
  -H 'Content-Type: application/json' -H "X-API-Key: $KEY" \
  -d '{"name":"OAMP"}' | jq -r .id)
JID=$(curl -sf -X POST localhost:8082/api/v1/projects \
  -H 'Content-Type: application/json' -H "X-API-Key: $KEY" \
  -d "{\"product_id\":\"$PID\",\"name\":\"oamp-core\"}" | jq -r .id)
RID=$(curl -sf -X POST localhost:8082/api/v1/releases \
  -H 'Content-Type: application/json' -H "X-API-Key: $KEY" \
  -d "{\"project_id\":\"$JID\",\"version\":\"R1917.256\"}" | jq -r .id)
echo "release: $RID"
```

### Step 1 — the SBOM, first (D6)

The document is sent as the **raw body**, not wrapped in JSON. `kind` and `format` are detected
(D5) and echoed back; send them explicitly to assert rather than detect.

```sh
# SPDX or CycloneDX, JSON. Release named by id...
curl -sf -X POST "localhost:8081/api/v1/intake?release_id=$RID" \
  -H 'Content-Type: application/json' -H "X-API-Key: $KEY" \
  --data-binary @sbom.spdx.json | jq .
```

```sh
# ...or named by the Product/Project/Release triple, resolved read-only
curl -sf -X POST localhost:8081/api/v1/intake \
  -H 'Content-Type: application/json' -H "X-API-Key: $KEY" \
  -G --data-urlencode 'product=OAMP' --data-urlencode 'project=oamp-core' \
     --data-urlencode 'version=R1917.256' \
  --data-binary @sbom.spdx.json | jq .
```

`201` response:

```json
{
  "intake_id": "9f2c…",
  "status": "filed",
  "evidence_id": "7a31…",
  "created": true,
  "release_id": "…",
  "detected_kind": "sbom",
  "detected_format": "spdx",
  "components": 1184,
  "warnings": ["3 components carried no identifier"],
  "status_url": "/api/v1/intake/9f2c…",
  "next_checks": [
    {"what": "posture", "url": "http://localhost:8083/api/v1/releases/…/posture"}
  ]
}
```

### Step 2 — the vulnerability report, second

**Cortex JSON** (the body that caused the incident — now a named, converted dialect):

```sh
curl -sf -X POST "localhost:8081/api/v1/intake?release_id=$RID" \
  -H 'Content-Type: application/json' -H "X-API-Key: $KEY" \
  --data-binary @R1917.256.OAMP_Scan_Report.json | jq .
```

**Cortex CSV** — same endpoint, the content type is the whole difference:

```sh
curl -sf -X POST "localhost:8081/api/v1/intake?release_id=$RID" \
  -H 'Content-Type: text/csv' -H "X-API-Key: $KEY" \
  --data-binary @cortex-export.csv | jq .
```

**Raw Trivy JSON** — no jq recipe, no browser:

```sh
trivy image --format json --output trivy.json myimage:tag
curl -sf -X POST "localhost:8081/api/v1/intake?release_id=$RID" \
  -H 'Content-Type: application/json' -H "X-API-Key: $KEY" \
  --data-binary @trivy.json | jq .
```

**Already-curated** `{"findings":[…]}` passes through unconverted. All four produce:

```json
{
  "intake_id": "b7d1…", "status": "filed", "evidence_id": "c044…", "created": true,
  "detected_kind": "vuln-report", "detected_format": "cortex-json",
  "findings_total": 427, "findings_skipped": 0,
  "observed_at": "2026-09-29T07:23:22Z",
  "converted_by": "cortex@1",
  "source_digest": "sha256:…",
  "status_url": "/api/v1/intake/b7d1…",
  "next_checks": [
    {"what": "unresolved", "url": "http://localhost:8085/api/v1/scanner-reports/c044…/unresolved"},
    {"what": "posture",    "url": "http://localhost:8083/api/v1/releases/…/posture"}
  ]
}
```

Large files stream; `--data-binary @-` from a pipe works, as it does for `gf-upload-sbom.sh`.

### Step 3 — the checkpoint, when the work does not finish inline (D9)

Over `THEMIS_INTAKE_INLINE_BUDGET` (default `5s`) the response is `202` and terminal fields are
absent:

```json
{"intake_id": "b7d1…", "status": "accepted", "status_url": "/api/v1/intake/b7d1…",
 "retry_after_seconds": 2}
```

Come back to it, as often as needed:

```sh
curl -sf "localhost:8081/api/v1/intake/b7d1…" -H "X-API-Key: $KEY" | jq .
```

```sh
# or block until terminal, polling the receipt
until curl -sf "localhost:8081/api/v1/intake/$ID" -H "X-API-Key: $KEY" \
      | jq -e '.status | IN("filed","rejected","failed")' >/dev/null; do sleep 2; done
curl -sf "localhost:8081/api/v1/intake/$ID" -H "X-API-Key: $KEY" | jq .
```

Retry-safe: pass `-H "Idempotency-Key: $(uuidgen)"` and a repeat of the same request returns the
**original** receipt instead of filing again (D12).

### Refusals: two fields, never concatenated (D11)

```json
{
  "title": "intake refused",
  "status": 422,
  "reason": "schema_invalid",
  "detail": "finding[0]: 'cve' is required; found keys: asset_name, package_purl, …",
  "intake_id": "e551…"
}
```

A consumer **switches on `reason`** and **displays `detail`**. The pair stays two fields because
Governance flattened exactly this into `"<reason>: <detail>"`, turning a closed enum into free text
and making every table lookup miss (fixed 2026-09-22).

The body that halted the stream for 31 hours now returns, in milliseconds:

```json
{"status": 422, "reason": "schema_invalid",
 "detail": "body is a JSON array of Cortex records but carries no recognised Cortex field set"}
```

…or, once the Cortex dialect is recognised, it simply converts — which is the point.

### What SBOM-first refusal looks like (D6)

```json
{"status": 409, "reason": "no_inventory_for_release",
 "detail": "release R1917.256 has no SBOM-derived inventory; upload the SBOM first, or resend with allow_without_sbom=true"}
```

```sh
# the deliberate override, recorded in provenance
curl -sf -X POST "localhost:8081/api/v1/intake?release_id=$RID&allow_without_sbom=true" \
  -H 'Content-Type: text/csv' -H "X-API-Key: $KEY" --data-binary @cortex-export.csv | jq .
```

## Why the body is raw and the metadata is query parameters

`POST /evidence` wraps the document in a JSON envelope (`{"document": "<escaped JSON string>"}`),
which forces the client to JSON-escape an entire SBOM — the reason `gf-upload-sbom.sh` exists and
the reason a 60 MB SBOM is awkward from `curl`. Intake inverts it: **the body is the artifact**, and
the metadata that used to be envelope fields becomes query parameters. That makes `--data-binary @file`
the whole client, keeps streaming natural for large files, and is what allows one content-type header
to be the only difference between the CSV and JSON roads.

`expected_checksum`, `provenance_source` and `provenance_image_digest` are query parameters too,
carrying the same meanings they have on `POST /evidence`.

## Ordering inside `app.Intake`, and why

First failure wins, nothing is filed until every check has passed:

1. **size** (`payload_too_large`) — before reading the body into memory.
2. **detect** (`unrecognised_format`) — cheapest discriminator; a body we cannot name gets no further.
3. **resolve release** (`unknown_release`) — before conversion, because converting for a release that
   does not exist is wasted work on the common typo.
4. **parse/convert** (`malformed_body`, `observed_at_underivable`, `conversion_failed`).
5. **schema-validate the converted result** (`schema_invalid`, `empty_report`) — **E1**. On the
   *converted* document, because that is what gets filed.
6. **SBOM-first** (`no_inventory_for_release`) — after validation, so a report that is both invalid
   and early reports the invalidity, which is the more actionable fault.
7. **file** → trust gate, aggregate, persist + outbox (unchanged Evidence path).

Steps 1–6 are pure and side-effect-free; only 7 writes. A rejected intake therefore leaves a
receipt and nothing else — no evidence, no event, no bus traffic.

## Explicitly out of scope

- **Retaining the operator's original bytes** for a converted submission. Provenance records the
  source digest and converter identity; the vendor artifact is not stored (EDR-INTAKE-01 honest
  limits). A separate decision if an estate needs it.
- **A pipeline-complete signal.** D10 — the receipt is terminal at `filed`; a correlation-complete
  event keyed to the evidence id is a bus-level follow-up, filed not faked.
- **Non-JSON SBOMs** (SPDX tag-value, CycloneDX XML). The ask is SPDX/CycloneDX **JSON**, and
  admitting XML at the border reopens exactly the contract question D2 routes around.
- **Healing past mis-attribution.** KN-SCAN-4's shape is untouched: corrected rows land beside the
  old ones. One converter keeps identities stable going forward; it repairs nothing historical.
