# Themis v0.3.8 — Scoped vulnerability-listing endpoints

Release tag: `v0.3.8` (**non-breaking** — additive API only; no schema change, rebuild + restart).
Adds product/project/version-scoped finding lists so callers no longer have to resolve the latest
scan first.

## What's new

Three read endpoints that return the current findings (latest scan per artifact) rolled up to a
scope, in the **same `ScanVulnerabilityList` shape** as `GET /scans/{id}/vulnerabilities`:

| Endpoint | Scope |
| -------- | ----- |
| `GET /api/v1/products/{id}/vulnerabilities` | every artifact under a product |
| `GET /api/v1/projects/{id}/vulnerabilities` | every artifact under a project |
| `GET /api/v1/products/{id}/versions/{v}/vulnerabilities` | one product version |

All three support the same filters and cursor pagination as the scan endpoint:
`?severity=`, `?effective_state=`, `?cve_id=`, `?limit=`, `?cursor=`.

```sh
# All high-severity findings for a product, no need to find the scan first
curl -s "$BASE_URL/api/v1/products/$PRODUCT_ID/vulnerabilities?severity=high" \
  -H "X-API-Key: $API_KEY" | jq '.items | length'

# Everything currently confirmed on a specific version
curl -s "$BASE_URL/api/v1/products/$PRODUCT_ID/versions/latest/vulnerabilities?effective_state=confirmed" \
  -H "X-API-Key: $API_KEY" | jq '.items[] | {cve_id, component_purl, installed_version, fixed_version}'
```

## How it works

- Store: `PostgresScanQueryRepository.ListScopedVulnerabilities` drives off the `v_latest_findings`
  view (latest, non-deleted scan per artifact) with a one-line scope predicate
  (`proj.product_id` / `ver.project_id` / `proj.product_id + ver.version`). The SELECT projection,
  joins, filter builder, and row scan are shared with `ListScanVulnerabilities`
  (`scanVulnerabilitySelect`, `scanVulnerabilityJoins`, `appendVulnerabilityFilters`,
  `collectScanVulnerabilities`) — the scope query is a thin wrapper.
- API: manual routes in `internal/adapter/api/mount.go` alongside the existing product/version
  endpoints (vex, blast-radius). Product scope authorizes against the URL product; project scope
  resolves the project's product via `GetProjectProductID` (404 if the project is unknown).

## Notes

- Findings are listed **per artifact** (the `risk_context` identity), so the same CVE on the same
  component can appear once per artifact under a product — each artifact is a distinct deployment.
  An optional `?dedupe=true` to collapse to unique CVEs is a deferred follow-on.
- No schema change — rebuild + restart. See the README "Registration and management" table.

## Added (since v0.3.7)

- `feat(api)` — scoped vulnerability-listing endpoints for product / project / product version,
  reusing the scan-findings query shape via `v_latest_findings`.
