# themis-mcp

A [Model Context Protocol](https://modelcontextprotocol.io) server that exposes
Themis to LLM clients (Claude Code, Claude Desktop, and any MCP-capable host) as
a set of tools.

`themis-mcp` is a **standalone API client**: it talks to a running Themis server
over its REST API (`/api/v1`) and has no database access of its own. It lives in
the Themis module for versioning and discoverability but stays decoupled from the
core layers — it only imports the MCP SDK and the standard library.

## Build

```sh
make build                 # builds ./bin/themis (the server)
go build -o bin/themis-mcp ./cmd/themis-mcp
```

## Configure

| Setting | How | Default |
| --- | --- | --- |
| Themis base URL | `THEMIS_BASE_URL` env / `--base-url` | `http://localhost:8080` |
| API key | `THEMIS_API_KEY` env | *(required for `/api/v1` calls)* |
| Read-only mode | `THEMIS_MCP_READ_ONLY=1` / `--read-only` | off |
| Transport | `--http :9000` for HTTP; omit for stdio | stdio |
| HTTP timeout | `--timeout` | `60s` |

Create an API key with the Themis admin CLI (there is no HTTP endpoint for it):

```sh
./bin/themis admin create-key --name mcp --admin        # or --product-id <uuid>
# prints: key_id=<uuid>  api_key=<64-hex>   → use api_key as THEMIS_API_KEY
```

Only `themis_health` works without a key; every other tool needs `THEMIS_API_KEY`.

## Run

Stdio (local; the usual way an LLM client launches it):

```sh
claude mcp add themis --env THEMIS_API_KEY=<key> --env THEMIS_BASE_URL=http://localhost:8080 -- /path/to/bin/themis-mcp
```

Streamable HTTP (networked / shared gateway — put your own auth in front of it):

```sh
THEMIS_API_KEY=<key> ./bin/themis-mcp --http :9000
```

## Tools

34 tools (21 in `--read-only` mode). Read tools are annotated `readOnlyHint`;
tools that add data are `additive`; tools that change finding state or remove
data are `destructiveHint` so clients can prompt before calling them.

**Read** — `themis_health`, `themis_status`, `themis_list_products`,
`themis_list_projects`, `themis_list_versions`, `themis_list_scans`,
`themis_get_scan`, `themis_list_scan_vulnerabilities`,
`themis_list_product_vulnerabilities`, `themis_list_project_vulnerabilities`,
`themis_list_components`, `themis_list_cve_watch`, `themis_list_sboms`,
`themis_get_ingestion`, `themis_wait_for_ingestion`, `themis_get_triage_history`,
`themis_get_blast_radius`, `themis_export_vex`, `themis_get_vex_coverage`,
`themis_get_notification_config`, `themis_get_scanner_config`.

**Additive (ingest / inventory)** — `themis_create_product`,
`themis_create_project`, `themis_create_version`, `themis_register_artifact`,
`themis_create_microservice`, `themis_create_deployment`, `themis_create_customer`,
`themis_upload_sbom`.

**Destructive (state change / delete)** — `themis_upload_vex`,
`themis_submit_triage`, `themis_delete_sbom`, `themis_update_notification_config`,
`themis_update_scanner_config`.

### Ingestion is async

`themis_upload_sbom` returns `202 Accepted` with an `ingestion_id` — the SBOM is
**not** processed yet. Call `themis_wait_for_ingestion` (it polls to a terminal
state), then read findings by the returned `scan_id`. Register the artifact
(`themis_register_artifact`) before uploading an SBOM that references it.

## Safety note (D-WRITE-1)

Themis holds a hard invariant: **AI is advisory-only — it must not autonomously
change a finding's state; state changes require a human.** Three tools cross that
line and are called out in their descriptions:

- `themis_submit_triage` writes `risk_context.effective_state` and generates a
  `themis_generated` VEX assertion that re-applies on future scans.
- `themis_upload_vex` can suppress a finding via a `not_affected`/`fixed`
  assertion, without a triage record.
- `themis_delete_sbom` hides a scan and its findings.

The Themis API does **not** distinguish a machine-submitted decision from a human
one — both are attributed to the API key's UUID in `audit_log`. This build honors
the "full control" configuration and leaves these tools enabled, but:

- run with `--read-only` (or `THEMIS_MCP_READ_ONLY=1`) to hide every mutating tool;
- give the server a dedicated, narrowly-scoped API key so its actions are
  distinguishable and revocable in the audit log;
- treat the destructive tools as human-authorized actions, not autonomous ones.
