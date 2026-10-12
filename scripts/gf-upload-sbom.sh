#!/usr/bin/env bash
# Greenfield (Phase-3) SBOM upload helper: register a Product -> Project -> Release in
# the Registry, then send the SBOM through Evidence's one intake door. This is the
# go-forward counterpart to scripts/upload-sbom.sh (which targets the frozen v0.3.x
# monolith on :8080 with an API key + artifact/image model).
#
# ONE intake call per document (EDR-INTAKE-01 D1): the body IS the artifact, so the SBOM
# streams straight from disk — no JSON envelope, no temp file, no 128KB argv ceiling.
# `kind` and `format` are detected server-side (D5) and echoed back on the receipt.
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: gf-upload-sbom.sh -f SBOM.json [options]

Required:
  -f PATH        CycloneDX or SPDX SBOM file (format auto-detected)

Identity (a fresh Product -> Project -> Release is created unless -r is given):
  -p NAME        Product name    (default: the SBOM file's base name)
  -j NAME        Project name    (default: "default")
  -v VERSION     Release version (default: "1.0.0")
  -r RELEASE_ID  Reuse an existing Release id (skips Product/Project/Release creation)

Endpoints:
  -R URL         Registry base URL (default: $THEMIS_REGISTRY_URL or http://localhost:8082)
  -E URL         Evidence base URL (default: $THEMIS_EVIDENCE_URL or http://localhost:8081)

Environment:
  THEMIS_API_KEY  sent as X-API-Key on every write (registration and intake) when set;
                  omitted when unset — a dev estate that logs AUTH DISABLED needs no key

Prints the Release id at the end so you can query posture:
  curl -s "http://localhost:8083/api/v1/releases/<RELEASE_ID>/posture" | jq .

Example:
  ./scripts/gf-upload-sbom.sh -f scripts/oamp.json -p oamp -j oamp-app -v 1.0.0
EOF
}

REGISTRY_URL="${THEMIS_REGISTRY_URL:-http://localhost:8082}"
EVIDENCE_URL="${THEMIS_EVIDENCE_URL:-http://localhost:8081}"
SBOM_FILE=""; PRODUCT=""; PROJECT="default"; VERSION="1.0.0"; RELEASE_ID=""

while getopts "f:p:j:v:r:R:E:h" opt; do
  case "$opt" in
    f) SBOM_FILE="$OPTARG" ;;
    p) PRODUCT="$OPTARG" ;;
    j) PROJECT="$OPTARG" ;;
    v) VERSION="$OPTARG" ;;
    r) RELEASE_ID="$OPTARG" ;;
    R) REGISTRY_URL="$OPTARG" ;;
    E) EVIDENCE_URL="$OPTARG" ;;
    h) usage; exit 0 ;;
    *) usage; exit 1 ;;
  esac
done

[[ -n "$SBOM_FILE" ]] || { usage; exit 1; }
[[ -f "$SBOM_FILE" ]] || { echo "error: SBOM file not found: $SBOM_FILE" >&2; exit 1; }
command -v jq >/dev/null 2>&1 || { echo "error: jq is required" >&2; exit 1; }
[[ -n "$PRODUCT" ]] || PRODUCT="$(basename "$SBOM_FILE")"; PRODUCT="${PRODUCT%.*}"

# --fail-with-body, never -f: on a refusal the BODY is the useful part — intake names its
# reason and elaborates it in `detail` (two fields, never concatenated — EDR-INTAKE-01
# D11). Plain -f discards it and leaves a bare exit code, which is how a refusal that
# said exactly what to do next reads as "the upload broke". The status is still non-zero.
CURL=(-sS --fail-with-body)

# The key goes in a HEADER, never in a URL: a query string lands in access logs and in
# shell history. An unset key sends no header at all (dev estates run auth-off). It is
# appended to an already non-empty array, because `"${EMPTY[@]}"` under `set -u` is an
# unbound-variable error in bash 3.2 (which is what macOS ships).
if [[ -n "${THEMIS_API_KEY:-}" ]]; then
  CURL+=(-H "X-API-Key: $THEMIS_API_KEY")
fi

J=("${CURL[@]}" -H "content-type: application/json")

# register_id POSTs one Registry entity and echoes its id. The whole response is captured
# so a refusal reaches the operator instead of being swallowed by a jq that found no id.
register_id() { # $1=path $2=json-body $3=label
  local resp id rc=0
  resp="$(curl "${J[@]}" "$REGISTRY_URL/api/v1/$1" -d "$2")" || rc=$?
  id="$(printf '%s' "$resp" | jq -r '.id // empty' 2>/dev/null)" || id=""
  if [[ $rc -ne 0 || -z "$id" ]]; then
    echo "error: $3 registration failed — is the Registry up at $REGISTRY_URL?" >&2
    printf '%s\n' "$resp" >&2
    # `return`, not `exit`: this function runs in a command substitution, where an exit
    # would end only the subshell. The caller's `|| exit 1` is what stops the script.
    return 1
  fi
  printf '%s' "$id"
}

# Detect the format from the document for the progress line only. The intake door detects
# it again, authoritatively, and echoes it back as `detected_format` — this is a hint for
# the human reading the terminal, never an assertion sent to the server.
format="$(jq -r 'if .bomFormat? == "CycloneDX" then "cyclonedx" elif .spdxVersion? != null then "spdx" else "unknown" end' "$SBOM_FILE")"

if [[ -z "$RELEASE_ID" ]]; then
  pid="$(register_id products "$(jq -n --arg n "$PRODUCT" '{name:$n}')" product)" || exit 1
  jid="$(register_id projects "$(jq -n --arg p "$pid" --arg n "$PROJECT" '{product_id:$p,name:$n}')" project)" || exit 1
  RELEASE_ID="$(register_id releases "$(jq -n --arg j "$jid" --arg v "$VERSION" '{project_id:$j,version:$v}')" release)" || exit 1
  echo "registered: product=$pid  project=$jid  release=$RELEASE_ID  ($PRODUCT / $PROJECT / $VERSION)"
else
  echo "using existing release=$RELEASE_ID"
fi

echo "uploading $SBOM_FILE (looks like $format) -> Evidence intake ..."
# One call, body-is-the-artifact: --data-binary @FILE streams the document however large.
# RELEASE_ID is a Registry uuid, so it needs no escaping in the query string.
rc=0
receipt="$(curl "${CURL[@]}" -X POST "$EVIDENCE_URL/api/v1/intake?release_id=$RELEASE_ID" \
  -H "content-type: application/json" --data-binary @"$SBOM_FILE")" || rc=$?
# The receipt (or the refusal) is printed either way — jq when it parses, verbatim when
# it does not, because an unparseable body is itself the thing the operator needs to see.
printf '%s\n' "$receipt" | jq . 2>/dev/null || printf '%s\n' "$receipt"
if [[ $rc -ne 0 ]]; then
  echo "error: intake refused or failed (curl exit $rc) — the reason and detail are above" >&2
  exit 1
fi

echo
echo "RELEASE_ID=$RELEASE_ID"
echo "posture: curl -s \"http://localhost:8083/api/v1/releases/$RELEASE_ID/posture\" | jq 'length'"
