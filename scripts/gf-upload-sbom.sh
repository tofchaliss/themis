#!/usr/bin/env bash
# Greenfield (Phase-3) SBOM upload helper: register a Product -> Project -> Release in
# the Registry, then upload an SBOM to the Evidence context. This is the go-forward
# counterpart to scripts/upload-sbom.sh (which targets the frozen v0.3.x monolith on
# :8080 with an API key + artifact/image model). The greenfield services are
# unauthenticated (dev) and identify a subject by Release id.
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

J=(-sS -H "content-type: application/json")

require_id() { # $1=value $2=label
  if [[ -z "$1" || "$1" == "null" ]]; then
    echo "error: $2 registration returned no id (got '$1') — is the Registry up at $REGISTRY_URL?" >&2
    exit 1
  fi
}

# Detect the format from the document (same rule as the monolith helper).
format="$(jq -r 'if .bomFormat? == "CycloneDX" then "cyclonedx" elif .spdxVersion? != null then "spdx" else "cyclonedx" end' "$SBOM_FILE")"

if [[ -z "$RELEASE_ID" ]]; then
  pid="$(curl "${J[@]}" "$REGISTRY_URL/api/v1/products" -d "$(jq -n --arg n "$PRODUCT" '{name:$n}')" | jq -r '.id')"
  require_id "$pid" "product"
  jid="$(curl "${J[@]}" "$REGISTRY_URL/api/v1/projects" -d "$(jq -n --arg p "$pid" --arg n "$PROJECT" '{product_id:$p,name:$n}')" | jq -r '.id')"
  require_id "$jid" "project"
  RELEASE_ID="$(curl "${J[@]}" "$REGISTRY_URL/api/v1/releases" -d "$(jq -n --arg j "$jid" --arg v "$VERSION" '{project_id:$j,version:$v}')" | jq -r '.id')"
  require_id "$RELEASE_ID" "release"
  echo "registered: product=$pid  project=$jid  release=$RELEASE_ID  ($PRODUCT / $PROJECT / $VERSION)"
else
  echo "using existing release=$RELEASE_ID"
fi

echo "uploading $SBOM_FILE (format=$format) -> Evidence ..."
# Build the request body into a temp file and stream it with --data-binary @FILE. An inline
# `-d "$payload"` breaks for large SBOMs: a single command-line argument is capped at 128KB on
# Linux (MAX_ARG_STRLEN), so an 849KB body yields "Argument list too long".
payload="$(mktemp)"
trap 'rm -f "$payload"' EXIT
jq -n --arg r "$RELEASE_ID" --arg fmt "$format" --rawfile d "$SBOM_FILE" \
  '{kind:"sbom", format:$fmt, subject_release_id:$r, document:$d}' > "$payload"
resp="$(curl "${J[@]}" "$EVIDENCE_URL/api/v1/evidence" --data-binary @"$payload")"
echo "evidence: $resp"
echo
echo "RELEASE_ID=$RELEASE_ID"
echo "posture: curl -s \"http://localhost:8083/api/v1/releases/$RELEASE_ID/posture\" | jq 'length'"
