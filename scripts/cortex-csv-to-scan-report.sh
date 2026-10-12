#!/usr/bin/env bash
# Cortex CSV export -> Themis, through the one intake door.
#
# This script used to CONVERT (a CPython CSV->curated-JSON pass) and print the curated
# document for you to upload separately. It no longer converts anything: EDR-INTAKE-01 D4
# moved the one Cortex converter server-side into internal/evidence/adapters/report, so
# the CSV is now POSTed to `/api/v1/intake` verbatim and Evidence converts, validates and
# files it. CSV is a REQUEST ENCODING, never an evidence document (D2).
#
# What that changes for you: what comes back on stdout is the intake RECEIPT (D9) — the
# evidence id, the detected dialect, the finding counts — not a document to upload. There
# is no second step, and no local python3 is needed.
#
# The name and the CLI are unchanged on purpose, so documented procedures and muscle
# memory survive. The Python that used to live here is frozen as a TEST ORACLE at
# internal/evidence/adapters/report/testdata/oracle/ — it is on no operator road, and
# running it is not a supported way to get data into Themis (TESTING.md: a second
# converter is a defect, not a convenience).
#
# Usage:  cortex-csv-to-scan-report.sh <cortex.csv> [observed_at RFC3339] > receipt.json
#
# Environment — the release the report is about (intake RESOLVES identity, never creates
# it, D7, so the release must already be registered; scripts/gf-upload-sbom.sh registers):
#   RELEASE_ID                      the release id, named directly (wins when set), or
#   PRODUCT + PROJECT + VERSION     the Product/Project/Release triple, resolved read-only
#   THEMIS_EVIDENCE_URL             Evidence base URL (default http://localhost:8081)
#   THEMIS_API_KEY                  sent as X-API-Key when set; omitted when unset (a dev
#                                   estate that logs AUTH DISABLED needs no key)

set -euo pipefail

usage() {
  cat <<'EOF'
Usage: cortex-csv-to-scan-report.sh <cortex.csv> [observed_at RFC3339] > receipt.json

POSTs the CSV to Evidence's intake door; the server converts and files it, and the
intake receipt is printed to stdout.

Name the release through the environment (it must already be registered — intake
resolves identity read-only and never creates it):

  RELEASE_ID=<uuid>                       ./scripts/cortex-csv-to-scan-report.sh scan.csv
  PRODUCT=OAMP PROJECT=oamp-core VERSION=R1917.256 \
                                          ./scripts/cortex-csv-to-scan-report.sh scan.csv

  THEMIS_EVIDENCE_URL   Evidence base URL (default http://localhost:8081)
  THEMIS_API_KEY        sent as X-API-Key when set; omitted when unset

observed_at is OPTIONAL and is an assertion about WHICH observation this is. Omitted,
the server derives it from the export's own data (Cortex max(last_observed)) — it is
never the upload time, so re-submitting the same export dedups instead of filing a
second scan.
EOF
}

CSV="${1:-}"
if [ -z "$CSV" ] || [ "$CSV" = "-h" ] || [ "$CSV" = "--help" ]; then
  usage >&2
  exit 2
fi
if [ ! -f "$CSV" ]; then
  echo "error: no such file: $CSV" >&2
  exit 2
fi

EVIDENCE_URL="${THEMIS_EVIDENCE_URL:-http://localhost:8081}"

# urlencode builds the query string by hand because curl's own --data-urlencode cannot be
# used here: it needs -G, and -G moves EVERY --data* argument into the URL — including the
# --data-binary that carries the CSV. Measured: curl refuses the combination outright with
# "URL rejected: Malformed input to a URL function", having tried to append the whole
# document to the query string. The body has to stay the body (that is the whole point of
# the intake door), so the metadata is encoded here. LC_ALL=C makes the loop walk BYTES, so
# a non-ASCII product name is percent-encoded per byte, as UTF-8 requires.
urlencode() {
  local LC_ALL=C s="$1" i c out=""
  for ((i = 0; i < ${#s}; i++)); do
    c="${s:i:1}"
    case "$c" in
      [a-zA-Z0-9.~_-]) out+="$c" ;;
      *) out+="$(printf '%%%02X' "'$c")" ;;
    esac
  done
  printf '%s' "$out"
}

if [ -n "${RELEASE_ID:-}" ]; then
  QUERY="release_id=$(urlencode "$RELEASE_ID")"
elif [ -n "${PRODUCT:-}" ] && [ -n "${PROJECT:-}" ] && [ -n "${VERSION:-}" ]; then
  QUERY="product=$(urlencode "$PRODUCT")&project=$(urlencode "$PROJECT")&version=$(urlencode "$VERSION")"
else
  echo "error: name the release first — set RELEASE_ID, or PRODUCT + PROJECT + VERSION" >&2
  echo >&2
  usage >&2
  exit 2
fi
if [ -n "${2:-}" ]; then
  QUERY="$QUERY&observed_at=$(urlencode "$2")"
fi

# --fail-with-body, not -f: a refusal's BODY is the useful part (intake names its reason
# and elaborates it in `detail` — two fields, never concatenated, D11). Plain -f throws
# the body away and leaves the operator with a bare exit code, which is how a refusal
# that said exactly what to do next reads as "the upload broke". The exit status is still
# non-zero on 4xx/5xx, so a script wrapping this one still sees the failure.
#
# The arguments are accumulated in ONE array that is never empty, because `"${EMPTY[@]}"`
# under `set -u` is an unbound-variable error in bash 3.2 (which is what macOS ships).
ARGS=(-sS --fail-with-body -X POST "$EVIDENCE_URL/api/v1/intake?$QUERY"
      -H 'Content-Type: text/csv')

# The key goes in a HEADER, never in the URL: a query string lands in access logs and in
# shell history. An unset key sends no header at all.
if [ -n "${THEMIS_API_KEY:-}" ]; then
  ARGS+=(-H "X-API-Key: $THEMIS_API_KEY")
fi

# The BODY is the artifact: --data-binary @FILE streams the CSV from disk, however large.
ARGS+=(--data-binary "@$CSV")

exec curl "${ARGS[@]}"
