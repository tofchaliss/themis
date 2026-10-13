#!/usr/bin/env bash
# Greenfield (Phase-3) SBOM upload helper: register a Product -> Project -> Release in
# the Registry, then send the SBOM through Evidence's one intake door. This is the
# go-forward counterpart to scripts/upload-sbom.sh (which targets the frozen v0.3.x
# monolith on :8080 with an API key + artifact/image model).
#
# ONE intake call per document (EDR-INTAKE-01 D1): the body IS the artifact, so the SBOM
# streams straight from disk — no JSON envelope, no temp file, no 128KB argv ceiling.
# `kind` and `format` are detected server-side (D5) and echoed back on the receipt.
#
# With -c it drives the BOT road instead (EDR-INTAKE-01 B2): no Registry call at all — the
# triple goes to intake with create_release=true and intake finds-or-creates the version,
# which is the one part of the identity triple that is new on every build. One request files
# ONE artifact (B1), so a scan report for the same release is a SECOND invocation, after
# this one — D6's SBOM-before-report rule holds across the two requests.
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: gf-upload-sbom.sh -f SBOM.json [options]

Required:
  -f PATH        CycloneDX or SPDX SBOM file (format auto-detected)

Identity (a fresh Product -> Project -> Release is created unless -r or -c is given):
  -p NAME        Product name    (default: the SBOM file's base name)
                 NOTE, long-standing: everything from the last "." on is stripped — so
                 `-p my.app` is sent as `my`. A product whose registered name contains
                 a dot cannot be addressed through this script.
  -j NAME        Project name    (default: "default")
  -v VERSION     Release version (default: "1.0.0")
  -r RELEASE_ID  Reuse an existing Release id (skips Product/Project/Release creation)
  -c             The bot road: let Evidence intake create the Release VERSION
                 (create_release=true). NO Registry call is made. Requires -p, -j and
                 -v to be given EXPLICITLY, and is incompatible with -r. The Product
                 and the Project must already exist — intake creates the version and
                 nothing above it (EDR-INTAKE-01 B2), so a name that does not resolve
                 is a refusal, never a creation.
  -b BUILD_ID    Provenance label for the pipeline run (EDR-INTAKE-01 B5): stored on
                 the evidence row, echoed on the receipt, and read by nothing — it
                 takes no part in dedup, correlation or current-SBOM selection. At most
                 256 Unicode code points and valid UTF-8; over that it is refused by
                 name (400 build_id_invalid), never truncated.

Endpoints:
  -R URL         Registry base URL (default: $THEMIS_REGISTRY_URL or http://localhost:8082)
  -E URL         Evidence base URL (default: $THEMIS_EVIDENCE_URL or http://localhost:8081)

Environment:
  THEMIS_API_KEY  sent as X-API-Key on every write (registration and intake) when set;
                  omitted when unset — a dev estate that logs AUTH DISABLED needs no key.
                  It must be ONE opaque token (minted keys are `thm_` + base64url); a value
                  containing whitespace is refused here rather than sent as a broken header

Prints the Release id at the end so you can query posture:
  curl -s "http://localhost:8083/api/v1/releases/<RELEASE_ID>/posture" | jq .

Examples:
  # a human registering the whole chain, then uploading
  ./scripts/gf-upload-sbom.sh -f scripts/oamp.json -p oamp -j oamp-app -v 1.0.0
  # a CI bot: the version is created by intake, under identity a human already owns
  ./scripts/gf-upload-sbom.sh -f sbom.json -p oamp -j oamp-core -v R1917.256 -c -b "$CI_PIPELINE_ID"
  # the same with the key in the environment (env VAR=value cmd — never VAR=value cmd)
  env THEMIS_API_KEY=key-… ./scripts/gf-upload-sbom.sh -f sbom.json -p oamp -j oamp-core -v R20.1 -c
EOF
}

REGISTRY_URL="${THEMIS_REGISTRY_URL:-http://localhost:8082}"
EVIDENCE_URL="${THEMIS_EVIDENCE_URL:-http://localhost:8081}"
SBOM_FILE=""; PRODUCT=""; PROJECT="default"; VERSION="1.0.0"; RELEASE_ID=""
CREATE_RELEASE=0; BUILD_ID=""
# Whether the triple was given EXPLICITLY, which is what -c needs. The defaults above are
# fine for a run that REGISTERS what it needs; they are not fine for a run that asks intake
# to create a version under a Product and Project a human already owns, because a defaulted
# "default" project is a name that almost certainly does not resolve — and a name that does
# not resolve is a refusal a product-scoped key cannot even tell apart from "not yours" (B3).
PRODUCT_SET=0; PROJECT_SET=0; VERSION_SET=0

while getopts "f:p:j:v:r:R:E:b:ch" opt; do
  case "$opt" in
    f) SBOM_FILE="$OPTARG" ;;
    p) PRODUCT="$OPTARG"; PRODUCT_SET=1 ;;
    j) PROJECT="$OPTARG"; PROJECT_SET=1 ;;
    v) VERSION="$OPTARG"; VERSION_SET=1 ;;
    r) RELEASE_ID="$OPTARG" ;;
    R) REGISTRY_URL="$OPTARG" ;;
    E) EVIDENCE_URL="$OPTARG" ;;
    b) BUILD_ID="$OPTARG" ;;
    c) CREATE_RELEASE=1 ;;
    h) usage; exit 0 ;;
    *) usage; exit 1 ;;
  esac
done

[[ -n "$SBOM_FILE" ]] || { usage; exit 1; }
[[ -f "$SBOM_FILE" ]] || { echo "error: SBOM file not found: $SBOM_FILE" >&2; exit 1; }
command -v jq >/dev/null 2>&1 || { echo "error: jq is required" >&2; exit 1; }
# -c is refused locally for the two shapes intake itself refuses (rows 5 and 6 of the
# EDR-INTAKE-01 status-code table): naming the release twice, and an incomplete triple. The
# server is still the authority; this just spends no request to learn it. Checked BEFORE the
# default below, so a -c run never falls back to a product derived from the file name or to the
# defaulted project. (The extension strip below still applies to -p — see the note on it.)
if [[ $CREATE_RELEASE -eq 1 ]]; then
  if [[ -n "$RELEASE_ID" ]]; then
    echo "error: -c and -r name the release two ways — intake answers 400 create_release_conflict" >&2
    usage >&2; exit 1
  fi
  if [[ $PRODUCT_SET -ne 1 || $PROJECT_SET -ne 1 || $VERSION_SET -ne 1 ]] ||
     [[ -z "$PRODUCT" || -z "$PROJECT" || -z "$VERSION" ]]; then
    echo "error: -c needs the whole triple given explicitly: -p PRODUCT -j PROJECT -v VERSION" >&2
    echo "       (intake answers 400 incomplete_release_triple; the defaults are not a triple)" >&2
    usage >&2; exit 1
  fi
fi

# UNCHANGED, deliberately: the default product is the SBOM's base name, and the extension strip
# then runs on WHATEVER `$PRODUCT` holds — including a name given with -p. So `-p my.app` has
# always been sent as `my`, on every road this script drives, and that is left exactly as it was
# (the `;` here is the original line's, not a typo of `&&`). Two consequences to know rather than
# discover: a product whose registered name contains a dot cannot be addressed by this script at
# all, and on the -c road the truncated name does not resolve, which for a product-scoped key is
# B3's non-disclosing 403 with nothing in it to point at the cause. Changing it is a behaviour
# change and needs the owner's say-so; usage() states the limit so it is visible meanwhile.
[[ -n "$PRODUCT" ]] || PRODUCT="$(basename "$SBOM_FILE")"; PRODUCT="${PRODUCT%.*}"

# New road only, so no existing answer moves: `-p .json` strips to the empty string, and sending
# `product=` would be an incomplete triple discovered by the server a request later.
if [[ $CREATE_RELEASE -eq 1 && -z "$PRODUCT" ]]; then
  echo "error: -c: the product name is empty after the extension strip — see -p in usage" >&2
  exit 1
fi

# --fail-with-body, never -f: on a refusal the BODY is the useful part — intake names its
# reason and elaborates it in `detail` (two fields, never concatenated — EDR-INTAKE-01
# D11). Plain -f discards it and leaves a bare exit code, which is how a refusal that
# said exactly what to do next reads as "the upload broke". The status is still non-zero.
CURL=(-sS --fail-with-body)

# The key goes in a HEADER, never in a URL: a query string lands in access logs and in
# shell history. An unset key sends no header at all (dev estates run auth-off). It is
# appended to an already non-empty array, because `"${EMPTY[@]}"` under `set -u` is an
# unbound-variable error in bash 3.2 (which is what macOS ships).
#
# A minted key is an opaque single token (`thm_` + base64url — no whitespace by construction),
# and the array form above already prevents word-splitting, so the guard below cannot fire for a
# real key. It is there for the way this actually goes wrong: a token pasted with a stray newline
# or a trailing space, which curl would either refuse or send as a header no bcrypt compare can
# match — i.e. an unreadable 401 instead of a sentence naming the cause.
if [[ -n "${THEMIS_API_KEY:-}" ]]; then
  if [[ "$THEMIS_API_KEY" =~ [[:space:]] ]]; then
    echo "error: THEMIS_API_KEY contains whitespace — a key is one opaque token; re-copy it" >&2
    exit 1
  fi
  CURL+=(-H "X-API-Key: $THEMIS_API_KEY")
fi

J=("${CURL[@]}" -H "Content-Type: application/json")

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

# The two lines this change adds go to STDERR, not stdout: a caller that greps this script's
# stdout (for `RELEASE_ID=` or the registration line) sees exactly the stream it saw before.
if [[ $CREATE_RELEASE -eq 1 ]]; then
  echo "bot road: intake will find-or-create the version ($PRODUCT / $PROJECT / $VERSION) — no Registry call" >&2
elif [[ -z "$RELEASE_ID" ]]; then
  pid="$(register_id products "$(jq -n --arg n "$PRODUCT" '{name:$n}')" product)" || exit 1
  jid="$(register_id projects "$(jq -n --arg p "$pid" --arg n "$PROJECT" '{product_id:$p,name:$n}')" project)" || exit 1
  RELEASE_ID="$(register_id releases "$(jq -n --arg j "$jid" --arg v "$VERSION" '{project_id:$j,version:$v}')" release)" || exit 1
  echo "registered: product=$pid  project=$jid  release=$RELEASE_ID  ($PRODUCT / $PROJECT / $VERSION)"
else
  echo "using existing release=$RELEASE_ID"
fi

# The triple is human text, so it is percent-encoded before it goes in the query string.
# curl's -G/--data-urlencode cannot build it: -G moves EVERY --data* argument into the query,
# including the --data-binary carrying the document (measured — curl refuses outright with
# "URL rejected: Malformed input to a URL function"). jq is already a hard requirement above.
urlenc() { jq -rn --arg v "$1" '$v|@uri'; }

# RELEASE_ID is a Registry uuid, so it needs no escaping.
if [[ $CREATE_RELEASE -eq 1 ]]; then
  QUERY="product=$(urlenc "$PRODUCT")&project=$(urlenc "$PROJECT")&version=$(urlenc "$VERSION")&create_release=true"
else
  QUERY="release_id=$RELEASE_ID"
fi
if [[ -n "$BUILD_ID" ]]; then
  QUERY="$QUERY&build_id=$(urlenc "$BUILD_ID")"
  echo "build_id=$BUILD_ID (provenance only — nothing reads it)" >&2
fi

echo "uploading $SBOM_FILE (looks like $format) -> Evidence intake ..."
# One call, body-is-the-artifact: --data-binary @FILE streams the document however large.
# Content-Type is set HERE and only here: this call uses CURL (which carries no content type),
# not J — J is the Registry-only argument set, so there is exactly one such header per request.
rc=0
receipt="$(curl "${CURL[@]}" -X POST "$EVIDENCE_URL/api/v1/intake?$QUERY" \
  -H "Content-Type: application/json" --data-binary @"$SBOM_FILE")" || rc=$?
# The receipt (or the refusal) is printed either way — jq when it parses, verbatim when
# it does not, because an unparseable body is itself the thing the operator needs to see.
printf '%s\n' "$receipt" | jq . 2>/dev/null || printf '%s\n' "$receipt"
if [[ $rc -ne 0 ]]; then
  echo "error: intake refused or failed (curl exit $rc) — the reason and detail are above" >&2
  exit 1
fi

# On the bot road the release id is the SERVER's answer, so it is read off the receipt
# (`release_id`, which names the created-or-found version) instead of captured from a
# registration this run never made. `jq -e` is the whole test: it exits non-zero when the
# field is absent (no output) or null, so the `if` decides and nothing has to be unset again.
if [[ -z "$RELEASE_ID" ]]; then
  if id_from_receipt="$(printf '%s' "$receipt" | jq -er '.release_id // empty' 2>/dev/null)"; then
    RELEASE_ID="$id_from_receipt"
  fi
fi

echo
if [[ -n "$RELEASE_ID" ]]; then
  echo "RELEASE_ID=$RELEASE_ID"
  echo "posture: curl -s \"http://localhost:8083/api/v1/releases/$RELEASE_ID/posture\" | jq 'length'"
else
  echo "the receipt named no release_id — read the receipt above" >&2
fi
