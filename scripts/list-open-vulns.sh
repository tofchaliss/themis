#!/usr/bin/env bash
#
# list-open-vulns.sh — list OPEN vulnerabilities from the Themis v0.3.x API.
#
# Everything the call needs is discovered automatically:
#   1. base URL          — default http://localhost:8080 (override: THEMIS_BASE_URL)
#   2. an admin API key  — reused from a cache file, else created via the admin CLI
#                          and cached (override: THEMIS_API_KEY, or THEMIS_API_KEY_FILE)
#   3. the product ids   — listed from GET /api/v1/products (no need to know any id)
#
# It then pages GET /api/v1/products/{id}/vulnerabilities for every product, keeps the
# rows whose effective_state is "open", and prints a table + a summary.
#
# Endpoints hit (all under /api/v1, all authed with X-API-Key):
#   GET /healthz                              liveness preflight
#   GET /products                             discover product ids   (paginated)
#   GET /products/{id}/vulnerabilities        the findings           (paginated)
#
# Requirements: a running ./bin/themis, curl, jq. Postgres is only touched once, to
# mint the admin key (needs THEMIS_DATABASE_DSN — defaulted to the local dev DSN).
#
# Usage:  scripts/list-open-vulns.sh
set -euo pipefail

# ---- configuration (all overridable by env; sensible local-dev defaults) ----------
BASE_URL="${THEMIS_BASE_URL:-http://localhost:8080}"
API="${BASE_URL%/}/api/v1"
DSN="${THEMIS_DATABASE_DSN:-postgres://themis:themis-dev-password@localhost:5432/themis?sslmode=disable}"
BIN="${THEMIS_BIN:-./bin/themis}"
KEY_FILE="${THEMIS_API_KEY_FILE:-$HOME/.themis_admin_api_key}"
PAGE_LIMIT="${THEMIS_PAGE_LIMIT:-200}"
# "open" = effective_state values that still need attention. Everything else
# (resolved / not_affected / false_positive / suppressed) is treated as closed.
OPEN_STATES="${THEMIS_OPEN_STATES:-detected confirmed in_triage accepted_risk}"
# Every run drops a stable, diff-friendly snapshot here (persists across days so a
# later run can show a day-over-day diff). Override with THEMIS_SNAPSHOT_DIR.
SNAP_DIR="${THEMIS_SNAPSHOT_DIR:-$HOME/.themis-vuln-snapshots}"

KEY=""   # resolved by acquire_key
say()  { printf '%s\n' "$*" >&2; }
die()  { printf 'error: %s\n' "$*" >&2; exit 1; }

# ---- 0. dependencies + preflight ---------------------------------------------------
for c in curl jq; do command -v "$c" >/dev/null || die "missing dependency: $c"; done
curl -fsS -o /dev/null "${BASE_URL%/}/healthz" 2>/dev/null \
  || die "Themis is not reachable at ${BASE_URL} — start it first (./bin/themis)."

# ---- 1. acquire an admin API key (reuse cache → else create + cache) ---------------
key_valid() { # uses $KEY; 0 if GET /products returns 200
  [ -n "$KEY" ] || return 1
  [ "$(curl -s -o /dev/null -w '%{http_code}' -H "X-API-Key: $KEY" "${API}/products?limit=1")" = "200" ]
}
acquire_key() {
  if [ -n "${THEMIS_API_KEY:-}" ]; then
    KEY="$THEMIS_API_KEY"; key_valid && { say "→ key: THEMIS_API_KEY"; return; }
    die "THEMIS_API_KEY was set but the server rejected it (401)."
  fi
  if [ -f "$KEY_FILE" ]; then
    KEY="$(cat "$KEY_FILE")"; key_valid && { say "→ key: reused cache ($KEY_FILE)"; return; }
    say "→ cached key invalid; minting a new one"
  fi
  [ -x "$BIN" ] || die "themis binary not found at $BIN (build it: make build)."
  say "→ key: creating an admin key ($BIN admin create-key --admin)"
  local out
  out="$(THEMIS_DATABASE_DSN="$DSN" "$BIN" admin create-key --admin --name list-open-vulns 2>&1)" \
    || die "create-key failed:\n$out"
  KEY="$(printf '%s\n' "$out" | sed -n 's/^api_key=//p')"
  [ -n "$KEY" ] || die "could not parse api_key from create-key output:\n$out"
  ( umask 077; printf '%s' "$KEY" > "$KEY_FILE" )
  key_valid || die "the freshly minted key was rejected — unexpected."
  say "→ key: created + cached ($KEY_FILE)"
}

# ---- generic paginator: echoes every .items[] of a path as compact JSON lines ------
fetch_paged() { # $1 = path (e.g. /products or /products/<id>/vulnerabilities)
  local path="$1" cursor="" url body enc
  while :; do
    url="${API}${path}?limit=${PAGE_LIMIT}"
    [ -n "$cursor" ] && { enc="$(jq -rn --arg x "$cursor" '$x|@uri')"; url="${url}&cursor=${enc}"; }
    body="$(curl -fsS -H "X-API-Key: $KEY" "$url")" || die "request failed: $url"
    printf '%s' "$body" | jq -c '.items[]?'
    cursor="$(printf '%s' "$body" | jq -r '.next_cursor // ""')"
    { [ -z "$cursor" ] || [ "$cursor" = "null" ]; } && break
  done
}

# ---- 2. + 3. run it ----------------------------------------------------------------
acquire_key
OPEN_JSON="$(printf '%s\n' $OPEN_STATES | jq -R . | jq -sc .)"

products="$(fetch_paged "/products" | jq -rc '{id, name}')"
[ -n "$products" ] || die "no products registered yet — upload an SBOM first (scripts/upload-sbom.sh)."

ALL="$(mktemp)"; trap 'rm -f "$ALL"' EXIT
while IFS= read -r p; do
  pid="$(printf '%s' "$p"   | jq -r '.id')"
  pname="$(printf '%s' "$p" | jq -r '.name')"
  say "→ scanning product: $pname ($pid)"
  fetch_paged "/products/$pid/vulnerabilities" \
    | jq -c --arg p "$pname" '. + {product:$p}' >> "$ALL"
done <<< "$products"

# ---- 4. render: open-vulnerabilities table -----------------------------------------
echo
echo "================ OPEN VULNERABILITIES (${BASE_URL}) ================"
{
  printf 'SEVERITY\tSTATE\tCVE\tPRODUCT\tCOMPONENT\tINSTALLED→FIXED\tFLAGS\tEPSS\tRISK\n'
  jq -s -r --argjson open "$OPEN_JSON" '
    def sev_rank: {"critical":0,"high":1,"medium":2,"low":3}[(.//""|ascii_downcase)] // 4;
    map(select(.effective_state as $s | ($open | index($s)) != null))
    | sort_by((.severity|sev_rank), -((.enrichment.risk_score)//0))
    | .[]
    | [ (.severity // "?"),
        (.effective_state // "?"),
        (.cve_id // "?"),
        (.product // "-"),
        (.component_purl // "-"),
        ((.installed_version // "-") + "→" + (.fixed_version // "-")),
        ([ (if (.enrichment.kev_listed // false) then "KEV" else empty end),
           (if (.enrichment.exploit_public // false) then "exploit" else empty end)
         ] | join(",") // "" ),
        ((.enrichment.epss_score // 0) | tostring),
        ((.enrichment.risk_score // 0) | tostring)
      ] | @tsv
  ' "$ALL"
} | column -t -s "$(printf '\t')"

# ---- 5. summary --------------------------------------------------------------------
echo
echo "-------- summary --------"
jq -s -r --argjson open "$OPEN_JSON" '
  def is_open: .effective_state as $s | ($open | index($s)) != null;
  (map(select(is_open))) as $o
  | "findings total : \(length)",
    "open            : \($o | length)   (states: \($open | join(", ")))",
    "closed          : \((length) - ($o | length))",
    "",
    "open by severity:",
    ( $o | group_by(.severity // "?")
         | map("  \(.[0].severity // "?"): \(length)") | .[] ),
    "",
    "by effective_state (all):",
    ( group_by(.effective_state // "?")
         | map("  \(.[0].effective_state // "?"): \(length)") | .[] )
' "$ALL"

# ---- 6. write a stable, diff-friendly snapshot + diff vs the previous one -----------
mkdir -p "$SNAP_DIR"
SNAP="$SNAP_DIR/open-vulns-$(date +%Y%m%d-%H%M%S).tsv"
# one line per OPEN finding, keyed by product|cve|component and stably sorted, so a
# plain field-wise comparison against an earlier snapshot is meaningful.
jq -s -r --argjson open "$OPEN_JSON" '
  map(select(.effective_state as $s | ($open | index($s)) != null))
  | sort_by([.product, .cve_id, (.component_purl // "")])
  | .[]
  | [ (.product//"-"), (.cve_id//"?"), (.component_purl//"-"),
      (.severity//"?"), (.effective_state//"?"),
      ((.installed_version//"-")+"→"+(.fixed_version//"-")),
      ((.enrichment.kev_listed//false)|tostring),
      ((.enrichment.exploit_public//false)|tostring),
      ((.enrichment.epss_score//0)|tostring),
      ((.enrichment.risk_score//0)|tostring) ] | @tsv
' "$ALL" > "$SNAP"

echo
echo "-------- snapshot --------"
say "→ wrote $SNAP  ($(wc -l < "$SNAP" | tr -d ' ') open findings)"

# previous snapshot = the newest existing one other than the file just written
PREV="$(ls -1 "$SNAP_DIR"/open-vulns-*.tsv 2>/dev/null | grep -vF "$SNAP" | tail -1 || true)"
if [ -n "${PREV:-}" ]; then
  echo "→ diff vs previous ($(basename "$PREV")):"
  # columns: 1=product 2=cve 3=component 4=severity 5=state 6=inst→fix 7=kev 8=exploit 9=epss 10=risk
  awk -F'\t' '
    FNR==NR { k=$1 FS $2 FS $3; o[k]=$0; next }
    { k=$1 FS $2 FS $3; seen[k]=1
      if (!(k in o))       { print "  + NEW      " $4 "  " $2 "  " $3; n++; next }
      if (o[k] != $0) {
        split(o[k], a, FS); m=""
        if (a[4]  != $4)  m=m " sev:"   a[4]  "→" $4
        if (a[5]  != $5)  m=m " state:" a[5]  "→" $5
        if (a[10] != $10) m=m " risk:"  a[10] "→" $10
        if (a[6]  != $6)  m=m " fix:"   a[6]  "→" $6
        print "  ~ CHANGED  " $2 "  " $3 m; c++
      }
    }
    END {
      for (k in o) if (!(k in seen)) { split(o[k],a,FS); print "  - CLOSED   " a[4] "  " a[2] "  " a[3]; r++ }
      printf "  ── %d new · %d changed · %d closed ──\n", n+0, c+0, r+0
    }
  ' "$PREV" "$SNAP"
else
  say "  (no earlier snapshot — this is the baseline; re-run later for a day-over-day diff)"
fi
