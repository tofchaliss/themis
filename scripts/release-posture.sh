#!/usr/bin/env bash
# release-posture.sh — the consolidated security posture of one Release, from the CLI.
#
# This is a READ-ONLY client over the existing APIs. It adds no workflow and stores nothing: every
# number below is fetched live from Registry, Governance and Knowledge, and an operator, a GUI or
# this script see exactly the same thing.
#
# It is also, deliberately, the specification for what a GUI needs. Anything this script has to do
# by hand — enumerate, join, re-fetch — is a gap in the read surface, tracked as DASH-1/DASH-2:
#   * a release UUID must be supplied, because Registry has no list or lookup-by-name;
#   * the severity BAND costs one Knowledge call per Faultline, because PostureEntry carries
#     base_score but not the band Knowledge already computes.
#
# Usage:
#   scripts/release-posture.sh <release-id> [--top N] [--ai N] [--all]
#
#   --top N   how many rows to show (default 20)
#   --ai N    ask the Intelligence Gateway to recommend a position for the top N undecided
#             Findings (default 0 = off). SLOW: a grounded recommendation on a local model takes
#             ~30-60s each, so start with 1 or 2.
#   --all     include Findings already decided (residual_priority 0), which are hidden by default
#
# Env: THEMIS_REGISTRY_URL, THEMIS_GOVERNANCE_URL, THEMIS_KNOWLEDGE_URL, THEMIS_API_KEY
set -uo pipefail

REL="${1:-}"
[ -n "$REL" ] || { echo "usage: $0 <release-id> [--top N] [--ai N] [--all]" >&2; exit 2; }
shift

TOP=20; AI=0; SHOW_ALL=0; FIXWIDTH=40
while [ $# -gt 0 ]; do
  case "$1" in
    --top) TOP="$2"; shift 2 ;;
    --ai)  AI="$2";  shift 2 ;;
    --all) SHOW_ALL=1; shift ;;
    # --fix-width 0 disables clipping, for piping into a file or a wide terminal.
    --fix-width) FIXWIDTH="$2"; shift 2 ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
done

REGISTRY="${THEMIS_REGISTRY_URL:-http://localhost:8082}"
GOVERNANCE="${THEMIS_GOVERNANCE_URL:-http://localhost:8083}"
KNOWLEDGE="${THEMIS_KNOWLEDGE_URL:-http://localhost:8085}"
EVIDENCE="${THEMIS_EVIDENCE_URL:-http://localhost:8081}"

# Inbound-edge auth is optional (EDR-SECURITY-01): send the key only when one is configured.
get() {
  if [ -n "${THEMIS_API_KEY:-}" ]; then curl -sf -H "X-API-Key: $THEMIS_API_KEY" "$@"; else curl -sf "$@"; fi
}
post() {
  if [ -n "${THEMIS_API_KEY:-}" ]; then curl -s -H "X-API-Key: $THEMIS_API_KEY" -X POST "$@"; else curl -s -X POST "$@"; fi
}

command -v jq >/dev/null || { echo "jq is required" >&2; exit 2; }

# ── Header ────────────────────────────────────────────────────────────────────────────────────
release=$(get "$REGISTRY/api/v1/releases/$REL" 2>/dev/null || echo '{}')
version=$(echo "$release" | jq -r '.version // "unknown"')
# Blast radius is the ENTERPRISE half of priority (C2): how many customers this release reaches.
# It is why two releases with the same CVE can rank differently.
# `.unique_customers`, not `length`: the endpoint returns an OBJECT, and `length` on an object
# counts KEYS — which reported "2 customers" for a release reaching none, and made Governance's
# correct 1.0x multiplier look like a bug.
customers=$(get "$REGISTRY/api/v1/releases/$REL/blast-radius" 2>/dev/null | jq -r '.unique_customers // 0' 2>/dev/null || echo 0)

# Distro packages carry THREE names for one thing: the binary RPM shipped (python3-pyyaml), the
# source RPM it was built from (PyYAML), and the upstream project. Vulnerability feeds key fixes on
# the SOURCE name, the SBOM's PURL carries the BINARY name, and `python3-pyyaml -> PyYAML` is not
# derivable by any rule — it is data. Evidence's inventory is the only place that mapping exists, so
# build purl->source once here; without it every fix lookup misses and the FIX column reads
# "94 unattributed" for a card that knows the answer perfectly well.
#
# Held in a FILE, not a variable: a real inventory runs to hundreds of components, and passing the
# accumulated map back through `jq --argjson` on each iteration overflowed ARG_MAX ("Argument list
# too long"). jq then received no map, every lookup fell through to an empty package name, and an
# empty name matched the UNATTRIBUTED bucket -- printing all 94 versions of every package into one
# cell. A silent size limit turning into confidently wrong output is worth the temp file.
srcfile="${TMPDIR:-/tmp}/themis-posture-src.$$.json"
trap 'rm -f "$srcfile"' EXIT
for ev in $(get "$EVIDENCE/api/v1/evidence?release=$REL" 2>/dev/null | jq -r '.[].id' 2>/dev/null); do
  get "$EVIDENCE/api/v1/evidence/$ev/inventory" 2>/dev/null || true
done | jq -s 'map(.components // []) | add // [] | map({key: .purl, value: (.source // .name)}) | from_entries' \
  > "$srcfile" 2>/dev/null || echo '{}' > "$srcfile"
[ -s "$srcfile" ] || echo '{}' > "$srcfile"

posture=$(get "$GOVERNANCE/api/v1/releases/$REL/posture") || { echo "cannot read posture for $REL" >&2; exit 1; }
total=$(echo "$posture" | jq 'length')
[ "$total" != "0" ] || { echo "no Findings for release $REL"; exit 0; }

open=$(echo "$posture" | jq '[.[] | select(.residual_priority > 0)] | length')
decided=$((total - open))
caveated=$(echo "$posture" | jq '[.[] | select(.reservation != null)] | length')

printf '\n\033[1mRELEASE %s\033[0m  version=%s  customers-reached=%s\n' "$REL" "$version" "$customers"
printf '  %s Findings — \033[1m%s need attention\033[0m, %s already decided' "$total" "$open" "$decided"
[ "$caveated" != "0" ] && printf ', %s resting on weaker-than-observed evidence' "$caveated"
printf '\n\n'

# ── Rows ──────────────────────────────────────────────────────────────────────────────────────
# Sorted by residual_priority: intrinsic severity scaled by what was DECIDED (EDR-GOVERNANCE-01
# D14). This is the "what do I still have to do" ranking — a Finding marked not_affected drops to
# zero without losing the effective_priority that records how bad it actually is.
filter='.residual_priority > 0'
[ "$SHOW_ALL" = "1" ] && filter='true'

# `dash` substitutes for null AND for the empty string. jq's `//` only catches null, and an
# undecided Finding carries stance "" — which would emit an empty TSV field. Bash treats tab as
# whitespace in IFS, so it COLLAPSES runs of them, and one empty field silently shifts every
# later column left. (It did, on first run: the caveat column showed faultline UUIDs.)
jqprog='
  def dash: if . == null or . == "" then "-" else . end;
  [.[] | select(FILTER)] | sort_by(-.residual_priority) | .[0:$n] | .[]
  | [.residual_priority, .effective_priority, .base_score, .blast_multiplier,
     (.cve|dash), (.stance|dash), (.reservation|dash), (.faultline_id|dash), (.finding_id|dash)]
  | @tsv'
jqprog=${jqprog/FILTER/$filter}
rows=$(echo "$posture" | jq -r --argjson n "$TOP" "$jqprog")

{
  printf 'RANK\tBAND\tCVE\tRESID\tEFFECT\tBLAST\tKEV\tEPSS\tCOMPONENT\tFIX\tSTANCE\tCAVEAT\n'
  rank=0
  while IFS=$'\t' read -r resid effect base blast cve stance reservation flid fid; do
    [ -n "$cve" ] || continue
    rank=$((rank + 1))
    # The severity BAND and the FIX come from Knowledge. The band is exploitability-aware, not raw
    # CVSS: `critical` means CVSS>=9 AND KEV-listed; `high+` means CVSS>=9 with a public exploit.
    fl=$(get "$KNOWLEDGE/api/v1/faultlines/$flid" 2>/dev/null || echo '{}')
    band=$(echo "$fl" | jq -r '.view.priority // "-"')
    purl=$(get "$GOVERNANCE/api/v1/findings/$fid/assessment" 2>/dev/null | jq -r '(.finding.components // []) | if length == 0 then "-" else .[0].purl end')
    comp=$(echo "$purl" | sed 's#pkg:[a-z]*/##; s#?.*##')
    kev=$(echo "$fl" | jq -r 'if .view.kev then "yes" else "-" end')
    epss=$(echo "$fl" | jq -r 'if .view.epss then (.view.epss * 100 | floor | tostring + "%") else "-" end')
    # THE fix for THIS component, from the package-attributed `fixes` (KN-FIX-1). The flat
    # `fixed_versions` is a union across every package the CVE affects — reading it printed
    # "upgrade python3-ply 3.9 to 0.1.7", a different package's fix entirely. Matching on the
    # package name is what turns the column from a hazard into an instruction.
    #
    # Falls back to a candidate count when nothing is attributed to this package: a card whose
    # source never named the package (NVD CPE data, scanner reports) still shows that a fix
    # exists, without pretending to know which one applies.
    # Prefer the source-package name from Evidence; fall back to the PURL's binary name for
    # non-distro components (npm, pypi, go), where the two are the same thing.
    pkg=$(jq -r --arg u "$purl" --arg b "$(echo "$comp" | sed 's#.*/##; s#@.*##')" '.[$u] // $b' "$srcfile")
    # An empty package name would match the unattributed bucket, so refuse the lookup outright.
    [ -n "$pkg" ] || pkg=' no-such-package'
    # Shown newest-first and capped: one package legitimately has many published fixes (separate
    # el8 module streams), and a cell holding 90 of them is as unreadable as no answer at all.
    #
    # The cell is also WIDTH-capped. `column -t` sizes a column to its widest cell, so a single row
    # carrying three 45-character NEVRAs stretched the table past the terminal and wrapped every
    # other row — the long value did not just look bad, it destroyed the alignment that makes the
    # other 231 rows scannable. One over-wide cell is a whole-table defect.
    fix=$(echo "$fl" | jq -r --arg p "$pkg" --argjson w "$FIXWIDTH" '
      def clip: if ($w > 0 and (.|length) > $w) then (.[0:$w-1] + "…") else . end;
      ((.view.fixes // []) | map(select((.package // "") | ascii_downcase == ($p|ascii_downcase))) | map(.version) | unique | reverse) as $mine
      | if ($mine|length) > 3 then ((($mine[0:3]|join(", "))|clip) + " (+\($mine|length - 3))")
        elif ($mine|length) > 0 then (($mine|join(", "))|clip)
        elif ((.view.fixed_versions // [])|length) == 0 then "none published"
        else "\((.view.fixed_versions|length)) unattributed"
        end')
    printf '%s\t%s\t%s\t%s\t%s\t%sx\t%s\t%s\t%s\t%s\t%s\t%s\n' \
      "$rank" "$band" "$cve" "$resid" "$effect" "$blast" "$kev" "$epss" "$comp" "$fix" "$stance" "$reservation"
  done <<< "$rows"
} | column -t -s $'\t'

# ── AI mitigation assistance (optional, advisory) ─────────────────────────────────────────────
# The Gateway PROPOSES; it never decides (EDR-TRUST-01 T4). Anything it returns is recorded as an
# advisory proposal on `inferred` evidence, which no policy may auto-accept — a human does.
[ "$AI" -gt 0 ] 2>/dev/null || exit 0

printf '\n\033[1mAI ASSISTANCE\033[0m — advisory only; every recommendation below is recorded as a\n'
printf 'proposal on inferred evidence and is constitutionally barred from auto-acceptance.\n\n'

echo "$posture" | jq -r --argjson n "$AI" '[.[] | select(.residual_priority > 0 and .has_position == false)] | sort_by(-.residual_priority) | .[0:$n] | .[] | [.cve, .finding_id] | @tsv' |
while IFS=$'\t' read -r cve fid; do
  [ -n "$fid" ] || continue
  printf '  %s (%s) ... ' "$cve" "$fid"
  out=$(post "$GOVERNANCE/api/v1/findings/$fid/recommend" -w '\n%{http_code}')
  code=$(echo "$out" | tail -1)
  case "$code" in
    201)
      pid=$(echo "$out" | head -n -1 | jq -r '.proposal_id')
      printf 'proposed\n'
      # Read it back from the system of record rather than the response, so what is shown is what
      # was actually stored — including the UNVERIFIED MENTIONS caveat when the model's narrative
      # named an identifier nobody gave it (TRUST-8).
      psql "${THEMIS_GOVERNANCE_DSN:-}" -At -F'|' -c \
        "select stance, evidence_trust, rationale from finding_proposals where proposal_id='$pid'" 2>/dev/null |
        awk -F'|' '{printf "      stance=%s  evidence=%s\n      %s\n", $1, $2, $3}' ||
        printf '      (set THEMIS_GOVERNANCE_DSN to show the recorded rationale)\n'
      ;;
    204) printf 'no recommendation (AI disabled, unreachable, or it declined — a safe outcome)\n' ;;
    *)   printf 'error HTTP %s\n' "$code" ;;
  esac
done
printf '\n'
