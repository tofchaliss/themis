#!/usr/bin/env bash
# release-posture.sh — the consolidated security posture of one Release, from the CLI.
#
# This is a READ-ONLY client over the existing APIs. It adds no workflow and stores nothing: every
# number below is fetched live from Registry, Governance and Knowledge, and an operator, a GUI or
# this script see exactly the same thing.
#
# It is also, deliberately, the specification for what a GUI needs. Anything this script has to do
# by hand — enumerate, join, re-fetch — is a gap in the read surface. Two such gaps are now CLOSED:
#   * DASH-1 — a release UUID no longer has to be captured at upload: Registry serves
#     GET /products -> /products/{id}/projects -> /projects/{id}/releases, so a posture is
#     reachable by NAME. (This script still takes a UUID; the traversal is the caller's.)
#   * DASH-2 — the severity BAND, the matched COMPONENT and the published FIX ride the posture
#     row itself. This loop used to cost two extra calls per row.
# One N+1 remains on purpose: KEV/EPSS are exploit SIGNALS rather than posture, so they stay on
# Knowledge and are paid for only on the rows actually shown. See docs/BACKLOG.md.
#
# Usage:
#   scripts/release-posture.sh <release-id> [--top N] [--ai N] [--all]
#
#   --top N   how many rows to show (default 20)
#   --plan    ask the Intelligence Gateway for a release-scoped remediation plan: what to upgrade,
#             in what order, and what each step closes. ADVISORY and ephemeral (EDR-TRUST-01 T7) —
#             it recommends no stance on any Finding, so nothing enters Governance.
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

TOP=20; AI=0; SHOW_ALL=0; FIXWIDTH=40; PLAN=0
while [ $# -gt 0 ]; do
  case "$1" in
    --top) TOP="$2"; shift 2 ;;
    --ai)  AI="$2";  shift 2 ;;
    --all) SHOW_ALL=1; shift ;;
    # Ask the Gateway for a release-scoped remediation PLAN (plan_remediation@v1). Advisory and
    # ephemeral: it proposes no stance on any Finding, so nothing enters Governance.
    --plan) PLAN=1; shift ;;
    # --fix-width 0 disables clipping, for piping into a file or a wide terminal.
    --fix-width) FIXWIDTH="$2"; shift 2 ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
done

REGISTRY="${THEMIS_REGISTRY_URL:-http://localhost:8082}"
GOVERNANCE="${THEMIS_GOVERNANCE_URL:-http://localhost:8083}"
KNOWLEDGE="${THEMIS_KNOWLEDGE_URL:-http://localhost:8085}"

# Share list-open-vulns.sh's cached admin key when the caller set none. Without this, an
# auth-enabled estate made every call 401 and `curl -sf` swallowed it — the script printed
# NOTHING, which read as "the finding disappeared" during a live validation (2026-09-02).
KEY_FILE="${THEMIS_API_KEY_FILE:-$HOME/.themis_admin_api_key}"
if [ -z "${THEMIS_API_KEY:-}" ] && [ -r "$KEY_FILE" ]; then
  THEMIS_API_KEY="$(cat "$KEY_FILE")"
fi

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

# The header file captures response headers so a 204 can state WHY (AI-204-1).
hdrfile="${TMPDIR:-/tmp}/themis-posture-hdr.$$.txt"
trap 'rm -f "$hdrfile"' EXIT

# NOTE: this script no longer builds a purl→source map from Evidence's inventory. It used to, and
# the reason it can stop is the point of DASH-2: Governance's posture row now carries the component
# (with its SOURCE package) and the per-component fix selection, so the join that every client had
# to re-implement is done once, by the context that owns it.

posture=$(get "$GOVERNANCE/api/v1/releases/$REL/posture") || {
  echo "cannot read posture for $REL from $GOVERNANCE" >&2
  echo "  (on an auth-enabled node a missing/invalid key 401s silently — set THEMIS_API_KEY," >&2
  echo "   or run scripts/list-open-vulns.sh once so its cached key at $KEY_FILE exists)" >&2
  exit 1
}
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
# Sorted by residual_priority, then by BASE SCORE as a tiebreak (GOV-15).
#
# The tiebreak is load-bearing, not cosmetic. The blast multiplier is per-release CONSTANT, so it
# cannot change the relative order of a release's own Findings — but EffectivePriority CLAMPS to
# 100, and at a 2.0x multiplier every Finding with base >= 50 pins there. Measured on a 12-customer
# estate: all 120 rows read 100, and the worst item on the release (base 76) fell out of the top
# three because the order among equal values is arbitrary. Falling back to base_score restores the
# ranking the clamp erased.
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
  [.[] | select(FILTER)] | sort_by(-.residual_priority, -.base_score) | .[0:$n] | .[]
  | [.residual_priority, .effective_priority, .base_score, .blast_multiplier,
     (.cve|dash), (.stance|dash), (.reservation|dash), (.faultline_id|dash), (.finding_id|dash),
     (.band|dash),
     ((.components // []) | if length == 0 then "-" else .[0].purl end),
     ((.components // []) | length),
     ((.fixes // []) | map(.version) | if length == 0 then "" else join(", ") end),
     ((.fixes // []) | length)]
  | @tsv'
jqprog=${jqprog/FILTER/$filter}
rows=$(echo "$posture" | jq -r --argjson n "$TOP" "$jqprog")

{
  printf 'RANK\tBAND\tCVE\tRESID\tEFFECT\tBLAST\tKEV\tEPSS\tCOMPONENT\tFIX\tSTANCE\tCAVEAT\n'
  rank=0
  while IFS=$'\t' read -r resid effect base blast cve stance reservation flid fid band purl compn fixlist fixn; do
    [ -n "$cve" ] || continue
    rank=$((rank + 1))
    comp=$(echo "$purl" | sed 's#pkg:[a-z]*/##; s#?.*##')
    # Show the OTHER matched components as a count. Printing components[0] beside fixes drawn
    # from ALL of them made a 3-component Finding read as "setuptools -> a PyYAML fix" — the
    # exact cross-package contamination KN-FIX-1 removed, manufactured by the renderer. A column
    # that silently drops rows does not just omit information, it asserts something false.
    [ "${compn:-1}" -gt 1 ] 2>/dev/null && comp="$comp (+$((compn - 1)))"

    # The BAND, the COMPONENT and the FIX now ride the posture row itself (DASH-2 / PLAN-3).
    # This loop used to make TWO calls per row — one Knowledge read for the band and one
    # Governance assessment for the component — which is ~460 calls to render one table. A rollup
    # whose cost is linear in its own length cannot serve a dashboard, and every workaround here
    # was a gap in the read surface rather than a fact about the data.
    #
    # KEV and EPSS still cost one Knowledge read per row. They are exploit SIGNALS rather than
    # posture, and pushing them onto the rollup would put a fourth Knowledge field on the Finding;
    # left as the one remaining N+1, and only paid for the rows actually shown.
    fl=$(get "$KNOWLEDGE/api/v1/faultlines/$flid" 2>/dev/null || echo '{}')
    kev=$(echo "$fl" | jq -r 'if .view.kev then "yes" else "-" end')
    epss=$(echo "$fl" | jq -r 'if .view.epss then (.view.epss * 100 | floor | tostring + "%") else "-" end')

    # Width-capped: `column -t` sizes a column to its widest cell, so one row carrying three
    # 45-character NEVRAs stretched the table past the terminal and wrapped every other row.
    if [ -z "$fixlist" ]; then
      fix="none attributable"
    else
      fix=$(jq -rn --arg v "$fixlist" --argjson w "$FIXWIDTH" \
        'if ($w > 0 and ($v|length) > $w) then ($v[0:$w-1] + "…") else $v end')
      [ "$fixn" -gt 3 ] 2>/dev/null && fix="$fix (+$((fixn - 3)))"
    fi

    printf '%s\t%s\t%s\t%s\t%s\t%sx\t%s\t%s\t%s\t%s\t%s\t%s\n' \
      "$rank" "$band" "$cve" "$resid" "$effect" "$blast" "$kev" "$epss" "$comp" "$fix" "$stance" "$reservation"
  done <<< "$rows"
} | column -t -s $'\t'

# ── Release remediation plan (optional, advisory) ─────────────────────────────────────────────
# An INFORMATION capability (EDR-TRUST-01 T7): the answer is rendered for a human and discarded.
# It proposes no stance, so there is nothing to accept or reject and nothing reaches Governance.
#
# The grouping — "these nine CVEs share one module upgrade" — is computed by Governance's posture
# projection before the model is called. The model is asked only for the part needing judgement:
# sequencing and trade-offs.
if [ "$PLAN" = "1" ]; then
  printf '\n\033[1mREMEDIATION PLAN\033[0m — advisory; recommends no stance and enters no record.\n\n'
  INTELLIGENCE="${THEMIS_INTELLIGENCE_URL:-http://localhost:8086}"
  body=$(jq -nc --arg r "$REL" '{subject:{type:"release",ids:[$r]}}')
  rm -f "$hdrfile"
  out=$(post "$INTELLIGENCE/api/v1/capabilities/plan_remediation/invoke" \
        -H 'Content-Type: application/json' -d "$body" -D "$hdrfile" -w '\n%{http_code}')
  code=$(echo "$out" | tail -1)
  case "$code" in
    200) echo "$out" | head -n -1 | jq -r '.information // "(no plan text returned)"' | fold -s -w 100 ;;
    204)
      # BOTH headers: the reason names the class of failure, the detail names the instance.
      # "business_invalid" alone does not say WHICH citation was ungrounded, and that is the
      # only thing an operator can act on (the TRUST-6 argument, applied at the edge).
      why=$(grep -i '^X-Themis-AI-Reason:' "$hdrfile" 2>/dev/null | sed 's/^[^:]*: *//; s/\r$//')
      det=$(grep -i '^X-Themis-AI-Detail:' "$hdrfile" 2>/dev/null | sed 's/^[^:]*: *//; s/\r$//')
      printf 'no plan: %s%s\n' "${why:-reason not reported}" "${det:+ — $det}" ;;
    *) printf 'no plan: HTTP %s\n' "$code" ;;
  esac
  printf '\n'
fi

# ── AI mitigation assistance (optional, advisory) ─────────────────────────────────────────────
# The Gateway PROPOSES; it never decides (EDR-TRUST-01 T4). Anything it returns is recorded as an
# advisory proposal on `inferred` evidence, which no policy may auto-accept — a human does.
[ "$AI" -gt 0 ] 2>/dev/null || exit 0

printf '\n\033[1mAI ASSISTANCE\033[0m — advisory only; every recommendation below is recorded as a\n'
printf 'proposal on inferred evidence and is constitutionally barred from auto-acceptance.\n\n'

echo "$posture" | jq -r --argjson n "$AI" '[.[] | select(.residual_priority > 0 and .has_position == false)] | sort_by(-.residual_priority, -.base_score) | .[0:$n] | .[] | [.cve, .finding_id] | @tsv' |
while IFS=$'\t' read -r cve fid; do
  [ -n "$fid" ] || continue
  printf '  %s (%s) ... ' "$cve" "$fid"
  # -D captures the response headers: a 204 carries WHY on X-Themis-AI-Reason (AI-204-1),
  # because "the model declined" and "the provider is down" are the same status code and
  # opposite responses. This line used to print all three causes as one guess.
  rm -f "$hdrfile"
  out=$(post "$GOVERNANCE/api/v1/findings/$fid/recommend" -D "$hdrfile" -w '\n%{http_code}')
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
    204)
      why=$(grep -i '^X-Themis-AI-Reason:' "$hdrfile" 2>/dev/null | sed 's/^[^:]*: *//; s/\r$//')
      case "$why" in
        "")           printf 'no recommendation (reason not reported — an older Governance node)\n' ;;
        disabled)     printf 'no recommendation: AI is DISABLED on this node (config — set THEMIS_GOVERNANCE_AI_ENABLED=1)\n' ;;
        unreachable*) printf 'no recommendation: Intelligence UNREACHABLE (%s) — an outage, not a verdict\n' "$why" ;;
        insufficient*) printf 'no recommendation: the model DECLINED for want of grounding (%s) — the seam working as designed\n' "$why" ;;
        provider_error*) printf 'no recommendation: PROVIDER ERROR (%s) — check THEMIS_LLM_TIMEOUT and THEMIS_INTELLIGENCE_TIMEOUT\n' "$why" ;;
        business_verification_failed) printf 'no recommendation: the claim FAILED Business Verification against our truth (T8)\n' ;;
        *)            printf 'no recommendation: %s\n' "$why" ;;
      esac
      ;;
    *)   printf 'error HTTP %s\n' "$code" ;;
  esac
done
printf '\n'
