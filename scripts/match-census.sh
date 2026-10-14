#!/usr/bin/env bash
# match-census.sh — read-only census of the Knowledge match table, looking for the SHAPE of a
# false-positive class before anyone reads a single CVE.
#
# WHY THIS EXISTS. KN-GO-1 (2026-10-14): one Go component spelled `go1.27.1` opened 165 CVEs,
# 155 of them false, and it was found by a human reading ONE finding. The class was visible all
# along in the match table — one component with far more CVEs than any other, and a version
# column that disagreed with the purl — but nothing looked. This script looks. It prints the
# signs; it classifies nothing and changes nothing (R4: measure first).
#
# Four signs, each a query:
#   1. fan-out   — components with the most distinct CVEs. A healthy component has a handful; a
#                  version the feed could not parse gets the package's whole history.
#   2. spelling  — the version in the purl and the version column disagree. That seam is where a
#                  spelling bug hides (`1.27.1` vs `go1.27.1`).
#   3. shape     — versions that start with a letter, per ecosystem. rpm/apk never do; a letter
#                  first sorts below every digit in the generic comparator.
#   4. feed      — for the top fan-out components, ask OSV with the PURL's version and compare
#                  the count with what is matched. A large gap means the feed was asked with the
#                  wrong spelling (opt-in: needs network; set CENSUS_OSV=0 to skip).
#
# STRICTLY READ-ONLY: one psql connection, SELECTs only, and GET/POST query calls to OSV's
# public API that return advisories. No Themis API, no writes.
#
# Usage:
#   PGBASE="postgres://themis:PASSWORD@localhost:5432" ./scripts/match-census.sh [TOP]
#     TOP: how many fan-out rows to show and cross-check (default 15)
#   CENSUS_MATCHES_TSV=file   replay seam: a TSV of (purl, version, ecosystem, faultline_id,
#                             verdict_state, source) — the last two may be empty
#                             instead of the database, so the analysis runs without an estate.
#   CENSUS_OSV=0              skip the OSV cross-check.
#   CENSUS_FANOUT_FLAG=N      flag a component at N or more CVEs (default 30).
set -uo pipefail

TOP="${1:-15}"
FLAG_AT="${CENSUS_FANOUT_FLAG:-30}"
OSV="${CENSUS_OSV:-1}"
OSV_URL="${OSV_URL:-https://api.osv.dev/v1/query}"

for tool in awk sort; do
  command -v "$tool" >/dev/null || { echo "match-census: $tool is required" >&2; exit 2; }
done

# ── Load the population: purl \t version \t ecosystem \t faultline_id \t verdict \t source ──────
TSV="$(mktemp -t match-census.XXXXXX)"
trap 'rm -f "$TSV"' EXIT
if [ -n "${CENSUS_MATCHES_TSV:-}" ]; then
  cp "$CENSUS_MATCHES_TSV" "$TSV"
else
  command -v psql >/dev/null || { echo "match-census: psql is required" >&2; exit 2; }
  if [ -z "${PGBASE:-}" ]; then
    echo "match-census: set PGBASE, e.g. PGBASE=\"postgres://themis:\$PW@localhost:5432\" (or CENSUS_MATCHES_TSV=file)" >&2
    exit 2
  fi
  psql "$PGBASE/knowledge?sslmode=disable" -AtF $'\t' -c \
    "SELECT component_purl, component_version, component_ecosystem, faultline_id, verdict_state, component_source
       FROM faultline_matches WHERE retired_at IS NULL" > "$TSV" || { echo "match-census: query failed" >&2; exit 2; }
fi

TOTAL="$(wc -l < "$TSV" | tr -d ' ')"
printf '\n\033[1mTHEMIS — match census\033[0m  %s   (%s open matches)\n' "$(date '+%Y-%m-%d %H:%M')" "$TOTAL"
hdr()  { printf '\n\033[1m%s\033[0m\n' "$1"; }
flag() { printf '  \033[31m✗\033[0m %s\n' "$1"; }
ok()   { printf '  \033[32m✓\033[0m %s\n' "$1"; }
FLAGS=0

# purl helpers (awk): name = before '@'; purl version = after '@', before '?' or '#'
# shellcheck disable=SC2016
AWK_PURL='function purlname(p){ i=index(p,"@"); return i?substr(p,1,i-1):p }
          function purlver(p){ i=index(p,"@"); if(!i) return ""; v=substr(p,i+1); j=match(v,/[?#]/); return j?substr(v,1,j-1):v }
          function purltype(p){ sub(/^pkg:/,"",p); i=index(p,"/"); return i?substr(p,1,i-1):p }
          function hexv(ch){ return index("0123456789ABCDEF", toupper(ch)) - 1 }
          function pctdec(v,  o,h){ o=""; while(match(v,/%[0-9A-Fa-f][0-9A-Fa-f]/)){ o=o substr(v,1,RSTART-1); h=substr(v,RSTART+1,2); o=o sprintf("%c", hexv(substr(h,1,1))*16+hexv(substr(h,2,1))); v=substr(v,RSTART+3) }; return o v }'

# ── 1. fan-out ────────────────────────────────────────────────────────────────────────────────
hdr "1. Fan-out — distinct CVEs per component, split by verdict (top $TOP; flagged at ≥ $FLAG_AT OPEN)"
# A long history that Rocky has already fixed shows as cleared_vendor_fix and is not a sign of
# anything; only the OPEN count can point at a parse or spelling defect.
awk -F'\t' "$AWK_PURL"'{ k=purlname($1) "\t" $2; if(!(k SUBSEP $4 in seen)){ seen[k SUBSEP $4]=1; n[k]++; if($5=="" || $5=="open") op[k]++; else cl[k]++ } }
  END{ for(k in n) print n[k] "\t" op[k]+0 "\t" cl[k]+0 "\t" k }' "$TSV" | sort -t$'\t' -k1,1nr | head -n "$TOP" > "$TSV.fan"
printf '  %6s %5s %7s  %-42s %s\n' CVEs open cleared component version
FAN=0
while IFS=$'\t' read -r cnt op cl name ver; do
  mark=" "; if [ "$op" -ge "$FLAG_AT" ]; then mark="!"; FAN=$((FAN+1)); fi
  printf '  %s%5s %5s %7s  %-42s %s\n' "$mark" "$cnt" "$op" "$cl" "$name" "$ver"
done < "$TSV.fan"
FLAGS=$((FLAGS+FAN))
[ "$FAN" -gt 0 ] && flag "$FAN component(s) with $FLAG_AT or more OPEN CVEs — a feed asked with a version it could not parse answers with the package's whole history; a long history already cleared does not count" || ok "no component with $FLAG_AT or more open CVEs"

# ── 2. spelling — purl version vs version column ──────────────────────────────────────────────
hdr "2. Spelling — purl version ≠ version column, by purl type"
# An rpm purl drops the epoch the version column keeps (`1.28-423.el8_10` vs `0:1.28-423.el8_10`):
# same version, two spellings by design, so a difference that is ONLY a leading `N:` is not a gap.
awk -F'\t' "$AWK_PURL"'{ pv=pctdec(purlver($1)); col=$2; sub(/^[0-9]+:/,"",col); if(pv!="" && pv!=col){ t=purltype($1); m[t]++; c[t SUBSEP $1]=1; if(!(t in ex)) ex[t]=pv " vs " $2 } }
  END{ for(t in m){ nc=0; for(k in c){ split(k,a,SUBSEP); if(a[1]==t) nc++ }; print m[t] "\t" nc "\t" t "\t" ex[t] } }' "$TSV" \
  | sort -t$'\t' -k1,1nr > "$TSV.sp"
if [ -s "$TSV.sp" ]; then
  printf '  %7s %10s  %-10s %s\n' matches components type example
  while IFS=$'\t' read -r m nc t ex; do
    printf '  %7s %10s  %-10s %s\n' "$m" "$nc" "$t" "$ex"
  done < "$TSV.sp"
  other="$(wc -l < "$TSV.sp" | tr -d ' ')"
  flag "$other purl type(s) spell the version two ways beyond the epoch — the KN-GO-1 shape"; FLAGS=$((FLAGS+other))
else
  ok "purl and version column agree everywhere"
fi

# ── 3. shape — versions that start with a letter, per ecosystem ───────────────────────────────
hdr "3. Shape — versions that start with a letter, by ecosystem"
awk -F'\t' '$2 ~ /^[A-Za-z]/ { e=($3==""?"(none)":$3); n[e]++; if(!(e in ex)) ex[e]=$2 } END{ for(e in n) print n[e] "\t" e "\t" ex[e] }' "$TSV" \
  | sort -t$'\t' -k1,1nr > "$TSV.sh"
if [ -s "$TSV.sh" ]; then
  printf '  %7s  %-14s %s\n' matches ecosystem example
  while IFS=$'\t' read -r n e ex; do printf '  %7s  %-14s %s\n' "$n" "$e" "$ex"; done < "$TSV.sh"
  flag "a letter first sorts BELOW every digit in the generic comparator — each ecosystem here needs a normaliser like Go's, or a reason it is fine"
  FLAGS=$((FLAGS+1))
else
  ok "every matched version starts with a digit"
fi

# ── 4. feed cross-check — ask OSV with the PURL version for the top fan-out rows ──────────────
RUN_OSV=0
if [ "$OSV" = "1" ] && { [ -z "${CENSUS_MATCHES_TSV:-}" ] || [ -n "${CENSUS_OSV_FORCE:-}" ]; }; then RUN_OSV=1; fi
if [ "$RUN_OSV" = "1" ]; then
  hdr "4. Feed cross-check — OSV asked with the PURL's version vs CVEs matched"
  command -v curl >/dev/null && command -v jq >/dev/null || { echo "  (skipped: curl and jq required)"; }
  if command -v curl >/dev/null && command -v jq >/dev/null; then
    printf '  %6s %6s  %-50s %s\n' open osv component query
    while IFS=$'\t' read -r cnt op cl name ver; do
      # one representative row for this component+version
      IFS=$'\t' read -r purl src < <(awk -F'\t' -v n="$name" -v v="$ver" "$AWK_PURL"'purlname($1)==n && $2==v {print $1 "\t" $6; exit}' "$TSV")
      pp="${purl%%\?*}"; pp="${pp%%#*}"; pv="${pp##*@}"; base="${pp%@*}"
      case "$name" in
        pkg:rpm/*|pkg:apk/*|pkg:deb/*)
          # Distro packages are queried the way the client does it (osv_client.go): by the
          # distro ecosystem from the purl's distro= qualifier, the SOURCE package, and the
          # epoch-bearing version column — a purl query returns nothing for them.
          distro="$(printf '%s' "$purl" | sed -n 's/.*[?&]distro=\([^&#]*\).*/\1/p')"
          dname="${distro%%-*}"; dver="${distro#*-}"; dmaj="${dver%%.*}"
          case "$dname" in
            rocky|rockylinux) eco="Rocky Linux:$dmaj";; alma|almalinux) eco="AlmaLinux:$dmaj";;
            debian) eco="Debian:$dmaj";; alpine) eco="Alpine:v${dver%.*}";; rhel|redhat) eco="Red Hat";; *) eco="";;
          esac
          if [ -z "$eco" ]; then printf '  %s%5s %6s  %-50s %s\n' " " "$cnt" "n/a" "$name" "(no distro= qualifier)"; continue; fi
          pkg="${src:-${name##*/}}"
          body="$(jq -nc --arg n "$pkg" --arg e "$eco" --arg v "$ver" '{package:{name:$n,ecosystem:$e},version:$v}')"
          pv="$eco $pkg $ver"
          ;;
        *) body="$(jq -nc --arg p "$base@$pv" '{package:{purl:$p}}')";;
      esac
      n="$(curl -sf --max-time 20 -X POST "$OSV_URL" -d "$body" 2>/dev/null | jq -r '.vulns // [] | length' 2>/dev/null)"
      [ -z "$n" ] && n="?"
      mark=" "
      # OSV filters by version, so a fixed-and-cleared CVE never comes back; compare against the
      # OPEN matches only, which is what an unparseable spelling inflates.
      if [ "$n" != "?" ] && [ "$op" -gt $((n * 2 + 5)) ]; then mark="!"; FLAGS=$((FLAGS+1)); fi
      printf '  %s%5s %6s  %-50s %s\n' "$mark" "$op" "$n" "$name" "$pv"
    done < "$TSV.fan"
    echo "  ! = far more OPEN matches than the feed returns for this version today: the feed was asked with another spelling"
  fi
else
  hdr "4. Feed cross-check — skipped (CENSUS_OSV=0 or replay mode)"
fi

# ── Verdict ───────────────────────────────────────────────────────────────────────────────────
hdr "Result"
if [ "$FLAGS" -gt 0 ]; then
  flag "$FLAGS sign(s) of a false-positive class. This script measures; read the flagged rows before deciding anything."
  exit 1
fi
ok "no sign of a false-positive class in $TOTAL matches"
