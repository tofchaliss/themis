#!/usr/bin/env bash
# attribution-gap-census.sh — MEASURE the carrier attribution-gap population before anyone
# designs a taxonomy for it (EDR-ATTRIBUTION-01 D13; CONVENTIONS R4).
#
# WHY THIS EXISTS. D13 is a measurement, not a design, and it was written that way on purpose:
# "I wouldn't create this taxonomy yet. First measure the attribution-gap population and see
# whether multiple stable failure modes actually exist." A `claim_reason` beside `claim_class`
# (carrier_component_unresolved / carrier_missing / component_identity_unresolved /
# ambiguous_carrier_match) is DEFERRED until the estate says those classes are real. This script
# is how the estate says it.
#
# It is STRICTLY READ-ONLY — two SELECTs and some awk. It decides nothing, writes nothing, and
# names no class: it prints populations and lets a human read whether the shapes separate.
#
# WHY THE JOIN HAPPENS IN awk AND NOT IN SQL. The carrier products live in Knowledge's database
# and the matched components live in Governance's, and the architecture keeps those apart on
# purpose (no cross-database joins — that is what makes context isolation structural). So each
# database answers about itself and the two answers are joined outside both, which is the same
# thing the read APIs do, in the same direction.
#
# WHAT IT MEASURES, and why each number is separate.
#
#   1. THE THREE POPULATIONS. A Finding with components is in exactly one of:
#        attributed        — at least one component acts as carrier (carrier, or unknown)
#        gap               — carriers ARE named and no component matched any (the D1 gap)
#        no-carrier card   — the card names NO carrier at all
#      The third is the one D13 suspects is uncounted, and it is NOT a gap: ClassifyClaim returns
#      `unknown` when the carrier list is empty, and unknown acts as CARRIER (the fail-safe that
#      must never let missing evidence hide a live vulnerability). So those Findings are counted
#      as attributed everywhere — on evidence nobody supplied. `vm-verify` reports the whole gap
#      population as "carrier named, none matched", which cannot be true of a card that named
#      none; this splits them so the claim matches the data.
#
#   2. FAN-OUT. Gaps by component count (1 · 2-5 · 6-20 · 21+). A module-stream rebuild set
#      produces a large fan-out (the measured CVE-2026-42496 case: 37 components); an identity
#      mismatch like http_server ⇄ httpd produces one or two. If the population is bimodal here,
#      that is two failure modes visible without inventing a name for either.
#
#   3. LEXICAL PROXIMITY — A MEASUREMENT HEURISTIC, NEVER A RULE. For each gap, do any carrier
#      and any component share a token of >= 4 characters (http_server ⇄ httpd share "http")?
#      "Near" suggests a vocabulary problem between two names for one product; "far" suggests a
#      genuine bystander (a `requests` flaw whose only components are python3-ply and
#      python3-pyyaml). This is a LENS for reading the population, and deliberately not a
#      classifier: acting on a shared prefix is exactly the guess D7a refused, and the whole
#      point of R4 is that a predicate which collapses distinct cases is wrong however sensible
#      it looks. Nothing in Themis consumes this number.
#
# Usage:
#   PGBASE="postgres://themis:PASSWORD@localhost:5432" ./scripts/attribution-gap-census.sh
#
# Replay / test seam: set CENSUS_GOV_TSV and CENSUS_KN_TSV to files holding captured query output
# and no database is contacted. That is how the analysis below was exercised before it ever ran
# against an estate, and how a captured population can be re-read later without the estate.
set -uo pipefail

GOV_TSV="${CENSUS_GOV_TSV:-}"
KN_TSV="${CENSUS_KN_TSV:-}"
TMPDIR_CENSUS=""

if [ -z "$GOV_TSV" ] || [ -z "$KN_TSV" ]; then
  command -v psql >/dev/null || { echo "census: psql is required" >&2; exit 2; }
  if [ -z "${PGBASE:-}" ]; then
    echo "census: set PGBASE, e.g. PGBASE=\"postgres://themis:\$PW@localhost:5432\"" >&2
    exit 2
  fi
  TMPDIR_CENSUS="$(mktemp -d)"
  trap 'rm -rf "$TMPDIR_CENSUS"' EXIT
  GOV_TSV="$TMPDIR_CENSUS/gov.tsv"
  KN_TSV="$TMPDIR_CENSUS/kn.tsv"

  # One row per Finding that has at least one ACTIVE component (retired rows are withdrawn
  # matches — KN-SCAN-4(b) — and counting them would measure history, not the estate):
  #   faultline_id \t finding_id \t cve \t n_components \t n_scope \t n_carrier \t n_unknown \t names
  psql "$PGBASE/governance?sslmode=disable" -At -F $'\t' -c "
    select f.faultline_id, f.id, f.cve,
           count(*),
           count(*) filter (where c.claim_class = 'scope'),
           count(*) filter (where c.claim_class = 'carrier'),
           count(*) filter (where c.claim_class = ''),
           string_agg(distinct nullif(c.name, ''), ' ')
      from findings f
      join finding_components c on c.finding_id = f.id
     where c.retired_at is null
     group by f.faultline_id, f.id, f.cve" > "$GOV_TSV" 2>/dev/null

  #   faultline_id \t n_carriers \t carrier names
  psql "$PGBASE/knowledge?sslmode=disable" -At -F $'\t' -c "
    select id,
           coalesce(jsonb_array_length(view->'carrier_products'), 0),
           coalesce((select string_agg(value #>> '{}', ' ')
                       from jsonb_array_elements(view->'carrier_products')), '')
      from faultlines" > "$KN_TSV" 2>/dev/null
fi

for f in "$GOV_TSV" "$KN_TSV"; do
  [ -s "$f" ] || { echo "census: $f is empty — no data to measure" >&2; exit 1; }
done

awk -F'\t' '
  # ---- Knowledge first: carriers per card -------------------------------------------------
  FNR == NR { ncar[$1] = $2 + 0; carriers[$1] = $3; known[$1] = 1; next }

  # ---- Governance: one Finding per row ----------------------------------------------------
  {
    fl = $1; cve = $3; n = $4 + 0; nscope = $5 + 0; comps = $8
    findings++
    if (!(fl in known)) { orphan++; next }   # no card in Knowledge: nothing to measure against

    if (ncar[fl] == 0) {
      nocard++
      # A card that names no carrier CANNOT have produced a scope-class component: ClassifyClaim
      # returns `unknown` on an empty carrier list. So an all-scope Finding here means the classes
      # were written when the card DID name carriers and the card has since lost them — a STALE
      # classification, and the measurable form of the honest limit this EDR states about itself:
      # the gap derivation depends on classification currency. Non-zero means the
      # re-classification sweep is behind, not that the domain changed.
      if (nscope == n) { stale++; if (staleShown < 8) staleEx[++staleShown] = cve }
      next
    }
    if (nscope != n)   { attributed++; next }

    # A gap: carriers named, every active component scope-class.
    gaps++
    if (n == 1)       bucket["1"]++
    else if (n <= 5)  bucket["2-5"]++
    else if (n <= 20) bucket["6-20"]++
    else              bucket["21+"]++

    # What is actually installed on a gap, by name — the frequency table is what shows whether
    # the population is a handful of recurring vocabulary failures or a long tail.
    nc = split(comps, cn, " ")
    for (i = 1; i <= nc; i++) if (cn[i] != "") gapcomp[cn[i]]++
    nk = split(carriers[fl], ck, " ")
    for (i = 1; i <= nk; i++) if (ck[i] != "") gapcarr[ck[i]]++

    near = proximate(carriers[fl], comps)
    if (near) { nearN++; if (nearShown < 12) { nearEx[++nearShown] = sprintf("%-18s %-34s <- %s", cve, trunc(carriers[fl]), trunc(comps)) } }
    else      { farN++;  if (farShown  < 12) { farEx[++farShown]   = sprintf("%-18s %-34s <- %s", cve, trunc(carriers[fl]), trunc(comps)) } }
  }

  # Shared token of >= 4 characters between any carrier and any component name. A MEASUREMENT
  # LENS (see the header) — split on every non-alphanumeric so python3-pyyaml yields pyyaml,
  # and compare both containments so http_server ⇄ httpd counts through the token "http".
  function proximate(cs, ps,   i, j, a, b, na, nb, t, u) {
    na = split(tolower(cs), a, /[^a-z0-9]+/)
    nb = split(tolower(ps), b, /[^a-z0-9]+/)
    for (i = 1; i <= na; i++) {
      t = a[i]; if (length(t) < 4) continue
      for (j = 1; j <= nb; j++) {
        u = b[j]; if (length(u) < 4) continue
        if (t == u) return 1
        if (index(t, substr(u, 1, 4)) == 1 || index(u, substr(t, 1, 4)) == 1) return 1
      }
    }
    return 0
  }
  function trunc(s) { return length(s) > 32 ? substr(s, 1, 29) "..." : s }
  # Top-N by count, printed without sort(1) so the whole report stays one awk pass.
  function topn(arr, n,   k, i, bestk, bestv, used, shown) {
    for (shown = 0; shown < n; shown++) {
      bestv = -1; bestk = ""
      for (k in arr) if (!(k in used) && arr[k] > bestv) { bestv = arr[k]; bestk = k }
      if (bestv < 0) return
      used[bestk] = 1
      printf "     %6d  %s\n", bestv, bestk
    }
  }
  function pct(a, b) { return b ? sprintf("%5.1f%%", 100 * a / b) : "    -" }

  END {
    printf "\nATTRIBUTION-GAP CENSUS (EDR-ATTRIBUTION-01 D13) — a measurement, not a classification\n"
    printf "=====================================================================================\n\n"
    printf "Findings with at least one active component: %d\n\n", findings

    printf "1. THE THREE POPULATIONS\n"
    printf "   attributed       %6d  %s   at least one component acts as carrier\n", attributed, pct(attributed, findings)
    printf "   gap              %6d  %s   carriers named, NONE matched  <- the D1 gap\n", gaps, pct(gaps, findings)
    printf "   no-carrier card  %6d  %s   the card names NO carrier at all\n", nocard, pct(nocard, findings)
    if (orphan) printf "   (no card found)  %6d  %s   faultline absent from Knowledge — excluded\n", orphan, pct(orphan, findings)
    printf "\n   of the no-carrier cards, STALE classification (all components scope-class, which an\n"
    printf "   empty carrier list cannot produce): %d\n", stale
    if (staleShown) { printf "     "; for (i = 1; i <= staleShown; i++) printf "%s ", staleEx[i]; printf "\n" }
    printf "   Non-zero means the re-classification sweep is BEHIND — the honest limit this EDR\n"
    printf "   states about itself, measured. It does not mean the domain changed.\n"
    printf "\n   The third is NOT a gap and never can be: with an empty carrier list ClassifyClaim\n"
    printf "   returns `unknown`, and unknown acts as CARRIER. Those Findings are counted as\n"
    printf "   attributed everywhere in the system — on evidence nobody supplied. That is the\n"
    printf "   fail-safe working as designed, and it is also a population worth knowing the size\n"
    printf "   of, because `carrier named, none matched` is untrue of every one of them.\n\n"

    printf "2. GAP FAN-OUT (components per gap Finding)\n"
    split("1 2-5 6-20 21+", order, " ")
    for (i = 1; i <= 4; i++) printf "   %-6s %6d  %s\n", order[i], bucket[order[i]], pct(bucket[order[i]], gaps)
    printf "\n   A large fan-out is the module-stream rebuild set (measured: 37 components on one\n"
    printf "   card); one or two is an identity mismatch between two names for one product.\n\n"

    printf "3. LEXICAL PROXIMITY — a lens, NOT a classifier, and nothing consumes it\n"
    printf "   carrier and component share a >=4-char token   %6d  %s\n", nearN, pct(nearN, gaps)
    printf "   no shared token                                %6d  %s\n", farN, pct(farN, gaps)
    if (nearShown) { printf "\n   NEAR — candidate vocabulary mismatches (carrier <- components)\n"; for (i = 1; i <= nearShown; i++) printf "     %s\n", nearEx[i] }
    if (farShown)  { printf "\n   FAR — candidate genuine bystanders (carrier <- components)\n";     for (i = 1; i <= farShown; i++)  printf "     %s\n", farEx[i] }
    printf "\n4. WHAT IS ACTUALLY IN THE GAPS (top names, gap Findings only)\n"
    printf "   installed components\n"
    topn(gapcomp, 12)
    printf "   carriers named by the cards\n"
    topn(gapcarr, 12)
    printf "\n   A few names repeating across most of the population is ONE failure mode wearing\n"
    printf "   many CVE numbers; a long tail of distinct names is many. That distinction is what\n"
    printf "   D13 asks for, and it is visible here without any classifier at all.\n"

    printf "\n   A shared prefix is NOT evidence that two names are the same product: deriving\n"
    printf "   identity from the component name is exactly what D7a measured and refused. Read\n"
    printf "   this split only to answer D13: do two stable shapes exist, or one continuum?\n\n"

    printf "WHAT TO DO WITH THIS: if the shapes separate, D13 permits a claim_reason taxonomy and\n"
    printf "this output names its members. If they do not, the taxonomy stays deferred and the\n"
    printf "gap keeps saying the one true thing it says today.\n\n"
  }
' "$KN_TSV" "$GOV_TSV"
