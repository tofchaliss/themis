#!/usr/bin/env bash
set -euo pipefail

if [[ ! -f coverage.txt ]]; then
	echo "coverage.txt not found; run make coverage first" >&2
	exit 1
fi

module="github.com/themis-project/themis"

declare -a domain_pkgs=(
	domain parser trust enrichment triage queue notify config logging server
)
declare -a infra_pkgs=(
	store api ingestion watch
)

failed=0

check_threshold() {
	local pkg_path="$1"
	local threshold="$2"
	local import_path="${module}/internal/${pkg_path}"
	local output
	local pct

	output="$(go test -tags=integration -cover -covermode=atomic "./internal/${pkg_path}/..." 2>&1)"
	pct="$(echo "$output" | grep -oE 'coverage: [0-9.]+% of statements' | head -1 | grep -oE '[0-9.]+' || true)"

	if [[ -z "$pct" ]]; then
		echo "FAIL ${import_path}: no coverage data"
		failed=1
		return
	fi

	if awk -v pct="$pct" -v threshold="$threshold" 'BEGIN { exit !(pct + 0 >= threshold + 0) }'; then
		echo "OK   ${import_path}: ${pct}% (threshold ${threshold}%)"
	else
		echo "FAIL ${import_path}: ${pct}% (threshold ${threshold}%)"
		failed=1
	fi
}

for pkg in "${domain_pkgs[@]}"; do
	check_threshold "$pkg" 100
done

for pkg in "${infra_pkgs[@]}"; do
	check_threshold "$pkg" 90
done

if [[ "$failed" -ne 0 ]]; then
	exit 1
fi

echo "All package coverage thresholds satisfied."
