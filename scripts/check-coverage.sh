#!/usr/bin/env bash
set -euo pipefail

module="github.com/themis-project/themis"

declare -a domain_pkgs=(
	domain
	usecase/ingestion
	usecase/enrichment
	usecase/triage
	usecase/vexgen
	usecase/watch
	adapter/parser
	adapter/trust
	adapter/notify
)
declare -a infra_pkgs=(
	adapter/store
	adapter/api
	adapter/epsskev
	adapter/exploitdb
	adapter/assetgraph
	adapter/vexfeed
	infrastructure/db
	infrastructure/queue
	infrastructure/http
	infrastructure/config
	infrastructure/metrics
	infrastructure/cli
)

failed=0

threshold_for() {
	local pkg_path="$1"
	case "$pkg_path" in
		usecase/enrichment) echo 90; return ;;
		adapter/epsskev|adapter/exploitdb) echo 85; return ;;
		adapter/api) echo 80; return ;;
	esac
	for pkg in "${domain_pkgs[@]}"; do
		if [[ "$pkg" == "$pkg_path" ]]; then
			echo 100
			return
		fi
	done
	for pkg in "${infra_pkgs[@]}"; do
		if [[ "$pkg" == "$pkg_path" ]]; then
			echo 90
			return
		fi
	done
	echo "unknown package: ${pkg_path} (register it in scripts/check-coverage.sh)" >&2
	exit 2
}

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

coverage_percent_from_profile() {
	local pkg_path="$1"
	local prefix="${module}/internal/${pkg_path}/"
	awk -v prefix="$prefix" '
		$1 ~ prefix {
			n = $2
			c = $3
			total += n
			if (c > 0) {
				covered += n
			}
		}
		END {
			if (total == 0) {
				print "0"
			} else {
				printf "%.1f", (covered * 100) / total
			}
		}
	' coverage.out
}

check_threshold_from_profile() {
	local pkg_path="$1"
	local threshold="$2"
	local import_path="${module}/internal/${pkg_path}"
	local pct

	if [[ ! -f coverage.out ]]; then
		echo "FAIL ${import_path}: coverage.out not found"
		failed=1
		return
	fi

	pct="$(coverage_percent_from_profile "$pkg_path")"

	if awk -v pct="$pct" -v threshold="$threshold" 'BEGIN { exit !(pct + 0 >= threshold + 0) }'; then
		echo "OK   ${import_path}: ${pct}% (threshold ${threshold}%)"
	else
		echo "FAIL ${import_path}: ${pct}% (threshold ${threshold}%)"
		failed=1
	fi
}

# Task-group mode: check only the package(s) passed as arguments.
if [[ $# -gt 0 ]]; then
	for pkg_path in "$@"; do
		check_threshold "$pkg_path" "$(threshold_for "$pkg_path")"
	done
	if [[ "$failed" -ne 0 ]]; then
		exit 1
	fi
	echo "Package coverage threshold(s) satisfied."
	exit 0
fi

# Full-repo mode: used by `make coverage` after generating coverage.out.
if [[ ! -f coverage.txt ]]; then
	echo "coverage.txt not found; run make coverage first" >&2
	exit 1
fi

if [[ ! -f coverage.out ]]; then
	echo "coverage.out not found; run make coverage first" >&2
	exit 1
fi

for pkg in "${domain_pkgs[@]}"; do
	check_threshold_from_profile "$pkg" "$(threshold_for "$pkg")"
done

for pkg in "${infra_pkgs[@]}"; do
	check_threshold_from_profile "$pkg" "$(threshold_for "$pkg")"
done

if [[ "$failed" -ne 0 ]]; then
	exit 1
fi

echo "All package coverage thresholds satisfied."
