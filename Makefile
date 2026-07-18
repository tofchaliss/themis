export PATH := /opt/homebrew/bin:$(PATH)

# Prefer Homebrew Go (1.25+) over legacy /usr/local/go installs.
GO ?= $(shell PATH="/opt/homebrew/bin:$$PATH" command -v go 2>/dev/null || command -v go)
MODULE := github.com/themis-project/themis
BIN_DIR := bin
BINARY := $(BIN_DIR)/themis
MAIN_PKG := ./cmd/themis

COVERAGE_OUT := coverage.out
COVERAGE_TXT := coverage.txt

GO_BUILD_FLAGS ?=
GO_TEST_FLAGS ?=

COVERAGE_PKGS := ./internal/kernel/... ./internal/registry/... ./internal/evidence/... ./internal/knowledge/... ./internal/governance/... ./internal/communication/... ./internal/intelligence/... ./internal/platform/... ./internal/domain/... ./internal/usecase/... ./internal/adapter/... ./internal/infrastructure/... ./tests/acceptance/...

.PHONY: all build clean tidy test test-integration test-property lint coverage coverage-pkg deadcode clean-arch arch-test check \
	migrate-up migrate-down generate-api generate-api-evidence generate-api-registry generate-api-knowledge e2e-evidence verify-build

# Greenfield context-first trees under internal/ (ring names domain/app/adapters).
# Add a context here as it is scaffolded.
GREENFIELD_CONTEXTS := evidence registry knowledge governance communication intelligence

.DEFAULT_GOAL := build

all: build

# Full codebase: clean artifacts/cache and rebuild from scratch. Run after every task group.
verify-build: clean all

$(BIN_DIR):
	mkdir -p $(BIN_DIR)

build: $(BIN_DIR)
	$(GO) build $(GO_BUILD_FLAGS) -o $(BINARY) $(MAIN_PKG)

clean:
	rm -rf $(BIN_DIR)
	rm -f $(COVERAGE_OUT) $(COVERAGE_TXT)
	$(GO) clean -testcache
	$(GO) clean ./...

tidy:
	$(GO) mod tidy

test:
	$(GO) test $(GO_TEST_FLAGS) ./...

test-integration:
	$(GO) test $(GO_TEST_FLAGS) -tags=integration -p 1 ./...

# Deep property-based run: drives rapid with a high example count. Override with
# RAPID_CHECKS (e.g. make test-property RAPID_CHECKS=10000). Intended for nightly
# / pre-release runs; the same property tests also run as normal unit tests.
# Only packages that import rapid are passed, because the -rapid.checks flag is
# unknown to test binaries that do not register it.
test-property:
	@pkgs=$$(grep -rlE 'pgregory\.net/rapid' --include='*_test.go' internal tests | sed -e 's#/[^/]*$$##' -e 's#^#./#' | sort -u); \
	echo "property packages:" $$pkgs; \
	$(GO) test $(GO_TEST_FLAGS) $$pkgs -run 'Property|Prop_' -rapid.checks=$${RAPID_CHECKS:-1000}

lint:
	golangci-lint run ./...

coverage:
	$(GO) test $(GO_TEST_FLAGS) -tags=integration -p 1 -coverprofile=$(COVERAGE_OUT) -covermode=atomic $(COVERAGE_PKGS)
	$(GO) tool cover -func=$(COVERAGE_OUT) | tee $(COVERAGE_TXT)
	@scripts/check-coverage.sh

# Task-group coverage gate: check only the package(s) for the current task group.
# Usage: make coverage-pkg PKG=usecase/enrichment
#        make coverage-pkg PKG="usecase/enrichment adapter/store"
coverage-pkg:
	@test -n "$(PKG)" || (echo "usage: make coverage-pkg PKG=usecase/enrichment" >&2; exit 1)
	@scripts/check-coverage.sh $(PKG)

# Register new packages in scripts/check-coverage.sh (domain/usecase/parser/trust/notify → 100%;
# store/api/infrastructure → ≥90%).

deadcode:
	$(GO) run golang.org/x/tools/cmd/deadcode -test ./...

clean-arch:
	$(GO) run github.com/roblaszczak/go-cleanarch \
		-domain domain \
		-application usecase \
		-interfaces adapter \
		-infrastructure infrastructure \
		./internal
	@# Greenfield contexts are context-first (domain/app/adapters); go-cleanarch's
	@# flat model can't mix naming schemes in one run, so check each context tree.
	@for ctx in $(GREENFIELD_CONTEXTS); do \
		echo "[cleanarch] context internal/$$ctx"; \
		$(GO) run github.com/roblaszczak/go-cleanarch \
			-domain domain -application app -interfaces adapters \
			./internal/$$ctx || exit 1; \
	done

# Module-wide architecture test: context-first ring direction + no cross-context
# imports (rules go-cleanarch's flat model cannot express). See tests/architecture.
arch-test:
	$(GO) test $(GO_TEST_FLAGS) ./tests/architecture/...

check: build lint clean-arch arch-test coverage deadcode

# golang-migrate registers the postgres driver only with -tags postgres.
MIGRATE := $(GO) run -tags postgres github.com/golang-migrate/migrate/v4/cmd/migrate@v4.19.1

migrate-up:
	@test -n "$${THEMIS_DATABASE_DSN}" || (echo "THEMIS_DATABASE_DSN is required" >&2; exit 1)
	$(MIGRATE) -path migrations -database "$${THEMIS_DATABASE_DSN}" up

migrate-down:
	@test -n "$${THEMIS_DATABASE_DSN}" || (echo "THEMIS_DATABASE_DSN is required" >&2; exit 1)
	$(MIGRATE) -path migrations -database "$${THEMIS_DATABASE_DSN}" down

generate-api:
	$(GO) run github.com/oapi-codegen/oapi-codegen/v2/cmd/oapi-codegen@v2.7.1 --config=api/oapi-codegen.yaml api/openapi.yaml

# Evidence context (greenfield) API codegen — spec-first, own gen package.
generate-api-evidence:
	$(GO) run github.com/oapi-codegen/oapi-codegen/v2/cmd/oapi-codegen@v2.7.1 --config=api/evidence.oapi-codegen.yaml api/evidence.openapi.yaml

# Registry supporting context (greenfield) API codegen — spec-first, own gen package.
generate-api-registry:
	$(GO) run github.com/oapi-codegen/oapi-codegen/v2/cmd/oapi-codegen@v2.7.1 --config=api/registry.oapi-codegen.yaml api/registry.openapi.yaml

# Knowledge context (greenfield) read-API codegen — spec-first, own gen package.
generate-api-knowledge:
	$(GO) run github.com/oapi-codegen/oapi-codegen/v2/cmd/oapi-codegen@v2.7.1 --config=api/knowledge.oapi-codegen.yaml api/knowledge.openapi.yaml

# Governance context (greenfield) triage + read-API codegen — spec-first, own gen package.
generate-api-governance:
	$(GO) run github.com/oapi-codegen/oapi-codegen/v2/cmd/oapi-codegen@v2.7.1 --config=api/governance.oapi-codegen.yaml api/governance.openapi.yaml

# Communication context (greenfield) publish-trigger + read/preview API codegen — spec-first.
generate-api-communication:
	$(GO) run github.com/oapi-codegen/oapi-codegen/v2/cmd/oapi-codegen@v2.7.1 --config=api/communication.oapi-codegen.yaml api/communication.openapi.yaml

# Intelligence Gateway (greenfield) reactive invoke API codegen — spec-first.
generate-api-intelligence:
	$(GO) run github.com/oapi-codegen/oapi-codegen/v2/cmd/oapi-codegen@v2.7.1 --config=api/intelligence.oapi-codegen.yaml api/intelligence.openapi.yaml

# End-to-end smoke test for the Evidence service (embedded Postgres; no Docker).
# Drop your SBOM at tests/e2e/testdata/sample.sbom.json, or point at your own:
#   EVIDENCE_E2E_SBOM=/path/to/your.sbom.json make e2e-evidence
#   EVIDENCE_E2E_FORMAT=spdx make e2e-evidence
e2e-evidence:
	$(GO) test -tags=e2e -count=1 -v ./tests/e2e/...
