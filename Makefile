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

# Greenfield-only coverage scope. The frozen v0.3.x legacy tree (internal/{domain,
# usecase,adapter,infrastructure}, tests/acceptance) is reference-only and has
# platform-dependent integration tests green only on macOS's coarse clock, so CI gates
# the go-forward tree via `make check-ci`, not the whole repo.
COVERAGE_PKGS_GREENFIELD := ./internal/kernel/... ./internal/registry/... ./internal/evidence/... ./internal/knowledge/... ./internal/governance/... ./internal/communication/... ./internal/intelligence/... ./internal/platform/...

.PHONY: all build clean tidy test test-integration test-property lint coverage coverage-greenfield coverage-pkg deadcode clean-arch arch-test check check-ci \
	migrate-up migrate-down generate-api generate-api-evidence generate-api-registry generate-api-knowledge e2e-evidence e2e-pipeline e2e-llm e2e-embed verify-build

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

# Greenfield-only coverage (used by check-ci). check-coverage.sh skips any registered
# package absent from the profile, so the frozen legacy packages are simply not gated.
coverage-greenfield:
	$(GO) test $(GO_TEST_FLAGS) -tags=integration -p 1 -coverprofile=$(COVERAGE_OUT) -covermode=atomic $(COVERAGE_PKGS_GREENFIELD)
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

check: build test lint clean-arch arch-test coverage deadcode

# CI gate — greenfield-scoped: same as `check` but coverage covers only the go-forward
# tree (the frozen v0.3.x legacy integration tests are green only on macOS and are
# reference-only). Run by .github/workflows/{pr,main}.yml; `make check` stays whole-repo
# for local use.
check-ci: build test lint clean-arch arch-test coverage-greenfield deadcode

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

# Deterministic no-AI SBOM→VEX gate (M5 EB-08): registers a release through the real Registry,
# uploads an SBOM to Evidence, and drives all four contexts + the `bus` database on one embedded
# Postgres through the real event bus — correlate → open a Finding → govern an "affected"
# Position → publish OpenVEX — asserting the produced artifact names the CVE. Runs NO model (AI
# is off by construction: a nil advisor). Self-provisions Postgres (skips if unavailable). A
# deployment-faithful integration gate run on every PR (pr.yml) and post-merge (main.yml); it is
# not part of `make check` (which self-provisions its own Postgres only inside coverage).
e2e-pipeline:
	$(GO) test -tags=e2e -count=1 -v ./tests/pipeline/...

# Opt-in REAL-LLM e2e for the Intelligence Gateway: recommend_position against a running
# OpenAI-compatible model server. The provider is a pure OpenAI-compatible client, so it
# works with Ollama, LM Studio, or vLLM — just point THEMIS_LLM_URL at it. SKIPS when no
# server answers, so it is safe anywhere; NOT part of `make check` (non-deterministic).
#   Ollama:    THEMIS_LLM_URL=http://localhost:11434 THEMIS_LLM_MODEL=llama3.1:8b make e2e-llm
#   LM Studio: THEMIS_LLM_URL=http://localhost:1234  THEMIS_LLM_MODEL=<model>     make e2e-llm
e2e-llm:
	$(GO) test -tags=llm -count=1 -v -run TestE2ERealLLM ./internal/intelligence/adapters/http/...

# Opt-in embedding-model + what-to-embed evaluation for the Δ3a Knowledge Engine (R5). Embeds a
# small labeled corpus (findings grouped by shared component) with each candidate model + text
# composition and reports same-component sibling retrieval (recall@1/@3, MRR) + embed latency —
# higher recall/MRR + lower latency is better. Needs a running Ollama (or any OpenAI-compatible
# embedding server); SKIPS when none answers; NOT part of `make check`.
#   THEMIS_EMBED_MODELS=nomic-embed-text,mxbai-embed-large,bge-large make e2e-embed
e2e-embed:
	$(GO) test -tags=embed_eval -count=1 -v -run TestEmbeddingModelEval ./internal/intelligence/adapters/embed/...
