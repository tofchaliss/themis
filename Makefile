export PATH := /opt/homebrew/bin:$(PATH)

GO ?= go
MODULE := github.com/themis-project/themis
BIN_DIR := bin
BINARY := $(BIN_DIR)/themis
MAIN_PKG := ./cmd/themis

COVERAGE_OUT := coverage.out
COVERAGE_TXT := coverage.txt

GO_BUILD_FLAGS ?=
GO_TEST_FLAGS ?=

.PHONY: all build clean tidy test test-integration lint coverage deadcode clean-arch check \
	migrate-up migrate-down generate-api

.DEFAULT_GOAL := build

all: build

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
	$(GO) test $(GO_TEST_FLAGS) -tags=integration ./...

lint:
	golangci-lint run ./...

coverage:
	$(GO) test $(GO_TEST_FLAGS) -tags=integration -coverprofile=$(COVERAGE_OUT) -covermode=atomic ./...
	$(GO) tool cover -func=$(COVERAGE_OUT) | tee $(COVERAGE_TXT)
	@scripts/check-coverage.sh

deadcode:
	$(GO) run golang.org/x/tools/cmd/deadcode -test ./...

clean-arch:
	$(GO) run github.com/roblaszczak/go-cleanarch \
		-domain domain \
		-application usecase \
		-interfaces adapter \
		-infrastructure infrastructure \
		./internal

check: build lint clean-arch coverage deadcode

migrate-up:
	$(GO) run github.com/golang-migrate/migrate/v4/cmd/migrate@latest -path migrations -database "$${THEMIS_DATABASE_DSN}" up

migrate-down:
	$(GO) run github.com/golang-migrate/migrate/v4/cmd/migrate@latest -path migrations -database "$${THEMIS_DATABASE_DSN}" down

generate-api:
	$(GO) run github.com/oapi-codegen/oapi-codegen/v2/cmd/oapi-codegen@latest --help >/dev/null
