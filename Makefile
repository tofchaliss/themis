export PATH := /opt/homebrew/bin:$(PATH)

GO := go
MODULE := github.com/themis-project/themis
BINARY := bin/themis
COVERAGE_OUT := coverage.out
COVERAGE_TXT := coverage.txt

.PHONY: build test test-integration lint coverage deadcode check migrate-up migrate-down generate-api tidy

build:
	$(GO) build -o $(BINARY) ./cmd/themis

test:
	$(GO) test ./...

test-integration:
	$(GO) test -tags=integration ./...

lint:
	golangci-lint run ./...

coverage:
	$(GO) test -tags=integration -coverprofile=$(COVERAGE_OUT) -covermode=atomic ./...
	$(GO) tool cover -func=$(COVERAGE_OUT) | tee $(COVERAGE_TXT)
	@scripts/check-coverage.sh

deadcode:
	$(GO) run golang.org/x/tools/cmd/deadcode -test ./...

check: build lint coverage deadcode

migrate-up:
	$(GO) run github.com/golang-migrate/migrate/v4/cmd/migrate@latest -path migrations -database "$${THEMIS_DATABASE_DSN}" up

migrate-down:
	$(GO) run github.com/golang-migrate/migrate/v4/cmd/migrate@latest -path migrations -database "$${THEMIS_DATABASE_DSN}" down

generate-api:
	$(GO) run github.com/oapi-codegen/oapi-codegen/v2/cmd/oapi-codegen@latest --help >/dev/null

tidy:
	$(GO) mod tidy
