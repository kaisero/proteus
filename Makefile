BINARY  := panos-schemagen
PKG     := ./cmd/panos-schemagen
BIN_DIR := bin
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X main.version=$(VERSION)

# Host to pull a PAN-OS schema from, e.g. make schema-pull HOST=labadmin@10.0.0.5
HOST ?=
SCHEMA_DIR := schemas
DIGEST_DIR := schemadigest

# PAN-OS config version the schemas in $(SCHEMA_DIR) came from, e.g. 11.2.0.
# Read it from the <config version="..."> attribute of a config from that device.
PANOS_VERSION ?=

# Pinned dev-tool versions (CI installs the same ones; keep in sync with .github).
GOLANGCI_VERSION    := v2.13.1
GOFUMPT_VERSION     := v0.11.0
GOVULNCHECK_VERSION := latest

GOBIN       := $(shell go env GOPATH)/bin
GOLANGCI    := $(GOBIN)/golangci-lint
GOFUMPT     := $(GOBIN)/gofumpt
GOVULNCHECK := $(GOBIN)/govulncheck

.PHONY: help tools fmt fmt-check vet lint test test-race cover test-cov \
        vuln tidy-check gate ci build build-local generate generate-check schema-digest \
        schema-pull hooks clean

help: ## Show this help
	@grep -hE '^[a-z-]+:.*?## ' $(MAKEFILE_LIST) | sort | \
		awk 'BEGIN{FS=":.*?## "}{printf "  \033[36m%-16s\033[0m %s\n", $$1, $$2}'

## --- dev tools ---

tools: ## Install pinned dev tools (golangci-lint, gofumpt, govulncheck)
	go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_VERSION)
	go install mvdan.cc/gofumpt@$(GOFUMPT_VERSION)
	go install golang.org/x/vuln/cmd/govulncheck@$(GOVULNCHECK_VERSION)

## --- checks ---

fmt: ## Format the code (gofumpt + goimports, via golangci-lint)
	$(GOLANGCI) fmt

fmt-check: ## Fail if the code is not formatted
	$(GOLANGCI) fmt --diff

vet: ## go vet
	go vet ./...

lint: ## Run golangci-lint (linters + formatting check)
	$(GOLANGCI) run

test: ## Run unit tests
	go test ./...

test-race: ## Run unit tests with the race detector
	go test -race ./...

cover: ## Run tests and print a coverage summary (report-only, no gate)
	go test -coverprofile=coverage.out ./...
	@go tool cover -func=coverage.out | tail -1

test-cov: ## Run tests and fail if a package drops below its coverage floor
	@bash scripts/coverage-gate.sh coverage-floors.txt

vuln: ## Scan dependencies for known vulnerabilities
	$(GOVULNCHECK) ./...

tidy-check: ## Fail if go.mod/go.sum are not tidy
	go mod tidy -diff

## --- aggregates ---

gate: tidy-check lint test ## Fast pre-commit gate (tidy + lint + unit tests)

ci: tidy-check lint test-race test-cov generate-check digest-check context-check build vuln ## Everything CI runs

## --- generate / build ---

schema-digest: build-local ## Build committed digests from $(SCHEMA_DIR) (PANOS_VERSION=x.y.z)
	@test -n "$(PANOS_VERSION)" || { echo "usage: make schema-digest PANOS_VERSION=11.2.0"; exit 1; }
	$(BIN_DIR)/$(BINARY) digest -schema $(SCHEMA_DIR) -out $(DIGEST_DIR) -version $(PANOS_VERSION)

# go:embed cannot reach outside a package directory, so the digests are copied in.
# The originals in $(DIGEST_DIR) are the committed ones.
config/schemadigest: $(DIGEST_DIR)
	@mkdir -p config/schemadigest
	cp $(DIGEST_DIR)/*.json.gz config/schemadigest/

generate: build-local config/schemadigest ## Regenerate the config model from the committed digests
	$(BIN_DIR)/$(BINARY) generate -digest $(DIGEST_DIR) -out config

# Only the generated model is checked. config/ also holds hand-written code, and
# diffing the whole directory would report ordinary edits as generator drift.
GENERATED := config/v*/
generate-check: generate ## Fail if the committed model differs from a fresh run
	@git diff --exit-code -- $(GENERATED) || { \
		echo "The generated model is stale. Run 'make generate' and commit the result."; \
		exit 1; \
	}

schema-pull: ## Copy schema.xml/opschema.xml off a PAN-OS firewall (HOST=user@host)
	@test -n "$(HOST)" || { echo "usage: make schema-pull HOST=user@host"; exit 1; }
	@mkdir -p $(SCHEMA_DIR)
	scp $(HOST):/opt/pancfg/mgmt/factory/schema.xml $(SCHEMA_DIR)/
	scp $(HOST):/opt/pancfg/mgmt/factory/opschema.xml $(SCHEMA_DIR)/
	@echo "schemas in $(SCHEMA_DIR)/ — these are vendor files, see ARCHITECTURE.md before committing them"

context: ## Refresh the generated API blocks in .agents/context/
	@python3 scripts/context-api.py

context-check: ## Fail if the agent context docs have drifted from the real API
	@python3 scripts/context-api.py --check

digest-check: ## Fail if the embedded digests differ from the committed originals
	@for f in $(DIGEST_DIR)/*.json.gz; do \
		cmp -s "$$f" "config/schemadigest/$$(basename $$f)" || { \
			echo "config/schemadigest/$$(basename $$f) differs from $$f; run make config/schemadigest"; \
			exit 1; }; \
	done
	@echo "embedded digests match the originals"

tools-bin: ## Build panos-explore, panos-demo and panos-analyst for local use
	CGO_ENABLED=0 go build -ldflags '$(LDFLAGS)' -o $(BIN_DIR)/panos-explore ./cmd/panos-explore
	CGO_ENABLED=0 go build -ldflags '$(LDFLAGS)' -o $(BIN_DIR)/panos-demo ./cmd/panos-demo
	CGO_ENABLED=0 go build -ldflags '$(LDFLAGS)' -o $(BIN_DIR)/panos-analyst ./cmd/panos-analyst

build: ## Cross-compile a static linux/amd64 generator binary
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags '$(LDFLAGS)' -o $(BIN_DIR)/$(BINARY) $(PKG)

build-local: ## Native build for local use
	CGO_ENABLED=0 go build -ldflags '$(LDFLAGS)' -o $(BIN_DIR)/$(BINARY) $(PKG)

## --- misc ---

hooks: ## Enable the git pre-commit hook (runs `make gate`)
	git config core.hooksPath .githooks
	@echo "pre-commit hook enabled (core.hooksPath=.githooks)"

clean: ## Remove build artifacts
	rm -rf $(BIN_DIR) coverage.out
