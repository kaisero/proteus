BINARY  := proteus
PKG     := ./cmd/proteus
BIN_DIR := bin
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X main.version=$(VERSION)

# Host to pull a PAN-OS schema from, e.g. make schema-pull HOST=labadmin@10.0.0.5
HOST ?=
SCHEMA_DIR := schemas
DIGEST_DIR := internal/config/schemadigest

# PAN-OS config version the schemas in $(SCHEMA_DIR) came from, e.g. 11.2.0.
# Read it from the <config version="..."> attribute of a config from that device.
# The digest records it; proteus reads every version with the one digest.
PANOS_VERSION ?=

# The lab device of make app-lab, by its inventory name, and the file that holds
# its API key header (one line: X-PAN-KEY: <key>).
DEVICE            ?=
APPLAB_KEY_HEADER ?=

# Pinned dev-tool versions (CI installs the same ones; keep in sync with .github).
GOLANGCI_VERSION    := v2.14.0
GOFUMPT_VERSION     := v0.11.0
GOVULNCHECK_VERSION := v1.7.0

GOBIN       := $(shell go env GOPATH)/bin
GOLANGCI    := $(GOBIN)/golangci-lint
GOFUMPT     := $(GOBIN)/gofumpt
GOVULNCHECK := $(GOBIN)/govulncheck

.PHONY: help tools fmt fmt-check vet lint test test-race cover test-cov \
        bench-check vuln vuln-tool tidy-check gate ci build build-local schema-digest context context-check \
        schema-pull app-lab hooks clean

help: ## Show this help
	@grep -hE '^[a-z-]+:.*?## ' $(MAKEFILE_LIST) | sort | \
		awk 'BEGIN{FS=":.*?## "}{printf "  \033[36m%-16s\033[0m %s\n", $$1, $$2}'

## --- dev tools ---

tools: vuln-tool ## Install pinned dev tools (golangci-lint, gofumpt, govulncheck)
	go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_VERSION)
	go install mvdan.cc/gofumpt@$(GOFUMPT_VERSION)

vuln-tool: ## Install the pinned govulncheck (CI uses this too)
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

bench-check: ## Run every benchmark once, so a broken one fails (R7)
	go test -run '^$$' -bench . -benchtime 1x ./...

vuln: ## Scan dependencies for known vulnerabilities
	$(GOVULNCHECK) ./...

tidy-check: ## Fail if go.mod/go.sum are not tidy
	go mod tidy -diff

## --- aggregates ---

gate: tidy-check lint test ## Fast pre-commit gate (tidy + lint + unit tests)

ci: tidy-check lint test-race test-cov bench-check context-check build vuln ## Everything CI runs

## --- schema / build ---

schema-digest: ## Replace the one committed digest from $(SCHEMA_DIR) (PANOS_VERSION=x.y.z)
	@test -n "$(PANOS_VERSION)" || { echo "usage: make schema-digest PANOS_VERSION=11.2.0"; exit 1; }
	go run ./internal/tools/schemadigest -schema $(SCHEMA_DIR) -out $(DIGEST_DIR) -version $(PANOS_VERSION)

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

build: ## Cross-compile a static linux/amd64 proteus binary
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags '$(LDFLAGS)' -o $(BIN_DIR)/$(BINARY) $(PKG)

build-local: ## Build bin/proteus for this machine
	CGO_ENABLED=0 go build -ldflags '$(LDFLAGS)' -o $(BIN_DIR)/$(BINARY) $(PKG)

## --- lab ---

app-lab: ## Compare proteus with the lab device (DEVICE=…), not in CI
	@test -n "$(DEVICE)" || { echo "usage: make app-lab DEVICE=fw02 APPLAB_KEY_HEADER=<file>"; exit 1; }
	go run ./internal/tools/applab -device '$(DEVICE)' -key-header '$(APPLAB_KEY_HEADER)'

## --- misc ---

hooks: ## Enable the git pre-commit hook (runs `make gate`)
	git config core.hooksPath .githooks
	@echo "pre-commit hook enabled (core.hooksPath=.githooks)"

clean: ## Remove build artifacts
	rm -rf $(BIN_DIR) coverage.out
