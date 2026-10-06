# Bilyon developer entry points. `make help` lists the targets.
#
# Tests run against real infrastructure (see backend/internal/testinfra):
# local PostgreSQL, redis-server and tigerbeetle binaries are started on
# demand, or BILYON_TEST_DATABASE_URL / BILYON_TEST_REDIS_URL /
# BILYON_TIGERBEETLE_ADDRESSES point at running servers. CI sets
# BILYON_REQUIRE_INFRA=1 so that a missing server fails instead of skipping.

SHELL := /bin/bash
.SHELLFLAGS := -euo pipefail -c
GO ?= go
GO_MODULES := backend reference
GO_PACKAGES := ./backend/... ./reference/...
COMPOSE := docker compose -f deploy/docker-compose.yml
TEST_TIMEOUT ?= 15m

.DEFAULT_GOAL := help

.PHONY: help
help: ## List the targets
	@grep -hE '^[a-zA-Z_-]+:.*## ' $(MAKEFILE_LIST) | sort | \
		awk 'BEGIN {FS = ":.*## "}; {printf "  \033[36m%-14s\033[0m %s\n", $$1, $$2}'

.PHONY: build
build: ## Build every command into ./bin
	@mkdir -p bin
	cd backend && $(GO) build -trimpath -o ../bin/ ./cmd/...

.PHONY: test
test: ## Run every Go test in the workspace
	$(GO) test -timeout $(TEST_TIMEOUT) $(GO_PACKAGES)

.PHONY: test-race
test-race: ## Run every Go test with the race detector
	$(GO) test -race -timeout $(TEST_TIMEOUT) $(GO_PACKAGES)

.PHONY: vet
vet: ## go vet every package
	$(GO) vet $(GO_PACKAGES)

.PHONY: fmt
fmt: ## Format all Go code
	gofmt -w $(GO_MODULES)

.PHONY: fmt-check
fmt-check: ## Fail when Go code is not gofmt-clean
	@unformatted="$$(gofmt -l $(GO_MODULES))"; \
	if [[ -n "$$unformatted" ]]; then echo "gofmt needed:"; echo "$$unformatted"; exit 1; fi

.PHONY: tidy-check
tidy-check: ## Fail when a go.mod or go.sum is not tidy
	@for m in $(GO_MODULES); do (cd $$m && $(GO) mod tidy -diff) || { echo "run: cd $$m && go mod tidy"; exit 1; }; done

.PHONY: lint
lint: fmt-check vet tidy-check ## All static checks

.PHONY: up
up: ## Start the local stack (PostgreSQL, Redis, NATS, TigerBeetle)
	$(COMPOSE) up -d --wait

.PHONY: down
down: ## Stop the local stack (volumes are kept)
	$(COMPOSE) down

.PHONY: migrate
migrate: ## Apply ledger migrations to BILYON_DATABASE_URL
	cd backend && $(GO) run ./cmd/ledgerd migrate

.PHONY: ci
ci: lint test-race ## What CI runs
