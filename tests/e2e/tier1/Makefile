# Tier 1 E2E Testing Makefile
# Docker/Podman Compose based local development and testing
#
# Includes:
#   - Infrastructure management (infra-*)
#   - Application management (authz, portal)
#   - Testing commands

SHELL := /bin/bash
.DEFAULT_GOAL := help

# Include infrastructure targets
-include Makefile.infra

# Detect container runtime
RUNTIME := $(shell ./scripts/detect-runtime.sh detect 2>/dev/null || echo "docker")
COMPOSE := $(shell ./scripts/detect-runtime.sh compose 2>/dev/null || echo "docker compose")

# Directories
SCRIPT_DIR := scripts
COMPOSE_DIR := compose
CERTS_DIR := certs
TEST_DIR := tests

# Colors for output
GREEN := \033[0;32m
YELLOW := \033[1;33m
RED := \033[0;31m
NC := \033[0m

.PHONY: help
help: ## Show this help message
	@echo "Tier 1 E2E Testing Commands"
	@echo "==========================="
	@echo ""
	@echo "Runtime: $(RUNTIME)"
	@echo "Compose: $(COMPOSE)"
	@echo ""
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  $(GREEN)%-20s$(NC) %s\n", $$1, $$2}'

# ==================== Setup ====================

.PHONY: setup
setup: setup-certs setup-dirs ## Complete setup for Tier 1 testing
	@echo -e "$(GREEN)Setup complete!$(NC)"

.PHONY: setup-certs
setup-certs: ## Generate TLS certificates using mkcert
	@echo -e "$(YELLOW)Setting up TLS certificates...$(NC)"
	@chmod +x $(SCRIPT_DIR)/setup-certs.sh
	@$(SCRIPT_DIR)/setup-certs.sh

.PHONY: setup-dirs
setup-dirs: ## Create required directories
	@mkdir -p $(CERTS_DIR)
	@mkdir -p $(TEST_DIR)/results
	@mkdir -p $(TEST_DIR)/coverage

# ==================== Container Management ====================

.PHONY: up
up: ## Start all services
	@echo -e "$(YELLOW)Starting Tier 1 services...$(NC)"
	@cd $(COMPOSE_DIR) && $(COMPOSE) up -d
	@echo -e "$(GREEN)Services starting...$(NC)"
	@$(MAKE) wait

.PHONY: down
down: ## Stop all services
	@echo -e "$(YELLOW)Stopping Tier 1 services...$(NC)"
	@cd $(COMPOSE_DIR) && $(COMPOSE) down

.PHONY: destroy
destroy: ## Stop and remove all services, volumes, and images
	@echo -e "$(RED)Destroying Tier 1 environment...$(NC)"
	@cd $(COMPOSE_DIR) && $(COMPOSE) down -v --rmi local --remove-orphans

.PHONY: restart
restart: down up ## Restart all services

.PHONY: rebuild
rebuild: ## Rebuild and restart services
	@echo -e "$(YELLOW)Rebuilding services...$(NC)"
	@cd $(COMPOSE_DIR) && $(COMPOSE) build --no-cache
	@$(MAKE) restart

.PHONY: logs
logs: ## Show logs from all services
	@cd $(COMPOSE_DIR) && $(COMPOSE) logs -f

.PHONY: logs-authz
logs-authz: ## Show logs from authz-service only
	@cd $(COMPOSE_DIR) && $(COMPOSE) logs -f authz-service authz-service-external

.PHONY: ps
ps: ## Show running services
	@cd $(COMPOSE_DIR) && $(COMPOSE) ps

# ==================== Health & Status ====================

.PHONY: wait
wait: ## Wait for all services to be healthy
	@chmod +x $(SCRIPT_DIR)/wait-for-services.sh
	@$(SCRIPT_DIR)/wait-for-services.sh

.PHONY: status
status: ## Show service status and endpoints
	@echo ""
	@echo "Service Status"
	@echo "=============="
	@cd $(COMPOSE_DIR) && $(COMPOSE) ps
	@echo ""
	@echo "Endpoints"
	@echo "========="
	@echo "  Keycloak Admin:     http://localhost:8180 (admin/admin)"
	@echo "  authz-service:      http://localhost:8080"
	@echo "  authz-external:     http://localhost:9080"
	@echo "  OPA:                http://localhost:8181"
	@echo "  Redis:              localhost:6379"
	@echo "  Jaeger UI:          http://localhost:16686"
	@echo "  Prometheus:         http://localhost:9090"
	@echo "  Grafana:            http://localhost:3000 (admin/admin)"
	@echo ""
	@echo "Management Endpoints (Internal)"
	@echo "==============================="
	@echo "  Admin:              http://localhost:15000"
	@echo "  Health:             http://localhost:15020"
	@echo "  Ready:              http://localhost:15021"
	@echo ""
	@echo "Management Endpoints (External)"
	@echo "==============================="
	@echo "  Admin:              http://localhost:25000"
	@echo "  Health:             http://localhost:25020"
	@echo "  Ready:              http://localhost:25021"

# ==================== Token Management ====================

.PHONY: token-admin
token-admin: ## Get admin user token
	@chmod +x $(SCRIPT_DIR)/get-test-token.sh
	@$(SCRIPT_DIR)/get-test-token.sh admin

.PHONY: token-user
token-user: ## Get regular user token
	@chmod +x $(SCRIPT_DIR)/get-test-token.sh
	@$(SCRIPT_DIR)/get-test-token.sh user

.PHONY: token-service
token-service: ## Get service account token
	@chmod +x $(SCRIPT_DIR)/get-test-token.sh
	@$(SCRIPT_DIR)/get-test-token.sh service

.PHONY: token-external
token-external: ## Get external partner token
	@chmod +x $(SCRIPT_DIR)/get-test-token.sh
	@$(SCRIPT_DIR)/get-test-token.sh external

.PHONY: token-agent
token-agent: ## Get agent token
	@chmod +x $(SCRIPT_DIR)/get-test-token.sh
	@$(SCRIPT_DIR)/get-test-token.sh agent

# ==================== Testing ====================

.PHONY: test
test: wait ## Run all E2E tests
	@echo -e "$(YELLOW)Running E2E tests...$(NC)"
	@cd $(TEST_DIR) && go test -v -count=1 -timeout=10m ./...

.PHONY: test-short
test-short: wait ## Run quick smoke tests only
	@echo -e "$(YELLOW)Running smoke tests...$(NC)"
	@cd $(TEST_DIR) && go test -v -short -count=1 -timeout=5m ./...

.PHONY: test-auth
test-auth: wait ## Run authentication tests
	@echo -e "$(YELLOW)Running authentication tests...$(NC)"
	@cd $(TEST_DIR) && go test -v -count=1 -timeout=5m -run TestAuth ./...

.PHONY: test-authz
test-authz: wait ## Run authorization tests
	@echo -e "$(YELLOW)Running authorization tests...$(NC)"
	@cd $(TEST_DIR) && go test -v -count=1 -timeout=5m -run TestAuthz ./...

.PHONY: test-token-exchange
test-token-exchange: wait ## Run token exchange tests
	@echo -e "$(YELLOW)Running token exchange tests...$(NC)"
	@cd $(TEST_DIR) && go test -v -count=1 -timeout=5m -run TestTokenExchange ./...

.PHONY: test-delegation
test-delegation: wait ## Run agent delegation tests
	@echo -e "$(YELLOW)Running delegation tests...$(NC)"
	@cd $(TEST_DIR) && go test -v -count=1 -timeout=5m -run TestDelegation ./...

.PHONY: test-authz-to-authz
test-authz-to-authz: wait ## Run authz-to-authz tests
	@echo -e "$(YELLOW)Running authz-to-authz tests...$(NC)"
	@cd $(TEST_DIR) && go test -v -count=1 -timeout=5m -run TestAuthzToAuthz ./...

.PHONY: test-chaos
test-chaos: wait ## Run chaos engineering tests
	@echo -e "$(YELLOW)Running chaos tests...$(NC)"
	@cd $(TEST_DIR) && go test -v -count=1 -timeout=10m -run TestChaos ./...

.PHONY: test-coverage
test-coverage: wait ## Run tests with coverage
	@echo -e "$(YELLOW)Running tests with coverage...$(NC)"
	@cd $(TEST_DIR) && go test -v -count=1 -timeout=10m -coverprofile=results/coverage.out ./...
	@go tool cover -html=$(TEST_DIR)/results/coverage.out -o $(TEST_DIR)/results/coverage.html
	@echo -e "$(GREEN)Coverage report: $(TEST_DIR)/results/coverage.html$(NC)"

# ==================== Debugging ====================

.PHONY: shell-authz
shell-authz: ## Open shell in authz-service container
	@cd $(COMPOSE_DIR) && $(COMPOSE) exec authz-service /bin/sh

.PHONY: shell-external
shell-external: ## Open shell in authz-service-external container
	@cd $(COMPOSE_DIR) && $(COMPOSE) exec authz-service-external /bin/sh

.PHONY: shell-keycloak
shell-keycloak: ## Open shell in keycloak container
	@cd $(COMPOSE_DIR) && $(COMPOSE) exec keycloak /bin/bash

.PHONY: redis-cli
redis-cli: ## Open Redis CLI
	@cd $(COMPOSE_DIR) && $(COMPOSE) exec redis redis-cli

.PHONY: opa-shell
opa-shell: ## Open OPA REPL
	@cd $(COMPOSE_DIR) && $(COMPOSE) exec opa ./opa run --server --addr=localhost:0

# ==================== Cleanup ====================

.PHONY: clean
clean: ## Clean test artifacts
	@rm -rf $(TEST_DIR)/results/*
	@rm -rf $(CERTS_DIR)/*
	@echo -e "$(GREEN)Cleaned test artifacts$(NC)"

.PHONY: clean-all
clean-all: destroy clean ## Complete cleanup including containers

# ==================== CI/CD ====================

.PHONY: ci
ci: setup up test down ## Full CI pipeline: setup, start, test, stop
	@echo -e "$(GREEN)CI pipeline complete$(NC)"

.PHONY: ci-quick
ci-quick: up test-short down ## Quick CI: start, smoke tests, stop
	@echo -e "$(GREEN)Quick CI complete$(NC)"

# ==================== Application Management ====================

.PHONY: authz-up
authz-up: ## Start authz-service (requires infrastructure)
	@echo -e "$(YELLOW)Starting authz-service...$(NC)"
	@cd $(COMPOSE_DIR) && $(COMPOSE) -f docker-compose.authz.yaml up -d --build
	@echo -e "$(GREEN)authz-service started$(NC)"

.PHONY: authz-down
authz-down: ## Stop authz-service
	@cd $(COMPOSE_DIR) && $(COMPOSE) -f docker-compose.authz.yaml down

.PHONY: authz-logs
authz-logs: ## Follow authz-service logs
	@cd $(COMPOSE_DIR) && $(COMPOSE) -f docker-compose.authz.yaml logs -f

.PHONY: portal-up
portal-up: ## Start auth-portal (requires infrastructure)
	@echo -e "$(YELLOW)Starting auth-portal...$(NC)"
	@cd $(COMPOSE_DIR) && $(COMPOSE) -f docker-compose.portal.yaml up -d --build
	@echo -e "$(GREEN)auth-portal started$(NC)"

.PHONY: portal-down
portal-down: ## Stop auth-portal
	@cd $(COMPOSE_DIR) && $(COMPOSE) -f docker-compose.portal.yaml down

.PHONY: portal-logs
portal-logs: ## Follow auth-portal logs
	@cd $(COMPOSE_DIR) && $(COMPOSE) -f docker-compose.portal.yaml logs -f

# ==================== Full Stack ====================

.PHONY: stack-up
stack-up: infra-up authz-up portal-up ## Start full stack (infra + apps)
	@echo -e "$(GREEN)Full stack is ready!$(NC)"
	@$(MAKE) stack-status

.PHONY: stack-down
stack-down: portal-down authz-down infra-down ## Stop full stack
	@echo -e "$(GREEN)Full stack stopped$(NC)"

.PHONY: stack-status
stack-status: ## Show full stack status
	@echo ""
	@echo "$(GREEN)═══════════════════════════════════════════════════════════════$(NC)"
	@echo "$(GREEN)                     Full Stack Status$(NC)"
	@echo "$(GREEN)═══════════════════════════════════════════════════════════════$(NC)"
	@echo ""
	@echo "$(YELLOW)Infrastructure:$(NC)"
	@cd $(COMPOSE_DIR) && $(COMPOSE) -f docker-compose.infra.yaml ps 2>/dev/null || echo "  Not running"
	@echo ""
	@echo "$(YELLOW)Authz-Service:$(NC)"
	@cd $(COMPOSE_DIR) && $(COMPOSE) -f docker-compose.authz.yaml ps 2>/dev/null || echo "  Not running"
	@echo ""
	@echo "$(YELLOW)Auth-Portal:$(NC)"
	@cd $(COMPOSE_DIR) && $(COMPOSE) -f docker-compose.portal.yaml ps 2>/dev/null || echo "  Not running"
	@echo ""
	@echo "$(GREEN)═══════════════════════════════════════════════════════════════$(NC)"
	@echo ""
	@echo "Endpoints:"
	@echo "  Keycloak:        http://localhost:8180"
	@echo "  authz-service:   http://localhost:8080"
	@echo "  authz-external:  http://localhost:9080"
	@echo "  auth-portal:     http://localhost:8880"
	@echo "  Jaeger:          http://localhost:16686"
	@echo "  Grafana:         http://localhost:3000"
	@echo "  Prometheus:      http://localhost:9090"
	@echo ""

.PHONY: stack-destroy
stack-destroy: portal-down authz-down infra-destroy ## Destroy full stack (removes volumes)
	@echo -e "$(GREEN)Full stack destroyed$(NC)"
