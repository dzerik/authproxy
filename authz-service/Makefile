.PHONY: build test lint run clean deps tidy

# Variables
BINARY_NAME=authz
BUILD_DIR=bin
CMD_DIR=cmd/authz
CONFIG_PATH=configs/config.yaml

# Version info
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
BUILD_TIME = $(shell date -u '+%Y-%m-%dT%H:%M:%SZ')
GIT_COMMIT = $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")

# Go commands
GOCMD=go
GOBUILD=$(GOCMD) build
GOTEST=$(GOCMD) test
GOMOD=$(GOCMD) mod
GORUN=$(GOCMD) run

# Build flags
LDFLAGS=-ldflags="-w -s \
	-X main.Version=$(VERSION) \
	-X main.BuildTime=$(BUILD_TIME) \
	-X main.GitCommit=$(GIT_COMMIT)"

# Default target
all: build

# Build
build:
	@echo "Building $(BINARY_NAME)..."
	@mkdir -p $(BUILD_DIR)
	$(GOBUILD) $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME) ./$(CMD_DIR)

# Build for development (with debug info)
build-dev:
	@echo "Building $(BINARY_NAME) (dev)..."
	@mkdir -p $(BUILD_DIR)
	$(GOBUILD) -o $(BUILD_DIR)/$(BINARY_NAME) ./$(CMD_DIR)

# Run
run:
	$(GORUN) ./$(CMD_DIR) --config $(CONFIG_PATH)

# Run with hot reload (requires air: go install github.com/air-verse/air@latest)
dev:
	air

# Test
test:
	$(GOTEST) -v -race -coverprofile=coverage.out ./...

test-short:
	$(GOTEST) -v -short ./...

test-coverage:
	$(GOTEST) -v -race -coverprofile=coverage.out ./...
	$(GOCMD) tool cover -html=coverage.out -o coverage.html

# Integration tests
test-integration:
	$(GOTEST) -v -tags=integration ./tests/integration/...

# Lint (requires golangci-lint)
lint:
	golangci-lint run ./...

# Format
fmt:
	$(GOCMD) fmt ./...
	goimports -w .

# Dependencies
deps:
	$(GOMOD) download

tidy:
	$(GOMOD) tidy

# Generate (mocks, proto, etc.)
generate:
	$(GOCMD) generate ./...

# Generate JSON Schemas
schema:
	@echo "Generating JSON Schemas..."
	$(GORUN) ./cmd/authz --schema config --schema-output configs/config.schema.json
	$(GORUN) ./cmd/authz --schema rules --schema-output configs/rules.schema.json
	@echo "Generated:"
	@echo "  - configs/config.schema.json"
	@echo "  - configs/rules.schema.json"

schema-config:
	$(GORUN) ./cmd/authz --schema config --schema-output configs/config.schema.json

schema-rules:
	$(GORUN) ./cmd/authz --schema rules --schema-output configs/rules.schema.json

# Clean
clean:
	@echo "Cleaning..."
	@rm -rf $(BUILD_DIR)
	@rm -f coverage.out coverage.html

# Docker
docker-build:
	docker build -t $(BINARY_NAME):latest -f deployments/docker/Dockerfile .

docker-run:
	docker run -p 8080:8080 $(BINARY_NAME):latest

# Install dev tools
tools:
	go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
	go install golang.org/x/tools/cmd/goimports@latest
	go install github.com/air-verse/air@latest

# Help
help:
	@echo "Available targets:"
	@echo "  build          - Build the binary"
	@echo "  build-dev      - Build with debug info"
	@echo "  run            - Run the application"
	@echo "  dev            - Run with hot reload"
	@echo "  test           - Run all tests"
	@echo "  test-short     - Run short tests"
	@echo "  test-coverage  - Run tests with coverage"
	@echo "  lint           - Run linter"
	@echo "  fmt            - Format code"
	@echo "  deps           - Download dependencies"
	@echo "  tidy           - Tidy go.mod"
	@echo "  generate       - Run go generate"
	@echo "  schema         - Generate config JSON Schema"
	@echo "  clean          - Clean build artifacts"
	@echo "  docker-build   - Build Docker image"
	@echo "  tools          - Install dev tools"
