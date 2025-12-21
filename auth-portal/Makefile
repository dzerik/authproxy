.PHONY: all build run test lint clean docker up down logs help

# Variables
BINARY_NAME=auth-portal
DOCKER_IMAGE=auth-portal
VERSION?=dev
GO=go
GOFLAGS=-ldflags "-X main.Version=$(VERSION)"

# Default target
all: build

## help: Show this help message
help:
	@echo "Auth-Portal Makefile"
	@echo ""
	@echo "Usage:"
	@echo "  make <target>"
	@echo ""
	@echo "Targets:"
	@grep -E '^## ' $(MAKEFILE_LIST) | sed 's/## /  /'

## init: Initialize project (download dependencies)
init:
	$(GO) mod download
	$(GO) mod tidy

## build: Build the binary
build:
	CGO_ENABLED=0 $(GO) build $(GOFLAGS) -o bin/$(BINARY_NAME) ./cmd/auth-portal

## run: Run the application
run:
	$(GO) run ./cmd/auth-portal -config configs/auth-portal.yaml

## dev: Run with hot reload (requires air)
dev:
	@which air > /dev/null || (echo "Installing air..." && go install github.com/air-verse/air@latest)
	air

## test: Run tests
test:
	$(GO) test -v -race -cover ./...

## test-coverage: Run tests with coverage report
test-coverage:
	$(GO) test -v -race -coverprofile=coverage.out ./...
	$(GO) tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report: coverage.html"

## lint: Run linters
lint:
	@which golangci-lint > /dev/null || (echo "Installing golangci-lint..." && go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest)
	golangci-lint run ./...

## fmt: Format code
fmt:
	$(GO) fmt ./...
	goimports -w .

## clean: Clean build artifacts
clean:
	rm -rf bin/
	rm -f coverage.out coverage.html

## docker: Build Docker image
docker:
	docker build -t $(DOCKER_IMAGE):$(VERSION) -f deployments/Dockerfile .

## docker-dev: Build Docker image for development
docker-dev:
	docker build -t $(DOCKER_IMAGE):dev -f deployments/Dockerfile --target builder .

## up: Start docker-compose
up:
	docker-compose -f deployments/docker-compose.yaml up -d

## down: Stop docker-compose
down:
	docker-compose -f deployments/docker-compose.yaml down

## logs: Show docker-compose logs
logs:
	docker-compose -f deployments/docker-compose.yaml logs -f

## nginx-config: Generate nginx config from YAML
nginx-config:
	$(GO) run ./cmd/auth-portal -config configs/auth-portal.yaml -generate-nginx

## generate: Run go generate
generate:
	$(GO) generate ./...

## vendor: Vendor dependencies
vendor:
	$(GO) mod vendor

## check: Run all checks (fmt, lint, test)
check: fmt lint test
