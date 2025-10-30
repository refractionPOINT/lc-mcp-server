# Makefile for LimaCharlie MCP Server (Go)

# Variables
PROJECT_NAME := lc-mcp-server
BINARY_NAME := $(PROJECT_NAME)
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
BUILD_TIME := $(shell date -u '+%Y-%m-%d_%H:%M:%S')
GOVERSION := $(shell go version | awk '{print $$3}')

# Docker variables
DOCKER_IMAGE := $(PROJECT_NAME)
DOCKER_TAG := $(VERSION)

# Go build variables
GOFLAGS := -v
LDFLAGS := -w -s -X main.version=$(VERSION) -X main.buildTime=$(BUILD_TIME) -X main.goVersion=$(GOVERSION)

# Colors for output
GREEN  := $(shell tput -Txterm setaf 2)
YELLOW := $(shell tput -Txterm setaf 3)
RESET  := $(shell tput -Txterm sgr0)

.PHONY: all build test clean docker-build docker-run docker-test help

## help: Show this help message
help:
	@echo '$(GREEN)LimaCharlie MCP Server - Build Commands$(RESET)'
	@echo ''
	@echo 'Usage:'
	@echo '  make $(YELLOW)<target>$(RESET)'
	@echo ''
	@echo 'Targets:'
	@sed -n 's/^##//p' ${MAKEFILE_LIST} | column -t -s ':' | sed -e 's/^/ /'

## all: Build the binary
all: clean build

## build: Build the Go binary
build:
	@echo "$(GREEN)Building $(BINARY_NAME) v$(VERSION)...$(RESET)"
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
		$(GOFLAGS) \
		-ldflags="$(LDFLAGS)" \
		-o ./$(BINARY_NAME) \
		./cmd/server
	@echo "$(GREEN)Build complete: ./$(BINARY_NAME)$(RESET)"

## test: Run tests
test:
	@echo "$(GREEN)Running tests...$(RESET)"
	go test -v -race -cover ./...
	@echo "$(GREEN)Tests complete!$(RESET)"

## test-coverage: Run tests with coverage report
test-coverage:
	@echo "$(GREEN)Running tests with coverage...$(RESET)"
	go test -v -race -coverprofile=coverage.txt -covermode=atomic ./...
	go tool cover -html=coverage.txt -o coverage.html
	@echo "$(GREEN)Coverage report: coverage.html$(RESET)"

## lint: Run Go linters
lint:
	@echo "$(GREEN)Running linters...$(RESET)"
	@command -v golangci-lint >/dev/null 2>&1 || { echo "$(YELLOW)golangci-lint not installed. Run: go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest$(RESET)"; exit 1; }
	golangci-lint run ./...

## clean: Remove build artifacts
clean:
	@echo "$(GREEN)Cleaning build artifacts...$(RESET)"
	rm -f ./$(BINARY_NAME)
	rm -f ./server
	rm -f coverage.txt coverage.html
	rm -rf dist/
	@echo "$(GREEN)Clean complete!$(RESET)"

## docker-build: Build Docker image
docker-build:
	@echo "$(GREEN)Building Docker image $(DOCKER_IMAGE):$(DOCKER_TAG)...$(RESET)"
	docker build -t $(DOCKER_IMAGE):$(DOCKER_TAG) -t $(DOCKER_IMAGE):latest .
	@echo "$(GREEN)Docker build complete!$(RESET)"

## docker-run: Run Docker container
docker-run:
	@echo "$(GREEN)Running Docker container...$(RESET)"
	docker run --rm -it \
		-e MCP_MODE=stdio \
		-e MCP_PROFILE=all \
		-e LOG_LEVEL=info \
		$(DOCKER_IMAGE):latest

## docker-test: Run tests in Docker
docker-test:
	@echo "$(GREEN)Running tests in Docker...$(RESET)"
	docker-compose run --rm dev

## docker-compose-up: Start services with docker-compose
docker-compose-up:
	@echo "$(GREEN)Starting services with docker-compose...$(RESET)"
	docker-compose up --build

## docker-compose-down: Stop services
docker-compose-down:
	@echo "$(GREEN)Stopping services...$(RESET)"
	docker-compose down

## docker-scan: Scan Docker image for vulnerabilities
docker-scan:
	@echo "$(GREEN)Scanning Docker image for vulnerabilities...$(RESET)"
	@command -v trivy >/dev/null 2>&1 || { echo "$(YELLOW)trivy not installed. Run: brew install trivy or apt-get install trivy$(RESET)"; exit 1; }
	trivy image $(DOCKER_IMAGE):latest

## gcloud-build: Build using Google Cloud Build
gcloud-build:
	@echo "$(GREEN)Building with Google Cloud Build...$(RESET)"
	gcloud builds submit --config=cloudbuild.yaml

## gcloud-deploy: Deploy to Cloud Run
gcloud-deploy:
	@echo "$(GREEN)Deploying to Cloud Run...$(RESET)"
	gcloud builds submit --config=cloudbuild-deploy.yaml \
		--substitutions=_IMAGE_TAG=$(DOCKER_TAG),_ENV=staging

## deps: Download Go dependencies
deps:
	@echo "$(GREEN)Downloading dependencies...$(RESET)"
	go mod download
	go mod verify
	@echo "$(GREEN)Dependencies downloaded!$(RESET)"

## tidy: Tidy Go modules
tidy:
	@echo "$(GREEN)Tidying Go modules...$(RESET)"
	go mod tidy
	@echo "$(GREEN)Modules tidied!$(RESET)"

## fmt: Format Go code
fmt:
	@echo "$(GREEN)Formatting code...$(RESET)"
	go fmt ./...
	@echo "$(GREEN)Format complete!$(RESET)"

## vet: Run go vet
vet:
	@echo "$(GREEN)Running go vet...$(RESET)"
	go vet ./...
	@echo "$(GREEN)Vet complete!$(RESET)"

## version: Show version information
version:
	@echo "$(GREEN)Version:$(RESET)     $(VERSION)"
	@echo "$(GREEN)Build Time:$(RESET)  $(BUILD_TIME)"
	@echo "$(GREEN)Go Version:$(RESET)  $(GOVERSION)"

## run: Build and run locally
run: build
	@echo "$(GREEN)Running $(BINARY_NAME)...$(RESET)"
	./$(BINARY_NAME)

.DEFAULT_GOAL := help
