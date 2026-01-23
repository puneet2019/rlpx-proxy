# XDC Peer Sniffer Makefile
#
# Targets:
#   build          - Build the application binary
#   install-go     - Install using Go install to GOPATH/bin
#   docker-build   - Build Docker image
#   docker-run     - Run the application in Docker
#   docker-shell   - Start a shell in the Docker container
#   clean          - Remove build artifacts
#   help           - Show this help message

# Variables
BINARY_NAME = peer-sniffer
DOCKER_TAG = peer-sniffer:latest
BUILD_DIR = ./build

# Detect OS
UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Linux)
	GOOS = linux
endif
ifeq ($(UNAME_S),Darwin)
	GOOS = darwin
endif

.PHONY: help build install-go docker-build docker-run docker-shell clean

# Default target
help: ## Show this help message
	@echo "XDC Peer Sniffer Makefile"
	@echo ""
	@echo "Usage:"
	@echo "  make [target]"
	@echo ""
	@echo "Targets:"
	@grep -E '^[a-zA-Z_0-9%-]+:.*?## .*$$' $(word 1,$(MAKEFILE_LIST)) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "%-15s %s\n", $$1, $$2}'

build: ## Build the application binary
	@echo "Building $(BINARY_NAME) for $(GOOS)..."
	@mkdir -p $(BUILD_DIR)
	@go build -o $(BUILD_DIR)/$(BINARY_NAME) ./cmd/peer-sniffer
	@echo "Build completed. Binary located at $(BUILD_DIR)/$(BINARY_NAME)"

install-go: build ## Install using Go install to GOPATH/bin
	@echo "Installing $(BINARY_NAME) using go install..."
	go install ./cmd/peer-sniffer
	@echo "$(BINARY_NAME) installed to $(GOPATH)/bin/"

docker-build: ## Build Docker image
	@echo "Building Docker image $(DOCKER_TAG)..."
	docker build -t $(DOCKER_TAG) .

docker-run: docker-build ## Run the application in Docker
	@echo "Running $(BINARY_NAME) in Docker container..."
	@echo "Note: Running packet capture in Docker requires special privileges"
	@echo "This may require additional configuration depending on your use case"
	docker run --rm -it \
		--cap-add=NET_ADMIN \
		--sysctl net.ipv4.conf.all.rp_filter=0 \
		-v /tmp:/tmp \
		-e XDC_PRIVATE_KEY=$(XDC_PRIVATE_KEY) \
		$(DOCKER_TAG)

docker-shell: docker-build ## Start a shell in the Docker container
	@echo "Starting shell in Docker container..."
	docker run --rm -it \
		--cap-add=NET_ADMIN \
		--sysctl net.ipv4.conf.all.rp_filter=0 \
		-e XDC_PRIVATE_KEY=$(XDC_PRIVATE_KEY) \
		$(DOCKER_TAG) /bin/sh

clean: ## Remove build artifacts
	@echo "Cleaning build artifacts..."
	rm -rf $(BUILD_DIR)
	@echo "Clean completed"

# Development target to run without installing
dev: build
	@echo "Running in development mode..."
	sudo $(BUILD_DIR)/$(BINARY_NAME) start

# Test target
test:
	@echo "Running tests..."
	go test -v ./...

# Format code
fmt:
	@echo "Formatting code..."
	go fmt ./...

# Vet code
vet:
	@echo "Vetting code..."
	go vet ./...