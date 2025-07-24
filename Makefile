# Makefile for CoreSwitch S1AP Analyzer
# =====================================

.PHONY: all build clean test install help tools examples

# Variables
BINARY_NAME=s1ap-analyzer
BUILD_DIR=build
CMD_DIR=cmd/s1ap-analyzer
PKG_DIR=pkg
TOOLS_DIR=tools
EXAMPLES_DIR=examples

# Go parameters
GOCMD=go
GOBUILD=$(GOCMD) build
GOCLEAN=$(GOCMD) clean
GOTEST=$(GOCMD) test
GOGET=$(GOCMD) get
GOMOD=$(GOCMD) mod
GOFMT=$(GOCMD) fmt

# Build flags
LDFLAGS=-ldflags "-X main.version=$(shell git describe --tags --always --dirty) -X main.buildTime=$(shell date -u '+%Y-%m-%d_%H:%M:%S')"

# Default target
all: clean build

# Build the main application
build:
	@echo "🔨 Building $(BINARY_NAME)..."
	@mkdir -p $(BUILD_DIR)
	$(GOBUILD) $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME) ./$(CMD_DIR)
	@echo "✅ Build complete: $(BUILD_DIR)/$(BINARY_NAME)"

# Build development version
dev:
	@echo "🔨 Building development version..."
	@mkdir -p $(BUILD_DIR)
	$(GOBUILD) -race -o $(BUILD_DIR)/$(BINARY_NAME)-dev ./$(CMD_DIR)
	@echo "✅ Development build complete"

# Clean build artifacts
clean:
	@echo "🧹 Cleaning..."
	$(GOCLEAN)
	@rm -rf $(BUILD_DIR)
	@rm -f $(TOOLS_DIR)/*-analyzer
	@rm -f *_analyzer *.pcap *.log
	@echo "✅ Clean complete"

# Run tests
test:
	@echo "🧪 Running tests..."
	$(GOTEST) -v ./...
	@echo "✅ Tests complete"

# Run tests with coverage
test-coverage:
	@echo "🧪 Running tests with coverage..."
	$(GOTEST) -v -coverprofile=coverage.out ./...
	$(GOCMD) tool cover -html=coverage.out -o coverage.html
	@echo "✅ Coverage report generated: coverage.html"

# Install dependencies
deps:
	@echo "📦 Installing dependencies..."
	$(GOMOD) download
	$(GOMOD) tidy
	@echo "✅ Dependencies installed"

# Format code
fmt:
	@echo "📝 Formatting code..."
	$(GOFMT) ./...
	@echo "✅ Code formatted"

# Lint code (requires golangci-lint)
lint:
	@echo "🔍 Linting code..."
	@command -v golangci-lint >/dev/null 2>&1 || { echo "golangci-lint not installed. Run: go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest"; exit 1; }
	golangci-lint run
	@echo "✅ Linting complete"

# Install the binary to system
install: build
	@echo "📥 Installing $(BINARY_NAME)..."
	@sudo cp $(BUILD_DIR)/$(BINARY_NAME) /usr/local/bin/
	@echo "✅ Installed to /usr/local/bin/$(BINARY_NAME)"

# Create example PCAP samples
examples:
	@echo "📋 Creating example files..."
	@mkdir -p $(EXAMPLES_DIR)
	@echo "Example usage commands" > $(EXAMPLES_DIR)/README.md
	@echo "======================" >> $(EXAMPLES_DIR)/README.md
	@echo "" >> $(EXAMPLES_DIR)/README.md
	@echo "# Basic analysis" >> $(EXAMPLES_DIR)/README.md
	@echo "./$(BINARY_NAME) capture.pcap" >> $(EXAMPLES_DIR)/README.md
	@echo "" >> $(EXAMPLES_DIR)/README.md
	@echo "# Detailed analysis with limit" >> $(EXAMPLES_DIR)/README.md
	@echo "./$(BINARY_NAME) -format detailed -limit 1000 capture.pcap" >> $(EXAMPLES_DIR)/README.md
	@echo "" >> $(EXAMPLES_DIR)/README.md
	@echo "# JSON output" >> $(EXAMPLES_DIR)/README.md
	@echo "./$(BINARY_NAME) -format json capture.pcap > analysis.json" >> $(EXAMPLES_DIR)/README.md
	@echo "" >> $(EXAMPLES_DIR)/README.md
	@echo "# Statistics only" >> $(EXAMPLES_DIR)/README.md
	@echo "./$(BINARY_NAME) -stats capture.pcap" >> $(EXAMPLES_DIR)/README.md
	@echo "✅ Examples created in $(EXAMPLES_DIR)/"

# Build for multiple platforms
build-all:
	@echo "🔨 Building for multiple platforms..."
	@mkdir -p $(BUILD_DIR)
	
	# Linux amd64
	GOOS=linux GOARCH=amd64 $(GOBUILD) $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-linux-amd64 ./$(CMD_DIR)
	
	# Linux arm64
	GOOS=linux GOARCH=arm64 $(GOBUILD) $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-linux-arm64 ./$(CMD_DIR)
	
	# macOS amd64
	GOOS=darwin GOARCH=amd64 $(GOBUILD) $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-darwin-amd64 ./$(CMD_DIR)
	
	# macOS arm64
	GOOS=darwin GOARCH=arm64 $(GOBUILD) $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-darwin-arm64 ./$(CMD_DIR)
	
	# Windows amd64
	GOOS=windows GOARCH=amd64 $(GOBUILD) $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-windows-amd64.exe ./$(CMD_DIR)
	
	@echo "✅ Multi-platform build complete"

# Development workflow
dev-setup: deps fmt test build
	@echo "🚀 Development environment ready!"

# Quick development build and run
run: build
	@echo "🏃 Running $(BINARY_NAME)..."
	@./$(BUILD_DIR)/$(BINARY_NAME) -help

# Create documentation
docs:
	@echo "📚 Generating documentation..."
	@mkdir -p docs
	@echo "# S1AP Analyzer Documentation" > docs/README.md
	@echo "" >> docs/README.md
	@./$(BUILD_DIR)/$(BINARY_NAME) -help >> docs/README.md 2>&1 || true
	@echo "✅ Documentation generated in docs/"

# Check version
version:
	@echo "Version: $(shell git describe --tags --always --dirty)"
	@echo "Build Time: $(shell date -u '+%Y-%m-%d_%H:%M:%S')"

# Show help
help:
	@echo "CoreSwitch S1AP Analyzer - Makefile Help"
	@echo "========================================"
	@echo ""
	@echo "Available targets:"
	@echo "  build        - Build the main application"
	@echo "  dev          - Build development version with race detector"
	@echo "  clean        - Clean build artifacts and temporary files"
	@echo "  test         - Run all tests"
	@echo "  test-coverage- Run tests with coverage report"
	@echo "  deps         - Install/update dependencies"
	@echo "  fmt          - Format Go code"
	@echo "  lint         - Lint code (requires golangci-lint)"
	@echo "  install      - Install binary to system (/usr/local/bin)"
	@echo "  examples     - Create example usage files"
	@echo "  build-all    - Build for multiple platforms"
	@echo "  dev-setup    - Complete development environment setup"
	@echo "  run          - Build and show help"
	@echo "  docs         - Generate documentation"
	@echo "  version      - Show version information"
	@echo "  help         - Show this help message"
	@echo ""
	@echo "Examples:"
	@echo "  make build"
	@echo "  make test"
	@echo "  make dev-setup"
	@echo "  make install"
