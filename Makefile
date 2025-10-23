.PHONY: help build test clean dev serve install check fmt clippy watch all

# Default target
.DEFAULT_GOAL := help

# Colors for output
BLUE := \033[0;34m
GREEN := \033[0;32m
YELLOW := \033[0;33m
RED := \033[0;31m
NC := \033[0m # No Color

help: ## Show this help message
	@echo "$(BLUE)WASM AES-256 Encryption$(NC)"
	@echo "$(BLUE)========================$(NC)"
	@echo ""
	@echo "Available targets:"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  $(GREEN)%-15s$(NC) %s\n", $$1, $$2}'
	@echo ""
	@echo "Examples:"
	@echo "  $(YELLOW)make build$(NC)  - Build the WASM module"
	@echo "  $(YELLOW)make dev$(NC)    - Start development server"
	@echo "  $(YELLOW)make test$(NC)   - Run all tests"

all: clean build test ## Clean, build, and test everything

build: ## Build the WASM module using wasm-pack
	@echo "$(BLUE)Building WASM module...$(NC)"
	wasm-pack build --target web
	@echo "$(GREEN)Build complete!$(NC)"

install: ## Install required dependencies (wasm-pack)
	@echo "$(BLUE)Checking for wasm-pack...$(NC)"
	@if ! command -v wasm-pack &> /dev/null; then \
		echo "$(YELLOW)Installing wasm-pack...$(NC)"; \
		curl https://rustwasm.github.io/wasm-pack/installer/init.sh -sSf | sh; \
	else \
		echo "$(GREEN)wasm-pack is already installed$(NC)"; \
	fi
	@echo "$(BLUE)Checking for cargo...$(NC)"
	@if ! command -v cargo &> /dev/null; then \
		echo "$(RED)cargo not found. Please install Rust from https://rustup.rs/$(NC)"; \
		exit 1; \
	else \
		echo "$(GREEN)cargo is installed$(NC)"; \
	fi

test: ## Run Rust tests
	@echo "$(BLUE)Running tests...$(NC)"
	cargo test
	@echo "$(GREEN)Tests passed!$(NC)"

check: ## Check the code for errors without building
	@echo "$(BLUE)Checking code...$(NC)"
	cargo check --target wasm32-unknown-unknown
	@echo "$(GREEN)Check complete!$(NC)"

fmt: ## Format the code using rustfmt
	@echo "$(BLUE)Formatting code...$(NC)"
	cargo fmt
	@echo "$(GREEN)Code formatted!$(NC)"

clippy: ## Run clippy linter
	@echo "$(BLUE)Running clippy...$(NC)"
	cargo clippy --target wasm32-unknown-unknown -- -D warnings
	@echo "$(GREEN)Clippy passed!$(NC)"

clean: ## Clean build artifacts
	@echo "$(BLUE)Cleaning build artifacts...$(NC)"
	cargo clean
	rm -rf pkg/
	@echo "$(GREEN)Clean complete!$(NC)"

dev: build serve ## Build and start development server

serve: ## Start a local development server
	@echo "$(BLUE)Starting development server...$(NC)"
	@echo "$(GREEN)Server running at http://localhost:8000$(NC)"
	@echo "$(YELLOW)Press Ctrl+C to stop$(NC)"
	@if command -v python3 &> /dev/null; then \
		python3 -m http.server 8000; \
	elif command -v python &> /dev/null; then \
		python -m http.server 8000; \
	elif command -v npx &> /dev/null; then \
		npx http-server -p 8000; \
	else \
		echo "$(RED)Error: No suitable HTTP server found$(NC)"; \
		echo "$(YELLOW)Install Python or Node.js to use this target$(NC)"; \
		exit 1; \
	fi

watch: ## Watch for changes and rebuild (requires cargo-watch)
	@echo "$(BLUE)Watching for changes...$(NC)"
	@if ! command -v cargo-watch &> /dev/null; then \
		echo "$(YELLOW)cargo-watch not found. Installing...$(NC)"; \
		cargo install cargo-watch; \
	fi
	@echo "$(GREEN)Watching for changes. Press Ctrl+C to stop.$(NC)"
	cargo watch -s 'make build'

release: ## Build optimized release version
	@echo "$(BLUE)Building release version...$(NC)"
	wasm-pack build --target web --release
	@echo "$(GREEN)Release build complete!$(NC)"
	@echo "$(BLUE)WASM size:$(NC)"
	@ls -lh pkg/*.wasm | awk '{print "  " $$9 ": " $$5}'

size: ## Show size of built WASM files
	@echo "$(BLUE)WASM file sizes:$(NC)"
	@if [ -d "pkg" ]; then \
		ls -lh pkg/*.wasm 2>/dev/null | awk '{print "  " $$9 ": " $$5}' || echo "  $(YELLOW)No WASM files found. Run 'make build' first.$(NC)"; \
	else \
		echo "  $(YELLOW)pkg/ directory not found. Run 'make build' first.$(NC)"; \
	fi

validate: fmt check clippy test ## Run all validation checks (format, check, lint, test)
	@echo "$(GREEN)All validation checks passed!$(NC)"
