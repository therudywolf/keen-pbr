include version.mk

VERSION_RESOLVER := $(abspath build_scripts/resolve-version.sh)
KEEN_PBR_RELEASE := $(shell bash $(VERSION_RESOLVER) release "$(CURDIR)")
GCC_BUILD_DIR := cmake-build-gcc
CLANG_BUILD_DIR := cmake-build-clang
ORVAL_VERSION := $(shell sed -n 's/.*"orval": "\([^"]*\)".*/\1/p' frontend/package.json | head -1)

# Parallel build jobs. `cmake --build` without --parallel defaults to 1 with the
# Make generator, which makes single-target test builds painfully slow on hosts
# with idle cores. Override with `make JOBS=N`.
JOBS ?= $(shell nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 4)

# Prefer an explicitly installed compiler when available; C++17 is required.
GCC_CXX ?= $(shell command -v g++-13 2>/dev/null || command -v g++-12 2>/dev/null || command -v g++ 2>/dev/null || echo g++)
CLANG_CXX ?= clang++
COMMON_CMAKE_FLAGS := -DCMAKE_EXPORT_COMPILE_COMMANDS=ON -DKEEN_PBR_RELEASE=$(KEEN_PBR_RELEASE)
GCC_CMAKE_FLAGS := -DCMAKE_CXX_COMPILER=$(GCC_CXX) $(COMMON_CMAKE_FLAGS)
CLANG_CMAKE_FLAGS := -DCMAKE_CXX_COMPILER=$(CLANG_CXX) $(COMMON_CMAKE_FLAGS)
CLANG_FEATURE_CMAKE_FLAGS := -DWITH_API=ON -DUSE_KEENETIC_API=ON

.PHONY: all build clean distclean setup \
        frontend-build \
        frontend-api-generate \
        test \
        firewall-it-images firewall-it \
        clang-build clang-check clang-tidy \
        generate \
        help

## Native build ################################################################

all: build ## Build for host (native)

setup: ## Configure CMake
	cmake -S . -B $(GCC_BUILD_DIR) $(GCC_CMAKE_FLAGS)

build: ## Compile the project (parallel; override jobs with JOBS=N)
	cmake -S . -B $(GCC_BUILD_DIR) $(GCC_CMAKE_FLAGS)
	cmake --build $(GCC_BUILD_DIR) --parallel $(JOBS)

frontend-build: ## Build frontend assets with bun
	bash build_scripts/build-frontend.sh "$(abspath .)" "$(abspath frontend/dist)"

frontend-api-generate: ## Regenerate frontend API client using the Orval version pinned in frontend/package.json
	cd frontend && bunx --bun orval@$(ORVAL_VERSION) --config ./orval.config.ts

generate: ## Regenerate src/api/generated/api_types.hpp from docs/openapi.yaml (requires Node.js)
	bash build_scripts/generate_api_types.sh

test: ## Build and run unit tests (doctest) — parallel; override with JOBS=N
	cmake -S . -B $(GCC_BUILD_DIR) $(GCC_CMAKE_FLAGS) -DBUILD_TESTS=ON
	cmake --build $(GCC_BUILD_DIR) --target keen-pbr-tests crash-diagnostics-smoke --parallel $(JOBS)
	$(GCC_BUILD_DIR)/tests/keen-pbr-tests
	$(GCC_BUILD_DIR)/tests/crash-diagnostics-smoke

firewall-it-images: ## Build the Docker images for firewall integration tests (also compiles the harness inside Docker)
	docker build -t keen-pbr-firewall-it:iptables -f tests/firewall_it/docker/Dockerfile.iptables .
	docker build -t keen-pbr-firewall-it:nftables -f tests/firewall_it/docker/Dockerfile.nftables .

firewall-it: ## Run the Docker + netns firewall integration suite (builds images first)
	bash tests/firewall_it/scripts/run-suite.sh

clang-build: ## Configure and compile with Clang in a host-only build dir
	cmake -S . -B $(CLANG_BUILD_DIR) $(CLANG_CMAKE_FLAGS) $(CLANG_FEATURE_CMAKE_FLAGS)
	cmake --build $(CLANG_BUILD_DIR) --target keen-pbr --parallel $(JOBS)

clang-check: ## Compile with Clang thread-safety analysis enabled; never runs binaries
	cmake -S . -B $(CLANG_BUILD_DIR) $(CLANG_CMAKE_FLAGS) $(CLANG_FEATURE_CMAKE_FLAGS) -DBUILD_TESTS=ON -DENABLE_THREAD_SAFETY_ANALYSIS=ON
	cmake --build $(CLANG_BUILD_DIR) --target keen-pbr keen-pbr-tests thread-safety-smoke --parallel $(JOBS)

CLANGD_TIDY_ARGS ?=

clang-tidy: ## Run clangd-tidy against project-owned sources using the Clang compile database
	cmake -S . -B $(CLANG_BUILD_DIR) $(CLANG_CMAKE_FLAGS) $(CLANG_FEATURE_CMAKE_FLAGS) -DBUILD_TESTS=ON -DENABLE_THREAD_SAFETY_ANALYSIS=ON
	bash build_scripts/run-clangd-tidy.sh "$(abspath $(CLANG_BUILD_DIR))" $(CLANGD_TIDY_ARGS)

clean: ## Remove compiled artifacts
	rm -rf $(GCC_BUILD_DIR) $(CLANG_BUILD_DIR) build/packages

distclean: ## Remove all build artifacts including downloaded SDKs
	rm -rf build/ $(GCC_BUILD_DIR) $(CLANG_BUILD_DIR)

-include build_scripts/keenetic.mk

## Help ########################################################################

help: ## Show this help
	@grep -hE '^[a-zA-Z_-]+:.*##' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*## "}; {printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2}'
