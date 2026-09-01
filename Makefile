# k8s_stack_client_example_com — Validation & linting tooling
# ===========================================================
# Run `make help` to see available targets.

SHELL := /bin/bash
.SHELLFLAGS := -eu -o pipefail -c

# --- Tool discovery ---
KUBECONFORM := $(shell command -v kubeconform 2>/dev/null || echo "")
KUSTOMIZE   := $(shell command -v kustomize 2>/dev/null || echo "")
PRECOMMIT   := $(shell command -v pre-commit 2>/dev/null || echo "")
UV          := $(shell command -v uv 2>/dev/null || echo "")

# --- Colors ---
RED    := \033[31m
GREEN  := \033[32m
YELLOW := \033[33m
CYAN   := \033[36m
RESET  := \033[0m

.PHONY: help tools yaml-lint kustomize-validate contract-check platform-compatibility check pre-commit-install

help: ## Show this help
	@printf "$(CYAN)Available targets:$(RESET)\n"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
		| awk 'BEGIN {FS = ":.*?## "}; {printf "  $(GREEN)%-22s$(RESET) %s\n", $$1, $$2}'

tools: ## Check that required CLIs are installed
	@printf "$(CYAN)Checking required tools...$(RESET)\n"
	@errors=0; \
	for tool in "kubeconform" "kustomize" "uv"; do \
		path=$$(command -v "$$tool" 2>/dev/null || true); \
		if [ -z "$$path" ]; then \
			printf "  $(RED)✗$(RESET) $$tool — not found\n"; \
			errors=$$((errors + 1)); \
		else \
			case "$$tool" in \
				kubeconform) version=$$("$$tool" -v 2>/dev/null) ;; \
				kustomize) version=$$("$$tool" version 2>/dev/null) ;; \
				uv) version=$$("$$tool" --version 2>/dev/null) ;; \
			esac; \
			printf "  $(GREEN)✓$(RESET) $$tool — $$version\n"; \
		fi \
	done; \
	if [ "$$errors" -gt 0 ]; then \
		printf "\n$(RED)❌ $$errors tool(s) missing. Install them before running checks.$(RESET)\n"; \
		exit 1; \
	fi; \
	printf "$(GREEN)All required tools are installed.$(RESET)\n"

yaml-lint: ## Validate K8s manifest YAML files against Kubernetes schema
	@printf "$(CYAN)Validating YAML files with kubeconform...$(RESET)\n"
	@errors=0; \
	while IFS= read -r -d '' f; do \
		if $(KUBECONFORM) -strict -skip Kustomization,GitRepository,HelmRelease "$$f"; then \
			printf "  $(GREEN)✓$(RESET) %s\n" "$$f"; \
		else \
			printf "  $(RED)✗$(RESET) %s — invalid\n" "$$f"; \
			errors=$$((errors + 1)); \
		fi; \
	done < <(find apps infrastructure clusters -name "*.yaml" -not -path "*/values.yaml" -not -name "gotk-components.yaml" -not -name "gotk-sync.yaml" -print0); \
	if [ "$$errors" -gt 0 ]; then \
		printf "\n$(RED)❌ $$errors file(s) failed validation.$(RESET)\n"; \
		exit 1; \
	fi; \
	printf "$(GREEN)All files passed validation.$(RESET)\n"

kustomize-validate: ## Build and validate all client Kustomizations
	@printf "$(CYAN)Building and validating Kustomizations...$(RESET)\n"
	@tmpdir=$$(mktemp -d); \
	trap 'rm -rf "$$tmpdir"' EXIT; \
	for dir in apps infrastructure; do \
		output="$$tmpdir/rendered.yaml"; \
		$(KUSTOMIZE) build --load-restrictor LoadRestrictionsNone "$(CURDIR)/$$dir" > "$$output"; \
		if ! grep -Eq '^kind:[[:space:]]+' "$$output"; then \
			printf "$(RED)%s rendered zero resources$(RESET)\n" "$$dir"; exit 1; \
		fi; \
		$(KUBECONFORM) -strict -summary -ignore-missing-schemas "$$output"; \
	done; \
	output="$$tmpdir/rendered.yaml"; \
	$(KUSTOMIZE) build "$(CURDIR)/clusters/prod-eu-1" > "$$output"; \
	if ! grep -Eq '^kind:[[:space:]]+' "$$output"; then \
		printf "$(RED)clusters/prod-eu-1 rendered zero resources$(RESET)\n"; exit 1; \
	fi; \
	$(KUBECONFORM) -strict -summary -ignore-missing-schemas "$$output"; \
	printf "$(GREEN)All Kustomizations passed validation.$(RESET)\n"

contract-check: ## Verify client values and Flux composition contracts
	@if [ -z "$(UV)" ]; then printf "$(RED)uv is required$(RESET)\n"; exit 1; fi
	@$(UV) run --frozen python -m unittest discover -s tests/validation -p 'test_*.py'

platform-compatibility: ## Verify a changed platform pin against its public release
	@if [ -z "$(UV)" ]; then printf "$(RED)uv is required$(RESET)\n"; exit 1; fi
	@if [ -z "$(BASE_SHA)" ]; then printf "$(RED)BASE_SHA is required$(RESET)\n"; exit 1; fi
	@if [ -z "$(HEAD_SHA)" ]; then printf "$(RED)HEAD_SHA is required$(RESET)\n"; exit 1; fi
	@if [ -n "$(PR_NUMBER)" ] && [ -z "$(MERGE_SHA)" ]; then printf "$(RED)MERGE_SHA is required with PR_NUMBER$(RESET)\n"; exit 1; fi
	@$(UV) run --frozen python scripts/check_platform_compatibility.py \
		--base-sha "$(BASE_SHA)" --head-sha "$(HEAD_SHA)" \
		$(if $(PR_NUMBER),--pull-request-number "$(PR_NUMBER)" --merge-sha "$(MERGE_SHA)",)

check: tools yaml-lint kustomize-validate contract-check ## Run all validation checks

pre-commit-install: ## Install pre-commit hooks
	@if [ -n "$(PRECOMMIT)" ]; then \
		$(PRECOMMIT) install; \
		printf "$(GREEN)pre-commit hooks installed.$(RESET)\n"; \
	else \
		printf "$(RED)pre-commit not found. Install it first.$(RESET)\n"; \
		exit 1; \
	fi
