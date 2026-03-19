.PHONY: install install-dev uninstall update test test-unit test-int test-e2e lint fmt check clean run

UV := uv
BRANCH ?= main

install:            ## Install miya + create 'miya' command on PATH
	./run.sh install

install-dev:        ## Install with dev deps (pytest, ruff)
	./run.sh install-dev

uninstall:          ## Remove 'miya' command from PATH
	./run.sh uninstall

update:             ## Pull latest from git + re-sync deps
	MIYA_BRANCH=$(BRANCH) ./run.sh update

test:               ## Run all tests
	$(UV) run pytest -v

test-unit:          ## Run unit tests only
	$(UV) run pytest tests/unit -v

test-int:           ## Run integration tests only
	$(UV) run pytest tests/integration -v

test-e2e:           ## Run e2e tests only
	$(UV) run pytest tests/e2e -v

test-cov:           ## Run tests with coverage
	$(UV) run pytest --cov=miya --cov-report=term-missing

lint:               ## Run ruff linter
	$(UV) run ruff check miya tests

fmt:                ## Auto-format code
	$(UV) run ruff format miya tests

check: lint test    ## Lint + test

clean:              ## Remove build artifacts
	rm -rf .pytest_cache .ruff_cache __pycache__ dist .coverage
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true

run:                ## Run miya CLI
	$(UV) run miya $(ARGS)

help:               ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2}'
