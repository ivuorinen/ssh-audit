# Development tasks. The tool and its tests need only Python; ruff, mypy and
# coverage run through uvx at the versions pinned here and in .pre-commit-config.yaml.

PYTHON   ?= python3
UVX      ?= uvx
COVERAGE ?= $(UVX) coverage==7.16.1
RUFF     ?= $(UVX) ruff==0.16.8
MYPY     ?= $(UVX) mypy==2.3.1

.DEFAULT_GOAL := help
.PHONY: help test coverage coverage-html lint format typecheck hooks check clean

help: ## List the available targets
	@grep -E '^[a-z-]+:.*## ' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*## "} {printf "  %-14s %s\n", $$1, $$2}'

test: ## Run the test suite (standard library only)
	$(PYTHON) -W error -m unittest discover -s test

coverage: ## Run the tests under coverage; fail unless statements, lines and branches are all 100%
	$(COVERAGE) erase
	$(COVERAGE) run -m unittest discover -s test
	$(COVERAGE) report
	$(COVERAGE) json -q -o coverage.json
	@$(PYTHON) -c 'import json, sys; \
		t = json.load(open("coverage.json"))["totals"]; \
		print("statements %(covered_lines)d/%(num_statements)d, missing lines %(missing_lines)d, branches %(covered_branches)d/%(num_branches)d (%(num_partial_branches)d partial)" % t); \
		gaps = t["missing_lines"] or t["missing_branches"] or t["num_partial_branches"]; \
		sys.exit("coverage is below 100%" if gaps else 0)'

coverage-html: coverage ## Write a browsable coverage report to htmlcov/
	$(COVERAGE) html

lint: ## Check linting and formatting with ruff
	$(RUFF) check .
	$(RUFF) format --check .

format: ## Format and apply safe lint fixes with ruff
	$(RUFF) format .
	$(RUFF) check --fix .

typecheck: ## Type-check ssh-audit.py with mypy (strict)
	$(MYPY)

hooks: ## Run every prek hook on all files
	prek run --all-files

check: lint typecheck coverage ## Run lint, type check and tests with coverage

clean: ## Remove coverage data and tool caches
	rm -rf .coverage .coverage.* coverage.json htmlcov .ruff_cache .mypy_cache __pycache__ test/__pycache__
