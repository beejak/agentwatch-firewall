.PHONY: install test eval infra-up infra-down clean
PYTEST = .venv/bin/python -m pytest
PYTEST_FLAGS = -v --tb=short --asyncio-mode=auto -o addopts=""

## Install (pulls watchtower from the pinned git tag)
install:
	python3 -m venv .venv || true
	.venv/bin/pip install -e ".[dev]"

## Infra — only ClickHouse is needed for the integration tests
infra-up:
	docker compose up -d clickhouse

infra-down:
	docker compose down

## Tests — deterministic semantic backend (no API key); set LLM_API_KEY + drop
## WT_SEMANTIC_LLM=0 to exercise the LLM tier.
test:
	WT_SEMANTIC_LLM=0 $(PYTEST) tests/ $(PYTEST_FLAGS)

## Evaluation harness against the frozen corpus (held-out split)
eval:
	WT_SEMANTIC_LLM=0 .venv/bin/python -m eval.harness --split test

clean:
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	@echo clean
