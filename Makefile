.PHONY: install test eval clean

## Install (standalone — no external services)
install:
	python3 -m venv .venv || true
	.venv/bin/pip install -e ".[dev]"

## Tests — pure, infra-free, deterministic semantic backend (no API key).
## Set LLM_API_KEY to also run the optional `-m llm` live test.
test:
	.venv/bin/python -m pytest -q

## Evaluation harness against the frozen corpus (held-out split)
eval:
	.venv/bin/python -m tracewall.eval.harness --split test

clean:
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	@echo clean
