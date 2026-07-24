.PHONY: help venv install lint type test test-verbose run docker-build clean

PY ?= python3.12
VENV ?= .venv
BIN := $(VENV)/bin

help:
	@echo "Targets:"
	@echo "  make venv          Create .venv (Python 3.12)"
	@echo "  make install       Install runtime+dev deps into .venv"
	@echo "  make lint          Run ruff"
	@echo "  make type          Run mypy"
	@echo "  make test          Run pytest"
	@echo "  make test-verbose  Run pytest -v"
	@echo "  make run           uvicorn portal.main:app --reload"
	@echo "  make docker-build  Build internal+public images (placeholder until WI-18)"
	@echo "  make clean         Remove caches and venv"

venv:
	$(PY) -m venv $(VENV)
	$(BIN)/pip install --upgrade pip wheel

install: venv
	$(BIN)/pip install -r requirements.txt
	$(BIN)/pip install -e .

lint:
	$(BIN)/ruff check src tests
	$(BIN)/ruff format --check src tests

type:
	$(BIN)/mypy src

test:
	PYTHONPATH=src $(BIN)/pytest tests

test-verbose:
	PYTHONPATH=src $(BIN)/pytest tests -v

run:
	PYTHONPATH=src $(BIN)/uvicorn portal.main:app --reload --host 0.0.0.0 --port 8080

docker-build:
	@echo "Docker build is owned by WI-18 (production deployment batch)."
	@echo "For local dev: docker compose -f docker-compose.dev.yml up (when WI-18 lands)."

clean:
	rm -rf $(VENV) .pytest_cache .mypy_cache .ruff_cache htmlcov .coverage
	find . -name __pycache__ -type d -exec rm -rf {} +
