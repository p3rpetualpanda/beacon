.PHONY: install lint typecheck security test check data load quality clean

install:
	uv sync

lint:
	uv run ruff check .
	uv run ruff format --check .

typecheck:
	uv run mypy

security:
	uv run bandit -c pyproject.toml -r src -q
	uv run pip-audit --skip-editable

test:
	uv run pytest

check: lint typecheck security test

data:
	uv run beacon data fetch

load: data
	uv run beacon load

quality:
	uv run pytest tests/test_full_load_quality.py --no-cov -v

clean:
	rm -rf .pytest_cache .mypy_cache .ruff_cache .coverage htmlcov
