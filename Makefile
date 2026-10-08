.PHONY: install test lint run demo clean
install:
	pip install -e ".[dev]"
test:
	pytest --cov=vulntriage --cov-report=term-missing
lint:
	ruff check vulntriage tests
run:
	uvicorn vulntriage.main:app --reload --port 8000
demo:
	python -m vulntriage.cli demo
clean:
	rm -rf .pytest_cache .ruff_cache .coverage htmlcov
