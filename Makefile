.PHONY: install test lint clean

# Install in development mode
install:
	pip install -e ".[dev]"

# Install with venv (for externally-managed systems)
install-venv:
	python3 -m venv .venv
	.venv/bin/pip install -e ".[dev]"

# Run tests
test:
	PYTHONPATH=src python3 -m pytest tests/ -v

# Run tests with coverage
test-cov:
	PYTHONPATH=src python3 -m pytest tests/ -v --cov=splunk_diag_analyzer --cov-report=term-missing

# Lint and type-check
lint:
	ruff check src/ tests/
	ruff format --check src/ tests/

typecheck:
	mypy src/splunk_diag_analyzer/

# Clean build artifacts
clean:
	rm -rf dist/ build/ *.egg-info/
	rm -rf .venv/
	find . -type d -name __pycache__ -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete

# Run analyzer against a diag file (override DIAG_FILE)
DIAG_FILE ?= 
analyze:
	PYTHONPATH=src python3 -m splunk_diag_analyzer $(DIAG_FILE) -o report.md

# Generate HTML report
html:
	PYTHONPATH=src python3 -m splunk_diag_analyzer $(DIAG_FILE) --html -o report.html

# Quick usage without any setup
quick:
	python3 src/splunk_diag_analyzer/__main__.py $(DIAG_FILE)

# Quick HTML report
quick-html:
	python3 src/splunk_diag_analyzer/__main__.py $(DIAG_FILE) --html -o report.html

# Launch the TUI (terminal UI) for interactive diag browsing
tui:
	PYTHONPATH=src python3 src/splunk_diag_analyzer/tui.py $(DIAG_FILE)

# Quick TUI launch
tui-quick:
	python3 src/splunk_diag_analyzer/tui.py $(DIAG_FILE)
