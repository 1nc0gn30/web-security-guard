.PHONY: help install test test-internal lint audit serve mcp clean build

PYTHON ?= python3
PIP ?= pip3

help:
	@echo "🛡️ Web Security Guard - Developer Automation"
	@echo "============================================="
	@echo "make install        Install package in editable mode"
	@echo "make test           Run full pytest test suite"
	@echo "make test-internal  Run built-in engine verification test suite"
	@echo "make lint           Verify Python source syntax"
	@echo "make audit          Run security guard audit against local files"
	@echo "make serve          Start Google Material 3 Security Studio UI (:8085)"
	@echo "make mcp            Run Model Context Protocol stdio server"
	@echo "make build          Build wheel and sdist packages"
	@echo "make clean          Remove build and cache artifacts"

install:
	$(PIP) install -e .

test:
	PYTHONPATH=src pytest tests/ -v

test-internal:
	PYTHONPATH=src $(PYTHON) -m web_security_guard.cli --test

lint:
	$(PYTHON) -m py_compile src/web_security_guard/*.py tests/*.py

audit:
	PYTHONPATH=src $(PYTHON) -m web_security_guard.cli audit .

serve:
	PYTHONPATH=src $(PYTHON) -m web_security_guard.cli serve --port 8085

mcp:
	PYTHONPATH=src $(PYTHON) -m web_security_guard.cli mcp

build:
	$(PYTHON) -m build || $(PYTHON) setup.py sdist bdist_wheel

clean:
	rm -rf build/ dist/ *.egg-info .pytest_cache/ src/*.egg-info
	find . -type d -name "__pycache__" -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete
