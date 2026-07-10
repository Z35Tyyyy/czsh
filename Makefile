# Detection-as-Code — developer entry points.
# Mirrors the stages the CI pipeline runs (.github/workflows/detections-ci.yml).

PY ?= python

.PHONY: help install test lint validate translate coverage layer dashboard catalog docs all clean

help:
	@echo "make install    - install dev dependencies"
	@echo "make test       - run the offline detection unit tests (pytest)"
	@echo "make lint       - yamllint the rules + ruff the Python"
	@echo "make validate   - validate every rule with pySigma"
	@echo "make translate  - compile rules to Splunk SPL (sample output)"
	@echo "make coverage   - print ATT&CK technique coverage summary"
	@echo "make layer      - regenerate the ATT&CK Navigator layer JSON"
	@echo "make dashboard  - regenerate the coverage & health dashboard (docs/dashboard.html)"
	@echo "make catalog    - regenerate the detection catalog (docs/DETECTIONS.md)"
	@echo "make all        - lint + validate + test + coverage"

install:
	$(PY) -m pip install -r requirements-dev.txt

test:
	$(PY) -m pytest

lint:
	-yamllint detections/ tests/cases/
	-ruff check dac/ tools/ tests/

validate:
	$(PY) tools/validate_sigma.py detections/

translate:
	$(PY) tools/validate_sigma.py detections/ --translate splunk

coverage:
	$(PY) -m dac.cli coverage detections/

layer:
	$(PY) tools/generate_attack_layer.py detections/ --out docs/attack-layer.json

dashboard:
	$(PY) tools/generate_dashboard.py detections/ --out docs/dashboard.html

catalog:
	$(PY) tools/generate_catalog.py detections/ --out docs/DETECTIONS.md

docs: layer dashboard catalog

all: lint validate test coverage

clean:
	rm -rf .pytest_cache .ruff_cache **/__pycache__ attack-layer.json
