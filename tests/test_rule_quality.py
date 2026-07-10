"""Governance tests: enforce that every detection meets the repo's bar.

These are the "policy as code" guardrails a detection-engineering team relies on
so quality doesn't drift as the rule set grows:

* every rule parses and carries a unique UUID and a title;
* every rule is mapped to at least one MITRE ATT&CK technique;
* every rule declares a severity from the allowed set;
* **no detection ships without tests** — each rule must have a companion case
  file with at least one true-positive and one true-negative.
"""

from __future__ import annotations

import re
import uuid
from pathlib import Path

import pytest

from dac.loader import load_test_cases
from dac.matcher import load_rules

ROOT = Path(__file__).resolve().parent.parent
RULES_DIR = ROOT / "detections"
CASES_DIR = ROOT / "tests" / "cases"

_RULES = load_rules(RULES_DIR)
_CASES = {Path(c.rule).stem: c for c in load_test_cases(CASES_DIR)}
_ALLOWED_LEVELS = {"informational", "low", "medium", "high", "critical"}
_ATTACK_TAG = re.compile(r"^attack\.", re.IGNORECASE)


@pytest.mark.parametrize("rule", _RULES, ids=lambda r: r.path.stem)
def test_rule_has_valid_uuid(rule):
    uuid.UUID(str(rule.id))  # raises if not a valid UUID


def test_rule_ids_are_unique():
    ids = [r.id for r in _RULES]
    dupes = {i for i in ids if ids.count(i) > 1}
    assert not dupes, f"duplicate rule id(s): {dupes}"


def test_rule_titles_are_unique():
    titles = [r.title for r in _RULES]
    dupes = {t for t in titles if titles.count(t) > 1}
    assert not dupes, f"duplicate rule title(s): {dupes}"


@pytest.mark.parametrize("rule", _RULES, ids=lambda r: r.path.stem)
def test_rule_is_mapped_to_attack(rule):
    assert any(_ATTACK_TAG.match(t) for t in rule.tags), f"{rule.path.stem}: no attack.* tag"
    assert rule.attack_techniques, f"{rule.path.stem}: no attack.tXXXX technique tag"


@pytest.mark.parametrize("rule", _RULES, ids=lambda r: r.path.stem)
def test_rule_has_allowed_level(rule):
    assert rule.level in _ALLOWED_LEVELS, f"{rule.path.stem}: bad level {rule.level!r}"


@pytest.mark.parametrize("rule", _RULES, ids=lambda r: r.path.stem)
def test_rule_has_tests_with_both_polarities(rule):
    case = _CASES.get(rule.path.stem)
    assert case is not None, (
        f"{rule.path.stem}: no test case file at tests/cases/{rule.path.stem}.yml — "
        "detections must ship with tests"
    )
    assert case.true_positives, f"{rule.path.stem}: needs at least one true_positive"
    assert case.true_negatives, f"{rule.path.stem}: needs at least one true_negative"


def test_no_orphan_test_cases():
    rule_stems = {r.path.stem for r in _RULES}
    orphans = set(_CASES) - rule_stems
    assert not orphans, f"test case(s) with no matching rule: {sorted(orphans)}"
