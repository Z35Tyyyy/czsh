"""Behavioural tests: every rule fires on its true-positives and stays silent on
its true-negatives.

Each sample event becomes its own parametrised test so a failure names the exact
rule and scenario (e.g. ``proc_creation_lsass_dump::TP::comsvcs.dll minidump``).
This is the offline analogue of firing an Atomic Red Team test in the lab and
confirming the alert triggers — but it runs in milliseconds, in CI, on every PR.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from dac.loader import load_test_cases
from dac.matcher import load_rules

ROOT = Path(__file__).resolve().parent.parent
RULES_DIR = ROOT / "detections"
CASES_DIR = ROOT / "tests" / "cases"

_RULES = {r.path.stem: r for r in load_rules(RULES_DIR)}
_CASES = load_test_cases(CASES_DIR)


def _positives():
    for case in _CASES:
        stem = Path(case.rule).stem
        for tp in case.true_positives:
            yield pytest.param(stem, tp, id=f"{stem}::TP::{tp.name}")


def _negatives():
    for case in _CASES:
        stem = Path(case.rule).stem
        for tn in case.true_negatives:
            yield pytest.param(stem, tn, id=f"{stem}::TN::{tn.name}")


@pytest.mark.parametrize("stem,tp", list(_positives()))
def test_true_positive_fires(stem, tp):
    rule = _RULES.get(stem)
    assert rule is not None, f"no rule found for test case stem {stem!r}"
    assert rule.matches(tp.event), (
        f"rule {stem!r} FAILED to fire on true-positive {tp.name!r}. "
        "Either the rule is too narrow or the sample event is wrong."
    )


@pytest.mark.parametrize("stem,tn", list(_negatives()))
def test_true_negative_is_silent(stem, tn):
    rule = _RULES.get(stem)
    assert rule is not None, f"no rule found for test case stem {stem!r}"
    assert not rule.matches(tn.event), (
        f"rule {stem!r} FALSE-POSITIVED on benign event {tn.name!r}. "
        "The rule is too broad — tighten it or add a filter."
    )
