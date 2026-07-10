"""Detection-as-Code — an offline Sigma evaluation engine.

This package parses Sigma detection rules and evaluates them against individual
log events *in pure Python*, with no live SIEM required. That makes it possible
to unit-test detections in CI the same way you'd unit-test application code:
feed a rule a known-malicious event and assert it fires; feed it a benign event
and assert it stays quiet.

Public API:
    load_rule(path)            -> SigmaRule
    load_rules(dir)            -> list[SigmaRule]
    SigmaRule.matches(event)   -> bool

The supported Sigma subset is documented in ``docs/architecture.md`` and is a
deliberate design constraint: every rule in ``detections/`` is written to stay
inside it, so the offline evaluator and a real SIEM agree on what matches.
"""

from dac.loader import load_test_cases
from dac.matcher import SigmaRule, load_rule, load_rules

__all__ = ["SigmaRule", "load_rule", "load_rules", "load_test_cases"]
