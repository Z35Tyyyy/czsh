"""``dac`` command-line interface.

    dac test <rules_dir> <cases_dir>   run rules against their test cases
    dac coverage <rules_dir>           print ATT&CK tactic/technique coverage
    dac match <rule.yml> <event.json>  evaluate one rule against one event

Kept intentionally small; the authoritative test runner is pytest (``tests/``).
This CLI exists for quick local iteration and for the ``make coverage`` target.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import defaultdict
from pathlib import Path

from dac.loader import load_test_cases
from dac.matcher import load_rule, load_rules


def _cmd_test(args: argparse.Namespace) -> int:
    rules = {r.path.stem: r for r in load_rules(args.rules_dir)}
    cases = load_test_cases(args.cases_dir)
    failures = 0
    checked = 0
    for case in cases:
        stem = Path(case.rule).stem
        rule = rules.get(stem)
        if rule is None:
            print(f"FAIL  {case.path.name}: no rule matches stem {stem!r}")
            failures += 1
            continue
        for tp in case.true_positives:
            checked += 1
            if not rule.matches(tp.event):
                print(f"FAIL  {stem}: expected MATCH for TP {tp.name!r}")
                failures += 1
        for tn in case.true_negatives:
            checked += 1
            if rule.matches(tn.event):
                print(f"FAIL  {stem}: expected NO match for TN {tn.name!r}")
                failures += 1
    print(f"\n{checked} assertions across {len(cases)} cases — "
          f"{'ALL PASS' if failures == 0 else f'{failures} FAILED'}")
    return 1 if failures else 0


def _cmd_coverage(args: argparse.Namespace) -> int:
    rules = load_rules(args.rules_dir)
    by_tactic: dict[str, list[str]] = defaultdict(list)
    techniques: set[str] = set()
    for rule in rules:
        techniques.update(rule.attack_techniques)
        for tactic in rule.attack_tactics:
            by_tactic[tactic].append(rule.title)
    print(f"Rules: {len(rules)}    Unique ATT&CK techniques: {len(techniques)}\n")
    for tactic in sorted(by_tactic):
        print(f"  {tactic:<22} {len(by_tactic[tactic])} rule(s)")
    print("\nTechniques:", ", ".join(sorted(techniques)))
    return 0


def _cmd_match(args: argparse.Namespace) -> int:
    rule = load_rule(args.rule)
    event = json.loads(Path(args.event).read_text(encoding="utf-8"))
    fired = rule.matches(event)
    print(f"{'MATCH' if fired else 'no match'}: {rule.title}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="dac", description="Detection-as-Code offline runner")
    sub = parser.add_subparsers(dest="command", required=True)

    p_test = sub.add_parser("test", help="run rules against their test cases")
    p_test.add_argument("rules_dir", nargs="?", default="detections")
    p_test.add_argument("cases_dir", nargs="?", default="tests/cases")
    p_test.set_defaults(func=_cmd_test)

    p_cov = sub.add_parser("coverage", help="print ATT&CK coverage summary")
    p_cov.add_argument("rules_dir", nargs="?", default="detections")
    p_cov.set_defaults(func=_cmd_coverage)

    p_match = sub.add_parser("match", help="evaluate one rule against one JSON event")
    p_match.add_argument("rule")
    p_match.add_argument("event")
    p_match.set_defaults(func=_cmd_match)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
