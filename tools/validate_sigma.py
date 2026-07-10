#!/usr/bin/env python3
"""Validate the rule set with pySigma and (optionally) translate to a SIEM query.

The offline matcher in ``dac/`` is intentionally a *subset* of Sigma. This script
is the second opinion: it parses every rule with the real pySigma library, runs
Sigma's validators (misspelled modifiers, empty detections, unknown fields, ...),
and can compile each rule to a backend query language to prove the same rules
that pass unit tests also translate to what a production SIEM would run.

    python tools/validate_sigma.py detections/
    python tools/validate_sigma.py detections/ --translate splunk

pySigma is a heavy dependency, so it lives in requirements-dev.txt and this
script degrades gracefully (exit 2) if it isn't installed.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path


def _load_pysigma():
    try:
        from sigma.collection import SigmaCollection  # noqa: PLC0415
        from sigma.validation import SigmaValidator  # noqa: PLC0415

        return SigmaCollection, SigmaValidator
    except ImportError:
        print(
            "pySigma is not installed. Install dev deps first:\n"
            "    python -m pip install -r requirements-dev.txt",
            file=sys.stderr,
        )
        return None, None


def _default_validator(SigmaValidator):
    """Build a validator running the full set of built-in pySigma checks.

    Falls back to an empty validator (parse-only) if the registry can't be
    instantiated, so structural parsing still runs everywhere.
    """
    try:
        from sigma.validators.core import validators as registry  # noqa: PLC0415

        instances = []
        for cls in registry.values():
            try:
                instances.append(cls())
            except Exception:  # noqa: BLE001 - a validator needing config; skip it
                continue
        return SigmaValidator(instances)
    except Exception:  # noqa: BLE001
        return SigmaValidator([])


def _backend(name: str):
    if name == "splunk":
        from sigma.backends.splunk import SplunkBackend  # noqa: PLC0415

        return SplunkBackend()
    if name in ("elasticsearch", "elastic", "lucene"):
        from sigma.backends.elasticsearch import LuceneBackend  # noqa: PLC0415

        return LuceneBackend()
    raise SystemExit(f"unknown backend {name!r} (supported: splunk, elasticsearch)")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("rules_dir", nargs="?", default="detections", type=Path)
    parser.add_argument("--translate", metavar="BACKEND", help="splunk | elasticsearch")
    args = parser.parse_args(argv)

    SigmaCollection, SigmaValidator = _load_pysigma()
    if SigmaCollection is None:
        return 2

    if args.rules_dir.is_file():
        rule_files = [args.rules_dir]
    else:
        rule_files = sorted(args.rules_dir.rglob("*.yml"))
    if not rule_files:
        print(f"no rules found under {args.rules_dir}", file=sys.stderr)
        return 1

    validator = _default_validator(SigmaValidator)
    backend = _backend(args.translate) if args.translate else None

    failures = 0
    for path in rule_files:
        try:
            collection = SigmaCollection.from_yaml(path.read_text(encoding="utf-8"))
            issues = validator.validate_rules(collection.rules)
            if issues:
                failures += 1
                print(f"ISSUES  {path}:")
                for issue in issues:
                    print(f"          - {issue}")
            else:
                print(f"OK      {path}")
            if backend is not None:
                for query in backend.convert(collection):
                    print(f"          {args.translate}> {query}")
        except Exception as exc:  # noqa: BLE001 - report and continue
            failures += 1
            print(f"ERROR   {path}: {exc}")

    print(f"\n{len(rule_files)} rules checked, {failures} with problems.")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
