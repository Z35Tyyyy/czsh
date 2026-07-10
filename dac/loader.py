"""Load detection test cases and pair them with their rules.

A test case file lives at ``tests/cases/<rule-stem>.yml`` and declares sample
events that *should* fire the rule (``true_positives``) and events that should
*not* (``true_negatives``)::

    rule: execution/proc_creation_powershell_encoded.yml
    true_positives:
      - name: powershell -enc base64 blob
        event:
          EventID: 1
          Image: 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe'
          CommandLine: 'powershell.exe -nop -w hidden -enc SQBFAFgA...'
    true_negatives:
      - name: benign powershell one-liner
        event:
          EventID: 1
          Image: 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe'
          CommandLine: 'powershell.exe Get-Process'

This mirrors real detection-engineering practice: detections ship with their
tests, and CI refuses to merge a rule that has none.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml


@dataclass
class TestEvent:
    name: str
    event: dict[str, Any]


@dataclass
class TestCase:
    rule: str  # rule path relative to detections/, as written in the file
    true_positives: list[TestEvent]
    true_negatives: list[TestEvent]
    path: Path

    @property
    def total(self) -> int:
        return len(self.true_positives) + len(self.true_negatives)


def _events(items: Any, where: Path, kind: str) -> list[TestEvent]:
    if items is None:
        return []
    if not isinstance(items, list):
        raise ValueError(f"{where}: '{kind}' must be a list")
    out = []
    for idx, item in enumerate(items):
        if not isinstance(item, dict) or "event" not in item:
            raise ValueError(f"{where}: {kind}[{idx}] must be a mapping with an 'event' key")
        out.append(TestEvent(name=item.get("name", f"{kind}[{idx}]"), event=item["event"]))
    return out


def load_test_case(path: str | Path) -> TestCase:
    path = Path(path)
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict) or "rule" not in data:
        raise ValueError(f"{path}: test case must be a mapping with a 'rule' key")
    return TestCase(
        rule=data["rule"],
        true_positives=_events(data.get("true_positives"), path, "true_positives"),
        true_negatives=_events(data.get("true_negatives"), path, "true_negatives"),
        path=path,
    )


def load_test_cases(directory: str | Path) -> list[TestCase]:
    directory = Path(directory)
    return [load_test_case(p) for p in sorted(directory.rglob("*.yml"))]
