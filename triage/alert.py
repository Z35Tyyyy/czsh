"""The Alert model and how alerts are produced.

An alert is one detection firing on one event. To get a realistic queue without a
live SIEM, :func:`build_alerts` replays the true-positive sample events from the
detection test cases through the matcher — every rule that fires on an event
becomes an alert, exactly as it would in production.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from dac.loader import load_test_cases
from dac.matcher import SigmaRule, load_rules

_ROOT = Path(__file__).resolve().parent.parent


@dataclass
class Alert:
    """A single detection firing on a single event."""

    alert_id: str
    rule_title: str
    rule_id: str
    rule_stem: str
    severity: str  # the detection's own declared level
    techniques: list[str]
    tactics: list[str]
    event: dict[str, Any]
    scenario: str = ""  # name of the sample scenario that produced it
    host: str = "WORKSTATION-01"
    enrichment: dict[str, Any] = field(default_factory=dict)

    @property
    def command_line(self) -> str:
        return str(self.event.get("CommandLine", ""))


def build_alerts(
    rules_dir: Path | None = None,
    cases_dir: Path | None = None,
    host: str = "WORKSTATION-01",
) -> list[Alert]:
    """Replay every rule's true-positive events through the matcher; each match
    that fires becomes an :class:`Alert` (mirroring a real detection firing)."""
    rules_dir = rules_dir or _ROOT / "detections"
    cases_dir = cases_dir or _ROOT / "tests" / "cases"

    rules = {r.path.stem: r for r in load_rules(rules_dir)}
    cases = load_test_cases(cases_dir)

    alerts: list[Alert] = []
    seq = 0
    for case in cases:
        stem = Path(case.rule).stem
        rule: SigmaRule | None = rules.get(stem)
        if rule is None:
            continue
        for tp in case.true_positives:
            if not rule.matches(tp.event):
                continue  # only fired detections become alerts
            seq += 1
            alerts.append(
                Alert(
                    alert_id=f"ALERT-{seq:04d}",
                    rule_title=rule.title,
                    rule_id=str(rule.id),
                    rule_stem=stem,
                    severity=rule.level,
                    techniques=list(rule.attack_techniques),
                    tactics=list(rule.attack_tactics),
                    event=dict(tp.event),
                    scenario=tp.name,
                    host=host,
                )
            )
    return alerts
