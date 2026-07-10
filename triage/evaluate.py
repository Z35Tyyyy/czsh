"""Evaluate triage quality against a ground-truth proxy.

There's no labelled dataset here, so the evaluation uses the **detection's own
declared severity** as the reference: a good triage should mostly agree with it,
and where it disagrees, the disagreement should be explainable (an alert with a
live C2 indicator arguably deserves escalation). This is a proxy, not truth — but
it makes "is the LLM's judgement reasonable?" a measurable question instead of a
vibe, which is the point of shipping an eval at all.
"""

from __future__ import annotations

from dataclasses import dataclass

from triage.pipeline import TriagedAlert
from triage.schema import SEVERITIES

_SEV_RANK = {s: i for i, s in enumerate(SEVERITIES)}  # informational=0 ... critical=4


@dataclass
class EvalReport:
    n: int
    severity_agreement: float           # fraction where triage sev == detection sev
    escalated: int                      # triage rated it MORE severe than the detection
    de_escalated: int                   # triage rated it LESS severe
    mean_abs_severity_delta: float      # avg |rank difference|, in severity steps
    true_positive_rate: float           # fraction flagged likely_true_positive
    priority_distribution: dict[str, int]

    def as_dict(self) -> dict:
        return {
            "n": self.n,
            "severity_agreement": round(self.severity_agreement, 3),
            "escalated": self.escalated,
            "de_escalated": self.de_escalated,
            "mean_abs_severity_delta": round(self.mean_abs_severity_delta, 3),
            "true_positive_rate": round(self.true_positive_rate, 3),
            "priority_distribution": self.priority_distribution,
        }


def evaluate(triaged: list[TriagedAlert]) -> EvalReport:
    if not triaged:
        return EvalReport(0, 0.0, 0, 0, 0.0, 0.0, {})

    agree = escalated = de_escalated = tp = 0
    abs_delta_total = 0
    prio: dict[str, int] = {}

    for t in triaged:
        detection_sev = t.alert.severity
        triage_sev = t.result.recommended_severity
        d = _SEV_RANK.get(triage_sev, 0) - _SEV_RANK.get(detection_sev, 0)
        if d == 0:
            agree += 1
        elif d > 0:
            escalated += 1
        else:
            de_escalated += 1
        abs_delta_total += abs(d)
        if t.result.likely_true_positive:
            tp += 1
        prio[t.result.priority] = prio.get(t.result.priority, 0) + 1

    n = len(triaged)
    return EvalReport(
        n=n,
        severity_agreement=agree / n,
        escalated=escalated,
        de_escalated=de_escalated,
        mean_abs_severity_delta=abs_delta_total / n,
        true_positive_rate=tp / n,
        priority_distribution=dict(sorted(prio.items())),
    )
