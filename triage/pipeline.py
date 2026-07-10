"""Orchestrate enrichment + triage over one or many alerts."""

from __future__ import annotations

from dataclasses import dataclass

from triage.alert import Alert
from triage.clients import HeuristicTriageClient, TriageClient
from triage.enrich import enrich
from triage.schema import TriageResult


@dataclass
class TriagedAlert:
    alert: Alert
    result: TriageResult


def triage_alert(alert: Alert, client: TriageClient | None = None) -> TriagedAlert:
    client = client or HeuristicTriageClient()
    enrich(alert)
    return TriagedAlert(alert=alert, result=client.triage(alert))


def triage_alerts(
    alerts: list[Alert], client: TriageClient | None = None
) -> list[TriagedAlert]:
    client = client or HeuristicTriageClient()
    return [triage_alert(a, client) for a in alerts]
