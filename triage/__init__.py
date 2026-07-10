"""LLM-assisted alert triage — an AI layer on top of the detection engine.

When a detection fires, a tier-1 analyst has to answer the same questions every
time: what happened, how bad is it, is it a true positive, and what do I do next.
This package drafts that triage automatically.

Flow:
    detection fires  ->  Alert  ->  enrich (IOCs + ATT&CK context)  ->  triage

The triage step is pluggable (:mod:`triage.clients`):

* ``HeuristicTriageClient`` — deterministic, offline, no API key. Used by the test
  suite and CI, and as a graceful fallback.
* ``GroqTriageClient`` — calls an LLM via the Groq API (JSON mode) with
  prompt-injection defenses, since alert data is attacker-controlled. The provider
  lives behind the client interface, so swapping it is a one-file change.

The point isn't to replace the analyst — it's to draft the boring 80% so the
analyst spends their time on judgement. The evaluation harness
(:mod:`triage.evaluate`) measures how the LLM's severity calls line up with the
detections' own severities.
"""

from triage.alert import Alert, build_alerts
from triage.pipeline import triage_alert, triage_alerts
from triage.schema import TriageResult

__all__ = ["Alert", "TriageResult", "build_alerts", "triage_alert", "triage_alerts"]
