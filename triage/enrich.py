"""Alert enrichment: extract indicators and attach ATT&CK context.

Enrichment is the cheap, deterministic work you want done *before* an analyst (or
an LLM) looks at an alert: pull the IOCs out of the raw event and translate the
technique IDs into names. It runs with no external services so it's fully
testable, and it gives the triage step concrete evidence to reason over.
"""

from __future__ import annotations

import re
from typing import Any

from triage.alert import Alert

# Technique ID -> human name, for the techniques this repo's rules cover.
_TECHNIQUE_NAMES = {
    "T1003.001": "LSASS Memory Dumping",
    "T1003.002": "Security Account Manager (SAM) Theft",
    "T1003.003": "NTDS.dit Extraction",
    "T1047": "Windows Management Instrumentation",
    "T1053.005": "Scheduled Task",
    "T1059": "Command and Scripting Interpreter",
    "T1059.001": "PowerShell",
    "T1070.001": "Clear Windows Event Logs",
    "T1087.002": "Domain Account Discovery",
    "T1098": "Account Manipulation",
    "T1105": "Ingress Tool Transfer",
    "T1136.001": "Create Local Account",
    "T1218.005": "Mshta Proxy Execution",
    "T1482": "Domain Trust Discovery",
    "T1490": "Inhibit System Recovery",
    "T1547.001": "Registry Run Keys / Startup Folder",
    "T1562.001": "Disable or Modify Tools",
}

_IPV4 = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
_URL = re.compile(r"\b(?:https?|ftp)://[^\s\"'<>]+", re.IGNORECASE)
_SHA256 = re.compile(r"\b[A-Fa-f0-9]{64}\b")
_MD5 = re.compile(r"\b[A-Fa-f0-9]{32}\b")
_DOMAIN = re.compile(
    r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"(?:com|net|org|io|ru|cn|info|biz|xyz|top|example)\b",
    re.IGNORECASE,
)

# Fields whose values are worth scanning for indicators.
_SCAN_FIELDS = ("CommandLine", "Image", "ParentImage", "TargetObject", "Details", "TargetFilename")


def technique_name(technique_id: str) -> str:
    return _TECHNIQUE_NAMES.get(technique_id.upper(), technique_id)


def extract_indicators(event: dict[str, Any]) -> dict[str, list[str]]:
    """Pull IOCs (IPs, URLs, domains, hashes) out of an event's textual fields."""
    blob = " ".join(str(event.get(f, "")) for f in _SCAN_FIELDS)
    ipv4 = sorted(set(_IPV4.findall(blob)))
    urls = sorted(set(_URL.findall(blob)))
    domains = sorted(set(_DOMAIN.findall(blob)))
    hashes = sorted(set(_SHA256.findall(blob)) | set(_MD5.findall(blob)))
    # Domains embedded in URLs are already represented; keep both lists but avoid
    # double-flagging bare hostnames that are only part of a URL.
    domains = [d for d in domains if not any(d in u for u in urls)]
    out = {}
    if ipv4:
        out["ipv4"] = ipv4
    if urls:
        out["url"] = urls
    if domains:
        out["domain"] = domains
    if hashes:
        out["hash"] = hashes
    return out


def enrich(alert: Alert) -> Alert:
    """Attach indicators and ATT&CK context to an alert in place; return it."""
    indicators = extract_indicators(alert.event)
    alert.enrichment = {
        "indicators": indicators,
        "indicator_count": sum(len(v) for v in indicators.values()),
        "techniques": [
            {"id": t, "name": technique_name(t)} for t in alert.techniques
        ],
        "tactics": alert.tactics,
        "has_network_ioc": bool(indicators.get("ipv4") or indicators.get("url")),
    }
    return alert
