"""The triage output contract — shared by every client.

``TriageResult`` is what a triage client must return for one alert. The same shape
is enforced two ways: as a dataclass the offline client constructs directly, and
as a JSON Schema the Claude client passes to the API's structured-output mode so
the model's response is validated to match before it ever reaches Python.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field, fields

SEVERITIES = ("informational", "low", "medium", "high", "critical")
CONFIDENCES = ("low", "medium", "high")
# Priority: P1 = act now, P4 = review when convenient.
PRIORITIES = ("P1", "P2", "P3", "P4")


@dataclass
class TriageResult:
    """A drafted triage for a single alert."""

    summary: str
    recommended_severity: str
    priority: str
    likely_true_positive: bool
    confidence: str
    recommended_actions: list[str] = field(default_factory=list)
    reasoning: str = ""

    def __post_init__(self) -> None:
        if self.recommended_severity not in SEVERITIES:
            raise ValueError(f"bad severity: {self.recommended_severity!r}")
        if self.priority not in PRIORITIES:
            raise ValueError(f"bad priority: {self.priority!r}")
        if self.confidence not in CONFIDENCES:
            raise ValueError(f"bad confidence: {self.confidence!r}")

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict) -> TriageResult:
        """Build from a (possibly noisy) model response, ignoring unknown keys.

        A missing required field raises ``KeyError``; enum validation happens in
        ``__post_init__``. This tolerates a model that adds extra keys but not one
        that omits required ones.
        """
        known = {f.name for f in fields(cls)}
        return cls(**{k: v for k, v in data.items() if k in known})


# JSON Schema handed to the Anthropic API's structured-output mode. Mirrors the
# dataclass so a validated model response constructs a TriageResult cleanly.
TRIAGE_JSON_SCHEMA = {
    "type": "object",
    "properties": {
        "summary": {
            "type": "string",
            "description": "2-3 sentence analyst summary of what the alert shows.",
        },
        "recommended_severity": {"type": "string", "enum": list(SEVERITIES)},
        "priority": {
            "type": "string",
            "enum": list(PRIORITIES),
            "description": "P1 = act now (active compromise), P4 = review when convenient.",
        },
        "likely_true_positive": {
            "type": "boolean",
            "description": "Whether this looks like real malicious activity vs a benign trigger.",
        },
        "confidence": {"type": "string", "enum": list(CONFIDENCES)},
        "recommended_actions": {
            "type": "array",
            "items": {"type": "string"},
            "description": "Concrete next steps for the analyst, most important first.",
        },
        "reasoning": {
            "type": "string",
            "description": "Brief justification tied to the evidence in the alert.",
        },
    },
    "required": [
        "summary",
        "recommended_severity",
        "priority",
        "likely_true_positive",
        "confidence",
        "recommended_actions",
        "reasoning",
    ],
    "additionalProperties": False,
}
