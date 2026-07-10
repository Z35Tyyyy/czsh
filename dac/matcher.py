"""Compile Sigma detection blocks into predicates and evaluate them on events.

The entry points are :func:`load_rule` / :func:`load_rules` and the
:class:`SigmaRule` they return. ``SigmaRule.matches(event)`` answers a single
question: *would this rule fire on this one log event?*

Only the field-matching semantics live here; boolean combination of search
identifiers is delegated to :mod:`dac.condition`.

Supported value modifiers: ``contains``, ``startswith``, ``endswith``, ``all``,
``re``, ``cased``. Matching is case-insensitive by default (Sigma's default),
and Sigma wildcards ``*`` (any run) and ``?`` (any single char) are honoured.
This is a subset of full Sigma, chosen to cover the constructs the rules in this
repo actually use; unsupported modifiers raise so a rule can never *silently*
evaluate differently here than in a real backend.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from dac.condition import Node, parse_condition

_SUPPORTED_MODIFIERS = {"contains", "startswith", "endswith", "all", "re", "cased"}


class RuleError(ValueError):
    """Raised when a Sigma rule is structurally invalid or uses unsupported syntax."""


def _sigma_glob_to_regex_body(pattern: str) -> str:
    """Translate a Sigma value (with ``*``/``?`` wildcards) into a regex body.

    No anchors are added — callers apply ``^``/``$`` and any modifier wildcards
    themselves, so that a value which ends in a backslash (e.g. ``\\Run\\``) never
    merges with an appended ``*`` into an accidental ``\\*`` escape. Backslashes
    are literal (Windows paths are the common case) except when escaping a
    wildcard or another backslash: ``\\*`` is a literal asterisk.
    """
    out: list[str] = []
    i = 0
    while i < len(pattern):
        char = pattern[i]
        if char == "\\":
            nxt = pattern[i + 1] if i + 1 < len(pattern) else ""
            if nxt in ("*", "?", "\\"):
                out.append(re.escape(nxt))
                i += 2
                continue
            out.append(re.escape("\\"))
            i += 1
            continue
        if char == "*":
            out.append(".*")
        elif char == "?":
            out.append(".")
        else:
            out.append(re.escape(char))
        i += 1
    return "".join(out)


@dataclass
class FieldMatcher:
    """Matches one ``field|modifiers: value(s)`` entry of a Sigma selection."""

    field_name: str
    modifiers: tuple[str, ...]
    values: list[Any]

    def __post_init__(self) -> None:
        bad = set(self.modifiers) - _SUPPORTED_MODIFIERS
        if bad:
            raise RuleError(
                f"unsupported Sigma modifier(s) {sorted(bad)} on field {self.field_name!r}"
            )
        flags = 0 if "cased" in self.modifiers else re.IGNORECASE
        self._regexes = [self._compile(v, flags) for v in self.values]

    def _compile(self, value: Any, flags: int):
        if value is None:
            return None  # null-match sentinel
        text = str(value)
        if "re" in self.modifiers:
            return re.compile(text, flags)
        body = _sigma_glob_to_regex_body(text)
        # Anchor per modifier at the regex level (not by string-concatenating a
        # wildcard, which would corrupt values ending in a backslash).
        if "contains" in self.modifiers:
            pattern = body
        elif "startswith" in self.modifiers:
            pattern = "^" + body
        elif "endswith" in self.modifiers:
            pattern = body + "$"
        else:
            pattern = "^" + body + "$"
        return re.compile(pattern, flags)

    def _match_one(self, regex, actual: Any) -> bool:
        if regex is None:  # expected null
            return actual is None
        if actual is None:
            return False
        if isinstance(actual, (list, tuple)):
            return any(self._match_one(regex, item) for item in actual)
        return regex.search(str(actual)) is not None

    def matches(self, event: dict[str, Any]) -> bool:
        present = self.field_name in event
        actual = event.get(self.field_name)
        results = [self._match_one(rx, actual if present else None) for rx in self._regexes]
        # `|all` means every listed value must match the same field; otherwise OR.
        if "all" in self.modifiers:
            return all(results)
        return any(results)


@dataclass
class KeywordMatcher:
    """A bare-list search identifier: match a term against any string field value."""

    values: list[Any]

    def __post_init__(self) -> None:
        # Keyword semantics are "contains", so a bare (unanchored) regex body
        # searched against each field value is exactly right.
        self._regexes = [
            re.compile(_sigma_glob_to_regex_body(str(v)), re.IGNORECASE) for v in self.values
        ]

    def matches(self, event: dict[str, Any]) -> bool:
        haystack = [str(v) for v in event.values() if v is not None]
        return any(rx.search(h) for rx in self._regexes for h in haystack)


@dataclass
class Selection:
    """One search identifier: a map of field matchers (AND), a keyword list (OR),
    or a list of maps (OR of AND-groups)."""

    matchers: list[Any]  # list of (list[FieldMatcher]) groups OR a single KeywordMatcher list
    is_keyword: bool

    def matches(self, event: dict[str, Any]) -> bool:
        if self.is_keyword:
            return any(m.matches(event) for m in self.matchers)
        # list of groups; each group is a list of FieldMatchers combined with AND;
        # groups are combined with OR (mirrors a Sigma list-of-maps selection).
        return any(all(fm.matches(event) for fm in group) for group in self.matchers)


def _parse_field_entry(key: str, value: Any) -> FieldMatcher:
    parts = key.split("|")
    field_name = parts[0]
    modifiers = tuple(parts[1:])
    values = value if isinstance(value, list) else [value]
    return FieldMatcher(field_name=field_name, modifiers=modifiers, values=values)


def _build_selection(name: str, spec: Any) -> Selection:
    # Keyword list: a plain list of scalars (not a list of dicts).
    if isinstance(spec, list) and all(not isinstance(item, dict) for item in spec):
        return Selection(matchers=[KeywordMatcher(spec)], is_keyword=True)
    # List of maps: OR of AND-groups.
    if isinstance(spec, list):
        groups = []
        for item in spec:
            if not isinstance(item, dict):
                raise RuleError(f"selection {name!r} mixes maps and scalars")
            groups.append([_parse_field_entry(k, v) for k, v in item.items()])
        return Selection(matchers=groups, is_keyword=False)
    # Single map: one AND-group.
    if isinstance(spec, dict):
        group = [_parse_field_entry(k, v) for k, v in spec.items()]
        return Selection(matchers=[group], is_keyword=False)
    raise RuleError(f"selection {name!r} has unsupported shape: {type(spec).__name__}")


@dataclass
class SigmaRule:
    """A loaded, compiled Sigma rule ready to evaluate against events."""

    title: str
    id: str
    level: str
    logsource: dict[str, Any]
    tags: list[str]
    selections: dict[str, Selection]
    condition_ast: Node
    raw: dict[str, Any] = field(repr=False, default_factory=dict)
    path: Path | None = field(default=None, repr=False)

    @property
    def attack_techniques(self) -> list[str]:
        """MITRE technique IDs (e.g. ``T1059.001``) parsed from ``attack.*`` tags."""
        techniques = []
        for tag in self.tags:
            low = tag.lower()
            if low.startswith("attack.t"):
                techniques.append(tag.split(".", 1)[1].upper())
        return techniques

    @property
    def attack_tactics(self) -> list[str]:
        """Tactic names (e.g. ``execution``) parsed from ``attack.*`` tags."""
        known = {
            "reconnaissance", "resource_development", "initial_access", "execution",
            "persistence", "privilege_escalation", "defense_evasion", "credential_access",
            "discovery", "lateral_movement", "collection", "command_and_control",
            "exfiltration", "impact",
        }
        return [t.split(".", 1)[1] for t in self.tags
                if "." in t and t.split(".", 1)[1] in known]

    def matches(self, event: dict[str, Any]) -> bool:
        results = {name: sel.matches(event) for name, sel in self.selections.items()}
        return self.condition_ast.eval(results)


REQUIRED_FIELDS = ("title", "id", "logsource", "detection")


def load_rule(path: str | Path) -> SigmaRule:
    path = Path(path)
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise RuleError(f"{path}: rule is not a YAML mapping")

    missing = [f for f in REQUIRED_FIELDS if f not in data]
    if missing:
        raise RuleError(f"{path}: missing required field(s): {missing}")

    detection = data["detection"]
    if "condition" not in detection:
        raise RuleError(f"{path}: detection block has no 'condition'")

    selections = {
        name: _build_selection(name, spec)
        for name, spec in detection.items()
        if name != "condition"
    }
    if not selections:
        raise RuleError(f"{path}: detection block defines no search identifiers")

    condition = detection["condition"]
    if isinstance(condition, list):
        raise RuleError(f"{path}: list conditions (rule aggregations) are not supported")

    ast = parse_condition(condition)
    referenced = ast.identifiers()
    unknown = referenced - set(selections)
    if unknown:
        raise RuleError(f"{path}: condition references undefined identifier(s): {sorted(unknown)}")

    return SigmaRule(
        title=data["title"],
        id=data["id"],
        level=data.get("level", "medium"),
        logsource=data["logsource"],
        tags=data.get("tags", []),
        selections=selections,
        condition_ast=ast,
        raw=data,
        path=path,
    )


def load_rules(directory: str | Path) -> list[SigmaRule]:
    directory = Path(directory)
    rules = [load_rule(p) for p in sorted(directory.rglob("*.yml"))]
    if not rules:
        raise RuleError(f"no rules (*.yml) found under {directory}")
    return rules
