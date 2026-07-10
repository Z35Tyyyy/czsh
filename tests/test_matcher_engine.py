"""Unit tests for the Sigma evaluation engine (dac.matcher / dac.condition).

The detection tests prove the *rules* are correct; these prove the *engine* they
run on is correct — field modifiers, wildcard globbing, backslash handling, null
matching, and the condition grammar. Written against synthetic rules so they
don't depend on the shipped detection content.
"""

from __future__ import annotations

import pytest

from dac.condition import ConditionError, parse_condition
from dac.matcher import RuleError, SigmaRule, _build_selection
from dac.matcher import _sigma_glob_to_regex_body as body  # noqa: PLC2701 (test-only)


def make_rule(detection: dict) -> SigmaRule:
    data = {
        "title": "t",
        "id": "00000000-0000-0000-0000-000000000000",
        "logsource": {"product": "windows", "category": "process_creation"},
        "detection": detection,
    }
    import tempfile
    from pathlib import Path

    import yaml

    from dac.matcher import load_rule

    p = Path(tempfile.mkdtemp()) / "r.yml"
    p.write_text(yaml.safe_dump(data), encoding="utf-8")
    return load_rule(p)


# --- value matching ----------------------------------------------------------


@pytest.mark.parametrize(
    "spec,event,expected",
    [
        ({"selection": {"Image|endswith": "\\cmd.exe"}, "condition": "selection"},
         {"Image": "C:\\Windows\\System32\\cmd.exe"}, True),
        ({"selection": {"Image|endswith": "\\cmd.exe"}, "condition": "selection"},
         {"Image": "C:\\Windows\\System32\\cmd.exe.txt"}, False),
        ({"selection": {"CommandLine|contains": "mimikatz"}, "condition": "selection"},
         {"CommandLine": "run MIMIKATZ now"}, True),  # case-insensitive
        ({"selection": {"CommandLine|contains|all": ["a", "b"]}, "condition": "selection"},
         {"CommandLine": "x a y b z"}, True),
        ({"selection": {"CommandLine|contains|all": ["a", "b"]}, "condition": "selection"},
         {"CommandLine": "x a y"}, False),  # 'all' requires every value
        ({"selection": {"Path|contains": "\\Run\\"}, "condition": "selection"},
         {"Path": "HKLM\\...\\CurrentVersion\\Run\\Foo"}, True),  # trailing-backslash value
        ({"selection": {"Field": None}, "condition": "selection"},
         {"Other": "x"}, True),  # null matches absent field
        ({"selection": {"Field": None}, "condition": "selection"},
         {"Field": "present"}, False),
        ({"selection": {"CommandLine|re": "-e(nc)?\\s"}, "condition": "selection"},
         {"CommandLine": "pwsh -enc AAAA"}, True),
        ({"selection": {"User|cased": "SYSTEM"}, "condition": "selection"},
         {"User": "system"}, False),  # cased => case-sensitive
    ],
)
def test_field_matching(spec, event, expected):
    assert make_rule(spec).matches(event) is expected


def test_wildcards():
    rule = make_rule({"selection": {"Field": "foo*ci?co"}, "condition": "selection"})
    assert rule.matches({"Field": "fooXYZcisco"})   # * spans, ? is one char
    assert rule.matches({"Field": "fooci0co"})       # * can span zero chars
    assert not rule.matches({"Field": "foocico"})    # ? needs exactly one char
    assert not rule.matches({"Field": "prefoo_cisco"})  # anchored: no leading text


def test_escaped_wildcard_is_literal():
    # Per Sigma, a backslash escapes the following wildcard: `\*` is a literal
    # asterisk, NOT "backslash then any-run". This is a classic footgun and the
    # engine must honour it so offline results match a real backend.
    rule = make_rule({"selection": {"Field": "a\\*b"}, "condition": "selection"})
    assert rule.matches({"Field": "a*b"})
    assert not rule.matches({"Field": "aXYZb"})


def test_glob_body_escapes_regex_metachars():
    # dots and parens in the value are literal, not regex operators
    assert body("a.b(c)") == r"a\.b\(c\)"
    assert body("x*y?z") == "x.*y.z"


# --- selection shapes --------------------------------------------------------


def test_list_of_maps_is_or_of_and_groups():
    sel = _build_selection(
        "s", [{"Image|endswith": "\\a.exe"}, {"OriginalFileName": "A.EXE"}]
    )
    assert sel.matches({"Image": "C:\\a.exe"})
    assert sel.matches({"OriginalFileName": "A.EXE"})
    assert not sel.matches({"Image": "C:\\b.exe"})


def test_keyword_list_matches_any_field():
    sel = _build_selection("s", ["secretsdump", "lsass"])
    assert sel.matches({"CommandLine": "python secretsdump.py", "Image": "x"})
    assert not sel.matches({"CommandLine": "benign", "Image": "x"})


# --- condition grammar -------------------------------------------------------


@pytest.mark.parametrize(
    "cond,results,expected",
    [
        ("a and b", {"a": True, "b": False}, False),
        ("a or b", {"a": False, "b": True}, True),
        ("a and not b", {"a": True, "b": False}, True),
        ("not (a or b)", {"a": False, "b": False}, True),
        ("1 of sel_*", {"sel_x": False, "sel_y": True}, True),
        ("all of sel_*", {"sel_x": True, "sel_y": False}, False),
        ("all of them", {"a": True, "b": True}, True),
        ("2 of sel_*", {"sel_a": True, "sel_b": True, "sel_c": False}, True),
        ("2 of sel_*", {"sel_a": True, "sel_b": False, "sel_c": False}, False),
    ],
)
def test_condition_eval(cond, results, expected):
    assert parse_condition(cond).eval(results) is expected


def test_unknown_identifier_raises():
    with pytest.raises(ConditionError):
        parse_condition("a and missing").eval({"a": True})


def test_unsupported_modifier_raises():
    with pytest.raises(RuleError):
        make_rule({"selection": {"Field|base64offset": "x"}, "condition": "selection"})


def test_condition_referencing_undefined_selection_raises():
    with pytest.raises(RuleError):
        make_rule({"selection": {"A": "1"}, "condition": "selection and ghost"})
