#!/usr/bin/env python3
"""Generate a MITRE ATT&CK Navigator layer from the detection rule set.

Reads every Sigma rule under a directory, tallies how many rules cover each
technique, and emits a Navigator layer JSON that renders as a heatmap of your
coverage. Drop the file into https://mitre-attack.github.io/attack-navigator/
(Open Existing Layer -> Upload from local) to get the screenshot that goes in
your README.

    python tools/generate_attack_layer.py detections/ --out docs/attack-layer.json
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from dac.matcher import load_rules  # noqa: E402

# Color ramp from low to high coverage (Navigator uses per-technique hex colors).
_COLORS = ["#fdd0a2", "#fd8d3c", "#e6550d", "#a63603"]


def _color_for(count: int) -> str:
    return _COLORS[min(count, len(_COLORS)) - 1]


def build_layer(rules_dir: Path, name: str) -> dict:
    rules = load_rules(rules_dir)
    by_technique: dict[str, list[str]] = defaultdict(list)
    for rule in rules:
        for tech in rule.attack_techniques:
            by_technique[tech].append(rule.title)

    techniques = []
    for tech, titles in sorted(by_technique.items()):
        count = len(titles)
        techniques.append(
            {
                "techniqueID": tech,
                "score": count,
                "color": _color_for(count),
                "comment": "; ".join(titles),
                "enabled": True,
            }
        )

    max_score = max((t["score"] for t in techniques), default=1)
    return {
        "name": name,
        "versions": {"attack": "14", "navigator": "4.9.0", "layer": "4.5"},
        "domain": "enterprise-attack",
        "description": (
            f"Detection coverage generated from {len(rules)} Sigma rules "
            f"spanning {len(by_technique)} ATT&CK techniques."
        ),
        "techniques": techniques,
        "gradient": {
            "colors": ["#fdd0a2", "#a63603"],
            "minValue": 0,
            "maxValue": max_score,
        },
        "legendItems": [
            {"label": "1 rule", "color": _COLORS[0]},
            {"label": "2+ rules", "color": _COLORS[1]},
            {"label": "3+ rules", "color": _COLORS[2]},
        ],
        "layout": {"layout": "side", "showID": True, "showName": True},
        "hideDisabled": False,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("rules_dir", nargs="?", default="detections", type=Path)
    parser.add_argument("--out", type=Path, default=Path("docs/attack-layer.json"))
    parser.add_argument("--name", default="Detection-as-Code Coverage")
    args = parser.parse_args(argv)

    layer = build_layer(args.rules_dir, args.name)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(layer, indent=2) + "\n", encoding="utf-8")
    print(
        f"Wrote {args.out} — {len(layer['techniques'])} techniques "
        f"from {layer['description']}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
