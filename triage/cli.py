"""``triage`` command-line interface.

    python -m triage.cli queue                 build the alert queue from detections
    python -m triage.cli run [--offline]       triage every alert (Claude if key set)
    python -m triage.cli evaluate [--offline]  triage + print evaluation metrics

Defaults to Claude when ANTHROPIC_API_KEY is set, otherwise the offline heuristic
client. Pass --offline to force the heuristic client even with a key present.
"""

from __future__ import annotations

import argparse
import json
import sys

from triage.alert import build_alerts
from triage.clients import get_client
from triage.evaluate import evaluate
from triage.pipeline import triage_alerts


def _resolve_offline(args) -> bool | None:
    if getattr(args, "offline", False):
        return True
    return None  # auto: Claude if a key is present, else heuristic


def _cmd_queue(args) -> int:
    alerts = build_alerts()
    print(f"{len(alerts)} alert(s) in the queue:\n")
    for a in alerts:
        print(f"  {a.alert_id}  [{a.severity:<8}] {a.rule_title}  ({', '.join(a.techniques)})")
    return 0


def _cmd_run(args) -> int:
    client = get_client(_resolve_offline(args))
    triaged = triage_alerts(build_alerts(), client)
    for t in triaged:
        r = t.result
        print(f"{t.alert.alert_id}  {r.priority}  sev={r.recommended_severity:<8} "
              f"TP={'Y' if r.likely_true_positive else 'N'}  conf={r.confidence}")
        print(f"    {r.summary}")
        if args.verbose:
            for action in r.recommended_actions:
                print(f"      - {action}")
    return 0


def _cmd_evaluate(args) -> int:
    client = get_client(_resolve_offline(args))
    triaged = triage_alerts(build_alerts(), client)
    report = evaluate(triaged)
    print(json.dumps(report.as_dict(), indent=2))
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="triage", description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    p_queue = sub.add_parser("queue", help="build and print the alert queue")
    p_queue.set_defaults(func=_cmd_queue)

    p_run = sub.add_parser("run", help="triage every alert")
    p_run.add_argument("--offline", action="store_true", help="force the heuristic client")
    p_run.add_argument("-v", "--verbose", action="store_true", help="show recommended actions")
    p_run.set_defaults(func=_cmd_run)

    p_eval = sub.add_parser("evaluate", help="triage + print evaluation metrics")
    p_eval.add_argument("--offline", action="store_true", help="force the heuristic client")
    p_eval.set_defaults(func=_cmd_evaluate)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
