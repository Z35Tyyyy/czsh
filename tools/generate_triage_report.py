#!/usr/bin/env python3
"""Generate a SOC triage-queue report (docs/triage-report.html).

Builds the alert queue from the detections, runs each alert through the triage
pipeline, and renders a self-contained, theme-aware HTML page — a prioritized
queue of alerts with their AI-drafted triage (summary, severity, next steps).

    python tools/generate_triage_report.py --out docs/triage-report.html

Defaults to the deterministic offline client so the committed report is
reproducible in CI; pass --online to use Claude when an API key is set.
"""

from __future__ import annotations

import argparse
import html
import sys
from datetime import date
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from triage.alert import build_alerts  # noqa: E402
from triage.clients import get_client  # noqa: E402
from triage.evaluate import evaluate  # noqa: E402
from triage.pipeline import triage_alerts  # noqa: E402

_PRIORITY_ORDER = {"P1": 0, "P2": 1, "P3": 2, "P4": 3}


def _esc(s) -> str:
    return html.escape(str(s), quote=True)


_CSS = """
:root{color-scheme:light;--page:#f9f9f7;--surface:#fcfcfb;--text:#0b0b0b;--text-2:#52514e;
 --muted:#898781;--grid:#e1e0d9;--border:rgba(11,11,11,.10);--accent:#2a78d6;
 --good:#0ca30c;--good-ink:#006300;--warning:#fab219;--serious:#ec835a;--critical:#d03b3b}
:root[data-theme="dark"]{color-scheme:dark;--page:#0d0d0d;--surface:#1a1a19;--text:#fff;
 --text-2:#c3c2b7;--muted:#898781;--grid:#2c2c2a;--border:rgba(255,255,255,.10);--accent:#3987e5;
 --good-ink:#0ca30c}
*{box-sizing:border-box}
body{margin:0;background:var(--page);color:var(--text);
 font-family:system-ui,-apple-system,"Segoe UI",sans-serif;line-height:1.45}
.wrap{max-width:1000px;margin:0 auto;padding:32px 20px 56px}
h1{font-size:1.5rem;margin:0;font-weight:650;letter-spacing:-.01em}
.sub{color:var(--text-2);margin:4px 0 0;font-size:.9rem}
.head{display:flex;justify-content:space-between;align-items:flex-start;gap:16px;margin-bottom:22px}
.theme-btn{background:var(--surface);border:1px solid var(--border);color:var(--text-2);
 width:34px;height:34px;border-radius:9px;cursor:pointer;font-size:1rem;flex-shrink:0}
.kpis{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin-bottom:22px}
.kpi{background:var(--surface);border:1px solid var(--border);border-radius:12px;padding:14px 16px}
.kpi .l{color:var(--muted);font-size:.7rem;text-transform:uppercase;letter-spacing:.05em;font-weight:600}
.kpi .v{font-size:1.7rem;font-weight:650;margin-top:4px}
.note{color:var(--muted);font-size:.82rem;margin:0 0 18px}
.alert{background:var(--surface);border:1px solid var(--border);border-left:4px solid var(--muted);
 border-radius:10px;padding:14px 16px;margin-bottom:12px}
.alert.P1{border-left-color:var(--critical)} .alert.P2{border-left-color:var(--serious)}
.alert.P3{border-left-color:var(--warning)} .alert.P4{border-left-color:var(--good)}
.a-top{display:flex;align-items:center;gap:10px;flex-wrap:wrap;margin-bottom:6px}
.prio{font-weight:700;font-variant-numeric:tabular-nums}
.a-title{font-weight:600}
.a-id{color:var(--muted);font-family:ui-monospace,Consolas,monospace;font-size:.76rem;margin-left:auto}
.badge{display:inline-flex;align-items:center;gap:6px;font-size:.72rem;font-weight:600;
 padding:2px 9px;border-radius:999px;border:1px solid var(--border);white-space:nowrap}
.badge .dot{width:7px;height:7px;border-radius:50%}
.sev-critical{color:var(--critical)} .sev-critical .dot{background:var(--critical)}
.sev-high{color:var(--serious)} .sev-high .dot{background:var(--serious)}
.sev-medium{color:var(--text)} .sev-medium .dot{background:var(--warning)}
.sev-low{color:var(--good-ink)} .sev-low .dot{background:var(--good)}
.sev-informational{color:var(--text-2)} .sev-informational .dot{background:var(--muted)}
.tp-y{color:var(--critical)} .tp-n{color:var(--text-2)}
.summary{margin:4px 0 8px;font-size:.92rem}
.meta{display:flex;gap:14px;flex-wrap:wrap;color:var(--text-2);font-size:.8rem;margin-bottom:8px}
.iocs code{background:color-mix(in srgb,var(--critical) 12%,transparent);padding:1px 5px;
 border-radius:4px;font-size:.78rem;margin-right:4px}
.actions{margin:6px 0 0;padding-left:18px;font-size:.85rem;color:var(--text-2)}
.actions li{margin:2px 0}
.foot{color:var(--muted);font-size:.8rem;margin-top:26px;border-top:1px solid var(--grid);padding-top:14px}
@media (max-width:720px){.kpis{grid-template-columns:repeat(2,1fr)}}
"""

_HEAD_SCRIPT = (
    "<script>(function(){var r=document.documentElement,s=null;"
    "try{s=localStorage.getItem('dac-theme');}catch(e){}"
    "var d=s?(s==='dark'):(window.matchMedia&&window.matchMedia('(prefers-color-scheme:dark)').matches);"
    "r.setAttribute('data-theme',d?'dark':'light');})();</script>"
)
_TOGGLE_SCRIPT = (
    "<script>document.getElementById('theme').addEventListener('click',function(){"
    "var r=document.documentElement,n=r.getAttribute('data-theme')==='dark'?'light':'dark';"
    "r.setAttribute('data-theme',n);try{localStorage.setItem('dac-theme',n);}catch(e){}});</script>"
)


def _alert_html(t) -> str:
    a, r = t.alert, t.result
    sev = r.recommended_severity
    tp_cls, tp_txt = ("tp-y", "likely TRUE POSITIVE") if r.likely_true_positive else (
        "tp-n", "possible false positive")
    iocs = a.enrichment.get("indicators", {})
    ioc_html = ""
    if iocs:
        chips = "".join(
            f"<code>{_esc(v)}</code>" for vals in iocs.values() for v in vals
        )
        ioc_html = f'<div class="meta iocs"><span>Indicators:</span> <span>{chips}</span></div>'
    actions = "".join(f"<li>{_esc(x)}</li>" for x in r.recommended_actions)
    techs = ", ".join(f'{_esc(t2["id"])} {_esc(t2["name"])}' for t2 in a.enrichment.get("techniques", []))
    return f"""    <div class="alert {r.priority}">
      <div class="a-top">
        <span class="prio">{r.priority}</span>
        <span class="badge sev-{sev}"><span class="dot"></span>{_esc(sev)}</span>
        <span class="a-title">{_esc(a.rule_title)}</span>
        <span class="a-id">{_esc(a.alert_id)} · {_esc(a.host)}</span>
      </div>
      <div class="summary">{_esc(r.summary)}</div>
      <div class="meta">
        <span class="{tp_cls}">{tp_txt}</span>
        <span>confidence: {_esc(r.confidence)}</span>
        <span>{techs}</span>
      </div>
      {ioc_html}
      <ul class="actions">{actions}</ul>
    </div>"""


def render(triaged, report, client_name: str) -> str:
    triaged = sorted(triaged, key=lambda t: (_PRIORITY_ORDER.get(t.result.priority, 9),
                                             t.alert.alert_id))
    prio = report.priority_distribution
    kpis = [
        ("Alerts in queue", report.n),
        ("P1 / P2 (urgent)", prio.get("P1", 0) + prio.get("P2", 0)),
        ("Likely true positive", f'{round(report.true_positive_rate * 100)}%'),
        ("Triaged by", client_name),
    ]
    kpi_html = "\n      ".join(
        f'<div class="kpi"><div class="l">{_esc(label)}</div><div class="v">{_esc(val)}</div></div>'
        for label, val in kpis
    )
    alerts_html = "\n".join(_alert_html(t) for t in triaged)
    return f"""<!doctype html>
<html lang="en" data-theme="auto">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="light dark">
<title>SOC Triage Queue — Detection-as-Code Lab</title>
{_HEAD_SCRIPT}
<style>{_CSS}</style>
</head>
<body>
<div class="wrap">
  <div class="head">
    <div>
      <h1>SOC Triage Queue</h1>
      <p class="sub">AI-drafted triage for alerts raised by the detection set · generated {date.today().isoformat()}</p>
    </div>
    <button id="theme" class="theme-btn" type="button" aria-label="Toggle theme">◐</button>
  </div>
  <section class="kpis">
      {kpi_html}
  </section>
  <p class="note">Each alert is a detection firing on a sample event; the triage
  (summary, severity, next steps) is drafted automatically. An analyst reviews the
  queue top-down by priority instead of starting each alert from scratch.</p>
{alerts_html}
  <footer class="foot">Generated by <code>tools/generate_triage_report.py</code>.
  The triage client is pluggable — this report used the <strong>{_esc(client_name)}</strong> client.</footer>
</div>
{_TOGGLE_SCRIPT}
</body>
</html>
"""


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, default=Path("docs/triage-report.html"))
    parser.add_argument("--online", action="store_true",
                        help="use Claude when an API key is set (default: offline heuristic)")
    args = parser.parse_args(argv)

    offline = None if args.online else True
    client = get_client(offline)
    client_name = type(client).__name__.replace("TriageClient", "")
    triaged = triage_alerts(build_alerts(), client)
    report = evaluate(triaged)

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(render(triaged, report, client_name), encoding="utf-8")
    print(f"Wrote {args.out} — {report.n} alerts triaged by {client_name} client")
    return 0


if __name__ == "__main__":
    sys.exit(main())
