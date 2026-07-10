#!/usr/bin/env python3
"""Generate a self-contained coverage & health dashboard (docs/dashboard.html).

Reads every rule, runs the offline harness against each rule's test cases, and
renders a single static HTML file — no backend, no external requests — with:

  * KPI tiles (detections, ATT&CK techniques, tactics, test assertions, pass rate)
  * a rules-by-tactic bar view
  * ATT&CK technique coverage chips grouped by tactic
  * a filterable / sortable detections table showing each rule's live test status

Because it embeds *real* test results computed at generation time, the dashboard
is a health monitor, not just a catalog: a rule that regresses shows up red.

    python tools/generate_dashboard.py detections/ --out docs/dashboard.html

The page is theme-aware (light/dark) and fully readable with JavaScript disabled;
JS only adds filtering, sorting, and row expansion.
"""

from __future__ import annotations

import argparse
import html
import sys
from collections import defaultdict
from datetime import date
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from dac.loader import load_test_cases  # noqa: E402
from dac.matcher import load_rules  # noqa: E402

_TACTIC_ORDER = [
    "initial_access", "execution", "persistence", "privilege_escalation",
    "defense_evasion", "credential_access", "discovery", "lateral_movement",
    "collection", "command_and_control", "exfiltration", "impact",
]
_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4}


def _tactic_label(tactic: str) -> str:
    return tactic.replace("_", " ").title()


def _evaluate(rule, case):
    """Run a rule against its case; return (passed, assertions, failures)."""
    failures = []
    assertions = 0
    if case:
        for tp in case.true_positives:
            assertions += 1
            if not rule.matches(tp.event):
                failures.append(f"missed true-positive: {tp.name}")
        for tn in case.true_negatives:
            assertions += 1
            if rule.matches(tn.event):
                failures.append(f"false-positive on: {tn.name}")
    return (not failures and assertions > 0), assertions, failures


def collect(rules_dir: Path, cases_dir: Path) -> dict:
    rules = load_rules(rules_dir)
    cases = {Path(c.rule).stem: c for c in load_test_cases(cases_dir)}

    rows = []
    tactic_rules: dict[str, int] = defaultdict(int)
    tactic_techs: dict[str, set] = defaultdict(set)
    all_techniques: set[str] = set()
    total_assertions = passed_assertions = 0
    passing_rules = 0

    for rule in sorted(rules, key=lambda r: r.title):
        case = cases.get(rule.path.stem)
        ok, assertions, failures = _evaluate(rule, case)
        tp = len(case.true_positives) if case else 0
        tn = len(case.true_negatives) if case else 0
        total_assertions += assertions
        passed_assertions += assertions - len(failures)
        passing_rules += 1 if ok else 0

        tactics = rule.attack_tactics or ["uncategorized"]
        for t in tactics:
            tactic_rules[t] += 1
            tactic_techs[t].update(rule.attack_techniques)
        all_techniques.update(rule.attack_techniques)

        rows.append({
            "stem": rule.path.stem,
            "title": rule.title,
            "primary_tactic": tactics[0],
            "tactics": tactics,
            "techniques": rule.attack_techniques,
            "level": rule.level,
            "tp": tp,
            "tn": tn,
            "assertions": assertions,
            "passed": ok,
            "failures": failures,
            "description": " ".join((rule.raw.get("description") or "").split()),
            "falsepositives": rule.raw.get("falsepositives") or [],
        })

    ordered_tactics = [t for t in _TACTIC_ORDER if t in tactic_rules]
    ordered_tactics += [t for t in tactic_rules if t not in _TACTIC_ORDER]
    tactics = [
        {"name": t, "label": _tactic_label(t), "rules": tactic_rules[t],
         "techniques": sorted(tactic_techs[t])}
        for t in ordered_tactics
    ]

    return {
        "rules": rows,
        "tactics": tactics,
        "summary": {
            "rules": len(rules),
            "techniques": len(all_techniques),
            "tactics": len(tactic_rules),
            "assertions": total_assertions,
            "passed_assertions": passed_assertions,
            "passing_rules": passing_rules,
            "pass_rate": round(100 * passed_assertions / total_assertions) if total_assertions else 0,
        },
    }


# --- HTML rendering ----------------------------------------------------------

_PAGE = """<!doctype html>
<html lang="en" data-theme="auto">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="light dark">
<title>__TITLE__</title>
<script>
/* Resolve the theme to an explicit attribute before first paint (no flash, and
   colour resolution never depends on a media query — see notes in the CSS). */
(function(){var r=document.documentElement,s=null;
try{s=localStorage.getItem('dac-theme');}catch(e){}
var dark=s?(s==='dark'):(window.matchMedia&&window.matchMedia('(prefers-color-scheme:dark)').matches);
r.setAttribute('data-theme',dark?'dark':'light');})();
</script>
<style>__CSS__</style>
</head>
<body>
<div class="wrap">
  <header class="page-head">
    <div>
      <h1>__TITLE__</h1>
      <p class="sub">Detection-as-Code coverage &amp; health &middot; generated __DATE__ from the rule set</p>
    </div>
    <div class="head-right">
      __HEALTH_PILL__
      <button id="theme" class="theme-btn" type="button" aria-label="Toggle theme">◐</button>
    </div>
  </header>

  <section class="kpis" aria-label="Key metrics">
    __KPIS__
  </section>

  <section class="card">
    <h2>Rules by ATT&amp;CK tactic</h2>
    <p class="card-sub">How the __NRULES__ detections distribute across the kill chain (a rule can map to more than one tactic).</p>
    <div class="bars">
      __BARS__
    </div>
  </section>

  <section class="card">
    <h2>ATT&amp;CK technique coverage</h2>
    <p class="card-sub">__NTECH__ techniques covered, grouped by tactic.</p>
    <div class="chip-grid">
      __CHIPS__
    </div>
  </section>

  <section class="card">
    <div class="table-head">
      <h2>Detections</h2>
      <div class="filters">
        <input id="q" type="search" placeholder="Search title or technique…" aria-label="Search detections">
        <select id="f-tactic" aria-label="Filter by tactic"><option value="">All tactics</option>__TACTIC_OPTS__</select>
        <select id="f-sev" aria-label="Filter by severity"><option value="">All severities</option><option>critical</option><option>high</option><option>medium</option><option>low</option><option>informational</option></select>
        <select id="f-status" aria-label="Filter by test status"><option value="">All statuses</option><option value="pass">Passing</option><option value="fail">Failing</option></select>
      </div>
    </div>
    <div class="table-scroll">
      <table id="tbl">
        <thead>
          <tr>
            <th data-sort="title" class="sortable">Detection</th>
            <th data-sort="tactic" class="sortable">Tactic</th>
            <th>Techniques</th>
            <th data-sort="sev" class="sortable">Severity</th>
            <th data-sort="tests" class="sortable num">Tests</th>
            <th data-sort="status" class="sortable">Status</th>
          </tr>
        </thead>
        <tbody>
          __ROWS__
        </tbody>
      </table>
    </div>
    <p id="empty" class="empty" hidden>No detections match these filters.</p>
  </section>

  <footer class="page-foot">
    Generated by <code>tools/generate_dashboard.py</code> &middot; every figure is computed
    from the rules and their live test results. Regenerate with <code>make dashboard</code>.
  </footer>
</div>
<script>__JS__</script>
</body>
</html>
"""

_CSS = """
/* Theme is driven purely by the [data-theme] attribute (set by the head script
   from a saved preference or the OS setting). Colour resolution deliberately does
   NOT use a prefers-color-scheme media query, so toggling to light always wins
   even on a dark-mode OS. :root is the light default (also the no-JS fallback). */
:root{
  color-scheme:light;
  --page:#f9f9f7; --surface:#fcfcfb; --text:#0b0b0b; --text-2:#52514e; --muted:#898781;
  --grid:#e1e0d9; --border:rgba(11,11,11,.10); --accent:#2a78d6;
  --seq-1:#86b6ef; --seq-2:#3987e5; --seq-3:#1c5cab;
  --good:#0ca30c; --warning:#fab219; --serious:#ec835a; --critical:#d03b3b;
  --good-ink:#006300;
}
:root[data-theme="dark"]{
  color-scheme:dark;
  --page:#0d0d0d; --surface:#1a1a19; --text:#fff; --text-2:#c3c2b7; --muted:#898781;
  --grid:#2c2c2a; --border:rgba(255,255,255,.10); --accent:#3987e5;
  --seq-1:#3987e5; --seq-2:#5598e7; --seq-3:#86b6ef;
  --good-ink:#0ca30c;
}
*{box-sizing:border-box}
body{margin:0;background:var(--page);color:var(--text);
  font-family:system-ui,-apple-system,"Segoe UI",sans-serif;line-height:1.45;
  -webkit-font-smoothing:antialiased}
.wrap{max-width:1120px;margin:0 auto;padding:32px 20px 56px}
h1{font-size:1.55rem;margin:0;font-weight:650;letter-spacing:-.01em}
h2{font-size:1.02rem;margin:0 0 2px;font-weight:600}
.sub{color:var(--text-2);margin:4px 0 0;font-size:.9rem}
.card-sub{color:var(--muted);margin:0 0 16px;font-size:.83rem}
a{color:var(--accent)}
code{font-family:ui-monospace,"Cascadia Code",Consolas,monospace;font-size:.86em;
  background:color-mix(in srgb,var(--muted) 16%,transparent);padding:1px 5px;border-radius:4px}

.page-head{display:flex;justify-content:space-between;align-items:flex-start;gap:16px;margin-bottom:24px}
.head-right{display:flex;align-items:center;gap:10px;flex-shrink:0}
.theme-btn{background:var(--surface);border:1px solid var(--border);color:var(--text-2);
  width:34px;height:34px;border-radius:9px;cursor:pointer;font-size:1rem}
.theme-btn:hover{color:var(--text)}
.pill{display:inline-flex;align-items:center;gap:7px;padding:6px 12px;border-radius:999px;
  font-size:.82rem;font-weight:600;border:1px solid var(--border)}
.pill .dot{width:8px;height:8px;border-radius:50%}
.pill.ok{color:var(--good-ink)} .pill.ok .dot{background:var(--good)}
.pill.bad{color:var(--critical)} .pill.bad .dot{background:var(--critical)}

.kpis{display:grid;grid-template-columns:repeat(5,1fr);gap:12px;margin-bottom:24px}
.kpi{background:var(--surface);border:1px solid var(--border);border-radius:12px;padding:16px 16px 14px}
.kpi .k-label{color:var(--muted);font-size:.72rem;text-transform:uppercase;letter-spacing:.05em;font-weight:600}
.kpi .k-val{font-size:1.9rem;font-weight:650;margin-top:6px;letter-spacing:-.02em}
.kpi .k-sub{color:var(--text-2);font-size:.78rem;margin-top:2px}
.kpi.hero .k-val{color:var(--good-ink)}
.kpi.hero.bad .k-val{color:var(--critical)}

.card{background:var(--surface);border:1px solid var(--border);border-radius:12px;padding:20px;margin-bottom:20px}

.bars{display:flex;flex-direction:column;gap:9px}
.bar-row{display:grid;grid-template-columns:150px 1fr 34px;align-items:center;gap:12px;font-size:.85rem}
.bar-row .b-label{color:var(--text-2);text-align:right;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.bar-track{height:14px;position:relative;display:block;width:100%}
.bar-fill{display:block;height:14px;background:var(--accent);border-radius:3px;min-width:3px}
.bar-row .b-val{font-variant-numeric:tabular-nums;color:var(--text-2);font-weight:600}

.chip-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(200px,1fr));gap:16px}
.chip-col .c-head{font-size:.74rem;text-transform:uppercase;letter-spacing:.04em;color:var(--muted);
  font-weight:600;margin-bottom:8px}
.chips{display:flex;flex-wrap:wrap;gap:6px}
.chip{font-size:.76rem;font-variant-numeric:tabular-nums;padding:3px 8px;border-radius:6px;
  background:color-mix(in srgb,var(--accent) 14%,transparent);
  color:var(--text);border:1px solid color-mix(in srgb,var(--accent) 26%,transparent)}

.table-head{display:flex;justify-content:space-between;align-items:center;gap:16px;flex-wrap:wrap;margin-bottom:14px}
.filters{display:flex;gap:8px;flex-wrap:wrap}
.filters input,.filters select{background:var(--page);color:var(--text);border:1px solid var(--border);
  border-radius:8px;padding:7px 10px;font-size:.83rem;font-family:inherit}
.filters input{min-width:210px}
.table-scroll{overflow-x:auto}
table{width:100%;border-collapse:collapse;font-size:.86rem}
thead th{text-align:left;color:var(--muted);font-weight:600;font-size:.74rem;text-transform:uppercase;
  letter-spacing:.04em;padding:8px 10px;border-bottom:1px solid var(--grid);white-space:nowrap;position:sticky;top:0;background:var(--surface)}
th.num,td.num{text-align:right}
th.sortable{cursor:pointer;user-select:none}
th.sortable:hover{color:var(--text-2)}
th.sortable::after{content:"⇅";opacity:.35;margin-left:4px;font-size:.9em}
th.sortable.asc::after{content:"↑";opacity:.9}
th.sortable.desc::after{content:"↓";opacity:.9}
tbody tr.rule{border-bottom:1px solid var(--grid);cursor:pointer}
tbody tr.rule:hover{background:color-mix(in srgb,var(--muted) 8%,transparent)}
td{padding:10px}
.r-title{font-weight:550}
.r-stem{color:var(--muted);font-size:.76rem;font-family:ui-monospace,Consolas,monospace}
.techs{font-variant-numeric:tabular-nums;color:var(--text-2);font-size:.8rem}
.badge{display:inline-flex;align-items:center;gap:6px;font-size:.76rem;font-weight:600;
  padding:2px 9px;border-radius:999px;border:1px solid var(--border);white-space:nowrap}
.badge .dot{width:8px;height:8px;border-radius:50%}
.sev-critical{color:var(--critical)} .sev-critical .dot{background:var(--critical)}
.sev-high{color:var(--serious)} .sev-high .dot{background:var(--serious)}
.sev-medium{color:var(--text)} .sev-medium .dot{background:var(--warning)}
.sev-low{color:var(--good-ink)} .sev-low .dot{background:var(--good)}
.sev-informational{color:var(--text-2)} .sev-informational .dot{background:var(--muted)}
.status-pass{color:var(--good-ink)} .status-fail{color:var(--critical)}
.tests-cell{font-variant-numeric:tabular-nums}
tr.detail td{padding:0 10px}
tr.detail .detail-box{padding:2px 0 16px;color:var(--text-2);font-size:.85rem;max-width:80ch}
tr.detail[hidden]{display:none}
.detail-box .d-fp{margin-top:8px}
.detail-box .d-fp li{margin:2px 0}
.detail-box .fail{color:var(--critical);margin-top:8px;font-weight:600}
.empty{color:var(--muted);text-align:center;padding:24px}
.page-foot{color:var(--muted);font-size:.8rem;margin-top:28px;border-top:1px solid var(--grid);padding-top:16px}

@media (max-width:820px){
  .kpis{grid-template-columns:repeat(2,1fr)}
  .bar-row{grid-template-columns:110px 1fr 30px}
}
"""

_JS = """
(function(){
  var root=document.documentElement, btn=document.getElementById('theme');
  btn.addEventListener('click',function(){
    var next=root.getAttribute('data-theme')==='dark'?'light':'dark';
    root.setAttribute('data-theme',next);
    try{localStorage.setItem('dac-theme',next);}catch(e){}
  });

  var tbody=document.querySelector('#tbl tbody');
  var rows=[].slice.call(tbody.querySelectorAll('tr.rule'));
  var q=document.getElementById('q'), ft=document.getElementById('f-tactic'),
      fs=document.getElementById('f-sev'), fst=document.getElementById('f-status'),
      empty=document.getElementById('empty');

  function apply(){
    var term=(q.value||'').toLowerCase(), t=ft.value, s=fs.value, st=fst.value, shown=0;
    rows.forEach(function(r){
      var det=r.nextElementSibling;
      var ok=(!term||r.dataset.search.indexOf(term)>-1)
        &&(!t||r.dataset.tactic===t)
        &&(!s||r.dataset.sev===s)
        &&(!st||r.dataset.status===st);
      r.hidden=!ok;
      if(det&&det.classList.contains('detail')){det.hidden=true;r.classList.remove('open');}
      if(ok)shown++;
    });
    empty.hidden=shown>0;
  }
  [q,ft,fs,fst].forEach(function(el){el.addEventListener('input',apply);});

  rows.forEach(function(r){
    r.addEventListener('click',function(e){
      if(e.target.closest('a'))return;
      var det=r.nextElementSibling;
      if(det&&det.classList.contains('detail')){det.hidden=!det.hidden;r.classList.toggle('open',!det.hidden);}
    });
  });

  var ths=[].slice.call(document.querySelectorAll('th.sortable'));
  ths.forEach(function(th){
    th.addEventListener('click',function(){
      var key=th.dataset.sort, asc=!th.classList.contains('asc');
      ths.forEach(function(o){o.classList.remove('asc','desc');});
      th.classList.add(asc?'asc':'desc');
      var pairs=rows.map(function(r){return [r,r.nextElementSibling];});
      pairs.sort(function(a,b){
        var x=a[0].dataset['sort'+key]||'', y=b[0].dataset['sort'+key]||'';
        var nx=parseFloat(x), ny=parseFloat(y);
        if(!isNaN(nx)&&!isNaN(ny)){x=nx;y=ny;}
        return (x<y?-1:x>y?1:0)*(asc?1:-1);
      });
      pairs.forEach(function(p){tbody.appendChild(p[0]);if(p[1])tbody.appendChild(p[1]);});
    });
  });
})();
"""


def _esc(s: str) -> str:
    return html.escape(str(s), quote=True)


def _render_kpis(s: dict) -> str:
    all_pass = s["passed_assertions"] == s["assertions"]
    tiles = [
        ("Detections", s["rules"], "Sigma rules"),
        ("ATT&amp;CK techniques", s["techniques"], "MITRE mapped"),
        ("Tactics", s["tactics"], "kill-chain phases"),
        ("Test assertions", s["assertions"], f'{s["passing_rules"]}/{s["rules"]} rules green'),
    ]
    out = []
    for label, val, sub in tiles:
        out.append(
            f'<div class="kpi"><div class="k-label">{label}</div>'
            f'<div class="k-val">{val}</div><div class="k-sub">{sub}</div></div>'
        )
    hero_cls = "kpi hero" if all_pass else "kpi hero bad"
    out.append(
        f'<div class="{hero_cls}"><div class="k-label">Test pass rate</div>'
        f'<div class="k-val">{s["pass_rate"]}%</div>'
        f'<div class="k-sub">{s["passed_assertions"]}/{s["assertions"]} assertions</div></div>'
    )
    return "\n    ".join(out)


def _render_bars(tactics: list[dict]) -> str:
    mx = max((t["rules"] for t in tactics), default=1)
    out = []
    for t in tactics:
        pct = round(100 * t["rules"] / mx)
        out.append(
            f'<div class="bar-row"><span class="b-label">{_esc(t["label"])}</span>'
            f'<span class="bar-track"><span class="bar-fill" style="width:{pct}%"></span></span>'
            f'<span class="b-val">{t["rules"]}</span></div>'
        )
    return "\n      ".join(out)


def _render_chips(tactics: list[dict]) -> str:
    out = []
    for t in tactics:
        chips = "".join(f'<span class="chip">{_esc(x)}</span>' for x in t["techniques"])
        out.append(
            f'<div class="chip-col"><div class="c-head">{_esc(t["label"])}</div>'
            f'<div class="chips">{chips}</div></div>'
        )
    return "\n      ".join(out)


def _render_rows(rows: list[dict]) -> str:
    out = []
    for r in rows:
        sev = r["level"]
        sev_sort = _SEVERITY_ORDER.get(sev, 9)
        status = "pass" if r["passed"] else "fail"
        status_html = (
            '<span class="badge status-pass">✔ PASS</span>' if r["passed"]
            else '<span class="badge status-fail">✘ FAIL</span>'
        )
        search = _esc(f'{r["title"]} {r["stem"]} {" ".join(r["techniques"])}'.lower())
        techs = _esc(", ".join(r["techniques"]))
        detail = f'<p>{_esc(r["description"])}</p>'
        if r["falsepositives"]:
            fps = "".join(f"<li>{_esc(x)}</li>" for x in r["falsepositives"])
            detail += f'<div class="d-fp"><strong>False positives:</strong><ul>{fps}</ul></div>'
        if r["failures"]:
            fails = "; ".join(_esc(f) for f in r["failures"])
            detail += f'<div class="fail">FAILING: {fails}</div>'

        out.append(
            f'<tr class="rule" data-tactic="{_esc(r["primary_tactic"])}" data-sev="{sev}" '
            f'data-status="{status}" data-search="{search}" '
            f'data-sorttitle="{_esc(r["title"].lower())}" data-sorttactic="{_esc(r["primary_tactic"])}" '
            f'data-sortsev="{sev_sort}" data-sorttests="{r["assertions"]}" data-sortstatus="{status}">'
            f'<td><span class="r-title">{_esc(r["title"])}</span><br>'
            f'<span class="r-stem">{_esc(r["stem"])}</span></td>'
            f'<td>{_esc(_tactic_label(r["primary_tactic"]))}</td>'
            f'<td class="techs">{techs}</td>'
            f'<td><span class="badge sev-{sev}"><span class="dot"></span>{_esc(sev)}</span></td>'
            f'<td class="num tests-cell">{r["assertions"]}</td>'
            f'<td>{status_html}</td></tr>'
        )
        out.append(
            f'<tr class="detail" hidden><td colspan="6"><div class="detail-box">{detail}</div></td></tr>'
        )
    return "\n          ".join(out)


def render(data: dict, title: str) -> str:
    s = data["summary"]
    all_pass = s["passed_assertions"] == s["assertions"]
    pill = (
        f'<span class="pill ok"><span class="dot"></span>All {s["rules"]} detections passing</span>'
        if all_pass else
        f'<span class="pill bad"><span class="dot"></span>'
        f'{s["rules"] - s["passing_rules"]} detection(s) failing</span>'
    )
    tactic_opts = "".join(
        f'<option value="{_esc(t["name"])}">{_esc(t["label"])}</option>' for t in data["tactics"]
    )
    body = (
        _PAGE
        .replace("__TITLE__", _esc(title))
        .replace("__DATE__", date.today().isoformat())
        .replace("__CSS__", _CSS)
        .replace("__JS__", _JS)
        .replace("__HEALTH_PILL__", pill)
        .replace("__NRULES__", str(s["rules"]))
        .replace("__NTECH__", str(s["techniques"]))
        .replace("__KPIS__", _render_kpis(s))
        .replace("__BARS__", _render_bars(data["tactics"]))
        .replace("__CHIPS__", _render_chips(data["tactics"]))
        .replace("__TACTIC_OPTS__", tactic_opts)
        .replace("__ROWS__", _render_rows(data["rules"]))
    )
    return body


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("rules_dir", nargs="?", default="detections", type=Path)
    parser.add_argument("--cases-dir", default="tests/cases", type=Path)
    parser.add_argument("--out", type=Path, default=Path("docs/dashboard.html"))
    parser.add_argument("--title", default="Detection-as-Code Lab")
    args = parser.parse_args(argv)

    data = collect(args.rules_dir, args.cases_dir)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(render(data, args.title), encoding="utf-8")
    s = data["summary"]
    print(
        f"Wrote {args.out} — {s['rules']} detections, {s['techniques']} techniques, "
        f"{s['pass_rate']}% test pass rate ({s['passing_rules']}/{s['rules']} rules green)"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
