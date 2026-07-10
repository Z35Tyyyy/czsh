# I gave my detection rules a CI/CD pipeline (and unit tests without a SIEM)

*Draft blog post — the story behind the [Detection-as-Code Lab](../README.md). Publish on your own site / dev.to / Medium and link it from your résumé.*

---

## The itch

I kept reading the same thing about detection engineering: teams treat detection
rules as config you poke at in a console, not as code. Someone edits a SIEM rule
live at 2am, it's too broad, it buries the SOC in false positives, and there's no
test and no rollback. Meanwhile every other kind of software has had version
control, code review, and CI for twenty years.

There's a name for doing it properly — **detection-as-code** — and the data says
it's a gap worth filling: in a 2025 survey, 63% of security pros said they *want*
to work this way and only 35% actually do. That's the sweet spot for a portfolio
project: in demand, not yet everywhere, and something I could actually build.

So I built the smallest complete version I could: real detections, real tests, a
real pipeline.

## The hard part: how do you unit-test a detection?

A Sigma rule is basically a query. The obvious way to test it is to stand up the
SIEM, replay some logs, and see if it fires. That's slow and heavy — you can't run
it on every commit. So most rule repos don't test at all; they lint the YAML and
call it a day.

I didn't want "the YAML is well-formed." I wanted "this rule catches the attack
**and** ignores the thing that looks like the attack." That's the difference
between a detection that works and one that pages you all night.

So I wrote a small **Sigma evaluation engine in pure Python** — a few hundred lines
that take a rule and a single log event and answer *does this fire?* No SIEM. The
two interesting pieces were:

- a **recursive-descent parser** for Sigma's `condition` grammar, so
  `1 of selection_* and not filter` evaluates correctly; and
- **field matching** with Sigma's modifiers and wildcards.

That second piece is where I hit the one genuinely nasty bug. Sigma values are
full of Windows paths, and a `contains` match on a value ending in a backslash —
like `\CurrentVersion\Run\` — silently failed. The cause: I was appending the `*`
wildcard as a *string* before converting to regex, so the trailing `\` merged with
the `*` into `\*`, which Sigma reads as an *escaped literal asterisk*. My run-key
persistence rule quietly stopped matching. The fix was to stop string-concatenating
wildcards and anchor at the regex layer instead. It's now pinned by a regression
test — which is exactly the point of having tests.

## Every rule ships with its own tests

Each detection has a companion file listing events it must catch
(`true_positives`) and benign look-alikes it must ignore (`true_negatives`):

```yaml
true_positives:
  - name: procdump full dump of lsass
    event: { EventID: 1, Image: 'C:\Tools\procdump.exe',
             CommandLine: 'procdump.exe -ma lsass.exe out.dmp' }
true_negatives:
  - name: procdump against a benign process
    event: { EventID: 1, Image: 'C:\Tools\procdump.exe',
             CommandLine: 'procdump.exe -ma notepad.exe np.dmp' }
```

pytest turns every event into its own test, and a governance test refuses to let a
rule exist without at least one positive *and* one negative. The full suite —
151 assertions across 15 detections — runs in about 0.2 seconds.

Writing the negatives taught me more than the positives. For a "delete shadow
copies" ransomware detection, the benign twin is `vssadmin list shadows`. For
"clear the event log," it's `wevtutil qe` (query, not clear). Modelling the benign
look-alike is most of the actual detection engineering.

## The pipeline

On every pull request, GitHub Actions runs the same gates a real detection team
would: **lint → validate with pySigma → run the offline tests → compile the rules
to Splunk/Elastic queries → regenerate the ATT&CK coverage map → dry-run deploy.**

I kept my hand-rolled engine as a documented *subset* of Sigma, and let the real
pySigma library validate every rule in CI as a second opinion — so anything my
engine doesn't model is still checked by the reference implementation, and the two
agree on what a production backend would run.

## What I'd do next

- token-level de-obfuscation for encoded PowerShell,
- Sigma correlation rules for multi-event detections,
- and an LLM triage layer that summarises a fired alert and proposes a severity,
  scored against my own manual triage.

## What I actually learned

The code was the easy half. The detection-engineering half — deciding what a
benign version of each attack looks like, and where to draw the line so the rule
is useful without being noisy — is the part that made me feel like I'd done the
job, not just built a tool. Every rule's `falsepositives:` section is me arguing
with myself about that line, which felt exactly like the work.

*Repo: [Detection-as-Code Lab](../README.md). Feedback welcome.*
