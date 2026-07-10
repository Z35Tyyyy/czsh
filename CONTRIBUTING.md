# Adding a detection

The whole point of this repo is that shipping a detection is a repeatable,
tested, reviewable process — not a live edit in a console. Here's the loop.

## 1. Write the rule

Create `detections/<tactic>/<name>.yml`. Keep it inside the [supported Sigma
subset](docs/architecture.md); required fields: `title`, `id` (a fresh UUID),
`logsource`, `detection`, plus `tags` with at least one `attack.tXXXX` technique.

```bash
python - <<'PY'
import uuid; print(uuid.uuid4())   # generate a rule id
PY
```

## 2. Write its tests (not optional)

Create `tests/cases/<name>.yml` with **at least one** `true_positive` (the attack)
and **at least one** `true_negative` (a benign look-alike). The negative is the
hard part — it's where you prove the rule won't drown the SOC in noise. A rule
with no test case fails CI.

## 3. Run the gates locally

```bash
make test        # offline harness — TP fires, TN stays silent
make validate    # pySigma parses the rule
make lint        # yamllint + ruff
make coverage    # sanity-check the ATT&CK mapping
```

## 4. Regenerate the derived docs

```bash
python tools/generate_catalog.py detections/ --out docs/DETECTIONS.md
python tools/generate_attack_layer.py detections/ --out docs/attack-layer.json
```

## 5. Open a PR

CI re-runs every gate. Merge only when it's green. If you have the [lab](lab/README.md)
running, attach a screenshot of the atomic test firing the detection.

## Conventions

- **Naming**: `<logsource>_<behaviour>.yml`, e.g. `proc_creation_certutil_download.yml`.
- **Severity**: `informational | low | medium | high | critical`.
- **Every rule maps to MITRE ATT&CK** via `attack.*` tags.
- **Reference the Atomic Red Team test** that exercises the rule in `references:`.
