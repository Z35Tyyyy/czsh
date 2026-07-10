# Architecture

## The problem

A Sigma rule is a query. To unit-test it, you normally need the target SIEM: load
the rule, replay events, see if it fires. That's slow, heavy, and impossible to
run on every pull request. So most detection repos don't test their rules at all —
they lint the YAML and hope.

This project takes a different route: a **small Sigma evaluation engine in pure
Python** that answers one question — *does this rule fire on this single event?* —
with no SIEM in the loop. That makes detection tests as cheap as any other unit
test, so they can gate CI.

## Components

```
dac/
├── condition.py   # tokenise + parse the `condition:` string into an AST
├── matcher.py     # compile field selections to predicates; evaluate a rule on an event
├── loader.py      # load test-case files (true_positives / true_negatives)
└── cli.py         # `dac test | coverage | match`
```

### Evaluation flow

```
rule.yml ──load_rule──▶ SigmaRule
                          ├─ selections: {name: Selection}   (compiled predicates)
                          └─ condition_ast: Node             (parsed boolean tree)

event (dict) ──▶ for each selection: predicate(event) -> bool
                 ──▶ {name: bool}
                 ──▶ condition_ast.eval({name: bool}) -> fires?
```

Each **search identifier** (`selection`, `filter`, `selection_susp`, …) compiles to
a predicate. The **condition** is parsed once into an AST and evaluated against the
per-identifier results. Separating "does this field match" from "how the
identifiers combine" keeps both parts small and independently testable.

### Field matching (`matcher.py`)

- **Modifiers**: `contains`, `startswith`, `endswith`, `all`, `re`, `cased`.
- **Wildcards**: Sigma `*` (any run) and `?` (any single char). `\*` / `\?` are
  literal (escaped) — a common footgun, so it's [explicitly tested](../tests/test_matcher_engine.py).
- **Case**: insensitive by default (Sigma's default); `cased` opts into
  case-sensitivity.
- **Lists**: a list of values is OR by default, AND when the `all` modifier is
  present.
- **null**: matches a field that is absent or explicitly null.
- **Selection shapes**: a single map (AND of fields), a list of maps (OR of
  AND-groups), or a bare keyword list (substring match over any field value).

Wildcard-to-regex conversion produces an *unanchored body*; the modifier decides
the anchoring (`^…$` for exact, `…$` for endswith, none for contains). Doing the
anchoring at the regex layer rather than by string-concatenating a `*` is what
lets a value ending in a backslash — like `\CurrentVersion\Run\` — work correctly
under `contains`. (Getting this wrong was the one real bug found during
development; it's now pinned by a regression test.)

### Condition grammar (`condition.py`)

Recursive-descent parser, precedence `not` > `and` > `or`:

```
or_expr    := and_expr ( "or"  and_expr )*
and_expr   := not_expr ( "and" not_expr )*
not_expr   := "not" not_expr | atom
atom       := "(" or_expr ")" | quantifier | IDENTIFIER
quantifier := ( NUMBER | "all" ) "of" ( IDENT_PATTERN | "them" )
```

`1 of selection_*` and `all of them` quantify over identifiers by glob;
`N of …` means "at least N". Referencing an undefined identifier is an error, not
a silent `false`.

## Supported Sigma subset — and why a subset

The engine implements the constructs the rules in this repo use. It deliberately
does **not** implement the whole spec (no `base64offset`, `|utf16`, aggregation
`count() by`, or `correlation` rules yet).

This is a feature, not a gap: **unsupported syntax raises** (`RuleError`) instead
of evaluating to something plausible-but-wrong. And the CI `validate` stage runs
every rule through the *real* pySigma library, so anything the offline engine
can't model is still parsed and checked by the reference implementation. The two
layers together mean a rule that passes here behaves the same on a production
backend — which is the whole point of testing detections before shipping them.

## Why not just use pySigma to evaluate events?

pySigma parses and *translates* Sigma to backend queries; it doesn't evaluate a
rule against an in-memory event (that's the SIEM's job). The offline engine fills
exactly that gap. pySigma is still used — for validation and for compiling rules
to Splunk/Elastic queries in CI — it's the right tool for those jobs, just not for
"does this event fire this rule" in a unit test.
