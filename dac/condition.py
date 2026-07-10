"""Sigma ``condition`` expression parser and evaluator.

A Sigma rule's ``detection`` block contains one or more *search identifiers*
(``selection``, ``filter``, ``selection_susp`` ...) plus a ``condition`` string
that combines them, e.g.::

    condition: selection and not filter
    condition: 1 of selection_* and not filter_main
    condition: all of them

This module turns that string into a small AST and evaluates it against a
mapping of ``{identifier_name: bool}`` (the per-identifier match results computed
by :mod:`dac.matcher`). Operator precedence follows Sigma: ``not`` binds tighter
than ``and``, which binds tighter than ``or``.

Supported grammar
-----------------
    or_expr   := and_expr ( "or" and_expr )*
    and_expr  := not_expr ( "and" not_expr )*
    not_expr  := "not" not_expr | atom
    atom      := "(" or_expr ")" | quantifier | IDENTIFIER
    quantifier:= ( NUMBER | "all" ) "of" ( IDENT_PATTERN | "them" )

``1 of them`` / ``all of them`` quantify over every identifier; ``1 of sel_*``
quantifies over identifiers whose name matches the glob ``sel_*``. A numeric
quantifier ``N of ...`` means "at least N of them match".
"""

from __future__ import annotations

import fnmatch
import re
from dataclasses import dataclass

_TOKEN_RE = re.compile(r"\s*(\(|\)|[A-Za-z0-9_*?]+)")
_KEYWORDS = {"and", "or", "not", "of", "them", "all"}


class ConditionError(ValueError):
    """Raised when a condition string cannot be tokenised or parsed."""


def tokenize(condition: str) -> list[str]:
    tokens: list[str] = []
    pos = 0
    while pos < len(condition):
        match = _TOKEN_RE.match(condition, pos)
        if not match:
            raise ConditionError(f"unexpected character at offset {pos}: {condition[pos:]!r}")
        tokens.append(match.group(1))
        pos = match.end()
    return tokens


# --- AST nodes ---------------------------------------------------------------


class Node:
    def eval(self, results: dict[str, bool]) -> bool:  # pragma: no cover - interface
        raise NotImplementedError

    def identifiers(self) -> set[str]:
        """Concrete identifier names referenced (excludes glob patterns)."""
        return set()


@dataclass
class Ident(Node):
    name: str

    def eval(self, results: dict[str, bool]) -> bool:
        if self.name not in results:
            raise ConditionError(f"condition references unknown identifier {self.name!r}")
        return results[self.name]

    def identifiers(self) -> set[str]:
        return {self.name}


@dataclass
class Not(Node):
    child: Node

    def eval(self, results: dict[str, bool]) -> bool:
        return not self.child.eval(results)

    def identifiers(self) -> set[str]:
        return self.child.identifiers()


@dataclass
class And(Node):
    left: Node
    right: Node

    def eval(self, results: dict[str, bool]) -> bool:
        return self.left.eval(results) and self.right.eval(results)

    def identifiers(self) -> set[str]:
        return self.left.identifiers() | self.right.identifiers()


@dataclass
class Or(Node):
    left: Node
    right: Node

    def eval(self, results: dict[str, bool]) -> bool:
        return self.left.eval(results) or self.right.eval(results)

    def identifiers(self) -> set[str]:
        return self.left.identifiers() | self.right.identifiers()


@dataclass
class Quantifier(Node):
    """`N of <pattern>` — at least N identifiers matching pattern are true.

    ``count`` is an int for a numeric quantifier, or the string ``"all"``.
    ``pattern`` is a glob, or ``"them"`` meaning every identifier.
    """

    count: int | str
    pattern: str

    def _matching(self, results: dict[str, bool]) -> list[bool]:
        if self.pattern == "them":
            names = list(results)
        else:
            names = [n for n in results if fnmatch.fnmatchcase(n, self.pattern)]
        return [results[n] for n in names]

    def eval(self, results: dict[str, bool]) -> bool:
        values = self._matching(results)
        hits = sum(1 for v in values if v)
        if self.count == "all":
            return hits == len(values)  # vacuously true when nothing matches the pattern
        return hits >= int(self.count)


# --- Parser (recursive descent) ----------------------------------------------


class _Parser:
    def __init__(self, tokens: list[str]):
        self.tokens = tokens
        self.i = 0

    def peek(self) -> str | None:
        return self.tokens[self.i] if self.i < len(self.tokens) else None

    def next(self) -> str:
        tok = self.tokens[self.i]
        self.i += 1
        return tok

    def expect(self, value: str) -> None:
        tok = self.peek()
        if tok != value:
            raise ConditionError(f"expected {value!r} but found {tok!r}")
        self.next()

    def parse(self) -> Node:
        node = self.parse_or()
        if self.peek() is not None:
            raise ConditionError(f"trailing tokens in condition: {self.tokens[self.i:]}")
        return node

    def parse_or(self) -> Node:
        node = self.parse_and()
        while self.peek() == "or":
            self.next()
            node = Or(node, self.parse_and())
        return node

    def parse_and(self) -> Node:
        node = self.parse_not()
        while self.peek() == "and":
            self.next()
            node = And(node, self.parse_not())
        return node

    def parse_not(self) -> Node:
        if self.peek() == "not":
            self.next()
            return Not(self.parse_not())
        return self.parse_atom()

    def parse_atom(self) -> Node:
        tok = self.peek()
        if tok is None:
            raise ConditionError("unexpected end of condition")
        if tok == "(":
            self.next()
            node = self.parse_or()
            self.expect(")")
            return node
        # quantifier: NUMBER of ... | all of ...
        if tok == "all" and self._lookahead_is_of():
            self.next()
            return self._parse_quantifier_tail("all")
        if tok.isdigit() and self._lookahead_is_of():
            self.next()
            return self._parse_quantifier_tail(int(tok))
        if tok in _KEYWORDS:
            raise ConditionError(f"unexpected keyword {tok!r} in condition")
        self.next()
        return Ident(tok)

    def _lookahead_is_of(self) -> bool:
        return self.i + 1 < len(self.tokens) and self.tokens[self.i + 1] == "of"

    def _parse_quantifier_tail(self, count: int | str) -> Node:
        self.expect("of")
        target = self.peek()
        if target is None:
            raise ConditionError("expected 'them' or a pattern after 'of'")
        self.next()
        return Quantifier(count=count, pattern=target)


def parse_condition(condition: str) -> Node:
    """Parse a Sigma condition string into an evaluable AST."""
    tokens = tokenize(condition)
    if not tokens:
        raise ConditionError("empty condition")
    return _Parser(tokens).parse()
