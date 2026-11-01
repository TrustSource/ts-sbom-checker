"""Syntax checks shared by the TR tests: URI, email, purl, CPE, SPDX licence expressions."""

from __future__ import annotations

import json
import re
from functools import cache

from packageurl import PackageURL

from .schema import is_rfc3339_date_time, load_schema

_URI = re.compile(r"[A-Za-z][A-Za-z0-9+.-]*:[A-Za-z0-9\-._~:/?#\[\]@!$&'()*+,;=%]+")
_BAD_PERCENT = re.compile(r"%(?![0-9A-Fa-f]{2})")
_NON_ASCII = re.compile(r"[^\x00-\x7f]")


def q(value) -> str:
    """Quotes a value for a message, like JSON.stringify."""
    return json.dumps(value, ensure_ascii=False)


def is_absolute_uri(value) -> bool:
    """Absolute URI in ASCII (TR 8.1.10: IRIs have to be transformed into URIs)."""
    return isinstance(value, str) and bool(_URI.fullmatch(value)) and not _BAD_PERCENT.search(value)


def uri_problem(value) -> str | None:
    if not isinstance(value, str) or value.strip() == "":
        return "is empty"
    if _NON_ASCII.search(value):
        return f'"{value}" contains non-ASCII characters (IRI must be converted to URI / Punycode, TR 8.1.10)'
    if not is_absolute_uri(value):
        return f'"{value}" is not a valid absolute URI'
    return None


_EMAIL = re.compile(r'[^\s@<>()",;]+@[^\s@<>()",;]+\.[^\s@<>()",;]+')


def is_email(value) -> bool:
    return isinstance(value, str) and bool(_EMAIL.fullmatch(value.strip()))


def is_url(value) -> bool:
    return isinstance(value, str) and is_absolute_uri(value.strip())


# CPE 2.2 (URI binding) and CPE 2.3 (formatted string) patterns as used by SPDX / CycloneDX.
_CPE22 = re.compile(r"[c][pP][eE]:/[AHOaho]?(:[A-Za-z0-9._\-~%]*){0,6}")
_CPE23_PART = r"""(((\?*|\*?)([a-zA-Z0-9\-._]|(\\[\\*?!"#$%&'()+,/:;<=>@\[\]^`{|}~]))+(\?*|\*?))|[*-])"""
_CPE23 = re.compile(
    r"cpe:2\.3:[aho*-]"
    + rf"(:{_CPE23_PART}){{5}}"
    + r"(:(([a-zA-Z]{2,3}(-([a-zA-Z]{2}|[0-9]{3}))?)|[*-]))"
    + rf"(:{_CPE23_PART}){{4}}"
)


def identifier_problem(kind: str, value) -> str | None:
    if not isinstance(value, str) or value.strip() == "":
        return f"{kind} is empty"
    if kind == "purl":
        try:
            PackageURL.from_string(value)
        except ValueError as err:
            return f'purl "{value}" is invalid: {err}'
        return None
    if kind == "cpe22":
        return None if _CPE22.fullmatch(value) else f'CPE 2.2 "{value}" is invalid'
    if kind == "cpe23":
        return None if _CPE23.fullmatch(value) else f'CPE 2.3 "{value}" is invalid'
    if kind == "cpe":
        if _CPE22.fullmatch(value) or _CPE23.fullmatch(value):
            return None
        return f'CPE "{value}" is neither a valid CPE 2.2 nor 2.3'
    return None  # swid: tagId only has to be non-empty


# ---- SPDX licence identifiers and expressions (TR 6.1) -----------------------------------------
# The licence and exception identifiers come from the bundled CycloneDX spdx.schema.json, which
# tracks the SPDX licence list.


@cache
def _ids() -> dict[str, str]:
    return {i.lower(): i for i in load_schema("spdx.schema.json")["enum"]}


_REF = re.compile(r"(DocumentRef-[A-Za-z0-9.-]+:)?LicenseRef-[A-Za-z0-9.-]+")
_ADDITION_REF = re.compile(r"(DocumentRef-[A-Za-z0-9.-]+:)?AdditionRef-[A-Za-z0-9.-]+")
_EXPR_TOKEN = re.compile(r"\(|\)|[^\s()]+")


def is_licence_id(value) -> bool:
    return isinstance(value, str) and (value.lower() in _ids() or bool(_REF.fullmatch(value)))


def _operator(tok: str | None) -> str | None:
    """AND / OR / WITH, either upper case or completely lower case."""
    if tok is None:
        return None
    up = tok.upper()
    if up in ("AND", "OR", "WITH") and tok in (up, up.lower()):
        return up
    return None


class _ExpressionError(Exception):
    pass


class _ExpressionParser:
    def __init__(self, expr: str):
        self.tokens = _EXPR_TOKEN.findall(expr)
        self.pos = 0

    def peek(self) -> str | None:
        return self.tokens[self.pos] if self.pos < len(self.tokens) else None

    def parse(self) -> None:
        self.or_expr()
        if self.pos < len(self.tokens):
            raise _ExpressionError(f'unexpected "{self.tokens[self.pos]}"')

    def or_expr(self) -> None:
        self.and_expr()
        while _operator(self.peek()) == "OR":
            self.pos += 1
            self.and_expr()

    def and_expr(self) -> None:
        self.with_expr()
        while _operator(self.peek()) == "AND":
            self.pos += 1
            self.with_expr()

    def with_expr(self) -> None:
        self.simple()
        if _operator(self.peek()) == "WITH":
            self.pos += 1
            exc = self.peek()
            if exc is None:
                raise _ExpressionError("missing exception after WITH")
            if exc.lower() not in _ids() and not _ADDITION_REF.fullmatch(exc):
                raise _ExpressionError(f'"{exc}" is not an SPDX licence exception')
            self.pos += 1

    def simple(self) -> None:
        tok = self.peek()
        if tok is None:
            raise _ExpressionError("unexpected end of expression")
        if tok == "(":
            self.pos += 1
            self.or_expr()
            if self.peek() != ")":
                raise _ExpressionError('missing ")"')
            self.pos += 1
            return
        if tok == ")" or _operator(tok):
            raise _ExpressionError(f'unexpected "{tok}"')
        licence = tok[:-1] if tok.endswith("+") else tok
        if not is_licence_id(licence):
            raise _ExpressionError(f'"{tok}" is not an SPDX licence identifier or LicenseRef')
        self.pos += 1


def licence_expression_problem(expr) -> str | None:
    """None if ``expr`` is a valid SPDX licence expression, otherwise a problem description."""
    if not isinstance(expr, str) or expr.strip() == "":
        return "licence expression is empty"
    try:
        _ExpressionParser(expr).parse()
    except _ExpressionError as err:
        return f'"{expr}": {err}'
    return None


def licence_entry_problem(kind: str, value) -> str | None:
    """Checks a normalised licence entry (kind: id | expression | name | text | other)."""
    if kind == "id":
        return None if is_licence_id(value) else f'"{value}" is not an SPDX licence identifier'
    if kind == "expression":
        return licence_expression_problem(value)
    if kind == "name":
        return f'licence given by name only ("{value}"), an SPDX identifier or expression is required (TR 6.1)'
    if kind == "text":
        return "licence given as text only, an SPDX identifier or expression is required (TR 6.1)"
    if kind == "other":
        return None
    return "unrecognised licence entry"


def has_path_separator(value: str) -> bool:
    return "/" in value or "\\" in value


def is_sha512(value) -> bool:
    return isinstance(value, str) and bool(re.fullmatch(r"[A-Fa-f0-9]{128}", value))


def is_date_time(value) -> bool:
    return isinstance(value, str) and is_rfc3339_date_time(value)


def non_empty(value) -> bool:
    return isinstance(value, str) and value.strip() != ""
