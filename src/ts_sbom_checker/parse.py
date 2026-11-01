"""Strict JSON parsing plus the positions of every value, used only to report 1-based line numbers.

``json.loads`` builds the data model. Positions are computed lazily by a small regex-based scanner
the first time a line is requested, so documents without findings pay nothing for it.
"""

from __future__ import annotations

import bisect
import json
import re

# One JSON token: string, structural character, or a literal / number.
_TOKEN = re.compile(r'"[^"\\]*(?:\\.[^"\\]*)*"|[{}\[\],:]|[^\s{}\[\],:"]+', re.S)
_NON_FINITE = ("NaN", "Infinity", "-Infinity")


class InvalidJsonError(Exception):
    def __init__(self, message: str, line: int):
        super().__init__(message)
        self.line = line


def strip_bom(text: str) -> str:
    return text[1:] if text.startswith("\ufeff") else text


def _line_starts(text: str) -> list[int]:
    return [0] + [m.end() for m in re.finditer("\n", text)]


def _index(text: str) -> dict[tuple, int]:
    """Maps the path of every value (tuple of keys / indices) to the offset where it starts.

    The text has already been accepted by ``json.loads``; the scanner relies on that.
    """
    offsets: dict[tuple, int] = {}
    path: list = []
    in_array: list[bool] = []
    key_next = False
    for m in _TOKEN.finditer(text):
        tok = m.group(0)
        c = tok[0]
        if c == ":":
            continue
        if c == ",":
            if in_array[-1]:
                path[-1] += 1
            else:
                path.pop()
                key_next = True
            continue
        if c == "}":
            if not key_next:  # the value of the last key ends here
                path.pop()
            in_array.pop()
            key_next = False
            continue
        if c == "]":
            path.pop()
            in_array.pop()
            continue
        if key_next:
            path.append(json.loads(tok) if "\\" in tok else tok[1:-1])
            key_next = False
            continue
        offsets[tuple(path)] = m.start()
        if c == "{":
            in_array.append(False)
            key_next = True
        elif c == "[":
            in_array.append(True)
            path.append(0)
    return offsets


class Locator:
    def __init__(self, text: str):
        self._text = text
        self._starts: list[int] | None = None
        self._offsets: dict[tuple, int] | None = None

    def line_at_offset(self, offset: int) -> int:
        if self._starts is None:
            self._starts = _line_starts(self._text)
        return bisect.bisect_right(self._starts, offset)

    def line(self, path=()) -> int:
        """Line of the value at ``path``. Falls back to the nearest existing ancestor, so a missing
        field reports the line where its parent object starts."""
        if self._offsets is None:
            self._offsets = _index(self._text)
        path = tuple(path)
        for length in range(len(path), -1, -1):
            offset = self._offsets.get(path[:length])
            if offset is not None:
                return self.line_at_offset(offset)
        return 1


def _reject_constant(name: str):
    raise ValueError(name)


def parse_sbom(text: str):
    """Returns ``(data, locator)``; raises ``InvalidJsonError``."""
    text = strip_bom(text)
    try:
        data = json.loads(text, parse_constant=_reject_constant)
    except json.JSONDecodeError as err:
        raise InvalidJsonError(f"invalid JSON: {err.msg} (line {err.lineno})", err.lineno) from None
    except ValueError as err:  # NaN / Infinity
        locator = Locator(text)
        line = next((locator.line_at_offset(m.start()) for m in _TOKEN.finditer(text) if m.group(0) in _NON_FINITE), 1)
        raise InvalidJsonError(f"invalid JSON: {err} is not allowed (line {line})", line) from None
    except RecursionError:
        raise InvalidJsonError("invalid JSON: nesting too deep", 1) from None
    if not isinstance(data, dict):
        raise InvalidJsonError("invalid SBOM: top-level value must be a JSON object", 1)
    return data, Locator(text)


def pointer_to_path(pointer: str) -> list:
    """Converts a JSON pointer ("/components/3/name") into a path list."""
    if not pointer:
        return []
    out: list = []
    for seg in pointer.split("/")[1:]:
        seg = seg.replace("~1", "/").replace("~0", "~")
        out.append(int(seg) if seg.isdigit() else seg)
    return out
