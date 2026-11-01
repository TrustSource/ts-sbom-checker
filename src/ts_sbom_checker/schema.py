"""Schema validation against the official JSON schemas bundled in ``schemas/``; nothing is fetched at runtime.

Validation uses jsonschema-rs (Rust). The pure-Python ``jsonschema`` needs about 15 ms per SPDX 3
element (anyOf over ~80 element classes combined with ``unevaluatedProperties``), far too slow for
SBOMs with thousands of elements; see ARCHITECTURE.md, ADR-002.
"""

from __future__ import annotations

import json
import re
from datetime import date, datetime
from functools import cache
from importlib.resources import files

import jsonschema_rs

from .detect import Format
from .parse import Locator

SCHEMA_FILES = {
    "cyclonedx-1.5": "bom-1.5.schema.json",
    "cyclonedx-1.6": "bom-1.6.schema.json",
    "cyclonedx-1.7": "bom-1.7.schema.json",
    "spdx-2.2": "spdx-2.2.schema.json",
    "spdx-2.3": "spdx-2.3.schema.json",
    "spdx-3.0.1": "spdx-3.0.1.schema.json",
}
_CYCLONEDX_SHARED = ("spdx.schema.json", "jsf-0.82.schema.json", "cryptography-defs.schema.json")
SPDX3_CONTEXT = "https://spdx.org/rdf/3.0.1/spdx-context.jsonld"


@cache
def load_schema(name: str) -> dict:
    return json.loads(files("ts_sbom_checker").joinpath("schemas", name).read_text(encoding="utf-8"))


# ---- formats ---------------------------------------------------------------------------------
# Formats used by the schemas. date-time, date, (idn-)email and uri are checked; iri-reference and
# similar are accepted leniently, the TR tests check the fields that matter more strictly.

_DATE_TIME = re.compile(r"(\d{4})-(\d{2})-(\d{2})[Tt](\d{2}):(\d{2}):(\d{2})(\.\d+)?([Zz]|[+-]\d{2}:\d{2})")
_EMAIL = re.compile(r"[^\s@]+@[^\s@]+")
_URI = re.compile(r"[A-Za-z][A-Za-z0-9+.-]*:[\x21-\x7e]*")


def is_rfc3339_date_time(value: str) -> bool:
    m = _DATE_TIME.fullmatch(value)
    if not m:
        return False
    try:
        datetime(*(int(m.group(i)) for i in range(1, 7)))
    except ValueError:
        return False
    tz = m.group(8)
    return tz in "Zz" or (int(tz[1:3]) <= 23 and int(tz[4:6]) <= 59)


def _is_date(value: str) -> bool:
    if not re.fullmatch(r"\d{4}-\d{2}-\d{2}", value):
        return False
    try:
        date.fromisoformat(value)
    except ValueError:
        return False
    return True


def _lenient(value: str) -> bool:
    return True


FORMATS = {
    "date-time": is_rfc3339_date_time,
    "date": _is_date,
    "email": lambda v: bool(_EMAIL.fullmatch(v)),
    "idn-email": lambda v: bool(_EMAIL.fullmatch(v)),
    "uri": lambda v: bool(_URI.fullmatch(v)),
    "iri": _lenient,
    "iri-reference": _lenient,
    "uri-reference": _lenient,
    "idn-hostname": _lenient,
}


# ---- validators ------------------------------------------------------------------------------


@cache
def _registry() -> jsonschema_rs.Registry:
    resources = []
    for name in _CYCLONEDX_SHARED:
        schema = load_schema(name)
        resources.append((schema["$id"], schema))
    return jsonschema_rs.Registry(resources)


@cache
def validator_for(schema_key: str):
    file = SCHEMA_FILES.get(schema_key)
    if not file:
        raise KeyError(f"no schema for {schema_key}")
    return jsonschema_rs.validator_for(
        load_schema(file),
        formats=FORMATS,
        validate_formats=True,
        registry=_registry(),
    )


def preload() -> None:
    """Loads all schemas and builds their validators (e.g. during a Lambda init phase)."""
    for key in SCHEMA_FILES:
        validator_for(key)


# ---- errors ----------------------------------------------------------------------------------

_GENERIC = ("oneOf", "anyOf")
_MAX_INSTANCE = 80
_MAX_MESSAGE = 300


def _pointer(path) -> str:
    if not path:
        return "/"
    return "".join("/" + str(p).replace("~", "~0").replace("/", "~1") for p in path)


def _short(value) -> str:
    text = json.dumps(value, ensure_ascii=False)
    return text if len(text) <= _MAX_INSTANCE else text[: _MAX_INSTANCE - 1] + "…"


def _flatten(errors):
    """oneOf/anyOf errors carry the errors of every failed branch in ``kind.context``; all of
    them are candidates for the report (``_reduce_noise`` then keeps the deepest ones)."""
    for err in errors:
        yield err
        if err.kind.name in _GENERIC:
            for branch in getattr(err.kind, "context", None) or ():
                yield from _flatten(branch)


def _reduce_noise(errors: list) -> list:
    """oneOf/anyOf schemas (SPDX 3 element classes, CycloneDX licences) fail in every branch. Keep only
    errors at the deepest paths: an error is dropped if another error exists below its path, and
    a generic oneOf/anyOf error is dropped if a more specific error exists at the same path."""
    paths = {tuple(e.instance_path) for e in errors}
    prefixes = {p[:i] for p in paths for i in range(len(p))}  # proper prefixes of every path
    leaf = [e for e in errors if tuple(e.instance_path) not in prefixes]
    specific = {tuple(e.instance_path) for e in leaf if e.kind.name not in _GENERIC}
    return [e for e in leaf if not (e.kind.name in _GENERIC and tuple(e.instance_path) in specific)]


def _duplicates(items) -> str:
    seen: dict[str, int] = {}
    for j, item in enumerate(items if isinstance(items, list) else ()):
        i = seen.setdefault(json.dumps(item, sort_keys=True, separators=(",", ":")), j)
        if i != j:
            return f" (items ## {i} and {j} are identical)"
    return ""


def _detail(err) -> str:
    """Error text without the full instance (jsonschema-rs embeds it, which can be huge)."""
    kind = err.kind.name
    if kind == "oneOf":
        return "must match exactly one schema in oneOf"
    if kind == "anyOf":
        return "must match a schema in anyOf"
    if kind == "uniqueItems":
        return "must NOT have duplicate items" + _duplicates(err.instance)
    if kind == "type":
        types = err.kind.as_dict().get("types") or []
        return f"{_short(err.instance)} is not of type {' or '.join(json.dumps(t) for t in types)}"
    if kind == "enum":
        options = err.kind.as_dict().get("options")
        allowed = ": " + ", ".join(str(o) for o in options) if isinstance(options, list) and len(options) <= 10 else ""
        return f"{_short(err.instance)} is not one of the allowed values{allowed}"
    message = err.message
    return message if len(message) <= _MAX_MESSAGE else message[: _MAX_MESSAGE - 1] + "…"


def validate_schema(data: dict, fmt: Format, locator: Locator, max_errors: int | None) -> dict:
    """Returns ``{"valid", "errors": [{"path", "line", "message"}], "total", "truncated"}``."""
    validator = validator_for(fmt.schema_key)
    subject = {**data, "@context": SPDX3_CONTEXT} if fmt.context_override else data
    if validator.is_valid(subject):
        return {"valid": True, "errors": [], "total": 0, "truncated": False}

    seen: set[str] = set()
    errors = []
    for err in _reduce_noise(list(_flatten(validator.iter_errors(subject)))):
        path = list(err.instance_path)
        message = f"{_pointer(path)} {_detail(err)}"
        if message in seen:
            continue
        seen.add(message)
        errors.append({"path": _pointer(path), "line": locator.line(path), "message": message})
    errors.sort(key=lambda e: e["line"])
    limit = len(errors) if max_errors is None else max_errors
    return {"valid": False, "errors": errors[:limit], "total": len(errors), "truncated": len(errors) > limit}
