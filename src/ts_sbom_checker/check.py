"""The check as a whole: parse, detect, schema, model, TR tests, report.

``check_sbom`` is shared by the CLI and the AWS Lambda; it does no I/O, prints nothing and keeps
no state between calls apart from the cached schema validators.
"""

from __future__ import annotations

from typing import Protocol

from . import schema
from .detect import UnsupportedSbomError, detect_format
from .model import build_model
from .parse import InvalidJsonError, parse_sbom
from .report import schema_invalid_report, test_report
from .tr03183 import run_tests

DEFAULT_MAX_FAILURES = 1000
DEFAULT_MAX_SCHEMA_ERRORS = 100


class StepLogger(Protocol):
    """Anything with ``step(description)``, e.g. ``eacg_logutil.Log`` in the Lambda."""

    def step(self, description: str) -> None: ...


def preload() -> None:
    """Loads and prepares all schemas, so the first check does not pay for it (Lambda init phase)."""
    schema.preload()


def _decode(data: bytes) -> str:
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError as err:
        line = data[: err.start].count(b"\n") + 1
        raise InvalidJsonError(f"invalid encoding: the SBOM must be UTF-8 (byte {err.start}, line {line})", line) from None


def check_sbom(
    data: str | bytes | None,
    max_failures: int | None = DEFAULT_MAX_FAILURES,
    max_schema_errors: int | None = DEFAULT_MAX_SCHEMA_ERRORS,
    max_bytes: int | None = None,
    log: StepLogger | None = None,
) -> tuple[int, dict]:
    """Checks an SBOM given as text or UTF-8 bytes.

    Returns ``(status_code, report)`` with HTTP semantics: 200 report (also for an invalid schema
    or failed tests), 400 input error (empty_body, invalid_json, unknown_format,
    unsupported_version), 413 larger than ``max_bytes``. ``None`` limits mean unlimited.
    Unexpected errors are raised, not converted.
    """

    def step(description: str) -> None:
        if log is not None:
            log.step(description)

    if data is None or len(data) == 0:
        return 400, {"ok": False, "error": "empty_body", "message": "the SBOM is empty"}
    size = len(data) if isinstance(data, bytes) else len(data.encode("utf-8"))
    if max_bytes is not None and size > max_bytes:
        return 413, {"ok": False, "error": "too_large", "maxBytes": max_bytes, "actualBytes": size}

    try:
        step("parsing JSON")
        text = _decode(data) if isinstance(data, bytes) else data
        doc, locator = parse_sbom(text)

        step("detecting format")
        fmt = detect_format(doc)

        step(f"validating against schema {fmt.schema_key}")
        result = schema.validate_schema(doc, fmt, locator, max_schema_errors)
        if not result["valid"]:
            return 200, schema_invalid_report(fmt, result)

        step("building component model")
        model = build_model(doc, fmt)

        step(f"running TR-03183-2 tests on {len(model.components)} components")
        outcomes = run_tests(model, fmt)

        step("compiling report")
        return 200, test_report(fmt, model, outcomes, locator, max_failures)
    except InvalidJsonError as err:
        return 400, {"ok": False, "error": "invalid_json", "message": str(err), "line": err.line}
    except UnsupportedSbomError as err:
        return 400, {"ok": False, "error": err.error, "message": str(err)}
