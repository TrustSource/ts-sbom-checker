"""Command line interface: ``ts-sbom-checker FILE [FILE ...]``."""

from __future__ import annotations

import json
import sys
from dataclasses import dataclass

import click

from . import __version__
from .check import check_sbom

EXIT_OK = 0
EXIT_FAILED = 1
EXIT_INPUT_ERROR = 2

_STATUS_MARK = {"passed": ("PASS", "green"), "failed": ("FAIL", "red"), "notApplicable": ("N/A ", "bright_black")}


@dataclass
class Outcome:
    file: str
    status_code: int
    report: dict

    @property
    def input_error(self) -> bool:
        return self.status_code != 200

    def failed(self, fail_on: str) -> bool:
        if fail_on == "never":
            return False
        if not self.report.get("schemaValid", False):
            return True
        return fail_on == "non-compliant" and not self.report["summary"]["compliant"]


def _read(file: str) -> bytes:
    if file == "-":
        return sys.stdin.buffer.read()
    with open(file, "rb") as fh:
        return fh.read()


def _check_file(file: str, max_failures, max_schema_errors, max_bytes) -> Outcome:
    try:
        data = _read(file)
    except OSError as err:
        reason = err.strerror or str(err)
        return Outcome(file, 400, {"ok": False, "error": "unreadable_file", "message": f"cannot read file: {reason}"})
    status, report = check_sbom(data, max_failures=max_failures, max_schema_errors=max_schema_errors, max_bytes=max_bytes)
    return Outcome(file, status, report)


# ---- text output -----------------------------------------------------------------------------


def _input_error_text(o: Outcome, style) -> list[str]:
    r = o.report
    if r["error"] == "too_large":
        detail = f"file is larger than {r['maxBytes']} bytes ({r['actualBytes']} bytes)"
    else:
        detail = r.get("message", "")
    return [f"{style(o.file, bold=True)}: {style('ERROR', fg='red', bold=True)} {r['error']}: {detail}"]


def _report_text(o: Outcome, style) -> list[str]:
    r = o.report
    s = r["summary"]
    fmt = f"{r['format']['type']} {r['format']['specVersion']}"
    if not r["schemaValid"]:
        verdict = style("SCHEMA INVALID", fg="red", bold=True)
    elif s["compliant"]:
        verdict = style(f"COMPLIANT with {s['tr']}", fg="green", bold=True)
    else:
        verdict = style(f"NOT COMPLIANT with {s['tr']}", fg="red", bold=True)
    lines = [f"{style(o.file, bold=True)}: {fmt} - {verdict}"]

    if not r["schemaValid"]:
        shown = len(r["schemaErrors"])
        more = f", showing {shown}" if r.get("schemaErrorsTruncated") else ""
        lines.append(f"  {r['schemaErrorsTotal']} schema error(s){more}; TR tests were not run")
        lines += [f"    line {e['line']}: {e['message']}" for e in r["schemaErrors"]]
    else:
        lines.append(
            f"  {s['testsTotal']} tests: {s['testsPassed']} passed, {s['testsFailed']} failed, "
            f"{s['testsNotApplicable']} not applicable; {s['componentsChecked']} components checked"
        )
        lines.append("")
        for t in s["tests"]:
            mark, colour = _STATUS_MARK[t["status"]]
            counts = ""
            if t["scope"] == "component":
                counts = f"  [{t['failed']} failed / {t['checked']} checked, {t['notApplicable']} n/a]"
            lines.append(f"  {style(mark, fg=colour)}  {t['id']:<31} TR {t['tr']:<14}{counts}".rstrip())
        for test_id, f in r["failures"].items():
            more = f", showing {len(f['items'])}" if f["truncated"] else ""
            lines += ["", f"  {style(test_id, fg='red', bold=True)} ({f['total']} failure(s){more})"]
            for item in f["items"]:
                who = item["component"] if not item["ref"] else f"{item['component']} ({item['ref']})"
                lines.append(f"    line {item['line']}: {who}: {item['message']}")

    if r["notes"]:
        lines += ["", "  Notes:"] + [f"  - {n}" for n in r["notes"]]
    return lines


def _text(outcomes: list[Outcome], colour: bool) -> str:
    def style(text, **kw):
        return click.style(text, **kw) if colour else text

    blocks = []
    for o in outcomes:
        blocks.append("\n".join(_input_error_text(o, style) if o.input_error else _report_text(o, style)))
    footer = f"ts-sbom-checker {__version__} - not an official tool of the BSI"
    return "\n\n".join(blocks) + "\n\n" + style(footer, fg="bright_black") + "\n"


def _json(outcomes: list[Outcome]) -> str:
    if len(outcomes) == 1:
        payload = outcomes[0].report
    else:
        payload = [{"file": o.file, **o.report} for o in outcomes]
    return json.dumps(payload, indent=2, ensure_ascii=False) + "\n"


# ---- command ---------------------------------------------------------------------------------


def _limit(value: int | None) -> int | None:
    return None if value is None or value <= 0 else value


@click.command(context_settings={"help_option_names": ["-h", "--help"]})
@click.argument("files", nargs=-1, required=True, metavar="FILE [FILE ...]")
@click.option(
    "--format",
    "output_format",
    type=click.Choice(["text", "json"]),
    default="text",
    show_default=True,
    help="Output format. json is the report of the ts-sbom-quality Lambda (a list for several files).",
)
@click.option(
    "-o",
    "--output",
    type=click.Path(dir_okay=False, writable=True),
    default=None,
    help="Write the output to this file instead of stdout.",
)
@click.option(
    "--fail-on",
    type=click.Choice(["non-compliant", "schema", "never"]),
    default="non-compliant",
    show_default=True,
    help="When to exit with code 1.",
)
@click.option(
    "--max-failures", type=int, default=None, metavar="N", help="List at most N failures per test (default: unlimited)."
)
@click.option(
    "--max-schema-errors", type=int, default=None, metavar="N", help="List at most N schema errors (default: unlimited)."
)
@click.option("--max-bytes", type=int, default=None, metavar="N", help="Reject files larger than N bytes (default: unlimited).")
@click.version_option(__version__, "--version", prog_name="ts-sbom-checker")
def main(files, output_format, output, fail_on, max_failures, max_schema_errors, max_bytes):
    """Checks SBOM files (CycloneDX 1.5-1.7, SPDX 2.1-2.3 / 3.0, JSON) against their schema and
    BSI TR-03183-2 v2.1.0. Use "-" to read from stdin.

    \b
    Exit codes:
      0  all files compliant (or nothing to fail on, see --fail-on)
      1  at least one file not compliant / schema invalid (see --fail-on)
      2  input error: unreadable file, no JSON, unknown format or version, too large

    Not an official tool of the BSI.
    """
    outcomes = [_check_file(f, _limit(max_failures), _limit(max_schema_errors), _limit(max_bytes)) for f in files]

    if output_format == "json":
        text = _json(outcomes)
    else:
        text = _text(outcomes, colour=output is None and sys.stdout.isatty())
    if output:
        with open(output, "w", encoding="utf-8") as fh:
            fh.write(text)
    else:
        click.echo(text, nl=False)

    if any(o.input_error for o in outcomes):
        sys.exit(EXIT_INPUT_ERROR)
    sys.exit(EXIT_FAILED if any(o.failed(fail_on) for o in outcomes) else EXIT_OK)


if __name__ == "__main__":
    main()
