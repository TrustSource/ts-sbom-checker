"""Human-readable rendering of a report for the command line: a table of all tests; with ``--details`` also the
findings, grouped by message, with every affected component and its line."""

from __future__ import annotations

import textwrap
from collections.abc import Callable

Style = Callable[..., str]

_UNICODE = {"pass": "✓", "fail": "✗", "na": "–", "rule": "─", "times": "×", "more": "…"}
_ASCII = {"pass": "+", "fail": "x", "na": "-", "rule": "-", "times": "x", "more": "..."}


def glyphs(encoding: str | None) -> dict[str, str]:
    """Unicode marks where the output encoding can carry them, ASCII otherwise."""
    try:
        "".join(_UNICODE.values()).encode(encoding or "ascii")
    except (LookupError, UnicodeEncodeError):
        return _ASCII
    return _UNICODE


def _ratio(t: dict) -> tuple[int, int] | None:
    """(checked, ok) of a test; document tests count as one check, None if not applicable."""
    if t["status"] == "notApplicable":
        return None
    if t["scope"] == "component":
        return t["checked"], t["succeeded"]
    return (1, 1) if t["status"] == "passed" else (1, 0)


def _ellipsis(parts: list[str], width: int, more: int, g: dict) -> str:
    """Joins parts with ", " within width; what does not fit is summarised as "… (+N)"."""
    out = ""
    for i, part in enumerate(parts):
        rest = len(parts) - i - 1 + more
        candidate = f"{out}, {part}" if out else part
        tail = f", {g['more']} (+{rest})" if rest else ""
        if len(candidate) + len(tail) > width and out:
            return f"{out}, {g['more']} (+{len(parts) - i + more})"
        out = candidate
    return f"{out}, {g['more']} (+{more})" if more else out


def _failing_lines(failure: dict | None, width: int, g: dict) -> str:
    if not failure:
        return ""
    lines = sorted({i["line"] for i in failure["items"] if i["line"] is not None})
    hidden = failure["total"] - len(failure["items"])
    return _ellipsis([str(n) for n in lines], width, hidden, g)


def _table(report: dict, width: int, style: Style, g: dict) -> list[str]:
    tests = report["summary"]["tests"]
    failures = report["failures"]
    id_w = max(len("Test"), *(len(t["id"]) for t in tests))
    tr_w = max(len("TR"), *(len(t["tr"]) for t in tests))
    ratio_w = len("Checked / 100  100 %")  # the slash lines up under the heading
    rows = []
    for t in tests:
        r = _ratio(t)
        ratio = "n/a" if r is None else f"{r[0]:>7} / {r[1]:<3}  {100 * r[1] // r[0]:>3} %"
        rows.append((t, ratio))
    ratio_w = max(ratio_w, *(len(x) for _, x in rows))
    fixed = 2 + 2 + 2 + 2 + id_w + 2 + tr_w + 2 + ratio_w + 2  # indent, number, mark, gaps
    lines_w = max(20, width - fixed)

    head = f"  {'#':>2}   {'Test':<{id_w}}  {'TR':<{tr_w}}  {'Checked / OK    OK %':<{ratio_w}}  Failing lines"
    lines = [style(head, bold=True), "  " + g["rule"] * (width - 2)]
    for n, (t, ratio) in enumerate(rows, 1):
        mark, colour = {
            "passed": (g["pass"], "green"),
            "failed": (g["fail"], "red"),
            "notApplicable": (g["na"], "bright_black"),
        }[t["status"]]
        if t["scope"] == "component" and t["checked"] > 1 and t["failed"] == t["checked"]:
            failing = "all components"
        else:
            failing = _failing_lines(failures.get(t["id"]), lines_w, g)
        lines.append(
            f"  {n:>2} {style(mark, fg=colour)} {t['id']:<{id_w}}  {t['tr']:<{tr_w}}  "
            f"{style(f'{ratio:>{ratio_w}}' if ratio == 'n/a' else f'{ratio:<{ratio_w}}', fg=colour)}  {failing}".rstrip()
        )
    return lines


def _group(items: list[dict]) -> list[tuple[str, list[dict]]]:
    """Groups failures by message; the component's own bom-ref inside a message does not split a group."""
    groups: dict[str, list[dict]] = {}
    for item in items:
        message = item["message"]
        if item["ref"]:
            message = message.replace(item["ref"], "<bom-ref>")
        groups.setdefault(message, []).append(item)
    return sorted(groups.items(), key=lambda kv: -len(kv[1]))


def _wrap(text: str, width: int, indent: str, first: str | None = None) -> list[str]:
    """Wraps at spaces only; a no-break space (U+00A0) keeps its neighbours on one line."""
    lines = textwrap.wrap(
        text,
        max(30, width),
        initial_indent=first or indent,
        subsequent_indent=indent,
        break_long_words=False,
        break_on_hyphens=False,
    )
    return [line.replace("\u00a0", " ") for line in lines] or [indent]


def _findings(report: dict, width: int, style: Style, g: dict) -> list[str]:
    tests = {t["id"]: t for t in report["summary"]["tests"]}
    out = []
    for test_id, failure in report["failures"].items():
        t = tests[test_id]
        scope = f"{failure['total']} of {t['checked']} components" if t["scope"] == "component" else "SBOM"
        out += ["", f"  {style(test_id, fg='red', bold=True)} (TR {t['tr']}): {scope}"]
        if t["scope"] == "document":
            for item in failure["items"]:
                out += _wrap(f"{item['message']} (line {item['line']})", width, "    ")
            continue
        for message, items in _group(failure["items"]):
            out += _wrap(message, width, " " * 10, f"    {len(items)}{g['times']:<{5 - len(str(len(items)))}} ")
            where = ", ".join(f"{i['component']}\u00a0({i['line']})".replace(" ", "\u00a0") for i in items)
            out += [style(line, fg="bright_black") for line in _wrap(where, width, " " * 10)]
        if failure["truncated"]:
            out.append(f"    ({len(failure['items'])} of {failure['total']} listed, see --max-failures)")
    return out


def render(file: str, report: dict, width: int, details: bool, style: Style, g: dict) -> list[str]:
    s = report["summary"]
    fmt = f"{report['format']['type']} {report['format']['specVersion']}"
    if not report["schemaValid"]:
        verdict = style("SCHEMA INVALID", fg="red", bold=True)
    elif s["compliant"]:
        verdict = style(f"COMPLIANT with {s['tr']}", fg="green", bold=True)
    else:
        verdict = style(f"NOT COMPLIANT with {s['tr']}", fg="red", bold=True)
    lines = [style(file, bold=True), f"  {fmt}: {verdict}"]

    if not report["schemaValid"]:
        shown = len(report["schemaErrors"])
        more = f", showing {shown}" if report.get("schemaErrorsTruncated") else ""
        lines.append(f"  {report['schemaErrorsTotal']} schema error(s){more}; TR tests were not run")
        lines.append("")
        for e in report["schemaErrors"]:
            lines += _wrap(f"line {e['line']}: {e['message']}", width, "        ", "    ")
    else:
        lines.append(
            f"  {s['componentsChecked']} components; {s['testsTotal']} tests: {s['testsPassed']} passed, "
            f"{s['testsFailed']} failed, {s['testsNotApplicable']} not applicable"
        )
        lines += ["", *_table(report, width, style, g)]
        if report["failures"] and details:
            lines += ["", style("  Findings", bold=True)]
            lines += _findings(report, width, style, g)
        elif report["failures"]:
            lines += ["", style("  Run with --details to list the findings per test.", fg="bright_black")]

    if report["notes"]:
        lines += ["", style("  Notes", bold=True)]
        for note in report["notes"]:
            lines += _wrap(note, width, "    ", "  - ")
    return lines
