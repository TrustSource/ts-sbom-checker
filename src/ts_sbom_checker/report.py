"""The report (identical to the ts-sbom-quality Lambda, see README "Report format")."""

from __future__ import annotations

from .detect import Format
from .model import Model
from .parse import Locator
from .tr03183 import TR_NAME

LIMITATION_NOTE = (
    "Logical components (TR 3.2.2) and merely identified components (TR 3.2.4) cannot be "
    "recognised from the SBOM alone; they are checked like fully described components."
)


def _display_name(c) -> str:
    if isinstance(c.name.value, str) and c.name.value.strip():
        return c.name.value
    return c.ref or "(unnamed)"


def _non_conformance_note(fmt: Format) -> str | None:
    if fmt.is_spdx2:
        return (
            "The TR permits SPDX only from version 3.0.1. An SPDX 2.x SBOM therefore cannot be TR-compliant; "
            "the tests show what would be missing after a migration. The TR defines no field mapping for SPDX 2.x, "
            "the mapping used here is an approximation."
        )
    if fmt.type == "SPDX" and fmt.spec_version == "3.0.0":
        return "The TR permits SPDX only from version 3.0.1. An SPDX 3.0.0 SBOM therefore cannot be TR-compliant."
    if fmt.type == "CycloneDX" and fmt.spec_version == "1.5":
        return (
            "The TR permits CycloneDX only from version 1.6. A CycloneDX 1.5 SBOM therefore cannot be TR-compliant; "
            "several fields used by the TR mapping (e.g. component manufacturer, licence acknowledgement) "
            "do not exist in 1.5."
        )
    return None


# TR section 7: an SBOM that was compliant at its delivery date remains compliant. TR v2.0.0 permitted
# CycloneDX >= 1.5 and SPDX >= 2.2.1; it could be applied until six months after v2.1.0 (2025-08-20).
TRANSITION_NOTE = (
    "This check applies TR-03183-2 v2.1.0. TR v2.0.0 permitted CycloneDX 1.5 and SPDX 2.2.1 or higher and could be "
    "applied until 2026-02-20 (six months after v2.1.0). According to TR section 7, an SBOM that was compliant "
    "at its delivery date remains compliant, so an SBOM delivered under v2.0.0 may still be compliant."
)


def _transition_note(fmt: Format) -> str | None:
    older = (fmt.type == "CycloneDX" and fmt.spec_version == "1.5") or (
        fmt.type == "SPDX" and fmt.spec_version in ("2.2", "2.3", "3.0.0")
    )
    return TRANSITION_NOTE if older else None


def _base(fmt: Format) -> dict:
    return {
        "ok": True,
        "format": {"type": fmt.type, "specVersion": fmt.spec_version},
        "schemaValid": True,
        "schemaErrors": [],
        "notes": list(fmt.notes),
    }


def _empty_summary() -> dict:
    return {
        "tr": TR_NAME,
        "compliant": False,
        "componentsChecked": 0,
        "testsTotal": 0,
        "testsPassed": 0,
        "testsFailed": 0,
        "testsNotApplicable": 0,
        "tests": [],
    }


def schema_invalid_report(fmt: Format, schema: dict) -> dict:
    return {
        **_base(fmt),
        "schemaValid": False,
        "schemaErrors": [{"line": e["line"], "path": e["path"], "message": e["message"]} for e in schema["errors"]],
        "schemaErrorsTotal": schema["total"],
        "schemaErrorsTruncated": schema["truncated"],
        "summary": _empty_summary(),
        "failures": {},
    }


def test_report(fmt: Format, model: Model, outcomes, locator: Locator, max_failures: int | None) -> dict:
    report = _base(fmt)
    for note in (_non_conformance_note(fmt), _transition_note(fmt)):
        if note:
            report["notes"].append(note)
    report["notes"].append(LIMITATION_NOTE)

    tests = []
    failures = {}
    for test, results in outcomes:
        failed = [r for r in results if r.status == "failed"]
        applicable = sum(1 for r in results if r.status != "notApplicable")
        status = "failed" if failed else "passed" if applicable else "notApplicable"
        entry = {
            "id": test.id,
            "tr": test.tr,
            "title": test.title,
            "category": test.category,
            "scope": test.scope,
            "status": status,
            "passed": status != "failed",
        }
        if test.scope == "component":
            entry.update(
                checked=applicable,
                succeeded=applicable - len(failed),
                failed=len(failed),
                notApplicable=len(results) - applicable,
            )
        tests.append(entry)

        if failed:
            limit = len(failed) if max_failures is None else max_failures
            items = []
            for r in failed[:limit]:
                path = r.finding.path if r.finding.path is not None else r.subject.path
                if test.scope == "document":
                    items.append({"component": "(SBOM)", "ref": None, "line": locator.line(path), "message": r.finding.message})
                else:
                    items.append(
                        {
                            "component": _display_name(r.subject),
                            "ref": r.subject.ref,
                            "line": locator.line(path),
                            "message": r.finding.message,
                        }
                    )
            failures[test.id] = {"total": len(failed), "truncated": len(failed) > limit, "items": items}

    def count(s):
        return sum(1 for t in tests if t["status"] == s)

    report["summary"] = {
        "tr": TR_NAME,
        "compliant": count("failed") == 0,
        "componentsChecked": len(model.components),
        "testsTotal": len(tests),
        "testsPassed": count("passed"),
        "testsFailed": count("failed"),
        "testsNotApplicable": count("notApplicable"),
        "tests": tests,
    }
    report["failures"] = failures
    return report
