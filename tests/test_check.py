"""Library API as used by the AWS Lambda and the CLI: status codes, limits, logging hook."""

import json

import pytest
from conftest import FIXTURES, check, dump, fixture, line_of

from ts_sbom_checker import __version__, check_sbom, preload
from ts_sbom_checker.tr03183 import TESTS

FIXTURE_BYTES = (FIXTURES / "cdx-1.6-compliant.json").read_bytes()


class StepLog:
    def __init__(self):
        self.steps = []

    def step(self, description):
        self.steps.append(description)


def test_version_is_set():
    assert __version__ and __version__ != "0.0.0+unknown"


def test_preload_builds_all_validators():
    preload()  # must not raise


def test_accepts_bytes_and_text():
    assert check_sbom(FIXTURE_BYTES)[0] == 200
    assert check_sbom(FIXTURE_BYTES.decode())[1]["summary"]["compliant"] is True


def test_accepts_utf8_bom_in_bytes():
    status, result = check_sbom(b"\xef\xbb\xbf" + FIXTURE_BYTES)
    assert status == 200
    assert result["summary"]["compliant"] is True


@pytest.mark.parametrize("empty", [None, b"", ""])
def test_empty_input(empty):
    status, result = check_sbom(empty)
    assert (status, result["ok"], result["error"]) == (400, False, "empty_body")


def test_too_large():
    status, result = check_sbom(FIXTURE_BYTES, max_bytes=100)
    assert status == 413
    assert result == {"ok": False, "error": "too_large", "maxBytes": 100, "actualBytes": len(FIXTURE_BYTES)}


def test_size_limit_counts_utf8_bytes_of_text():
    text = '{"a": "' + "ä" * 60 + '"}'
    assert check_sbom(text, max_bytes=100)[0] == 413
    assert check_sbom(text, max_bytes=200)[0] == 400  # unknown_format, but not too large


def test_exact_size_is_accepted():
    assert check_sbom(FIXTURE_BYTES, max_bytes=len(FIXTURE_BYTES))[0] == 200


def test_invalid_json_with_line():
    status, result = check_sbom('{\n  "bomFormat": "CycloneDX",\n  oops\n}')
    assert (status, result["error"], result["line"]) == (400, "invalid_json", 3)


def test_invalid_utf8_with_line():
    status, result = check_sbom(b'{\n"a": "\xff"}')
    assert (status, result["error"], result["line"]) == (400, "invalid_json", 2)
    assert "UTF-8" in result["message"]


def test_unknown_format_and_version():
    assert check_sbom('{"hello": "world"}')[1]["error"] == "unknown_format"
    assert check_sbom('{"bomFormat": "CycloneDX", "specVersion": "1.4"}')[1]["error"] == "unsupported_version"


def test_unlimited_failures_and_schema_errors(cdx):
    for c in [cdx["metadata"]["component"], *cdx["components"]]:
        del c["version"]
    _, result = check(cdx, max_failures=None, max_schema_errors=None)
    assert result["failures"]["component-version"]["total"] == 3
    assert result["failures"]["component-version"]["truncated"] is False


def test_logs_every_step():
    log = StepLog()
    check_sbom(FIXTURE_BYTES, log=log)
    assert log.steps == [
        "parsing JSON",
        "detecting format",
        "validating against schema cyclonedx-1.6",
        "building component model",
        "running TR-03183-2 tests on 3 components",
        "compiling report",
    ]


def test_log_shows_step_of_input_error():
    log = StepLog()
    check_sbom("{oops", log=log)
    assert log.steps == ["parsing JSON"]


def test_report_is_json_serialisable_and_has_the_lambda_shape():
    _, result = check_sbom(FIXTURE_BYTES)
    assert json.loads(json.dumps(result)) == result
    assert list(result) == ["ok", "format", "schemaValid", "schemaErrors", "notes", "summary", "failures"]
    test = result["summary"]["tests"][-1]
    assert set(test) == {
        "id",
        "tr",
        "title",
        "category",
        "scope",
        "status",
        "passed",
        "checked",
        "succeeded",
        "failed",
        "notApplicable",
    }


def test_schema_invalid_report_shape(cdx):
    cdx["components"][0]["version"] = 3
    _, result = check(cdx)
    assert {"schemaErrorsTotal", "schemaErrorsTruncated"} <= set(result)
    assert result["summary"]["testsTotal"] == 0


# ---- every TR test has a targeted failure case, reporting component and line ------------------

CDX = "cdx-1.6-compliant.json"
SPDX2 = "spdx-2.3.json"
SPDX3 = "spdx-3.0.1-compliant.json"


def _util(doc):
    return doc["components"][0]


def _cdx_prop(name, value):
    def mutate(doc):
        comp = _util(doc)
        comp["properties"] = [p for p in comp["properties"] if p["name"] != name] + [{"name": name, "value": value}]

    return mutate


# test id -> (fixture, mutation, expected component, needle on the expected line or None for "component start")
FAILURE_CASES = {
    "format-version": (
        SPDX3,
        lambda d: d.update({"@context": "https://spdx.org/rdf/3.0.0/spdx-context.jsonld"}),
        "(SBOM)",
        '"@context"',
    ),
    "sbom-creator": (CDX, lambda d: d["metadata"].pop("manufacturer"), "(SBOM)", '"metadata"'),
    "sbom-timestamp": (CDX, lambda d: d["metadata"].pop("timestamp"), "(SBOM)", '"metadata"'),
    "primary-component": (CDX, lambda d: d["metadata"].pop("component"), "(SBOM)", '"metadata"'),
    "no-vulnerabilities": (CDX, lambda d: d.update(vulnerabilities=[{"id": "CVE-1"}]), "(SBOM)", '"vulnerabilities"'),
    "sbom-uri": (SPDX2, lambda d: d.update(documentNamespace="https://x.example/a#b"), "(SBOM)", "https://x.example/a#b"),
    "component-creator": (CDX, lambda d: _util(d).pop("manufacturer"), "util", None),
    "component-name": (CDX, lambda d: _util(d).update(name=""), "pkg:maven/org.example/util@1.4.2", '"name": ""'),
    "component-version": (CDX, lambda d: _util(d).update(version=""), "util", '"version": ""'),
    "component-filename": (CDX, _cdx_prop("bsi:component:filename", "a/b.jar"), "util", "a/b.jar"),
    "component-dependencies": (CDX, lambda d: d["dependencies"].pop(1), "util", None),
    "dependency-completeness": (
        CDX,
        lambda d: d["compositions"][0]["dependencies"].remove("pkg:maven/org.example/util@1.4.2"),
        "util",
        None,
    ),
    "dependency-reachable": (CDX, lambda d: d["dependencies"][0].update(dependsOn=["runtime"]), "util", None),
    "component-distribution-licence": (CDX, lambda d: _util(d).update(licenses=[]), "util", None),
    "component-hash-sha512": (
        CDX,
        lambda d: _util(d)["externalReferences"][0]["hashes"][0].update(content="b" * 64),
        "util",
        '"' + "b" * 64 + '"',
    ),
    "component-executable": (CDX, _cdx_prop("bsi:component:executable", "yes"), "util", '"yes"'),
    "component-archive": (CDX, _cdx_prop("bsi:component:archive", "zip"), "util", '"zip"'),
    "component-structured": (CDX, _cdx_prop("bsi:component:structured", "maybe"), "util", '"maybe"'),
    "licence-identifiers": (CDX, _cdx_prop("bsi:component:effectiveLicence", "Apache 2"), "util", '"Apache 2"'),
    "component-source-uri": (
        CDX,
        lambda d: d["metadata"]["component"]["externalReferences"][1].update(url="src/x"),
        "acme-app",
        '"src/x"',
    ),
    "component-download-uri": (CDX, lambda d: _util(d)["externalReferences"][0].update(url="x.jar"), "util", '"x.jar"'),
    "component-identifiers": (CDX, lambda d: _util(d).update(purl="maven/x"), "util", '"maven/x"'),
    "component-original-licences": (
        CDX,
        lambda d: _util(d)["licenses"][1].update(license={"name": "Custom", "acknowledgement": "declared"}),
        "util",
        '"Custom"',
    ),
    "component-bom-reference": (
        CDX,
        lambda d: d["components"][1]["externalReferences"][0].update(url="x.json"),
        "runtime",
        '"x.json"',
    ),
}


def test_every_tr_test_has_a_failure_case():
    assert set(FAILURE_CASES) == {t.id for t in TESTS}


@pytest.mark.parametrize("test_id", list(FAILURE_CASES))
def test_failure_case_names_component_and_line(test_id):
    name, mutate, component, needle = FAILURE_CASES[test_id]
    doc = fixture(name)
    mutate(doc)
    status, result = check(doc)
    assert status == 200
    assert result["schemaValid"] is True, result["schemaErrors"]
    assert test_id in result["failures"]
    item = result["failures"][test_id]["items"][0]
    assert item["component"] == component
    if needle is None:  # missing field: line where the component object starts
        lines = dump(doc).split("\n")
        assert lines[item["line"] - 1].strip() == "{"
    else:
        assert item["line"] == line_of(doc, needle)
