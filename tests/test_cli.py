import json

import pytest
from click.testing import CliRunner
from conftest import FIXTURES, dump, fixture

from ts_sbom_checker import __version__
from ts_sbom_checker.cli import main

CDX = str(FIXTURES / "cdx-1.6-compliant.json")
SPDX2 = str(FIXTURES / "spdx-2.3.json")
SPDX3 = str(FIXTURES / "spdx-3.0.1-compliant.json")


@pytest.fixture
def run():
    runner = CliRunner()

    def invoke(*args, stdin=None):
        return runner.invoke(main, list(args), input=stdin, catch_exceptions=False)

    return invoke


def test_version(run):
    res = run("--version")
    assert res.exit_code == 0
    assert __version__ in res.output


def test_requires_a_file(run):
    assert run().exit_code == 2


def test_compliant_file_exits_0(run):
    res = run(CDX)
    assert res.exit_code == 0
    assert "COMPLIANT with BSI TR-03183-2 v2.1.0" in res.output
    assert "not an official tool of the BSI" in res.output
    assert f"ts-sbom-checker {__version__}" in res.output


def test_non_compliant_file_exits_1_and_shows_only_the_table(run):
    res = run(SPDX2)
    assert res.exit_code == 1
    assert "NOT COMPLIANT" in res.output
    lines = res.output.splitlines()
    header = next(line for line in lines if "Checked / OK" in line)
    assert "Failing lines" in header
    row = next(line for line in lines if " component-filename " in line)
    assert row.split()[-6:] == ["2", "/", "1", "50", "%", "33"]
    assert header.index("/") == row.index("/")
    assert any(" component-source-uri " in line and line.rstrip().endswith("n/a") for line in lines)
    assert "Findings" not in res.output
    assert "--details" in res.output


def test_details_lists_findings_with_components_and_lines(run):
    res = run("--details", SPDX2)
    assert "component-filename (TR 5.2.2): 1 of 2 components" in res.output
    assert "util (33)" in res.output


def test_findings_are_grouped_by_message(run, tmp_path):
    doc = fixture("cdx-1.6-compliant.json")
    components = [doc["metadata"]["component"], *doc["components"]]
    for c in components:
        del c["version"]
    for c in doc["components"]:  # the bom-ref of each component appears in its message
        doc["dependencies"] = [d for d in doc["dependencies"] if d["ref"] != c["bom-ref"]]
    path = tmp_path / "in.json"
    path.write_text(dump(doc))
    out = run("--details", str(path)).output
    assert f"{len(components)}× " in out or f"{len(components)}x " in out
    version_row = next(line for line in out.splitlines() if " component-version " in line)
    assert version_row.endswith("all components")
    deps = out[out.index("component-dependencies (TR") :]
    assert 'no entry with ref "<bom-ref>"' in deps
    assert deps.count('no entry with ref "') == 1


def test_wrapping_keeps_names_and_lines_together():
    from ts_sbom_checker.textreport import _wrap

    text = ", ".join(f"charset-normalizer\u00a0({n})" for n in range(1000, 1010))
    lines = _wrap(text, 40, "  ")
    assert all("charset-normalizer (" in line for line in lines)
    assert all(line.count("(") == line.count(")") for line in lines)


@pytest.mark.parametrize(("encoding", "mark"), [("utf-8", "✗"), ("ascii", "x")])
def test_marks_follow_the_output_encoding(encoding, mark):
    from ts_sbom_checker.textreport import glyphs

    assert glyphs(encoding)["fail"] == mark
    assert glyphs(None)["fail"] == "x"


def test_long_lists_are_shortened_to_the_width():
    from ts_sbom_checker.textreport import _ASCII, _ellipsis

    parts = [str(n) for n in range(100, 140)]
    text = _ellipsis(parts, 30, 0, _ASCII)
    assert len(text) <= 30
    assert text.endswith(f"(+{40 - text.count(',')})")
    assert _ellipsis(["a", "b"], 30, 0, _ASCII) == "a, b"
    assert _ellipsis(["a"], 30, 5, _ASCII) == "a, ... (+5)"


@pytest.mark.parametrize(("fail_on", "code"), [("non-compliant", 1), ("schema", 0), ("never", 0)])
def test_fail_on_non_compliant(run, fail_on, code):
    assert run("--fail-on", fail_on, SPDX2).exit_code == code


@pytest.mark.parametrize(("fail_on", "code"), [("non-compliant", 1), ("schema", 1), ("never", 0)])
def test_fail_on_schema_invalid(run, tmp_path, fail_on, code):
    doc = fixture("cdx-1.6-compliant.json")
    doc["components"][0]["version"] = 3
    path = tmp_path / "bad.json"
    path.write_text(dump(doc))
    res = run("--fail-on", fail_on, str(path))
    assert res.exit_code == code
    assert "SCHEMA INVALID" in res.output


def test_json_output_single_file_is_the_report(run):
    res = run("--format", "json", SPDX3)
    report = json.loads(res.output)
    assert report["ok"] is True
    assert report["summary"]["compliant"] is True
    assert "file" not in report


def test_json_output_several_files_is_a_list(run):
    res = run("--format", "json", CDX, SPDX2)
    reports = json.loads(res.output)
    assert [(r["file"], r["summary"]["compliant"]) for r in reports] == [(CDX, True), (SPDX2, False)]
    assert res.exit_code == 1


def test_stdin(run):
    res = run("--format", "json", "-", stdin=(FIXTURES / "cdx-1.6-compliant.json").read_bytes())
    assert res.exit_code == 0
    assert json.loads(res.output)["format"]["type"] == "CycloneDX"


@pytest.mark.parametrize(
    ("content", "error"),
    [
        (b"", "empty_body"),
        (b"{oops", "invalid_json"),
        (b'{"a": 1}', "unknown_format"),
        (b'{"bomFormat": "CycloneDX", "specVersion": "1.2"}', "unsupported_version"),
        (b'{"a": "\xff"}', "invalid_json"),
    ],
)
def test_input_errors_exit_2(run, tmp_path, content, error):
    path = tmp_path / "in.json"
    path.write_bytes(content)
    res = run("--format", "json", str(path))
    assert res.exit_code == 2
    assert json.loads(res.output)["error"] == error


def test_missing_file_exits_2(run, tmp_path):
    res = run(str(tmp_path / "nope.json"))
    assert res.exit_code == 2
    assert "unreadable_file" in res.output


def test_input_error_wins_over_failures(run, tmp_path):
    path = tmp_path / "in.json"
    path.write_text("{}")
    assert run(SPDX2, str(path)).exit_code == 2


def test_max_bytes(run):
    res = run("--max-bytes", "100", CDX)
    assert res.exit_code == 2
    assert "too_large" in res.output


def test_limits_default_to_unlimited_and_can_be_set(run, tmp_path):
    doc = fixture("cdx-1.6-compliant.json")
    for c in [doc["metadata"]["component"], *doc["components"]]:
        del c["version"]
    path = tmp_path / "in.json"
    path.write_text(dump(doc))
    unlimited = json.loads(run("--format", "json", str(path)).output)
    assert len(unlimited["failures"]["component-version"]["items"]) == 3
    limited = json.loads(run("--format", "json", "--max-failures", "1", str(path)).output)
    assert limited["failures"]["component-version"]["truncated"] is True


def test_output_file(run, tmp_path):
    out = tmp_path / "report.json"
    res = run("--format", "json", "-o", str(out), CDX)
    assert res.exit_code == 0
    assert res.output == ""
    assert json.loads(out.read_text())["summary"]["compliant"] is True


def test_text_output_to_file_has_no_colour_codes(run, tmp_path):
    out = tmp_path / "report.txt"
    run("-o", str(out), SPDX2)
    assert "\x1b[" not in out.read_text()
