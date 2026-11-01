import pytest

from ts_sbom_checker.detect import UnsupportedSbomError, detect_format
from ts_sbom_checker.parse import InvalidJsonError, parse_sbom, pointer_to_path

# ---- detect ------------------------------------------------------------------------------------


@pytest.mark.parametrize("version", ["1.5", "1.6", "1.7"])
def test_detects_cyclonedx(version):
    f = detect_format({"bomFormat": "CycloneDX", "specVersion": version})
    assert (f.type, f.spec_version, f.schema_key, f.notes) == ("CycloneDX", version, f"cyclonedx-{version}", ())


def test_rejects_cyclonedx_1_4():
    with pytest.raises(UnsupportedSbomError) as exc:
        detect_format({"bomFormat": "CycloneDX", "specVersion": "1.4"})
    assert exc.value.error == "unsupported_version"


def test_detects_spdx2_and_maps_2_1_to_2_2_schema():
    assert detect_format({"spdxVersion": "SPDX-2.3"}).schema_key == "spdx-2.3"
    assert detect_format({"spdxVersion": "SPDX-2.2"}).schema_key == "spdx-2.2"
    f = detect_format({"spdxVersion": "SPDX-2.1"})
    assert (f.spec_version, f.schema_key, len(f.notes)) == ("2.1", "spdx-2.2", 1)


def test_detects_spdx3_via_context():
    assert detect_format({"@context": "https://spdx.org/rdf/3.0.1/spdx-context.jsonld"}).spec_version == "3.0.1"
    f = detect_format({"@context": ["https://spdx.org/rdf/3.0.0/spdx-context.jsonld"]})
    assert f.spec_version == "3.0.0"
    assert f.context_override is True


def test_rejects_unknown_documents():
    with pytest.raises(UnsupportedSbomError) as exc:
        detect_format({"foo": 1})
    assert exc.value.error == "unknown_format"
    with pytest.raises(UnsupportedSbomError) as exc:
        detect_format({"spdxVersion": "SPDX-2.0"})
    assert exc.value.error == "unsupported_version"
    with pytest.raises(UnsupportedSbomError) as exc:
        detect_format({"@context": "https://spdx.org/rdf/3.0.9/spdx-context.jsonld"})
    assert exc.value.error == "unsupported_version"


# ---- parse -------------------------------------------------------------------------------------


def test_returns_data_and_locator_with_1_based_lines():
    data, locator = parse_sbom('{\n  "a": {\n    "b": [1,\n 2]\n  }\n}')
    assert data == {"a": {"b": [1, 2]}}
    assert locator.line([]) == 1
    assert locator.line(["a"]) == 2
    assert locator.line(["a", "b", 1]) == 4


def test_falls_back_to_nearest_existing_ancestor():
    _, locator = parse_sbom('{\n  "a": {\n    "x": 1\n  }\n}')
    assert locator.line(["a", "missing", "deeper"]) == 2


def test_locator_handles_escapes_empty_containers_and_nesting():
    text = '{\n "k\\"ey": [],\n "o": {},\n "n": [[1, {"x": "a,b:}"}], 2],\n "z": "\\u00e4"\n}'
    _, locator = parse_sbom(text)
    assert locator.line(['k"ey']) == 2
    assert locator.line(["o"]) == 3
    assert locator.line(["n", 0, 1, "x"]) == 4
    assert locator.line(["n", 1]) == 4
    assert locator.line(["z"]) == 5


def test_strips_utf8_bom():
    assert parse_sbom('\ufeff{"a":1}')[0] == {"a": 1}


def test_reports_line_of_syntax_error():
    with pytest.raises(InvalidJsonError) as exc:
        parse_sbom('{\n  "a": 1,\n  "b": \n}')
    assert exc.value.line == 4


@pytest.mark.parametrize("text", ['{"a": 1,}', '{"a": 1 // c\n}', "[1, 2]", '{"a": NaN}', '{\n"a": -Infinity}'])
def test_rejects_non_strict_json(text):
    with pytest.raises(InvalidJsonError):
        parse_sbom(text)


def test_reports_line_of_non_finite_number():
    with pytest.raises(InvalidJsonError) as exc:
        parse_sbom('{\n"a": 1,\n"b": NaN}')
    assert exc.value.line == 3


def test_pointer_to_path():
    assert pointer_to_path("") == []
    assert pointer_to_path("/components/3/name") == ["components", 3, "name"]
    assert pointer_to_path("/a~1b/c~0d") == ["a/b", "c~d"]
