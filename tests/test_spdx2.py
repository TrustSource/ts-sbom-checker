import re

import pytest
from conftest import check, failed_tests, failures_of, fixture, line_of, test_entry


@pytest.fixture(scope="module")
def spdx23():
    doc = fixture("spdx-2.3.json")
    return doc, *check(doc)


def test_schema_valid_never_compliant_with_note(spdx23):
    _, status, result = spdx23
    assert status == 200
    assert result["schemaValid"] is True
    assert result["summary"]["compliant"] is False
    assert any(re.search(r"SPDX 2\.x SBOM therefore cannot be TR-compliant", n) for n in result["notes"])


def test_expected_failures(spdx23):
    _, _, result = spdx23
    assert failed_tests(result) == [
        "format-version",
        "component-creator",
        "component-filename",
        "dependency-completeness",
        "component-distribution-licence",
        "component-hash-sha512",
        "component-executable",
        "component-archive",
        "component-structured",
    ]


def test_bsi_properties_not_expressible_for_every_package(spdx23):
    _, _, result = spdx23
    assert test_entry(result, "component-executable")["failed"] == 2
    assert re.search(r"not expressible in SPDX 2\.x", failures_of(result, "component-executable")[0]["message"])


def test_names_component_and_line(spdx23):
    doc, _, result = spdx23
    [item] = failures_of(result, "component-filename")
    assert item["component"] == "util"
    assert item["ref"] == "SPDXRef-util"
    assert item["line"] == line_of(doc, "lib/util-1.4.2.jar")


def test_none_is_an_empty_complete_dependency_list(spdx23):
    _, _, result = spdx23
    assert [i["component"] for i in failures_of(result, "dependency-completeness")] == ["acme-app"]


def test_source_uri_not_applicable(spdx23):
    _, _, result = spdx23
    assert test_entry(result, "component-source-uri")["status"] == "notApplicable"


def test_format_version_points_at_spdx_version(spdx23):
    doc, _, result = spdx23
    assert failures_of(result, "format-version")[0]["line"] == line_of(doc, '"spdxVersion"')


def test_sbom_uri_with_fragment(spdx2):
    spdx2["documentNamespace"] = "https://acme.example/spdx/acme-app#1"
    _, result = check(spdx2)
    assert "sbom-uri" in failed_tests(result)
    assert "#" in failures_of(result, "sbom-uri")[0]["message"]


def test_inverse_relationship_counts_as_dependency(spdx2):
    rels = spdx2["relationships"]
    for r in rels:
        if r["relationshipType"] == "DEPENDS_ON" and r["spdxElementId"] == "SPDXRef-acme-app":
            r["relationshipType"] = "DEPENDENCY_OF"
            r["spdxElementId"], r["relatedSpdxElement"] = r["relatedSpdxElement"], r["spdxElementId"]
    _, result = check(spdx2)
    assert "component-dependencies" not in failed_tests(result)
    assert "dependency-reachable" not in failed_tests(result)


def test_spdx_2_1_uses_2_2_schema_with_note(spdx2):
    spdx2["spdxVersion"] = "SPDX-2.1"
    spdx2["packages"][0]["externalRefs"][0]["referenceCategory"] = "PACKAGE_MANAGER"
    _, result = check(spdx2)
    assert result["schemaValid"] is True, result["schemaErrors"]
    assert result["format"] == {"type": "SPDX", "specVersion": "2.1"}
    assert any("SPDX 2.2 schema" in n for n in result["notes"])


def test_spdx_2_2_rejects_2_3_spelling(spdx2):
    spdx2["spdxVersion"] = "SPDX-2.2"
    _, result = check(spdx2)
    assert result["schemaValid"] is False
    assert "referenceCategory" in result["schemaErrors"][0]["path"]


def test_component_creator_with_originator_email(spdx2):
    pkg = spdx2["packages"][1]
    pkg["originator"] = "Organization: Example (dev@example.org)"
    _, result = check(spdx2)
    assert "component-creator" not in failed_tests(result)


def test_licence_identifiers_invalid(spdx2):
    spdx2["packages"][0]["licenseConcluded"] = "Apache 2"
    _, result = check(spdx2)
    assert "licence-identifiers" in failed_tests(result)
    assert failures_of(result, "licence-identifiers")[0]["line"] == line_of(spdx2, '"Apache 2"')
