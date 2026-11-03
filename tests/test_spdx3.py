import pytest
from conftest import check, failed_tests, failures_of, fixture, line_of, only_failure, test_entry

ID = "https://acme.example/spdx/"


def el(doc, eid):
    return next(e for e in doc["@graph"] if e.get("spdxId") == ID + eid or e.get("@id") == eid)


def without(doc, eid):
    doc["@graph"] = [e for e in doc["@graph"] if e.get("spdxId") != ID + eid]


def test_compliant_passes_all_tests(spdx3):
    status, result = check(spdx3)
    assert status == 200
    assert result["format"] == {"type": "SPDX", "specVersion": "3.0.1"}
    assert result["schemaValid"] is True
    assert result["summary"]["compliant"] is True
    assert result["summary"]["componentsChecked"] == 2


def test_sbom_creator_agent_without_identifier(spdx3):
    del el(spdx3, "Agent/acme")["externalIdentifier"]
    _, result = check(spdx3)
    # the same agent is also the creator of the primary component
    assert failed_tests(result) == ["sbom-creator", "component-creator"]


def test_component_version_missing_reports_object_start(spdx3):
    del el(spdx3, "Package/util")["software_packageVersion"]
    item = only_failure(spdx3, "component-version")
    assert item["component"] == "util"
    assert item["ref"] == f"{ID}Package/util"
    # missing field -> line where the package object starts ("{" before "type")
    assert item["line"] == line_of(spdx3, f'"spdxId": "{ID}Package/util"') - 2


def test_missing_distribution_file_fails_filename_hash_and_properties(spdx3):
    without(spdx3, "Rel/2")
    _, result = check(spdx3)
    assert failed_tests(result) == [
        "component-filename",
        "component-hash-sha512",
        "component-executable",
        "component-archive",
        "component-structured",
    ]


def test_component_structured_neither_container_nor_firmware(spdx3):
    el(spdx3, "File/util-1.4.2.jar")["software_additionalPurpose"] = ["executable", "archive"]
    only_failure(spdx3, "component-structured")


def test_component_filename_with_path(spdx3):
    el(spdx3, "File/util-1.4.2.jar")["name"] = "lib/util-1.4.2.jar"
    item = only_failure(spdx3, "component-filename")
    assert item["line"] == line_of(spdx3, '"lib/util-1.4.2.jar"')


def test_component_hash_sha256_only(spdx3):
    el(spdx3, "File/util-1.4.2.jar")["verifiedUsing"] = [{"type": "Hash", "algorithm": "sha256", "hashValue": "a" * 64}]
    only_failure(spdx3, "component-hash-sha512")


def test_dependency_completeness_missing(spdx3):
    del el(spdx3, "Rel/4")["completeness"]
    assert only_failure(spdx3, "dependency-completeness")["component"] == "util"


def test_component_dependencies_leaf_without_none_element(spdx3):
    without(spdx3, "Rel/4")
    _, result = check(spdx3)
    assert failed_tests(result) == ["component-dependencies", "dependency-completeness"]


def test_licence_identifiers_invalid_expression(spdx3):
    el(spdx3, "License/apache")["simplelicensing_licenseExpression"] = "Apache 2.0"
    item = only_failure(spdx3, "licence-identifiers")
    assert item["component"] == "acme-app"
    assert item["line"] == line_of(spdx3, '"Apache 2.0"')


def test_distribution_licence_missing(spdx3):
    for rel in spdx3["@graph"]:
        if rel.get("relationshipType") == "hasConcludedLicense" and rel.get("from") == f"{ID}Package/util":
            rel["relationshipType"] = "hasDeclaredLicense"
    _, result = check(spdx3)
    assert "component-distribution-licence" in failed_tests(result)
    assert failures_of(result, "component-distribution-licence")[0]["component"] == "util"


def test_no_vulnerabilities(spdx3):
    spdx3["@graph"].append({"type": "security_Vulnerability", "spdxId": f"{ID}Vuln/1", "creationInfo": "_:creationinfo"})
    only_failure(spdx3, "no-vulnerabilities")


def test_referenced_component_described_by_another_sbom(spdx3):
    spdx3["@graph"] += [
        {
            "type": "software_Sbom",
            "spdxId": f"{ID}Sbom/util",
            "creationInfo": "_:creationinfo",
            "externalRef": [
                {"type": "ExternalRef", "externalRefType": "buildMeta", "locator": ["https://example.org/sbom/util.spdx.json"]}
            ],
        },
        {
            "type": "Relationship",
            "spdxId": f"{ID}Rel/8",
            "creationInfo": "_:creationinfo",
            "from": f"{ID}Sbom/util",
            "relationshipType": "describes",
            "to": [f"{ID}Package/util"],
            "completeness": "complete",
        },
    ]
    _, result = check(spdx3)
    assert result["summary"]["compliant"] is True
    assert test_entry(result, "component-bom-reference")["checked"] == 1
    assert test_entry(result, "component-hash-sha512")["notApplicable"] == 1


def test_component_bom_reference_invalid(spdx3):
    spdx3["@graph"] += [
        {
            "type": "software_Sbom",
            "spdxId": f"{ID}Sbom/util",
            "creationInfo": "_:creationinfo",
            "externalRef": [{"type": "ExternalRef", "externalRefType": "buildMeta", "locator": ["sbom/util.json"]}],
        },
        {
            "type": "Relationship",
            "spdxId": f"{ID}Rel/8",
            "creationInfo": "_:creationinfo",
            "from": f"{ID}Sbom/util",
            "relationshipType": "describes",
            "to": [f"{ID}Package/util"],
            "completeness": "complete",
        },
    ]
    item = only_failure(spdx3, "component-bom-reference")
    assert item["component"] == "util"
    assert item["line"] == line_of(spdx3, '"sbom/util.json"')


def test_spdx_3_0_0_uses_3_0_1_schema_and_fails_format_version(spdx3):
    spdx3["@context"] = "https://spdx.org/rdf/3.0.0/spdx-context.jsonld"
    _, result = check(spdx3)
    assert result["schemaValid"] is True, result["schemaErrors"]
    assert failed_tests(result) == ["format-version"]
    assert any("3.0.0" in n for n in result["notes"])
    assert any("TR section 7" in n for n in result["notes"])


def test_sbom_uri_is_the_spdx_id_of_the_software_sbom(spdx3):
    """TR table 10: the SBOM-URI is the spdxId of the software_Sbom, not of the SpdxDocument."""
    import json

    sbom_id = f"{ID}Sbom/acme-app-2.1.0"
    bad_id = f"{ID}Sbom/äpp-2.1.0"  # valid IRI for the schema, but not an ASCII URI (TR 8.1.10)
    doc = json.loads(json.dumps(spdx3).replace(sbom_id, bad_id))
    item = only_failure(doc, "sbom-uri")
    assert "non-ASCII" in item["message"]
    assert item["line"] == line_of(doc, f'"spdxId": "{bad_id}"')


def test_schema_error_names_the_offending_element_not_every_one_of_branch(spdx3):
    el(spdx3, "File/util-1.4.2.jar")["software_downloadLocation"] = "https://example.org/util.jar"
    _, result = check(spdx3)
    assert result["schemaValid"] is False
    assert len(result["schemaErrors"]) == 1
    assert "software_downloadLocation" in result["schemaErrors"][0]["message"]


@pytest.mark.parametrize("bad_type", ["software_Package", "Relationship"])
def test_schema_error_inside_element(spdx3, bad_type):
    target = next(e for e in spdx3["@graph"] if e["type"] == bad_type)
    target["name" if bad_type == "software_Package" else "relationshipType"] = 42
    _, result = check(spdx3)
    assert result["schemaValid"] is False
    assert all(e["path"].startswith("/@graph/") for e in result["schemaErrors"])


def test_tr_spelling_of_external_identifiers_is_accepted():
    """TR 8.2 writes "externalIdentifiers"; the model accepts it (the schema would not, so the model is tested)."""
    from ts_sbom_checker.detect import detect_format
    from ts_sbom_checker.model import build_model

    doc = fixture("spdx-3.0.1-compliant.json")
    agent = el(doc, "Agent/acme")
    agent["externalIdentifiers"] = agent.pop("externalIdentifier")
    model = build_model(doc, detect_format(doc))
    assert model.document.creators
    assert model.document.creators[0].path[-3] == "externalIdentifiers"
