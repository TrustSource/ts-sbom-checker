import copy
import re

import pytest
from conftest import check, failed_tests, failures_of, fixture, line_of, only_failure, test_entry

from ts_sbom_checker.tr03183 import TESTS

UTIL = 0  # index of "util" in components[]


def with_util(mutate):
    doc = fixture("cdx-1.6-compliant.json")
    mutate(doc["components"][UTIL], doc)
    return doc


def set_prop(comp, name, value=None):
    comp["properties"] = [p for p in comp["properties"] if p["name"] != name]
    if value is not None:
        comp["properties"].append({"name": name, "value": value})


# ---- compliant document ------------------------------------------------------------------------


@pytest.fixture(scope="module")
def compliant():
    return check(fixture("cdx-1.6-compliant.json"))


def test_compliant_passes_all_tests(compliant):
    status, result = compliant
    assert status == 200
    assert result["schemaValid"] is True
    assert result["summary"]["compliant"] is True
    assert result["failures"] == {}
    assert result["summary"]["testsTotal"] == len(TESTS)
    assert result["summary"]["testsFailed"] == 0
    assert result["summary"]["componentsChecked"] == 3


def test_referenced_component_runs_only_creator_name_version_reachability_bom_reference(compliant):
    _, result = compliant
    assert test_entry(result, "component-hash-sha512")["notApplicable"] == 1
    assert test_entry(result, "component-creator")["checked"] == 3
    assert test_entry(result, "dependency-reachable")["checked"] == 3
    assert test_entry(result, "component-bom-reference")["checked"] == 1


def test_additional_tests_skip_absent_fields(compliant):
    _, result = compliant
    src = test_entry(result, "component-source-uri")
    assert (src["checked"], src["notApplicable"], src["status"]) == (1, 2, "passed")


def test_summary_counts(compliant):
    _, result = compliant
    s = result["summary"]
    assert s["testsPassed"] + s["testsFailed"] + s["testsNotApplicable"] == s["testsTotal"]
    assert s["tr"] == "BSI TR-03183-2 v2.1.0"


# ---- one test per defect, with component and line ----------------------------------------------


def test_component_version_missing_reports_component_start_line():
    doc = with_util(lambda c, d: c.pop("version"))
    item = only_failure(doc, "component-version")
    assert item["component"] == "util"
    assert item["ref"] == "pkg:maven/org.example/util@1.4.2"
    assert item["line"] == line_of(doc, '"components": [') + 1


def test_component_name_empty_reports_line_of_field():
    doc = with_util(lambda c, d: c.update(name=" "))
    item = only_failure(doc, "component-name")
    assert item["line"] == line_of(doc, '"name": " "')
    assert item["component"] == "pkg:maven/org.example/util@1.4.2"


def test_component_creator_supplier_only_with_hint():
    def mutate(c, d):
        c["supplier"] = c.pop("manufacturer")

    item = only_failure(with_util(mutate), "component-creator")
    assert "supplier" in item["message"]


def test_component_creator_invalid_email():
    # passes the schema's lenient idn-email format, but has no domain part with a dot
    doc = with_util(lambda c, d: c["manufacturer"]["contact"][0].update(email="dev@localhost"))
    item = only_failure(doc, "component-creator")
    assert item["line"] == line_of(doc, "dev@localhost")


def test_component_filename_path_instead_of_filename():
    doc = with_util(lambda c, d: set_prop(c, "bsi:component:filename", "lib/util-1.4.2.jar"))
    item = only_failure(doc, "component-filename")
    assert "contains a path" in item["message"]
    assert item["line"] == line_of(doc, "lib/util-1.4.2.jar")


def test_component_filename_duplicate_property():
    doc = with_util(lambda c, d: c["properties"].append({"name": "bsi:component:filename", "value": "x.jar"}))
    only_failure(doc, "component-filename")


def test_component_dependencies_no_entry():
    def mutate(c, d):
        d["dependencies"] = [x for x in d["dependencies"] if x["ref"] != c["bom-ref"]]

    only_failure(with_util(mutate), "component-dependencies")


def test_dependency_completeness_not_in_compositions():
    only_failure(with_util(lambda c, d: d["compositions"][0].update(dependencies=["acme-app"])), "dependency-completeness")


def test_dependency_completeness_aggregate_not_specified():
    doc = with_util(lambda c, d: d["compositions"][0].update(aggregate="not_specified"))
    _, result = check(doc)
    assert test_entry(result, "dependency-completeness")["failed"] == 2


def test_dependency_reachable_component_not_referenced_from_primary():
    only_failure(with_util(lambda c, d: d["dependencies"][0].update(dependsOn=["runtime"])), "dependency-reachable")


def test_distribution_licence_without_acknowledgement_with_hint():
    doc = with_util(lambda c, d: c.update(licenses=[{"license": {"id": "MIT"}}]))
    _, result = check(doc)
    assert failed_tests(result) == ["component-distribution-licence"]
    assert "acknowledgement" in failures_of(result, "component-distribution-licence")[0]["message"]


def test_hash_only_in_component_hashes_with_hint():
    def mutate(c, d):
        c["hashes"] = c["externalReferences"][0].pop("hashes")

    item = only_failure(with_util(mutate), "component-hash-sha512")
    assert "externalReferences[type=distribution]" in item["message"]


def test_hash_sha256_only():
    doc = with_util(lambda c, d: c["externalReferences"][0].update(hashes=[{"alg": "SHA-256", "content": "a" * 64}]))
    only_failure(doc, "component-hash-sha512")


BSI_PROPERTIES = [
    ("component-executable", "bsi:component:executable", "yes"),
    ("component-archive", "bsi:component:archive", "zip"),
    ("component-structured", "bsi:component:structured", "maybe"),
]


@pytest.mark.parametrize(("test_id", "name", "bad"), BSI_PROPERTIES)
def test_bsi_property_missing(test_id, name, bad):
    only_failure(with_util(lambda c, d: set_prop(c, name)), test_id)


@pytest.mark.parametrize(("test_id", "name", "bad"), BSI_PROPERTIES)
def test_bsi_property_invalid_value(test_id, name, bad):
    doc = with_util(lambda c, d: set_prop(c, name, bad))
    item = only_failure(doc, test_id)
    assert item["line"] == line_of(doc, f'"{bad}"')


def test_licence_identifiers_invalid_effective_licence():
    only_failure(with_util(lambda c, d: set_prop(c, "bsi:component:effectiveLicence", "Apache 2")), "licence-identifiers")


def test_licence_identifiers_name_only():
    def mutate(c, d):
        c["licenses"][0] = {"license": {"name": "MIT License", "acknowledgement": "concluded"}}

    item = only_failure(with_util(mutate), "licence-identifiers")
    assert "name only" in item["message"]


def test_licence_identifiers_invalid_expression_on_primary_component(cdx):
    cdx["metadata"]["component"]["licenses"][0]["expression"] = "Apache-2.0 WITH"
    assert only_failure(cdx, "licence-identifiers")["component"] == "acme-app"


def test_original_licences_invalid_declared_licence():
    def mutate(c, d):
        c["licenses"][1] = {"license": {"name": "Custom", "acknowledgement": "declared"}}

    only_failure(with_util(mutate), "component-original-licences")


def test_source_uri_non_ascii(cdx):
    cdx["metadata"]["component"]["externalReferences"][1]["url"] = "https://git.acme.example/äpp"
    only_failure(cdx, "component-source-uri")


def test_download_uri_relative():
    only_failure(with_util(lambda c, d: c["externalReferences"][0].update(url="util-1.4.2.jar")), "component-download-uri")


def test_identifiers_invalid_purl():
    only_failure(with_util(lambda c, d: c.update(purl="maven/org.example/util")), "component-identifiers")


def test_bom_reference_invalid_url(cdx):
    cdx["components"][1]["externalReferences"][0]["url"] = "sbom/runtime.json"
    assert only_failure(cdx, "component-bom-reference")["component"] == "runtime"


def test_referenced_component_requires_version(cdx):
    del cdx["components"][1]["version"]
    assert only_failure(cdx, "component-version")["component"] == "runtime"


# ---- document tests ----------------------------------------------------------------------------


def test_sbom_creator_missing_manufacturer_with_authors_hint(cdx):
    cdx["metadata"]["authors"] = [{"name": "Jane", "email": "jane@acme.example"}]
    del cdx["metadata"]["manufacturer"]
    item = only_failure(cdx, "sbom-creator")
    assert item["component"] == "(SBOM)"
    assert item["ref"] is None
    assert "authors" in item["message"]
    assert item["line"] == line_of(cdx, '"metadata"')


def test_sbom_timestamp_missing(cdx):
    del cdx["metadata"]["timestamp"]
    only_failure(cdx, "sbom-timestamp")


def test_primary_component_missing(cdx):
    del cdx["metadata"]["component"]
    _, result = check(cdx)
    assert "primary-component" in failed_tests(result)
    assert "dependency-reachable" in failed_tests(result)


def test_no_vulnerabilities(cdx):
    cdx["vulnerabilities"] = [{"id": "CVE-2021-44228"}]
    item = only_failure(cdx, "no-vulnerabilities")
    assert item["line"] == line_of(cdx, '"vulnerabilities"')


def test_sbom_uri_not_applicable_without_serial_number(cdx):
    del cdx["serialNumber"]
    _, result = check(cdx)
    assert test_entry(result, "sbom-uri")["status"] == "notApplicable"
    assert result["summary"]["compliant"] is True


# ---- versions ----------------------------------------------------------------------------------


def test_cyclonedx_1_7_is_accepted(cdx):
    cdx["specVersion"] = "1.7"
    _, result = check(cdx)
    assert result["schemaValid"] is True, result["schemaErrors"]
    assert result["summary"]["compliant"] is True


def test_cyclonedx_1_5_fails_format_version_with_note(cdx):
    cdx["specVersion"] = "1.5"
    cdx["metadata"]["component"]["externalReferences"].pop()  # "source-distribution" was introduced in 1.6
    for c in [cdx["metadata"]["component"], *cdx["components"]]:
        c.pop("manufacturer", None)
        for lic in c.get("licenses", []):
            lic.pop("acknowledgement", None)
            if "license" in lic:
                lic["license"].pop("acknowledgement", None)
    cdx["metadata"]["manufacture"] = cdx["metadata"].pop("manufacturer")
    _, result = check(cdx)
    assert result["schemaValid"] is True, result["schemaErrors"]
    assert "format-version" in failed_tests(result)
    assert "sbom-creator" not in failed_tests(result)
    assert any(re.search(r"CycloneDX 1\.5", n) for n in result["notes"])


# ---- schema validation -------------------------------------------------------------------------


def test_schema_errors_with_lines_and_no_tr_tests(cdx):
    cdx["components"][UTIL]["version"] = 3
    status, result = check(cdx)
    assert status == 200
    assert result["schemaValid"] is False
    assert result["summary"]["tests"] == []
    assert result["summary"]["compliant"] is False
    assert result["failures"] == {}
    assert result["schemaErrors"][0]["path"] == "/components/0/version"
    assert result["schemaErrors"][0]["line"] == line_of(cdx, '"version": 3')


def test_schema_detects_duplicate_components(cdx):
    cdx["components"].append(copy.deepcopy(cdx["components"][UTIL]))
    _, result = check(cdx)
    assert result["schemaValid"] is False
    assert "duplicate" in result["schemaErrors"][0]["message"]


def test_schema_error_limit(cdx):
    for i in range(5):
        cdx["components"].append({"type": "library", "name": i})
    _, result = check(cdx, max_schema_errors=2)
    assert len(result["schemaErrors"]) == 2
    assert result["schemaErrorsTruncated"] is True
    assert result["schemaErrorsTotal"] >= 5


def test_schema_invalid_timestamp(cdx):
    cdx["metadata"]["timestamp"] = "2026-13-01T00:00:00Z"
    _, result = check(cdx)
    assert result["schemaValid"] is False
    assert result["schemaErrors"][0]["path"] == "/metadata/timestamp"


# ---- report limits -----------------------------------------------------------------------------


def test_failures_per_test_are_truncated(cdx):
    for i in range(5):
        c = copy.deepcopy(cdx["components"][UTIL])
        c["bom-ref"] = c["name"] = f"x{i}"
        del c["version"]
        cdx["components"].append(c)
    _, result = check(cdx, max_failures=2)
    f = result["failures"]["component-version"]
    assert (f["total"], len(f["items"]), f["truncated"]) == (5, 2, True)
