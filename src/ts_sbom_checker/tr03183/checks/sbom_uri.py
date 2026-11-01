from ...syntax import uri_problem
from ..base import Finding, TrTest


def _check(doc, ctx):
    value, path = doc.sbom_uri.value, doc.sbom_uri.path
    problem = uri_problem(value)
    if problem:
        return Finding(f"SBOM-URI {problem}", path)
    if ctx.format.is_spdx2 and "#" in value:
        return Finding('documentNamespace must not contain "#"', path)
    return None


# TR 5.2.3: URI of the SBOM (only checked if present)
TEST = TrTest(
    id="sbom-uri",
    tr="5.2.3",
    category="additional",
    scope="document",
    title="SBOM-URI is a valid URI (if present)",
    check=_check,
    present=lambda doc, ctx: doc.sbom_uri is not None,
)
