from ..base import Finding, TrTest
from ..helpers import mapping


def _check(doc, ctx):
    if doc.primary is not None:
        return None
    where = mapping(
        ctx,
        "metadata.component",
        "software_Sbom.rootElement -> software_Package",
        "documentDescribes / DESCRIBES relationship to a package",
    )
    return Finding(f"no primary component ({where})", doc.path)


# TR 3.2.1: the primary component (root of the dependency tree) is a component of the SBOM
TEST = TrTest(
    id="primary-component",
    tr="3.2.1",
    category="required",
    scope="document",
    title="Primary component declared",
    check=_check,
)
