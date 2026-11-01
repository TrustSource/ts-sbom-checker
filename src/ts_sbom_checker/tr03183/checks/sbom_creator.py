from ..base import TrTest
from ..helpers import creator_finding, mapping


def _check(doc, ctx):
    return creator_finding(
        doc.creators,
        doc.creator_hints,
        doc.path,
        mapping(
            ctx,
            "metadata.manufacturer.url / metadata.manufacturer.contact[].email",
            "CreationInfo.createdBy -> externalIdentifier email / urlScheme",
            'creationInfo.creators "Organization|Person: name (email)"',
        ),
    )


# TR 5.2.1: creator of the SBOM (email address, otherwise URL)
TEST = TrTest(
    id="sbom-creator",
    tr="5.2.1",
    category="required",
    scope="document",
    title="Creator of the SBOM with email address or URL",
    check=_check,
)
