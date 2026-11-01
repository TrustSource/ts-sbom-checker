from ..base import Finding, TrTest
from ..helpers import mapping, with_hints


def _check(c, ctx):
    if c.distribution_licences:
        return None
    where = mapping(
        ctx,
        'licenses[] with acknowledgement "concluded"',
        "hasConcludedLicense relationship",
        "licenseConcluded other than NOASSERTION/NONE",
    )
    return Finding(with_hints(f"distribution licence is missing ({where})", c.licence_hints))


# TR 5.2.2: distribution licence(s)
TEST = TrTest(
    id="component-distribution-licence",
    tr="5.2.2",
    category="required",
    scope="component",
    title="Distribution licence of the component",
    check=_check,
)
