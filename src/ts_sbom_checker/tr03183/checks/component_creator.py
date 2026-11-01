from ..base import TrTest
from ..helpers import creator_finding, mapping


def _check(c, ctx):
    return creator_finding(
        c.creators,
        c.creator_hints,
        c.path,
        mapping(
            ctx,
            "manufacturer.url / manufacturer.contact[].email",
            "originatedBy -> externalIdentifier email / other",
            'originator "Organization|Person: name (email)"',
        ),
    )


# TR 5.2.2: component creator (email address, otherwise URL); also required for referenced components (TR 3.2.5)
TEST = TrTest(
    id="component-creator",
    tr="5.2.2",
    category="required",
    scope="component",
    title="Component creator with email address or URL",
    check=_check,
    for_referenced=True,
)
