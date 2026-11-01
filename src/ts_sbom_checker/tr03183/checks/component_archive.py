from ..base import TrTest
from ..helpers import property_finding

# TR 5.2.2: archive property
TEST = TrTest(
    id="component-archive",
    tr="5.2.2",
    category="required",
    scope="component",
    title="Archive property (archive / no archive)",
    check=lambda c, ctx: property_finding(c.archive, "bsi:component:archive", ("archive", "no archive"), ctx),
)
