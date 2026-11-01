from ..base import TrTest
from ..helpers import property_finding

# TR 5.2.2: executable property
TEST = TrTest(
    id="component-executable",
    tr="5.2.2",
    category="required",
    scope="component",
    title="Executable property (executable / non-executable)",
    check=lambda c, ctx: property_finding(c.executable, "bsi:component:executable", ("executable", "non-executable"), ctx),
)
