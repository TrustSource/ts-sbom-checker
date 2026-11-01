from ..base import TrTest
from ..helpers import text_finding

# TR 5.2.2: component name; also required for referenced components (TR 3.2.5)
TEST = TrTest(
    id="component-name",
    tr="5.2.2",
    category="required",
    scope="component",
    title="Component name",
    check=lambda c, ctx: text_finding(c.name, "name"),
    for_referenced=True,
)
