from ..base import TrTest
from ..helpers import text_finding

# TR 5.2.2: component version; also required for referenced components (TR 3.2.5)
TEST = TrTest(
    id="component-version",
    tr="5.2.2",
    category="required",
    scope="component",
    title="Component version",
    check=lambda c, ctx: text_finding(c.version, "version"),
    for_referenced=True,
)
