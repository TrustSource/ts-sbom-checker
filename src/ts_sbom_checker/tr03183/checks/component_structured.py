from ..base import TrTest
from ..helpers import property_finding

# TR 5.2.2: structured property
TEST = TrTest(
    id="component-structured",
    tr="5.2.2",
    category="required",
    scope="component",
    title="Structured property (structured / unstructured)",
    check=lambda c, ctx: property_finding(c.structured, "bsi:component:structured", ("structured", "unstructured"), ctx),
)
