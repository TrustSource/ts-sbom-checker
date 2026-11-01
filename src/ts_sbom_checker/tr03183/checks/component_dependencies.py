from ..base import Finding, TrTest

# TR 5.2.2: enumeration of all direct dependencies (an empty enumeration is still an enumeration)
TEST = TrTest(
    id="component-dependencies",
    tr="5.2.2",
    category="required",
    scope="component",
    title="Dependencies on other components enumerated",
    check=lambda c, ctx: None if c.dependency.ok else Finding(c.dependency.problem, c.dependency.path),
)
