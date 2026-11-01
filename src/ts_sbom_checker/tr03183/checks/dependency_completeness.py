from ..base import Finding, TrTest

# TR 5.2.2: the completeness of the dependency enumeration must be clearly indicated
TEST = TrTest(
    id="dependency-completeness",
    tr="5.2.2",
    category="required",
    scope="component",
    title="Completeness of the dependency enumeration indicated",
    check=lambda c, ctx: None if c.completeness.ok else Finding(c.completeness.problem, c.completeness.path),
)
