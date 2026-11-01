from ...syntax import uri_problem
from ..base import Finding, TrTest


def _check(c, ctx):
    for r in c.bom_refs:
        problem = uri_problem(r.value)
        if problem:
            return Finding(f"BOM reference {problem}", r.path)
    return None


# TR 3.2.5, 8.1.16: reference to another BOM; the URL must be a valid URI. The referenced BOM
# itself is not loaded.
TEST = TrTest(
    id="component-bom-reference",
    tr="3.2.5, 8.1.16",
    category="additional",
    scope="component",
    title="Reference to another BOM is a valid URI (referenced components only)",
    check=_check,
    present=lambda c, ctx: c.is_referenced and bool(c.bom_refs),
    for_referenced=True,
)
