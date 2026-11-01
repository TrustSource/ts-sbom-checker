from ...syntax import identifier_problem
from ..base import Finding, TrTest


def _check(c, ctx):
    for i in c.identifiers:
        problem = identifier_problem(i.type, i.value)
        if problem:
            return Finding(problem, i.path)
    return None


# TR 5.2.4: other unique identifiers such as purl or CPE (only checked if present)
TEST = TrTest(
    id="component-identifiers",
    tr="5.2.4",
    category="additional",
    scope="component",
    title="Other unique identifiers (purl, CPE, SWID) are syntactically valid (if present)",
    check=_check,
    present=lambda c, ctx: bool(c.identifiers),
)
