from ...syntax import licence_entry_problem
from ..base import Finding, TrTest


def _check(c, ctx):
    for entry in c.original_licences:
        problem = licence_entry_problem(entry.kind, entry.value)
        if problem:
            return Finding(problem, entry.path)
    return None


# TR 5.2.4, 6.1: original licences (only checked if present)
TEST = TrTest(
    id="component-original-licences",
    tr="5.2.4, 6.1",
    category="additional",
    scope="component",
    title="Original licences given as SPDX identifiers or expressions (if present)",
    check=_check,
    present=lambda c, ctx: bool(c.original_licences),
)
