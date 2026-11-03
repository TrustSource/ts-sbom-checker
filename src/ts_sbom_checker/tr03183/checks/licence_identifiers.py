from ...syntax import licence_entry_problem
from ..base import Finding, TrTest


def _check(c, ctx):
    # BSI taxonomy: bsi:component:effectiveLicence MUST occur exactly once per component (if used)
    if ctx.model.exactly_one_property and len(c.effective_licences) > 1:
        return Finding(
            f'property "bsi:component:effectiveLicence" occurs {len(c.effective_licences)} times, it must occur exactly once',
            c.effective_licences[1].path,
        )
    for entry in [*c.distribution_licences, *c.effective_licences]:
        problem = licence_entry_problem(entry.kind, entry.value)
        if problem:
            return Finding(problem, entry.path)
    return None


# TR 6.1: licences are named by SPDX licence identifiers or expressions (distribution licence and,
# if present, effective licence). Original licences are checked by component-original-licences.
TEST = TrTest(
    id="licence-identifiers",
    tr="6.1",
    category="required",
    scope="component",
    title="Distribution / effective licences given as SPDX identifiers or expressions",
    check=_check,
    present=lambda c, ctx: bool(c.distribution_licences or c.effective_licences),
)
