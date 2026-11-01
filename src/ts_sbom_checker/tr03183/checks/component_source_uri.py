from ...syntax import uri_problem
from ..base import Finding, TrTest


def _check(c, ctx):
    for u in c.source_uris:
        problem = uri_problem(u.value)
        if problem:
            return Finding(f"source code URI {problem}", u.path)
    return None


# TR 5.2.4: source code URI (only checked if present)
TEST = TrTest(
    id="component-source-uri",
    tr="5.2.4",
    category="additional",
    scope="component",
    title="Source code URI is a valid URI (if present)",
    check=_check,
    present=lambda c, ctx: bool(c.source_uris),
)
