from ...syntax import uri_problem
from ..base import Finding, TrTest


def _check(c, ctx):
    for u in c.download_uris:
        problem = uri_problem(u.value)
        if problem:
            return Finding(f"deployable form URI {problem}", u.path)
    return None


# TR 5.2.4: URI of the deployable form of the component (only checked if present)
TEST = TrTest(
    id="component-download-uri",
    tr="5.2.4",
    category="additional",
    scope="component",
    title="URI of the deployable form is a valid URI (if present)",
    check=_check,
    present=lambda c, ctx: bool(c.download_uris),
)
