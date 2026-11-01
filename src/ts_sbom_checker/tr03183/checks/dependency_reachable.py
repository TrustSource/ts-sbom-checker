from ..base import Finding, TrTest


def _check(c, ctx):
    if ctx.reachable is None:
        return Finding("no primary component, the dependency graph has no root")
    if c.id in ctx.reachable:
        return None
    return Finding("component is not reachable from the primary component (no path of dependencies leads to it)")


# TR 5.1: recursive dependency resolution from the primary component. A component that cannot be
# reached from the primary component points to a gap in the dependency graph.
TEST = TrTest(
    id="dependency-reachable",
    tr="5.1",
    category="required",
    scope="component",
    title="Component reachable from the primary component via the dependency graph",
    check=_check,
    for_referenced=True,
)
