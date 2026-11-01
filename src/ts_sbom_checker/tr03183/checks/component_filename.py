from ...syntax import has_path_separator, non_empty, q
from ..base import Finding, TrTest


def _check(c, ctx):
    f = c.filenames
    if f.mode != "values":
        return Finding(f.problem)
    if not f.values:
        return Finding("filename is missing")
    if ctx.model.exactly_one_property and len(f.values) > 1:
        return Finding(f"filename occurs {len(f.values)} times, it must occur at most once", f.values[1].path)
    for v in f.values:
        if not non_empty(v.value):
            return Finding("filename is empty", v.path)
        if has_path_separator(v.value):
            return Finding(f"filename {q(v.value)} contains a path; only the filename is allowed", v.path)
    return None


# TR 5.2.2: actual filename of the component (not its path)
TEST = TrTest(
    id="component-filename",
    tr="5.2.2",
    category="required",
    scope="component",
    title="Filename of the component (without path)",
    check=_check,
)
