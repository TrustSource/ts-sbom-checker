from ..base import Finding, TrTest


def _check(doc, ctx):
    fmt = ctx.format
    major, minor, patch, *_ = [int(x) for x in fmt.spec_version.split(".")] + [0, 0]
    if fmt.type == "CycloneDX":
        ok = (major, minor) >= (1, 6)
    else:
        ok = (major, minor, patch) >= (3, 0, 1)
    if ok:
        return None
    if fmt.type == "CycloneDX":
        path = ["specVersion"]
    else:
        path = ["spdxVersion"] if fmt.is_spdx2 else ["@context"]
    return Finding(
        f"{fmt.type} {fmt.spec_version} is not permitted by TR-03183-2 v2.1.0 "
        "(required: CycloneDX 1.6 or higher, SPDX 3.0.1 or higher)",
        path,
    )


# TR 4: CycloneDX >= 1.6 or SPDX >= 3.0.1
TEST = TrTest(
    id="format-version",
    tr="4",
    category="required",
    scope="document",
    title="SBOM format version permitted by the TR (CycloneDX >= 1.6, SPDX >= 3.0.1)",
    check=_check,
)
