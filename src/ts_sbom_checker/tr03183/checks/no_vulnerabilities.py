from ..base import Finding, TrTest


def _check(doc, ctx):
    n = doc.vulnerability_count
    if n == 0:
        return None
    return Finding(
        f"SBOM contains {n} vulnerability entr{'y' if n == 1 else 'ies'}; use CSAF/VEX instead", doc.vulnerability_path
    )


# TR 3.1, 8.1.14: an SBOM must not contain vulnerability information
TEST = TrTest(
    id="no-vulnerabilities",
    tr="3.1, 8.1.14",
    category="required",
    scope="document",
    title="No vulnerability information in the SBOM",
    check=_check,
)
