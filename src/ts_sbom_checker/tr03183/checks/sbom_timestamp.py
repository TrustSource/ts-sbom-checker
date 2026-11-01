from ...syntax import is_date_time, q
from ..base import Finding, TrTest


def _check(doc, ctx):
    if doc.timestamp is None:
        return Finding("timestamp is missing", doc.path)
    if not is_date_time(doc.timestamp.value):
        return Finding(f"timestamp {q(doc.timestamp.value)} is not a valid date-time (RFC 3339)", doc.timestamp.path)
    return None


# TR 5.2.1: timestamp of the SBOM data compilation
TEST = TrTest(
    id="sbom-timestamp",
    tr="5.2.1",
    category="required",
    scope="document",
    title="Timestamp of the SBOM compilation",
    check=_check,
)
