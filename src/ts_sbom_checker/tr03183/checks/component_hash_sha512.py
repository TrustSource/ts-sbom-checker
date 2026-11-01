from ...syntax import is_sha512, q
from ..base import Finding, TrTest
from ..helpers import mapping, with_hints


def _check(c, ctx):
    if not c.hashes:
        where = mapping(
            ctx,
            "externalReferences[type=distribution].hashes[alg=SHA-512]",
            "software_File (hasDistributionArtifact) verifiedUsing[algorithm=sha512]",
            "checksums[algorithm=SHA512]",
        )
        return Finding(with_hints(f"SHA-512 hash is missing ({where})", c.hash_hints))
    bad = next((h for h in c.hashes if not is_sha512(h.value)), None)
    if bad:
        return Finding(f"SHA-512 value {q(bad.value)} is not 128 hexadecimal characters", bad.path)
    return None


# TR 5.2.2: SHA-512 of the deployable component
TEST = TrTest(
    id="component-hash-sha512",
    tr="5.2.2",
    category="required",
    scope="component",
    title="SHA-512 hash of the deployable component",
    check=_check,
)
