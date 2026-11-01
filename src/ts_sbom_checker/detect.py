"""Detects SBOM format and version and picks the schema to validate against."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field


class UnsupportedSbomError(Exception):
    def __init__(self, error: str, message: str):
        super().__init__(message)
        self.error = error  # "unknown_format" | "unsupported_version"


@dataclass(frozen=True)
class Format:
    type: str  # "CycloneDX" | "SPDX"
    spec_version: str
    schema_key: str
    notes: tuple[str, ...] = field(default_factory=tuple)
    context_override: bool = False

    @property
    def is_spdx2(self) -> bool:
        return self.type == "SPDX" and self.spec_version.startswith("2.")


CYCLONEDX_VERSIONS = ("1.5", "1.6", "1.7")
_SPDX3_CONTEXT = re.compile(r"^https://spdx\.org/rdf/(3\.0\.\d+)/spdx-context\.jsonld$")


def _spdx3_version(data: dict) -> str | None:
    ctx = data.get("@context")
    for c in ctx if isinstance(ctx, list) else [ctx]:
        if isinstance(c, str):
            m = _SPDX3_CONTEXT.match(c)
            if m:
                return m.group(1)
    return None


def detect_format(data: dict) -> Format:
    if data.get("bomFormat") == "CycloneDX":
        v = data.get("specVersion")
        if v not in CYCLONEDX_VERSIONS:
            raise UnsupportedSbomError(
                "unsupported_version",
                f"CycloneDX specVersion {json.dumps(v)} is not supported (supported: {', '.join(CYCLONEDX_VERSIONS)})",
            )
        return Format("CycloneDX", v, f"cyclonedx-{v}")

    spdx_version = data.get("spdxVersion")
    if isinstance(spdx_version, str) and spdx_version.startswith("SPDX-2."):
        v = spdx_version[len("SPDX-") :]
        if v == "2.1":
            return Format(
                "SPDX",
                v,
                "spdx-2.2",
                notes=("SPDX 2.1 has no official JSON schema; the document was validated against the SPDX 2.2 schema.",),
            )
        if v in ("2.2", "2.3"):
            return Format("SPDX", v, f"spdx-{v}")
        raise UnsupportedSbomError(
            "unsupported_version",
            f"SPDX version {json.dumps(spdx_version)} is not supported (supported: SPDX-2.1, SPDX-2.2, SPDX-2.3, 3.0.0, 3.0.1)",
        )

    v = _spdx3_version(data)
    if v == "3.0.1":
        return Format("SPDX", v, "spdx-3.0.1")
    if v == "3.0.0":
        return Format(
            "SPDX",
            v,
            "spdx-3.0.1",
            context_override=True,
            notes=(
                "No official JSON schema is published for SPDX 3.0.0; the document was validated against the SPDX 3.0.1 schema.",
            ),
        )
    if v is not None:
        raise UnsupportedSbomError("unsupported_version", f"SPDX version {v} is not supported (supported: 3.0.0, 3.0.1)")

    raise UnsupportedSbomError(
        "unknown_format",
        "document is neither CycloneDX (bomFormat) nor SPDX 2.x (spdxVersion) nor SPDX 3 (@context)",
    )
