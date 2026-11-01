"""Checks SBOMs (CycloneDX 1.5-1.7, SPDX 2.1-2.3 / 3.0) against their JSON schema and BSI TR-03183-2 v2.1.0.

Library entry points:

- ``check_sbom(data, ...)`` -> ``(status_code, report)``
- ``preload()`` compiles all schemas up front (e.g. during the init phase of an AWS Lambda)
"""

from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("ts-sbom-checker")
except PackageNotFoundError:  # running from a source tree without installation
    __version__ = "0.0.0+unknown"

from .check import check_sbom, preload  # noqa: E402

__all__ = ["__version__", "check_sbom", "preload"]
