"""Format-independent model the TR tests operate on.

Every value carries the ``path`` (list of keys / indices) where it was found, so findings can be
reported with a line number. Each format module (``cyclonedx``, ``spdx2``, ``spdx3``) maps its
document onto these classes.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

Path = list  # list[str | int]


@dataclass
class Value:
    value: Any
    path: Path


@dataclass
class Contact:
    """Creator candidate: email address or URL."""

    kind: str  # "email" | "url"
    value: Any
    path: Path


@dataclass
class Licence:
    kind: str  # "id" | "expression" | "name" | "text" | "other"
    value: Any
    path: Path


@dataclass
class Identifier:
    type: str  # "purl" | "cpe" | "cpe22" | "cpe23" | "swid"
    value: Any
    path: Path


@dataclass
class Indication:
    """Whether something is declared (dependencies, completeness); ``problem`` explains why not."""

    ok: bool
    path: Path
    problem: str | None = None


@dataclass
class Property:
    """A BSI component property (filename, executable, archive, structured).

    mode "values":      ``values`` holds every occurrence (CycloneDX properties, SPDX filenames)
    mode "present":     the property is implied by the document structure; ``ok`` / ``problem``
    mode "unavailable": cannot be determined (e.g. no distribution file); ``problem``
    mode "unsupported": not expressible in the format (SPDX 2.x); ``problem``
    """

    mode: str
    values: list[Value] = field(default_factory=list)
    ok: bool = False
    problem: str | None = None


@dataclass
class Component:
    id: str  # unique within the graph (bom-ref / spdxId, or a synthetic "#path")
    ref: str | None  # bom-ref / spdxId / SPDXID as reported
    path: Path
    is_primary: bool
    is_referenced: bool
    name: Value
    version: Value
    creators: list[Contact]
    creator_hints: list[str]
    filenames: Property
    dependency: Indication
    completeness: Indication
    distribution_licences: list[Licence]
    original_licences: list[Licence]
    effective_licences: list[Licence]
    licence_hints: list[str]
    hashes: list[Value]  # SHA-512 of the deployable artefact
    hash_hints: list[str]
    executable: Property
    archive: Property
    structured: Property
    source_uris: list[Value]
    download_uris: list[Value]
    identifiers: list[Identifier]
    bom_refs: list[Value]


@dataclass
class Document:
    path: Path  # anchor for document-level findings
    creators: list[Contact]
    creator_hints: list[str]
    timestamp: Value | None
    primary: Value | None  # value = id of the primary component
    vulnerability_count: int
    vulnerability_path: Path
    sbom_uri: Value | None


@dataclass
class Graph:
    roots: list[str]
    edges: dict[str, list[str]]


@dataclass
class Model:
    document: Document
    components: list[Component]
    graph: Graph
    exactly_one_property: bool  # CycloneDX: each bsi:component:* property exactly once


def build_model(data: dict, fmt) -> Model:
    if fmt.type == "CycloneDX":
        from .cyclonedx import build

        return build(data, fmt)
    if fmt.is_spdx2:
        from .spdx2 import build

        return build(data, fmt)
    from .spdx3 import build

    return build(data, fmt)
