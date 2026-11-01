"""Maps an SPDX 2.1-2.3 JSON document onto the model.

The TR defines no mapping for SPDX 2.x (it requires SPDX >= 3.0.1); this mapping is our own approximation.
"""

from __future__ import annotations

import re

from . import Component, Contact, Document, Graph, Identifier, Indication, Licence, Model, Property, Value

ABSENT = {"NOASSERTION", "NONE"}
# Delivered dependencies (TR 3.2.7 includes contained, statically and dynamically linked
# components); build, dev and test dependencies are not counted.
DEP_TYPES = {"DEPENDS_ON", "CONTAINS", "STATIC_LINK", "DYNAMIC_LINK"}
INVERSE_DEP_TYPES = {
    "DEPENDENCY_OF",
    "CONTAINED_BY",
    "RUNTIME_DEPENDENCY_OF",
    "OPTIONAL_DEPENDENCY_OF",
    "PROVIDED_DEPENDENCY_OF",
}
IDENTIFIER_TYPES = {"purl": "purl", "cpe22Type": "cpe22", "cpe23Type": "cpe23", "swid": "swid"}

UNSUPPORTED_PROPERTY = (
    "not expressible in SPDX 2.x (TR 8.2 maps it to SPDX 3 software_additionalPurpose / CycloneDX bsi:component:* properties)"
)

# "Person: Jane Doe (jane@example.com)" / "Organization: ACME (info@acme.example)"
_ACTOR = re.compile(r"^(Person|Organization):.*\(([^()]*)\)\s*$", re.S)


def _arr(v) -> list:
    return v if isinstance(v, list) else []


def _actor_email(actor) -> str | None:
    if not isinstance(actor, str):
        return None
    m = _ACTOR.match(actor.strip())
    return m.group(2).strip() if m and m.group(2).strip() else None


def _licence(value, path) -> list[Licence]:
    if not isinstance(value, str) or value.strip() in ABSENT:
        return []
    return [Licence("expression", value, path)]


def build(data: dict, fmt) -> Model:
    packages = _arr(data.get("packages"))
    rels = _arr(data.get("relationships"))

    # primary component(s): documentDescribes or DOCUMENT DESCRIBES x
    primary_ids = [x for x in _arr(data.get("documentDescribes")) if isinstance(x, str)]
    doc_id = data.get("SPDXID") or "SPDXRef-DOCUMENT"
    for r in rels:
        if not isinstance(r, dict):
            continue
        if r.get("spdxElementId") == doc_id and r.get("relationshipType") == "DESCRIBES":
            primary_ids.append(r.get("relatedSpdxElement"))
        if r.get("relatedSpdxElement") == doc_id and r.get("relationshipType") == "DESCRIBED_BY":
            primary_ids.append(r.get("spdxElementId"))
    primary_ids = list(dict.fromkeys(primary_ids))

    # dependency relationships per element: id -> [(target, path)]
    dep_rels: dict[str, list[tuple]] = {}
    for i, r in enumerate(rels):
        if not isinstance(r, dict):
            continue
        kind = r.get("relationshipType")
        if kind in DEP_TYPES:
            dep_rels.setdefault(r.get("spdxElementId"), []).append((r.get("relatedSpdxElement"), ["relationships", i]))
        if kind in INVERSE_DEP_TYPES:
            dep_rels.setdefault(r.get("relatedSpdxElement"), []).append((r.get("spdxElementId"), ["relationships", i]))

    edges = {src: [t for t, _ in lst if t not in ABSENT] for src, lst in dep_rels.items()}

    components = []
    for i, p in enumerate(packages):
        if not isinstance(p, dict):
            continue
        path = ["packages", i]
        ref = p.get("SPDXID") if isinstance(p.get("SPDXID"), str) else None
        cid = ref or "#" + "/".join(map(str, path))

        email = _actor_email(p.get("originator"))
        creators = [Contact("email", email, [*path, "originator"])] if email else []
        creator_hints = []
        if not email and _actor_email(p.get("supplier")):
            creator_hints.append(
                'contact found in "supplier" only; the supplier is not the creator (TR 3.2.9), expected in "originator"'
            )
        if isinstance(p.get("originator"), str) and p["originator"].startswith("Tool:"):
            creator_hints.append('"originator" is a tool, not a person or organisation')

        deps = dep_rels.get(ref, []) if ref else []
        if deps:
            dependency = Indication(True, deps[0][1])
        else:
            dependency = Indication(
                False,
                path,
                "no dependency relationship (DEPENDS_ON, CONTAINS, STATIC_LINK, DYNAMIC_LINK or an inverse) for "
                'this package (use relatedSpdxElement "NONE" if it has no dependencies)',
            )

        marker = next((d for d in deps if d[0] in ABSENT), None)
        if marker:
            completeness = Indication(True, marker[1])
        else:
            completeness = Indication(
                False,
                deps[0][1] if deps else path,
                'SPDX 2.x can only express completeness via relatedSpdxElement "NONE" (no dependencies) '
                'or "NOASSERTION" (unknown)',
            )

        hashes = [
            Value(c.get("checksumValue"), [*path, "checksums", j, "checksumValue"])
            for j, c in enumerate(_arr(p.get("checksums")))
            if isinstance(c, dict) and c.get("algorithm") == "SHA512"
        ]
        identifiers = [
            Identifier(
                IDENTIFIER_TYPES[r["referenceType"]], r.get("referenceLocator"), [*path, "externalRefs", j, "referenceLocator"]
            )
            for j, r in enumerate(_arr(p.get("externalRefs")))
            if isinstance(r, dict) and r.get("referenceType") in IDENTIFIER_TYPES
        ]
        download = p.get("downloadLocation")
        download_uris = (
            [Value(download, [*path, "downloadLocation"])] if isinstance(download, str) and download.strip() not in ABSENT else []
        )
        filenames = [Value(p["packageFileName"], [*path, "packageFileName"])] if "packageFileName" in p else []

        components.append(
            Component(
                id=cid,
                ref=ref,
                path=path,
                is_primary=ref is not None and ref in primary_ids,
                is_referenced=False,
                name=Value(p.get("name"), [*path, "name"]),
                version=Value(p.get("versionInfo"), [*path, "versionInfo"]),
                creators=creators,
                creator_hints=creator_hints,
                filenames=Property("values", filenames),
                dependency=dependency,
                completeness=completeness,
                distribution_licences=_licence(p.get("licenseConcluded"), [*path, "licenseConcluded"]),
                original_licences=_licence(p.get("licenseDeclared"), [*path, "licenseDeclared"]),
                effective_licences=[],
                licence_hints=[],
                hashes=hashes,
                hash_hints=[],
                executable=Property("unsupported", problem=UNSUPPORTED_PROPERTY),
                archive=Property("unsupported", problem=UNSUPPORTED_PROPERTY),
                structured=Property("unsupported", problem=UNSUPPORTED_PROPERTY),
                source_uris=[],
                download_uris=download_uris,
                identifiers=identifiers,
                bom_refs=[],
            )
        )

    ci = data.get("creationInfo") if isinstance(data.get("creationInfo"), dict) else {}
    creators = []
    for i, c in enumerate(_arr(ci.get("creators"))):
        email = _actor_email(c)
        if email:
            creators.append(Contact("email", email, ["creationInfo", "creators", i]))
    doc_hints = []
    if not creators and _arr(ci.get("creators")):
        doc_hints.append("creators found, but none is a Person/Organization with an email address in parentheses")

    primary = next((c for c in components if c.is_primary), None)
    document = Document(
        path=["creationInfo"] if "creationInfo" in data else [],
        creators=creators,
        creator_hints=doc_hints,
        timestamp=Value(ci["created"], ["creationInfo", "created"]) if "created" in ci else None,
        primary=Value(primary.id, primary.path) if primary else None,
        vulnerability_count=0,
        vulnerability_path=[],
        sbom_uri=Value(data["documentNamespace"], ["documentNamespace"]) if "documentNamespace" in data else None,
    )
    return Model(document, components, Graph(primary_ids, edges), exactly_one_property=False)
