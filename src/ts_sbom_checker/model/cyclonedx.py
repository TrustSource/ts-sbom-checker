"""Maps a CycloneDX 1.5-1.7 JSON document onto the model. Field mapping follows TR-03183-2 v2.1.0, appendix 8.2."""

from __future__ import annotations

from . import Component, Contact, Document, Graph, Identifier, Indication, Licence, Model, Property, Value

BSI_FILENAME = "bsi:component:filename"
BSI_EXECUTABLE = "bsi:component:executable"
BSI_ARCHIVE = "bsi:component:archive"
BSI_STRUCTURED = "bsi:component:structured"
# The BSI taxonomy writes "Licence" (British English, as the TR text), table 12 of the TR "License";
# both are accepted.
BSI_EFFECTIVE_LICENCE = ("bsi:component:effectiveLicence", "bsi:component:effectiveLicense")
# TR v2.0.0 property, deprecated in the taxonomy for v2.1.0 (replaced by licences with acknowledgement)
BSI_ASSOCIATED_LICENCES = ("bsi:component:associatedLicences", "bsi:component:associatedLicenses")


def _arr(v) -> list:
    return v if isinstance(v, list) else []


def _entity_contacts(entity, path) -> list[Contact]:
    """Creator candidates of an organizationalEntity (manufacturer): url[] or contact[].email."""
    out: list[Contact] = []
    if not isinstance(entity, dict):
        return out
    for i, u in enumerate(_arr(entity.get("url"))):
        out.append(Contact("url", u, [*path, "url", i]))
    for i, c in enumerate(_arr(entity.get("contact"))):
        if isinstance(c, dict) and "email" in c:
            out.append(Contact("email", c["email"], [*path, "contact", i, "email"]))
    return out


def _properties(comp: dict, path, names) -> list[Value]:
    wanted = (names,) if isinstance(names, str) else names
    return [
        Value(p.get("value"), [*path, "properties", i, "value"])
        for i, p in enumerate(_arr(comp.get("properties")))
        if isinstance(p, dict) and p.get("name") in wanted
    ]


def _licences(comp: dict, path):
    distribution: list[Licence] = []
    original: list[Licence] = []
    unacknowledged = 0
    for i, item in enumerate(_arr(comp.get("licenses"))):
        if not isinstance(item, dict):
            continue
        p = [*path, "licenses", i]
        if isinstance(item.get("expression"), str):
            entry = Licence("expression", item["expression"], [*p, "expression"])
            ack = item.get("acknowledgement")
        elif isinstance(item.get("license"), dict):
            lic = item["license"]
            ack = lic.get("acknowledgement")
            if "id" in lic:
                entry = Licence("id", lic["id"], [*p, "license", "id"])
            elif "name" in lic:
                entry = Licence("name", lic["name"], [*p, "license", "name"])
            else:
                entry = Licence("text", None, [*p, "license"])
        else:
            continue
        if ack == "concluded":
            distribution.append(entry)
        elif ack == "declared":
            original.append(entry)
        else:
            unacknowledged += 1
    return distribution, original, unacknowledged


def _external_refs(comp: dict, path, kind: str):
    return [
        (r, [*path, "externalReferences", i])
        for i, r in enumerate(_arr(comp.get("externalReferences")))
        if isinstance(r, dict) and r.get("type") == kind
    ]


def _ref_urls(comp: dict, path, kind: str) -> list[Value]:
    return [Value(r.get("url"), [*rp, "url"]) for r, rp in _external_refs(comp, path, kind)]


def _hashes(comp: dict, path):
    found = [
        Value(h.get("content"), [*rp, "hashes", j, "content"])
        for r, rp in _external_refs(comp, path, "distribution")
        for j, h in enumerate(_arr(r.get("hashes")))
        if isinstance(h, dict) and h.get("alg") == "SHA-512"
    ]
    hints = []
    if not found and any(isinstance(h, dict) and h.get("alg") == "SHA-512" for h in _arr(comp.get("hashes"))):
        hints.append(
            'SHA-512 found in "hashes" of the component; TR 8.2 expects it in externalReferences[type=distribution].hashes'
        )
    return found, hints


def _identifiers(comp: dict, path) -> list[Identifier]:
    out = []
    if "purl" in comp:
        out.append(Identifier("purl", comp["purl"], [*path, "purl"]))
    if "cpe" in comp:
        out.append(Identifier("cpe", comp["cpe"], [*path, "cpe"]))
    swid = comp.get("swid")
    if isinstance(swid, dict) and "tagId" in swid:
        out.append(Identifier("swid", swid["tagId"], [*path, "swid", "tagId"]))
    return out


def _creator_hints(comp: dict, spec_version: str) -> list[str]:
    hints = []
    if spec_version == "1.5":
        hints.append('CycloneDX 1.5 has no "manufacturer" for components (introduced in 1.6)')
    supplier = comp.get("supplier")
    if isinstance(supplier, dict) and (
        _arr(supplier.get("url")) or any(isinstance(c, dict) and c.get("email") for c in _arr(supplier.get("contact")))
    ):
        hints.append('contact found in "supplier" only; the supplier is not the creator (TR 3.2.9, mapping: manufacturer)')
    if _arr(comp.get("authors")) or comp.get("author"):
        hints.append('"authors"/"author" present; TR 8.2 expects the creator in "manufacturer"')
    return hints


def _collect(data: dict):
    """(comp, path, id, parent_id, is_primary) for metadata.component and all components, recursively."""
    found = []

    def visit(comp, path, parent_id, is_primary):
        if not isinstance(comp, dict):
            return
        ref = comp.get("bom-ref")
        cid = ref if isinstance(ref, str) and ref != "" else "#" + "/".join(map(str, path))
        found.append((comp, path, cid, parent_id, is_primary))
        for i, child in enumerate(_arr(comp.get("components"))):
            visit(child, [*path, "components", i], cid, False)

    metadata = data.get("metadata")
    if isinstance(metadata, dict) and metadata.get("component"):
        visit(metadata["component"], ["metadata", "component"], None, True)
    for i, c in enumerate(_arr(data.get("components"))):
        visit(c, ["components", i], None, False)
    return found


def build(data: dict, fmt) -> Model:
    spec_version = fmt.spec_version
    metadata = data.get("metadata") if isinstance(data.get("metadata"), dict) else {}

    dep_entries: dict[str, list] = {}
    edges: dict[str, list[str]] = {}
    for i, d in enumerate(_arr(data.get("dependencies"))):
        if not isinstance(d, dict) or not isinstance(d.get("ref"), str):
            continue
        dep_entries.setdefault(d["ref"], ["dependencies", i])
        edges.setdefault(d["ref"], []).extend(t for t in _arr(d.get("dependsOn")) if isinstance(t, str))

    completeness: dict[str, tuple] = {}  # ref -> (aggregate, path)
    for i, c in enumerate(_arr(data.get("compositions"))):
        if not isinstance(c, dict):
            continue
        for key in ("dependencies", "assemblies"):
            for j, ref in enumerate(_arr(c.get(key))):
                if not isinstance(ref, str):
                    continue
                prev = completeness.get(ref)
                if prev is None or prev[0] == "not_specified":
                    completeness[ref] = (c.get("aggregate"), ["compositions", i, key, j])

    raw = _collect(data)
    # nesting counts as containment in the dependency graph (TR 8.2)
    for _, _, cid, parent_id, _ in raw:
        if parent_id:
            edges.setdefault(parent_id, []).append(cid)

    components = []
    for comp, path, cid, _, is_primary in raw:
        ref = comp.get("bom-ref") if isinstance(comp.get("bom-ref"), str) else None
        distribution, original, unacknowledged = _licences(comp, path)
        hashes, hash_hints = _hashes(comp, path)
        bom_refs = _ref_urls(comp, path, "bom")

        if not ref:
            dependency = Indication(False, path, 'component has no "bom-ref" and cannot appear in "dependencies"')
        elif ref in dep_entries:
            dependency = Indication(True, dep_entries[ref])
        else:
            dependency = Indication(
                False,
                path,
                f'no entry with ref "{ref}" in "dependencies" (components without dependencies need an empty entry)',
            )

        c = completeness.get(ref) if ref else None
        if c is None:
            compl = Indication(False, path, 'component is not listed in any "compositions" entry (dependencies/assemblies)')
        elif c[0] in ("not_specified", None):
            compl = Indication(False, c[1], 'composition aggregate is "not_specified"')
        else:
            compl = Indication(True, c[1])

        licence_hints = []
        if unacknowledged:
            entries = "entry has" if unacknowledged == 1 else "entries have"
            licence_hints.append(f'{unacknowledged} licence {entries} no "acknowledgement" (concluded/declared)')
        if _properties(comp, path, BSI_ASSOCIATED_LICENCES):
            licence_hints.append(
                'property "bsi:component:associatedLicences" is from TR v2.0.0 and deprecated; '
                'TR v2.1.0 expects licenses[] with acknowledgement "concluded"'
            )

        components.append(
            Component(
                id=cid,
                ref=ref,
                path=path,
                is_primary=is_primary,
                is_referenced=bool(bom_refs),
                name=Value(comp.get("name"), [*path, "name"]),
                version=Value(comp.get("version"), [*path, "version"]),
                creators=_entity_contacts(comp.get("manufacturer"), [*path, "manufacturer"]),
                creator_hints=_creator_hints(comp, spec_version),
                filenames=Property("values", _properties(comp, path, BSI_FILENAME)),
                dependency=dependency,
                completeness=compl,
                distribution_licences=distribution,
                original_licences=original,
                effective_licences=[
                    Licence("expression", v.value, v.path) for v in _properties(comp, path, BSI_EFFECTIVE_LICENCE)
                ],
                licence_hints=licence_hints,
                hashes=hashes,
                hash_hints=hash_hints,
                executable=Property("values", _properties(comp, path, BSI_EXECUTABLE)),
                archive=Property("values", _properties(comp, path, BSI_ARCHIVE)),
                structured=Property("values", _properties(comp, path, BSI_STRUCTURED)),
                source_uris=_ref_urls(comp, path, "source-distribution"),
                download_uris=_ref_urls(comp, path, "distribution"),
                identifiers=_identifiers(comp, path),
                bom_refs=bom_refs,
            )
        )

    # CycloneDX 1.5 calls the SBOM manufacturer "manufacture"
    manufacturer_key = "manufacturer" if metadata.get("manufacturer") else "manufacture"
    doc_hints = []
    if not metadata.get("manufacturer") and not metadata.get("manufacture"):
        if _arr(metadata.get("authors")):
            doc_hints.append('"metadata.authors" present; TR 8.2 expects the SBOM creator in "metadata.manufacturer"')
        if metadata.get("supplier"):
            doc_hints.append('"metadata.supplier" present; TR 8.2 expects the SBOM creator in "metadata.manufacturer"')

    primary = next((r for r in raw if r[4]), None)
    vulnerabilities = _arr(data.get("vulnerabilities"))

    document = Document(
        path=["metadata"] if "metadata" in data else [],
        creators=_entity_contacts(metadata.get(manufacturer_key), ["metadata", manufacturer_key]),
        creator_hints=doc_hints,
        timestamp=Value(metadata["timestamp"], ["metadata", "timestamp"]) if "timestamp" in metadata else None,
        primary=Value(primary[2], primary[1]) if primary else None,
        vulnerability_count=len(vulnerabilities),
        vulnerability_path=["vulnerabilities"],
        sbom_uri=Value(data["serialNumber"], ["serialNumber"]) if "serialNumber" in data else None,
    )
    return Model(document, components, Graph([primary[2]] if primary else [], edges), exactly_one_property=True)
