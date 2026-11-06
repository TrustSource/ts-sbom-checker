"""Maps an SPDX 3.0.x JSON-LD document onto the model. Field mapping follows TR-03183-2 v2.1.0, appendix 8.2.

Elements live in "@graph" and reference each other by spdxId (or "@id" for blank nodes such as
CreationInfo). References may also be inlined objects; both are handled.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from . import Component, Contact, Document, Graph, Identifier, Indication, Licence, Model, Property, Value

DEP_TYPES = {"dependsOn", "contains"}
IDENTIFIER_TYPES = {"packageUrl": "purl", "cpe22": "cpe22", "cpe23": "cpe23", "swid": "swid"}
_NONE_LIKE = re.compile(r"(NoneElement|NoAssertionElement)$")

NO_FILE = "no software_File linked via hasDistributionArtifact (TR 8.2 records this property there)"
NOT_STRUCTURED = (
    'software_additionalPurpose of the distribution file contains neither "container" (structured) nor "firmware" (unstructured)'
)


def _arr(v) -> list:
    if isinstance(v, list):
        return v
    return [] if v is None else [v]


def _id_of(obj) -> str | None:
    if not isinstance(obj, dict):
        return None
    return obj.get("spdxId") or obj.get("@id") or None


def _is_none_like(target) -> bool:
    return isinstance(target, str) and bool(_NONE_LIKE.search(target))


@dataclass(eq=False)
class _El:
    obj: dict
    path: list


def _id_key(obj: dict) -> str:
    """The 3.0.1 schema writes "externalIdentifier", TR 8.2 "externalIdentifiers"; both are accepted."""
    return "externalIdentifier" if _arr(obj.get("externalIdentifier")) else "externalIdentifiers"


def _external_identifiers(obj: dict) -> list:
    return _arr(obj.get(_id_key(obj)))


class _Index:
    def __init__(self, data: dict):
        graph = data.get("@graph")
        if isinstance(graph, list):
            self.elements = [_El(obj, ["@graph", i]) for i, obj in enumerate(graph) if isinstance(obj, dict)]
        else:
            self.elements = [_El(data, [])]
        self.by_id: dict[str, _El] = {}
        for e in self.elements:
            eid = _id_of(e.obj)
            if eid and eid not in self.by_id:
                self.by_id[eid] = e

    def resolve(self, ref, at) -> _El | None:
        """Resolves a reference (id string or inline object); an inline object gets the path ``at``."""
        if isinstance(ref, str):
            return self.by_id.get(ref)
        if isinstance(ref, dict):
            return _El(ref, at)
        return None


def _agent_contacts(index: _Index, refs, base_path) -> list[Contact]:
    """Creator candidates of the agents referenced by ``refs`` (createdBy / originatedBy)."""
    out = []
    for i, ref in enumerate(_arr(refs)):
        agent = index.resolve(ref, [*base_path, i])
        if not agent:
            continue
        key = _id_key(agent.obj)
        for j, x in enumerate(_external_identifiers(agent.obj)):
            if not isinstance(x, dict):
                continue
            path = [*agent.path, key, j, "identifier"]
            kind = x.get("externalIdentifierType")
            if kind == "email":
                out.append(Contact("email", x.get("identifier"), path))
            elif kind in ("urlScheme", "other"):
                out.append(Contact("url", x.get("identifier"), path))
    return out


def _locators(ref) -> list:
    return _arr(ref.get("locator")) if isinstance(ref, dict) else []


def build(data: dict, fmt) -> Model:
    index = _Index(data)
    elements = index.elements
    resolve = index.resolve

    rels_from: dict[str, list[_El]] = {}
    rels_to: dict[str, list[_El]] = {}
    for e in elements:
        if e.obj.get("type") not in ("Relationship", "LifecycleScopedRelationship"):
            continue
        if isinstance(e.obj.get("from"), str):
            rels_from.setdefault(e.obj["from"], []).append(e)
        for to in _arr(e.obj.get("to")):
            if isinstance(to, str):
                rels_to.setdefault(to, []).append(e)

    def outgoing(eid, kind, where=lambda r: True):
        return [r for r in rels_from.get(eid, []) if r.obj.get("relationshipType") == kind and where(r)]

    def targets(rels):
        return [(to, [*r.path, "to", i]) for r in rels for i, to in enumerate(_arr(r.obj.get("to")))]

    # document, SBOM, primary component
    doc_el = next((e for e in elements if e.obj.get("type") == "SpdxDocument"), None)
    sbom_el = None
    if doc_el:
        sbom_el = next(
            (
                x
                for x in (resolve(r, doc_el.path) for r in _arr(doc_el.obj.get("rootElement")))
                if x and x.obj.get("type") == "software_Sbom"
            ),
            None,
        )
    sbom_el = sbom_el or next((e for e in elements if e.obj.get("type") == "software_Sbom"), None)
    root_candidates = []
    if sbom_el:
        root_candidates += _arr(sbom_el.obj.get("rootElement"))
    if doc_el:
        root_candidates += _arr(doc_el.obj.get("rootElement"))
    primary_el = next(
        (
            x
            for x in (index.by_id.get(r) if isinstance(r, str) else None for r in root_candidates)
            if x and x.obj.get("type") == "software_Package"
        ),
        None,
    )
    primary_id = _id_of(primary_el.obj) if primary_el else None

    # creation info of the document (fallback: SBOM, then the first element carrying one)
    ci_owner = next((e for e in (doc_el, sbom_el) if e and e.obj.get("creationInfo")), None) or next(
        (e for e in elements if e.obj.get("creationInfo")), None
    )
    ci = resolve(ci_owner.obj["creationInfo"], [*ci_owner.path, "creationInfo"]) if ci_owner else None

    edges: dict[str, list[str]] = {}
    components = []
    for pkg in (e for e in elements if e.obj.get("type") == "software_Package"):
        obj, path = pkg.obj, pkg.path
        ref = _id_of(obj)
        cid = ref or "#" + "/".join(map(str, path))

        files = [
            f
            for f in (resolve(to, at) for to, at in targets(outgoing(cid, "hasDistributionArtifact")))
            if f and f.obj.get("type") == "software_File"
        ]

        dep_rels = [r for r in rels_from.get(cid, []) if r.obj.get("relationshipType") in DEP_TYPES]
        edges[cid] = [to for to, _ in targets(dep_rels) if isinstance(to, str) and not _is_none_like(to)]

        if dep_rels:
            dependency = Indication(True, dep_rels[0].path)
        else:
            dependency = Indication(
                False,
                path,
                'no dependsOn/contains relationship from this package (use "to": NoneElement if it has no dependencies)',
            )
        without = next((r for r in dep_rels if "completeness" not in r.obj), None)
        if not dep_rels:
            completeness = Indication(False, path, 'no dependency relationship that could carry "completeness"')
        elif without:
            completeness = Indication(False, without.path, 'dependency relationship without "completeness"')
        else:
            completeness = Indication(True, dep_rels[0].path)

        def licences_via(kind, where=lambda r: True, _cid=cid):
            out = []
            for to, at in targets(outgoing(_cid, kind, where)):
                el = resolve(to, at)
                if not el:
                    continue
                o = el.obj
                # The 3.0.1 serialisation uses "simplelicensing_" / "expandedlicensing_"; TR 8.2
                # writes "simpleLicensing_". Both are accepted.
                t = str(o.get("type")).lower()
                if t == "simplelicensing_licenseexpression":
                    key = next((k for k in o if k.lower() == "simplelicensing_licenseexpression"), "licenseExpression")
                    out.append(Licence("expression", o.get(key), [*el.path, key]))
                elif t == "expandedlicensing_listedlicense":
                    out.append(Licence("id", str(_id_of(o) or "").split("/")[-1], el.path))
                else:
                    out.append(Licence("other", o.get("type"), el.path))
            return out

        hashes, filenames, download_uris = [], [], []
        structured = False
        for f in files:
            if "name" in f.obj:
                filenames.append(Value(f.obj["name"], [*f.path, "name"]))
            for j, h in enumerate(_arr(f.obj.get("verifiedUsing"))):
                if isinstance(h, dict) and h.get("algorithm") == "sha512":
                    hashes.append(Value(h.get("hashValue"), [*f.path, "verifiedUsing", j, "hashValue"]))
            purposes = _arr(f.obj.get("software_additionalPurpose"))
            if "container" in purposes or "firmware" in purposes:
                structured = True
            if "software_downloadLocation" in f.obj:
                download_uris.append(Value(f.obj["software_downloadLocation"], [*f.path, "software_downloadLocation"]))
            for j, r in enumerate(_arr(f.obj.get("externalRef"))):
                if isinstance(r, dict) and r.get("externalRefType") == "binaryArtifact":
                    download_uris += [Value(loc, [*f.path, "externalRef", j, "locator", k]) for k, loc in enumerate(_locators(r))]
        if "software_downloadLocation" in obj:
            download_uris.append(Value(obj["software_downloadLocation"], [*path, "software_downloadLocation"]))

        source_uris = []
        bom_refs = []
        for r in rels_to.get(cid, []):
            kind = r.obj.get("relationshipType")
            if kind == "generates":
                src = resolve(r.obj.get("from"), [*r.path, "from"])
                if not src or src.obj.get("software_primaryPurpose") != "source":
                    continue
                for j, x in enumerate(_arr(src.obj.get("externalRef"))):
                    if isinstance(x, dict) and str(x.get("externalRefType")).lower() == "sourceartifact":
                        source_uris += [
                            Value(loc, [*src.path, "externalRef", j, "locator", k]) for k, loc in enumerate(_locators(x))
                        ]
            elif kind == "describes":
                # referenced component: described by another software_Sbom (TR 8.2 "References to another BOM")
                sbom = resolve(r.obj.get("from"), [*r.path, "from"])
                if not sbom or sbom.obj.get("type") != "software_Sbom" or sbom is sbom_el:
                    continue
                refs = _arr(sbom.obj.get("externalRef"))
                if not refs:
                    bom_refs.append(Value(None, sbom.path))
                for j, x in enumerate(refs):
                    bom_refs += [Value(loc, [*sbom.path, "externalRef", j, "locator", k]) for k, loc in enumerate(_locators(x))]

        identifiers = []
        key = _id_key(obj)
        for j, x in enumerate(_external_identifiers(obj)):
            if isinstance(x, dict) and x.get("externalIdentifierType") in IDENTIFIER_TYPES:
                identifiers.append(
                    Identifier(
                        IDENTIFIER_TYPES[x["externalIdentifierType"]],
                        x.get("identifier"),
                        [*path, key, j, "identifier"],
                    )
                )
        if "software_packageUrl" in obj:
            identifiers.append(Identifier("purl", obj["software_packageUrl"], [*path, "software_packageUrl"]))

        has_file = bool(files)
        components.append(
            Component(
                id=cid,
                ref=ref,
                path=path,
                is_primary=cid == primary_id,
                is_referenced=bool(bom_refs),
                name=Value(obj.get("name"), [*path, "name"]),
                version=Value(obj.get("software_packageVersion"), [*path, "software_packageVersion"]),
                creators=_agent_contacts(index, obj.get("originatedBy"), [*path, "originatedBy"]),
                creator_hints=(
                    ['only "suppliedBy" present; the supplier is not the creator (TR 3.2.9), expected in "originatedBy"']
                    if "originatedBy" not in obj and "suppliedBy" in obj
                    else []
                ),
                filenames=Property("values", filenames) if has_file else Property("unavailable", problem=NO_FILE),
                dependency=dependency,
                completeness=completeness,
                distribution_licences=licences_via("hasConcludedLicense"),
                original_licences=licences_via("hasDeclaredLicense"),
                effective_licences=licences_via("other", lambda r: r.obj.get("comment") == "hasEffectiveLicense"),
                licence_hints=[],
                hashes=hashes,
                hash_hints=[] if has_file else [NO_FILE],
                # the absence of "executable" / "archive" in software_additionalPurpose means
                # non-executable / no archive, so only the file itself is required
                executable=Property("present", ok=has_file, problem=None if has_file else NO_FILE),
                archive=Property("present", ok=has_file, problem=None if has_file else NO_FILE),
                structured=Property("present", ok=has_file and structured, problem=NOT_STRUCTURED if has_file else NO_FILE),
                source_uris=source_uris,
                download_uris=download_uris,
                identifiers=identifiers,
                bom_refs=bom_refs,
            )
        )

    vuln_els = [e for e in elements if isinstance(e.obj.get("type"), str) and e.obj["type"].startswith("security_")]
    doc_id = _id_of(doc_el.obj) if doc_el else None
    sbom_id = _id_of(sbom_el.obj) if sbom_el else None
    # TR table 10 maps the SBOM-URI to the spdxId of the software_Sbom; the SpdxDocument is the fallback
    uri_id = next((x for x in (sbom_id, doc_id) if isinstance(x, str) and not x.startswith("_:")), None)
    uri_owner = sbom_el if uri_id == sbom_id else doc_el

    document = Document(
        path=doc_el.path if doc_el else [],
        creators=_agent_contacts(index, ci.obj.get("createdBy"), [*ci.path, "createdBy"]) if ci else [],
        creator_hints=[],
        timestamp=Value(ci.obj["created"], [*ci.path, "created"]) if ci and "created" in ci.obj else None,
        primary=Value(primary_id, primary_el.path) if primary_el else None,
        vulnerability_count=len(vuln_els),
        vulnerability_path=vuln_els[0].path if vuln_els else [],
        sbom_uri=(Value(uri_id, [*uri_owner.path, "spdxId" if uri_owner.obj.get("spdxId") else "@id"]) if uri_id else None),
    )
    return Model(document, components, Graph([primary_id] if primary_id else [], edges), exactly_one_property=False)
