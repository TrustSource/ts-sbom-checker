"""BSI TR-03183-2 v2.1.0 test suite: one module per test in ``checks/``."""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass

from ..detect import Format
from ..model import Graph, Model
from .base import Context, Finding, TrTest
from .checks import (
    component_archive,
    component_bom_reference,
    component_creator,
    component_dependencies,
    component_distribution_licence,
    component_download_uri,
    component_executable,
    component_filename,
    component_hash_sha512,
    component_identifiers,
    component_name,
    component_original_licences,
    component_source_uri,
    component_structured,
    component_version,
    dependency_completeness,
    dependency_reachable,
    format_version,
    licence_identifiers,
    no_vulnerabilities,
    primary_component,
    sbom_creator,
    sbom_timestamp,
    sbom_uri,
)

TR_NAME = "BSI TR-03183-2 v2.1.0"

# Order = order in the report.
TESTS: tuple[TrTest, ...] = tuple(
    m.TEST
    for m in (
        format_version,
        sbom_creator,
        sbom_timestamp,
        primary_component,
        no_vulnerabilities,
        sbom_uri,
        component_creator,
        component_name,
        component_version,
        component_filename,
        component_dependencies,
        dependency_completeness,
        dependency_reachable,
        component_distribution_licence,
        component_hash_sha512,
        component_executable,
        component_archive,
        component_structured,
        licence_identifiers,
        component_source_uri,
        component_download_uri,
        component_identifiers,
        component_original_licences,
        component_bom_reference,
    )
)


@dataclass
class Result:
    subject: object  # Document or Component
    status: str  # "passed" | "failed" | "notApplicable"
    finding: Finding | None = None


def _reachable(graph: Graph) -> set[str] | None:
    if not graph.roots:
        return None
    seen = set(graph.roots)
    queue = deque(graph.roots)
    while queue:
        for nxt in graph.edges.get(queue.popleft(), ()):
            if nxt not in seen:
                seen.add(nxt)
                queue.append(nxt)
    return seen


def run_tests(model: Model, fmt: Format) -> list[tuple[TrTest, list[Result]]]:
    """Runs every test on every applicable subject; all tests always run to completion."""
    ctx = Context(model, fmt, _reachable(model.graph))
    outcomes = []
    for test in TESTS:
        subjects = [model.document] if test.scope == "document" else model.components
        results = []
        for subject in subjects:
            skipped_reference = test.scope == "component" and subject.is_referenced and not test.for_referenced
            if skipped_reference or (test.present and not test.present(subject, ctx)):
                results.append(Result(subject, "notApplicable"))
            else:
                finding = test.check(subject, ctx)
                results.append(Result(subject, "failed", finding) if finding else Result(subject, "passed"))
        outcomes.append((test, results))
    return outcomes
