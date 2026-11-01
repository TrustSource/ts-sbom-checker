import json
from pathlib import Path

import pytest

from ts_sbom_checker import check_sbom

FIXTURES = Path(__file__).parent / "fixtures"


def fixture(name: str) -> dict:
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


def dump(doc) -> str:
    """Serialisation used by all tests: 2-space indentation, like JSON.stringify(doc, null, 2)."""
    return doc if isinstance(doc, str) else json.dumps(doc, indent=2, ensure_ascii=False)


def check(doc, **options):
    return check_sbom(dump(doc), **options)


def test_entry(result: dict, test_id: str) -> dict:
    return next(t for t in result["summary"]["tests"] if t["id"] == test_id)


test_entry.__test__ = False  # not a test


def failures_of(result: dict, test_id: str) -> list:
    return result["failures"][test_id]["items"] if test_id in result["failures"] else []


def failed_tests(result: dict) -> list[str]:
    return [t["id"] for t in result["summary"]["tests"] if t["status"] == "failed"]


def line_of(doc, needle: str, start: int = 0) -> int:
    """1-based line of the first occurrence of ``needle`` in the serialised document."""
    for i, line in enumerate(dump(doc).split("\n")[start:], start):
        if needle in line:
            return i + 1
    raise AssertionError(f'"{needle}" not found')


def only_failure(doc, test_id: str) -> dict:
    """Asserts that ``test_id`` is the only failed test with exactly one item; returns the item."""
    status, result = check(doc)
    assert status == 200
    assert result["schemaValid"] is True, result["schemaErrors"]
    assert failed_tests(result) == [test_id]
    items = failures_of(result, test_id)
    assert len(items) == 1
    return items[0]


@pytest.fixture
def cdx():
    return fixture("cdx-1.6-compliant.json")


@pytest.fixture
def spdx3():
    return fixture("spdx-3.0.1-compliant.json")


@pytest.fixture
def spdx2():
    return fixture("spdx-2.3.json")
