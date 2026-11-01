import pytest

from ts_sbom_checker.syntax import (
    identifier_problem,
    is_date_time,
    is_email,
    is_sha512,
    licence_entry_problem,
    licence_expression_problem,
    uri_problem,
)

VALID_EXPRESSIONS = [
    "MIT",
    "mit",
    "Apache-2.0 OR MIT",
    "(MIT AND BSD-3-Clause) OR GPL-2.0-only",
    "GPL-2.0-or-later WITH Classpath-exception-2.0",
    "LicenseRef-scancode-public-domain",
    "LicenseRef-acme-proprietary",
    "DocumentRef-other:LicenseRef-x",
    "GPL-2.0+",
    "mit or apache-2.0",
]
INVALID_EXPRESSIONS = [
    "",
    "MIT OR",
    "Some License",
    "(MIT",
    "MIT AND OR Apache-2.0",
    "MIT WITH NotAnException",
    "Or MIT",
    "FOO-1.0",
]


@pytest.mark.parametrize("expr", VALID_EXPRESSIONS)
def test_accepts_licence_expression(expr):
    assert licence_expression_problem(expr) is None


@pytest.mark.parametrize("expr", INVALID_EXPRESSIONS)
def test_rejects_licence_expression(expr):
    assert licence_expression_problem(expr) is not None


def test_rejects_licences_by_name_or_text_only():
    assert "name only" in licence_entry_problem("name", "Apache License")
    assert "text only" in licence_entry_problem("text", None)
    assert licence_entry_problem("id", "Apache-2.0") is None


def test_purl():
    assert identifier_problem("purl", "pkg:maven/org.example/util@1.4.2") is None
    assert identifier_problem("purl", "maven:org.example/util") is not None


def test_cpe():
    assert identifier_problem("cpe23", "cpe:2.3:a:example:util:1.4.2:*:*:*:*:*:*:*") is None
    assert identifier_problem("cpe22", "cpe:/a:example:util:1.4.2") is None
    assert identifier_problem("cpe", "cpe:/a:example:util:1.4.2") is None
    assert identifier_problem("cpe23", "cpe:2.3:a:example") is not None


def test_swid_only_needs_a_value():
    assert identifier_problem("swid", "any-tag-id") is None
    assert identifier_problem("swid", " ") is not None


def test_absolute_ascii_uris_only():
    assert uri_problem("https://example.org/a?b=c#d") is None
    assert uri_problem("urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79") is None
    assert uri_problem("git+https://github.com/a/b.git") is None
    assert "non-ASCII" in uri_problem("https://bücher.example")
    assert "not a valid absolute URI" in uri_problem("/relative/path")
    assert "not a valid absolute URI" in uri_problem("https://exa mple.org")
    assert "not a valid absolute URI" in uri_problem("https://example.org/%zz")
    assert "not a valid absolute URI" in uri_problem("https://example.org/\n")
    assert "empty" in uri_problem("")


def test_email():
    assert is_email("sbom@acme.example")
    assert not is_email("acme.example")
    assert not is_email("dev@localhost")


def test_rfc3339_timestamps():
    assert is_date_time("2026-10-01T12:00:00Z")
    assert is_date_time("2026-10-01T12:00:00.123+02:00")
    assert not is_date_time("2026-10-01")
    assert not is_date_time("2026-02-30T12:00:00Z")
    assert not is_date_time("2026-10-01T12:00:00Z\n")


def test_sha512():
    assert is_sha512("a" * 128)
    assert not is_sha512("a" * 64)
    assert not is_sha512("g" * 128)
