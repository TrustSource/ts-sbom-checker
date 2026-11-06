# Changelog

All notable changes to this project are documented in this file.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- OpenSSF Scorecard workflow (pushes to `main`, weekly, branch protection changes): results published for the README
  badge and uploaded to GitHub code scanning; actions pinned to commit SHAs.
- Dependabot for GitHub Actions (weekly, grouped), so the pinned SHAs stay current.
- Semgrep workflow (Python and GitHub Actions rules): SARIF result imported into TrustSource (`/core/tests/sarif`) on
  pushes to `main`, like the Bandit result; findings and a failed import do not fail the run.

### Changed

- GitHub Actions moved off the deprecated Node 20 runtime and pinned to commit SHAs: `actions/checkout` v4 → v7.0.1,
  `actions/setup-python` v5 → v7.1.0, `actions/upload-artifact` v4 → v7.0.2; `pypa/gh-action-pypi-publish` and
  `TrustSource/ts-scan-action` pinned as well.

## [0.2.0] - 2026-11-06

### Changed

- Text output: a table of all tests with checked components, OK components, percentage and failing lines, instead of
  one line per failing component and test. A test that fails for every component shows "all components"; long lists
  are shortened to the terminal width.

### Added

- Option `--details`: below the table, the findings of each failed test, grouped by message, with every affected
  component and its line.

## [0.1.0] - 2026-11-06

### Added

- Supported Python versions: 3.12 and newer (AWS Lambda currently offers 3.13 and 3.14).

- Python package `ts-sbom-checker` (import `ts_sbom_checker`), ported from the JavaScript implementation of the
  TrustSource SBOM quality Lambda (`eacg-gmbh/ts-lambda`, `sbom-quality/`).
- Format detection and schema validation for CycloneDX 1.5 / 1.6 / 1.7 and SPDX 2.1 / 2.2 / 2.3 / 3.0.0 / 3.0.1 (JSON)
  against the bundled official schemas, with line numbers and noise reduction for `oneOf` / `anyOf`.
- 24 tests according to BSI TR-03183-2 v2.1.0 (6 document tests, 18 component tests), each failure with component,
  `ref` and line number.
- Library API `check_sbom()` returning `(status_code, report)` with the report format of the Lambda, `preload()` for
  Lambda init phases and a `log.step()` hook.
- Command `ts-sbom-checker` with text and JSON output, `--fail-on`, `--max-failures`, `--max-schema-errors`,
  `--max-bytes`, stdin support and exit codes 0 / 1 / 2.
- CI workflow (ruff, pytest on Python 3.12 to 3.14).
- Development tools (pytest, ruff, build) as dependency group `dev` (PEP 735), so they do not appear in the package
  metadata or in SBOM scans of the package.
- Release workflow: PyPI upload for tags `X.Y.Z`, with checks of tag, package version and changelog entry.
- TrustSource dependency scan workflow (project `ts-sbom-checker`).
- Bandit workflow: SARIF result imported into TrustSource (`/core/tests/sarif`) on pushes to `main`.
- Cross-check against the original text of TR-03183-2 v2.1.0 and the BSI property taxonomy v0.1.2:
  - SPDX 3: the SBOM-URI is taken from the `spdxId` of the `software_Sbom` (TR table 10), the `SpdxDocument` is only
    the fallback.
  - CycloneDX: `bsi:component:effectiveLicence` must occur at most once per component (`licence-identifiers`).
  - CycloneDX: hint for the deprecated `bsi:component:associatedLicences` (TR v2.0.0).
  - Report note on the transitional rule (TR section 7) for CycloneDX 1.5, SPDX 2.2 / 2.3 and SPDX 3.0.0.
  - README: XML is permitted by the TR but not read; logical primary components; notes on the TR text.

[Unreleased]: https://github.com/TrustSource/ts-sbom-checker/compare/0.2.0...HEAD
[0.2.0]: https://github.com/TrustSource/ts-sbom-checker/compare/0.1.0...0.2.0
[0.1.0]: https://github.com/TrustSource/ts-sbom-checker/releases/tag/0.1.0
