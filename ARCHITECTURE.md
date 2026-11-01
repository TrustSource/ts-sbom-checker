# Architecture

## System overview

ts-sbom-checker checks an SBOM file in two stages:

1. **Schema validation:** is the file a valid CycloneDX 1.5-1.7 or SPDX 2.1-2.3 / 3.0 document (JSON)?
2. **TR tests:** only if the schema is valid, 24 tests according to BSI TR-03183-2 v2.1.0. All tests always run to
   completion; component tests run for every component.

The result is a JSON report (summary plus failures with component, `ref` and line number). The package is used in
two ways that share the same core:

- the command `ts-sbom-checker` (developers, CI pipelines),
- as a library inside the TrustSource SBOM quality Lambda (`eacg-gmbh/ts-lambda`, `sbom-quality/`), which accepts the
  SBOM as an HTTP body and returns the report.

The package stores nothing, has no network access at runtime and no database. All schemas are bundled.

Diagram: [ARCHITECTURE.drawio](ARCHITECTURE.drawio).

## Components

All modules live in `src/ts_sbom_checker/`.

| Module | Responsibility |
|---|---|
| `cli.py` | Command line: reads files / stdin as bytes, calls `check_sbom`, renders text or JSON, sets the exit code. The only module that imports `click` or does I/O. |
| `check.py` | `check_sbom()`: the pipeline below, input limits (empty, `max_bytes`), mapping of input errors to status 400 / 413, `log.step()` announcements. `preload()`. |
| `parse.py` | Strict JSON parsing (`json.loads`, no `NaN`/`Infinity`, UTF-8 BOM stripped) and `Locator`: line numbers for JSON paths via a lazy regex token scanner. |
| `detect.py` | Format and version detection, choice of schema (`Format`). |
| `schema.py` | Schema validation with jsonschema-rs, custom format checks, noise reduction for `oneOf`/`anyOf`, error messages with lines. |
| `model/` | Format-independent model (`Model`, `Document`, `Component`, …) and one mapper per format: `cyclonedx.py`, `spdx2.py`, `spdx3.py`. Every value carries the JSON path where it was found. |
| `tr03183/` | Test list (`TESTS`, order = report order) and runner; `checks/` holds one module per TR test, `helpers.py` shared check logic, `base.py` the `TrTest` / `Finding` types. |
| `syntax.py` | URI, email, purl, CPE checks and a parser for SPDX licence expressions (licence IDs from the bundled `spdx.schema.json`). |
| `report.py` | Builds the report (summary, failures with line numbers, notes). |
| `schemas/` | Official JSON schemas, unmodified (see NOTICE). |

## Data flow

```
bytes/str ─▶ check_sbom
              ├─ size / empty check ─────────────────────▶ 400 empty_body / 413 too_large
              ├─ parse.parse_sbom ─▶ (data, Locator) ─────▶ 400 invalid_json (with line)
              ├─ detect.detect_format ─▶ Format ──────────▶ 400 unknown_format / unsupported_version
              ├─ schema.validate_schema ─▶ invalid ───────▶ 200 report (schemaValid: false)
              ├─ model.build_model ─▶ Model
              ├─ tr03183.run_tests ─▶ [(TrTest, [Result])]
              └─ report.test_report (Locator for lines) ──▶ 200 report
```

Line numbers are only computed when a finding needs one; the `Locator` builds its index of value offsets on first
use, so compliant documents never pay for it.

## Key interfaces

- `check_sbom(data, max_failures=1000, max_schema_errors=100, max_bytes=None, log=None) -> (status_code, report)`.
  `data` is `str` or UTF-8 `bytes`; `None` limits are unlimited; `log` is any object with `step(str)`
  (e.g. `eacg_logutil.Log`). Unexpected errors are raised, so the caller decides how to report them (the Lambda turns
  them into 500 `internal_error`).
- `preload()`: builds all schema validators; meant for the init phase of a Lambda.
- The report format is a contract shared with the Lambda: `ok`, `format`, `schemaValid`, `schemaErrors`, `notes`,
  `summary` (with `tests`), `failures`; on schema errors additionally `schemaErrorsTotal`, `schemaErrorsTruncated`.
  Changing it is a breaking change (MAJOR).
- A TR test is a `TrTest(id, tr, category, scope, title, check, present=None, for_referenced=False)`; `check(subject,
  ctx)` returns a `Finding(message, path)` or `None`.

## Infrastructure and deployment

- Distribution: PyPI package `ts-sbom-checker` (sdist and wheel; pure Python, depends on jsonschema-rs which ships
  abi3 wheels for Linux x86_64/aarch64, macOS and Windows).
- CI: GitHub Actions `ci.yml` (ruff, pytest on Python 3.10-3.13, smoke test of the command).
- Release: `release.yml`, triggered by a tag `X.Y.Z` (without "v") or manually with an existing tag. It checks that
  tag, `pyproject.toml` version and a `CHANGELOG.md` entry match, runs the tests, builds sdist and wheel, smoke-tests
  the wheel and uploads to PyPI with the organisation secret `PYPI_TOKEN`. No Docker image is published.
- Dependency scan: `trustsource-scan.yml` runs `TrustSource/ts-scan-action@v1` on pushes to and pull requests against
  `main` and uploads to the TrustSource project `ts-sbom-checker` (organisation secret `TRUSTSOURCE_API_KEY`).
- Security linting: `bandit.yml` runs Bandit on `src` (pushes, pull requests, weekly) and writes SARIF. On pushes to
  `main`, scheduled and manual runs the SARIF is imported into TrustSource with `curl`:
  `POST <TS_API_BASE_URL>/core/tests/sarif` (base URL `https://api.trustsource.io/v2`, header `x-api-key`, query
  `projectName` / `moduleName` `ts-sbom-checker`, `branch`, `tag` = commit SHA). Pull requests only scan.
- Lambda: `eacg-gmbh/ts-lambda`, `sbom-quality/`, Python 3.13, `ts-sbom-checker==X.Y.Z` in `requirements.txt`,
  logging via the `ts-shared-logging` layer. The handler is not part of this repository.

Performance (local, Apple Silicon, Python 3.12): CycloneDX with 2 700 components (8.3 MB) 0.3 s; SPDX 3 with
2 000 packages (7.1 MB) 1.2 s; building all validators 0.03 s.

## Architecture Decision Records

### ADR-001: Port of the JavaScript Lambda logic into a standalone Python package

- **Date:** 2026-11-01 (0.1.0)
- **Context:** The SBOM quality check was first written as a Node.js Lambda in `eacg-gmbh/ts-lambda` (PR #28). It
  should also be published as an open source tool (CLI) for TrustSource and the BSI, and the Lambda should not
  maintain a second implementation.
- **Decision:** Port the logic 1:1 to Python as package `ts-sbom-checker`. The report format stays identical to the
  Lambda's. The Lambda will be switched to Python and use the package as a dependency. The 111 JavaScript unit tests
  were ported to pytest and extended.
- **Consequences:** One implementation for CLI and Lambda; fixes reach both. The report format becomes a public
  contract governed by semver. The Lambda needs a Python runtime.

### ADR-002: jsonschema-rs instead of the pure-Python jsonschema

- **Date:** 2026-11-01 (0.1.0)
- **Context:** The plan was to use `jsonschema` (with `referencing`). Measurements showed about 15 ms per SPDX 3
  element (1.2 s for a 14-element document): the SPDX 3 schema validates every `@graph` element with `anyOf` over
  ~80 element classes plus `unevaluatedProperties`, which `jsonschema` evaluates by re-descending all branches.
  Validating each element directly against the class named in its `type` still took 4-15 ms per element. With
  thousands of elements this exceeds the 29 s Lambda timeout. `fastjsonschema` only supports up to draft-07.
- **Decision:** Use [jsonschema-rs](https://github.com/Stranger6667/jsonschema) (Rust, MIT) for all formats. It
  supports draft-07 and 2020-12 including `unevaluatedProperties`, reports `oneOf`/`anyOf` branch errors with absolute
  instance paths (needed for the noise reduction) and accepts Python callbacks for custom formats. `uniqueItems` is
  linear in Rust, so the custom replacement needed with Ajv is unnecessary.
- **Consequences:** SPDX 3 documents with 2 000 packages validate in about 1 s. The package depends on a compiled
  extension; abi3 wheels (cp310+) exist for the relevant platforms, but Lambda packaging must install the Linux wheel
  (x86_64: `manylinux2014`, arm64: `manylinux_2_28`; both fit the python3.13 runtime on Amazon Linux 2023), e.g. via
  `sam build --use-container` or `pip install --platform manylinux_2_28_aarch64 --only-binary=:all:`. Error
  messages are generated from the error kind (jsonschema-rs embeds whole instances in its own messages).

### ADR-003: Line numbers via a lazy token scanner

- **Date:** 2026-11-01 (0.1.0)
- **Context:** Python's `json` module provides no positions. The JavaScript version used `jsonc-parser`.
- **Decision:** Parse with `json.loads` (strict) for the data, and compute value offsets with a small regex token
  scanner over the already validated text, only when the first line number is requested. A missing field reports
  the line of the nearest existing ancestor (the enclosing object). Invalid JSON reports `JSONDecodeError.lineno`.
- **Consequences:** No extra dependency; compliant documents skip the scan entirely; an 8 MB document is indexed in
  well under a second.

### ADR-004: Library designed for use in AWS Lambda

- **Date:** 2026-11-01 (0.1.0)
- **Context:** The same code runs in a CLI and behind API Gateway / a Function URL with a 29 s timeout and the EACG
  Lambda logging principle (intro line, announced steps, masking).
- **Decision:** `check_sbom` does no I/O, prints nothing and keeps no state except cached validators. It handles the
  input limits itself and returns HTTP status codes (200 / 400 / 413), so the handler is a thin adapter. Progress is
  reported through an optional `log.step()` object compatible with `eacg_logutil.Log`. `preload()` lets the handler
  build validators during the init phase. Only `cli.py` imports `click`. The handler with its logging stays in
  `ts-lambda`.
- **Consequences:** The Lambda handler reduces to reading the event, calling `check_sbom` and logging; it keeps its own
  unit test for the logging principle. Defaults for limits differ: unlimited in the CLI, 1000 / 100 in the library
  (as in the Lambda).
