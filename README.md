# ts-sbom-checker

Checks a Software Bill of Materials (SBOM) against

1. the **JSON schema** of its format: CycloneDX 1.5 / 1.6 / 1.7 or SPDX 2.1 / 2.2 / 2.3 / 3.0 (JSON only), and
2. the requirements of **BSI TR-03183-2 v2.1.0**: 24 tests, one per requirement. Component tests run for every component,
   and every failure names the component, its identifier (`ref`) and the **line number** in the input file.

> **Not an official tool of the BSI.** ts-sbom-checker is an open source project by [TrustSource](https://www.trustsource.io)
> (EACG GmbH). It implements our reading of the Technical Guideline; the BSI has neither reviewed nor endorsed it.

## Why

The EU Cyber Resilience Act (CRA) makes SBOMs mandatory for products with digital elements. In Germany, the BSI's
Technical Guideline [TR-03183-2](https://www.bsi.bund.de/dok/TR-03183) describes what such an SBOM has to contain:
format and version, creator, timestamp, and for every component creator, name, version, filename, dependencies,
licences, SHA-512 hash and a few properties. ts-sbom-checker makes these requirements checkable in a build pipeline,
with findings that point to the exact line of the SBOM.

## Installation

```bash
pip install ts-sbom-checker        # library and command
pipx run ts-sbom-checker sbom.json # without installation
uvx ts-sbom-checker sbom.json      # without installation
```

Python 3.10 or newer is required.

## Usage

```
ts-sbom-checker FILE [FILE ...]     # "-" reads from stdin

  --format text|json                 text (default) or the JSON report; a list for several files
  -o, --output FILE                  write to FILE instead of stdout
  --fail-on non-compliant|schema|never
                                     when to exit with 1 (default: non-compliant)
  --max-failures N                   list at most N failures per test (default: unlimited)
  --max-schema-errors N              list at most N schema errors (default: unlimited)
  --max-bytes N                      reject files larger than N bytes (default: unlimited)
  --version
```

Examples:

```bash
ts-sbom-checker sbom.cdx.json
ts-sbom-checker --format json -o report.json sbom.spdx.json
cyclonedx-npm | ts-sbom-checker -
ts-sbom-checker --fail-on schema build/*.json      # only fail on schema errors
```

Text output (shortened):

```
sbom.spdx.json: SPDX 2.3 - NOT COMPLIANT with BSI TR-03183-2 v2.1.0
  24 tests: 13 passed, 9 failed, 2 not applicable; 2 components checked

  FAIL  format-version                  TR 4
  PASS  sbom-creator                    TR 5.2.1
  FAIL  component-filename              TR 5.2.2           [1 failed / 2 checked, 0 n/a]
  ...
  component-filename (1 failure(s))
    line 33: util (SPDXRef-util): filename "lib/util-1.4.2.jar" contains a path; only the filename is allowed
```

### Exit codes

| Code | Meaning |
|---|---|
| 0 | All files compliant (or nothing to fail on, see `--fail-on`) |
| 1 | At least one file not compliant or schema invalid (`--fail-on non-compliant`), or schema invalid (`--fail-on schema`) |
| 2 | Input error: unreadable file, empty file, invalid JSON or encoding, unknown format or version, larger than `--max-bytes` |

An input error takes precedence over 1.

## Supported formats

| Format | Versions | Schema | TR-compliant possible |
|---|---|---|---|
| CycloneDX JSON | 1.5, 1.6, 1.7 | official `bom-1.x.schema.json` | 1.6 and 1.7 |
| SPDX 2 JSON | 2.1, 2.2, 2.3 | official 2.2 / 2.3 schema (2.1 is validated against 2.2) | no, the TR requires SPDX 3.0.1 or newer |
| SPDX 3 JSON-LD | 3.0.0, 3.0.1 | official 3.0.1 schema (3.0.0 is validated against it with the `@context` replaced) | 3.0.1 |

All schemas are bundled; nothing is downloaded at runtime. Older versions are checked completely so you can see what
would be missing after a migration, but they always fail `format-version`.

## The tests

Category **required**: mandatory field of the TR (sections 4, 5.2.1, 5.2.2, 6.1). Category **additional**: fields of
TR 5.2.3 / 5.2.4 that are only required "if they exist". Whether they exist cannot be known from the file, so they are
checked (syntax) only when present; a component without the field counts as `notApplicable`. A failing additional
test still makes the SBOM non-compliant.

The CycloneDX and SPDX 3 columns follow the mapping of TR appendix 8.2. The SPDX 2 column is our own approximation.

### Document tests

| ID | TR | Cat. | Check | CycloneDX | SPDX 3 | SPDX 2 |
|---|---|---|---|---|---|---|
| `format-version` | 4 | required | Format version permitted by the TR | `specVersion` ≥ 1.6 | ≥ 3.0.1 | always fails |
| `sbom-creator` | 5.2.1 | required | SBOM creator with email or URL | `metadata.manufacturer` `url[]` / `contact[].email` | `CreationInfo.createdBy` → agent with `externalIdentifier` `email` / `urlScheme` | `creationInfo.creators` with email in parentheses |
| `sbom-timestamp` | 5.2.1 | required | Valid RFC 3339 timestamp | `metadata.timestamp` | `CreationInfo.created` | `creationInfo.created` |
| `primary-component` | 3.2.1 | required | Primary component declared | `metadata.component` | `software_Sbom.rootElement` → `software_Package` | `documentDescribes` / `DESCRIBES` |
| `no-vulnerabilities` | 3.1, 8.1.14 | required | No vulnerability information | no `vulnerabilities[]` | no `security_*` elements | always passes |
| `sbom-uri` | 5.2.3 | additional | SBOM URI is a valid absolute ASCII URI | `serialNumber` | `spdxId` of `SpdxDocument` / `software_Sbom` | `documentNamespace` (no `#`) |

### Component tests

| ID | TR | Cat. | Check | CycloneDX | SPDX 3 | SPDX 2 |
|---|---|---|---|---|---|---|
| `component-creator` | 5.2.2 | required | Creator with email or URL | `manufacturer` `url[]` / `contact[].email` | `originatedBy` → agent with `email` / `other` identifier | `originator` with email |
| `component-name` | 5.2.2 | required | Name not empty | `name` | `name` | `name` |
| `component-version` | 5.2.2 | required | Version not empty | `version` | `software_packageVersion` | `versionInfo` |
| `component-filename` | 5.2.2 | required | Filename present once, without path | property `bsi:component:filename` | `name` of the `software_File` (`hasDistributionArtifact`) | `packageFileName` |
| `component-dependencies` | 5.2.2 | required | Dependencies enumerated (an empty list counts) | entry in `dependencies[]` | `dependsOn` / `contains` relationship (`NoneElement` if none) | `DEPENDS_ON`, `CONTAINS`, `STATIC_LINK`, `DYNAMIC_LINK` or inverse (`NONE` if none) |
| `dependency-completeness` | 5.2.2 | required | Completeness of the dependencies indicated | listed in `compositions[]` with an `aggregate` | `completeness` on every dependency relationship | only via target `NONE` / `NOASSERTION` |
| `dependency-reachable` | 5.1 | required | Reachable from the primary component | `dependencies[]` and nested `components[]` | `dependsOn` / `contains` | `DEPENDS_ON` / `CONTAINS` / `DESCRIBES` |
| `component-distribution-licence` | 5.2.2 | required | Distribution licence given | `licenses[]` with `acknowledgement: "concluded"` | `hasConcludedLicense` | `licenseConcluded` |
| `component-hash-sha512` | 5.2.2 | required | SHA-512 of the deployable artefact | `externalReferences[type=distribution].hashes` | `verifiedUsing` of the `software_File` | `checksums[SHA512]` |
| `component-executable` | 5.2.2 | required | Property executable / non-executable | property `bsi:component:executable` exactly once | `software_File` present | not expressible, fails |
| `component-archive` | 5.2.2 | required | Property archive / no archive | property `bsi:component:archive` exactly once | `software_File` present | not expressible, fails |
| `component-structured` | 5.2.2 | required | Property structured / unstructured | property `bsi:component:structured` exactly once | `software_additionalPurpose` contains `container` or `firmware` | not expressible, fails |
| `licence-identifiers` | 6.1 | required | Distribution and effective licence are SPDX IDs or expressions | concluded licences, property `bsi:component:effectiveLicence` | linked `simplelicensing_LicenseExpression` | `licenseConcluded` |
| `component-source-uri` | 5.2.4 | additional | Source code URI valid | `externalReferences[type=source-distribution].url` | `sourceArtifact` ref of the source artefact (`generates`) | not applicable |
| `component-download-uri` | 5.2.4 | additional | Download URI valid | `externalReferences[type=distribution].url` | `binaryArtifact` ref of the file, `software_downloadLocation` | `downloadLocation` |
| `component-identifiers` | 5.2.4 | additional | purl, CPE 2.2/2.3, SWID syntactically valid | `purl`, `cpe`, `swid.tagId` | `externalIdentifier` `packageUrl`, `cpe22`, `cpe23`, `swid` | `externalRefs` `purl`, `cpe22Type`, `cpe23Type`, `swid` |
| `component-original-licences` | 5.2.4, 6.1 | additional | Original licences are SPDX IDs or expressions | `licenses[]` with `acknowledgement: "declared"` | `hasDeclaredLicense` | `licenseDeclared` |
| `component-bom-reference` | 3.2.5, 8.1.16 | additional | URL of a referenced BOM valid | `externalReferences[type=bom].url` | `externalRef` of the describing `software_Sbom` | not applicable |

Notes on the mapping:

- The mapping follows TR appendix 8.2 strictly: a SHA-512 in `components[].hashes` instead of the distribution reference,
  or a licence without `acknowledgement`, fails, and the message names the expected place.
- **Referenced components** (TR 3.2.5: CycloneDX `externalReferences[type=bom]`, SPDX 3 a further `software_Sbom` that
  `describes` the package) only need creator, name and version; only `component-creator`, `component-name`,
  `component-version`, `dependency-reachable` and `component-bom-reference` run for them. The referenced SBOM is not
  loaded.
- Both spellings are accepted where the TR and the format differ: `bsi:component:effectiveLicence` / `…License`,
  `simplelicensing_` / `simpleLicensing_`, `externalIdentifier` / `externalIdentifiers`.
- Licence identifiers come from the SPDX licence list bundled with CycloneDX (`spdx.schema.json`), case-insensitive.
  `LicenseRef-…`, `DocumentRef-…:LicenseRef-…` and `AdditionRef-…` are allowed; `AND` / `OR` / `WITH` must be upper or
  lower case.

## Report format

`--format json` (and the library) return the report below. It is identical to the report of the TrustSource SBOM
quality service.

```json
{
  "ok": true,
  "format": { "type": "CycloneDX", "specVersion": "1.6" },
  "schemaValid": true,
  "schemaErrors": [],
  "notes": ["..."],
  "summary": {
    "tr": "BSI TR-03183-2 v2.1.0",
    "compliant": false,
    "componentsChecked": 42,
    "testsTotal": 24, "testsPassed": 19, "testsFailed": 3, "testsNotApplicable": 2,
    "tests": [
      { "id": "component-version", "tr": "5.2.2", "title": "Component version", "category": "required",
        "scope": "component", "status": "failed", "passed": false,
        "checked": 42, "succeeded": 40, "failed": 2, "notApplicable": 0 }
    ]
  },
  "failures": {
    "component-version": {
      "total": 2, "truncated": false,
      "items": [
        { "component": "lodash", "ref": "pkg:npm/lodash@4.17.21", "line": 123, "message": "version is missing" }
      ]
    }
  }
}
```

- `status` per test: `passed`, `failed` or `notApplicable`; `testsPassed + testsFailed + testsNotApplicable = testsTotal`.
- At most one failure per test and component; `failures` only lists failed tests. Document tests use `"component": "(SBOM)"`.
- `line` (1-based): the line of the faulty field; for a missing field the line where the component object starts.
- If the schema is invalid, the report has `schemaValid: false`, `schemaErrors` (`line`, `path`, `message`),
  `schemaErrorsTotal`, `schemaErrorsTruncated`, an empty test list and `compliant: false`.
- Input errors produce `{"ok": false, "error": "empty_body" | "invalid_json" | "unknown_format" | "unsupported_version" | "too_large" | "unreadable_file", "message": "..."}`
  (`line` for `invalid_json`, `maxBytes` / `actualBytes` for `too_large`).

## Use in CI

GitHub Actions:

```yaml
- uses: actions/setup-python@v5
  with:
    python-version: "3.13"
- run: pipx run ts-sbom-checker --format json -o sbom-check.json sbom.cdx.json
```

GitLab CI:

```yaml
sbom-check:
  image: python:3.13-slim
  script:
    - pip install ts-sbom-checker
    - ts-sbom-checker sbom.cdx.json
```

## Use as a library

```python
from ts_sbom_checker import check_sbom, preload

preload()  # optional: build all schema validators up front (e.g. in the init phase of an AWS Lambda)

status, report = check_sbom(open("sbom.json", "rb").read(), max_failures=1000, max_schema_errors=100)
if status == 200 and report["summary"]["compliant"]:
    ...
```

`check_sbom(data, max_failures=1000, max_schema_errors=100, max_bytes=None, log=None)` accepts `str` or UTF-8 `bytes`
and returns `(status_code, report)` with HTTP semantics: 200 report, 400 input error, 413 too large. `None` disables a
limit. `log` is any object with a `step(description)` method; every processing step is announced there. The function
does no I/O and prints nothing.

## Limitations

These requirements of the TR cannot be checked from the file alone:

- the depth of the recursive resolution down to the first component outside the scope of delivery (TR 5.1);
  `dependency-reachable` only finds gaps in the graph,
- separate listing of several instances with different metadata (TR 5.1),
- whether version, licence and properties are correct,
- whether an "additional" field exists (TR 5.2.3, 5.2.4),
- conformance of referenced SBOMs (TR 5.1, 8.1.16),
- whether a component is a logical (TR 3.2.2) or merely identified (TR 3.2.4) component; all are checked like fully
  described components.

## Contributing

Issues and pull requests are welcome. Please run the checks before opening a pull request:

```bash
pip install --group dev -e .   # pip >= 25.1
ruff check src tests
pytest
```

Every TR test has at least one targeted failure case in `tests/` that checks component and line number; please keep it
that way. The TR text itself is not part of the repository.

## Licence

Apache-2.0, see [LICENSE](LICENSE). The bundled schemas are third-party works under their own licences, see
[NOTICE](NOTICE).
