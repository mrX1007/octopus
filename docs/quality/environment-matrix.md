# OCTOPUS environment matrix

Baseline date: 2026-07-24.

## Python support policy

OCTOPUS supports **CPython 3.10 through 3.12**. Python 3.10 is the packaging,
static-analysis, integration, and release baseline; the hermetic test matrix
also proves Python 3.11 and 3.12. A version is not considered supported merely
because the source parses on it.

| CPython | Status | Evidence / action |
|---|---|---|
| 3.9 | Unsupported | Upstream support ended; current security-fixed dependencies require Python 3.10+ |
| 3.10 | Supported baseline | Full CI, packaging, static analysis, integration jobs, and dependency audit |
| 3.11 | Supported | Hermetic test matrix and target-specific lock |
| 3.12 | Supported | Hermetic test matrix and target-specific lock |
| 3.13+ | Not supported | No target-specific lock or test-matrix evidence |

Changing the supported range requires a green CI matrix, target-specific locks,
and an updated copy of this document. Production and release checks use
CPython 3.10.

## Host platform status

| Host | Status | Notes |
|---|---|---|
| Ubuntu 22.04, x86_64 | Deployment/CI target | All CI jobs and Linux dependency locks target this environment |
| macOS 14, Apple Silicon | Development host | Use a managed CPython 3.10–3.12 environment; the system CPython 3.9 is not a supported project runtime |
| Windows host runtime | Not certified | No host-runtime CI or baseline is present; do not infer support from target/agent code |

The local macOS Python is linked against LibreSSL 2.8.3.  urllib3 2.x emits a
`NotOpenSSLWarning`; this is recorded in the baseline rather than suppressed.
Linux CI should use the OpenSSL-linked Python supplied by `actions/setup-python`.

## Dependency profiles

Dependencies are split without changing the legacy full-install command.

| File | Purpose | Included by hermetic tests |
|---|---|---:|
| `requirements/runtime.txt` | Mandatory Python runtime libraries | yes |
| `requirements/c2.txt` | Cryptographic and C2 protocol support exercised by contracts | yes |
| `requirements/reporting.txt` | Reporting support exercised by contracts | yes |
| `requirements/dev.txt` | pytest, coverage, Ruff, and mypy | yes |
| `requirements/test.txt` | One-file installer matching the locked runtime + C2 + reporting + dev test profile | n/a |
| `requirements/mysql.txt` | Optional MariaDB/MySQL connector | no |
| `requirements/external-tools.txt` | Optional service/browser Python integrations | no |
| `requirements/platform.txt` | Reserved explicit platform profile; currently no unconditional wheel | no |
| `requirements.txt` | Backward-compatible full development profile | all profiles |

Native tools such as nmap, nuclei, ffuf, and Go/vendor binaries are deliberately
not pip dependencies.  Their presence must be validated by marked integration
or external-tool jobs, not by the hermetic unit job.

## Reproducible clean-environment commands

Create and populate an environment without MySQL, browser automation, Shodan,
or other optional integrations:

```bash
python3.10 -m venv venv
venv/bin/python -m pip install --upgrade pip
venv/bin/python -m pip install -r requirements/test.txt
```

After that clean install succeeds, run the fast hermetic selector with one
command:

```bash
venv/bin/python -m pytest -q -m '(unit or contract) and not slow and not external_tools and not mysql and not platform'
```

Run every locally collectible test, including slow contracts and process
integration tests:

```bash
venv/bin/python -m pytest -q
```

## Pytest marker contract

Markers are registered with `--strict-markers` in `pyproject.toml`:

- `unit`: hermetic in-process test;
- `contract`: compatibility, serialization, or protocol boundary;
- `integration`: crosses a process or component boundary;
- `slow`: intentionally excluded from the fast suite;
- `external_tools`: requires a separate scanner, browser, or service;
- `mysql`: requires a live MariaDB/MySQL deployment and connector profile;
- `platform`: depends on a particular host facility.

Unclassified existing hermetic tests receive `unit` during collection.  New
tests that cross a boundary must declare the appropriate non-unit marker.

The Phase 0.1 macOS result is not itself proof of a clean/hermetic install: the
existing venv predates this dependency split and is missing part of
`requirements/test.txt`.  Clean-environment installation remains to be proved
on the Linux test host (or in a newly created local venv with package access).

## Optional MySQL behavior

Importing `db` no longer requires `mysql-connector-python`.  A real database
operation still fails closed with an actionable `RuntimeError` pointing to
`requirements/mysql.txt`.  Mocked DB unit tests therefore collect without the
optional connector, while live DB tests must use `@pytest.mark.mysql` and be
run only in a provisioned job.
