# OCTOPUS test baseline

Baseline date: 2026-07-14

Git revision: `7a402f4`
Worktree note: two pre-existing dirty vendor submodules were present; the
baseline was therefore not claimed as a pristine checkout.

## Environment

| Component | Observed value |
|---|---|
| Host | macOS 14.2.1 (23C71), arm64 |
| Python | CPython 3.9.6, Clang 15.0.0 |
| TLS library | LibreSSL 2.8.3 |
| pytest | 8.4.2 |
| pip health for installed distributions | `No broken requirements found` |

The local venv contained `mysql-connector-python==9.4.0`.  Absence of the
optional connector is nevertheless covered by a regression test that starts
an isolated Python process and blocks all `mysql` imports.

The active runtime + dev profiles contain 36 applicable direct requirements on
Python 3.9.  The existing venv has 24 of them and is missing 12:
`rich`, `pycryptodome`, `PySocks`, `beautifulsoup4`, `lxml`, `soupsieve`,
`markdown-it-py`, `mdurl`, `litellm`, `chromadb`, the Python-3.9 `ddgs<9.8`
requirement, and `paramiko`.  Consequently, `pip check` only proves consistency
of installed distributions; it does not prove completeness against
`requirements/test.txt`.

## Pre-Phase-0.1 baseline

Collection command:

```bash
venv/bin/python -m pytest --collect-only -q
```

Result:

```text
381 tests collected in 14.10s
```

Full-suite command:

```bash
venv/bin/python -m pytest -q
```

Result:

```text
381 passed, 1 warning in 191.11s (0:03:11)
```

These exact Phase 0.1 commands used the existing venv with no `PYTHONPATH` set.
There were no failures and no skips because optional imports are guarded; this
must not be read as proof that `requirements/test.txt` has been installed.  The
one warning was urllib3's
`NotOpenSSLWarning` for the macOS Python's LibreSSL 2.8.3 linkage.  It is an
environment warning, not a test skip, and remains visible.

Existing project-wide Mac runs may also use the following non-hermetic fallback
while the venv is incomplete:

```bash
PYTHONPATH=/Users/admin/Library/Python/3.9/lib/python/site-packages venv/bin/python -m pytest -q
```

Results from that fallback must be labelled separately because they can import
packages outside the venv.

## Post-Phase-0.1 local fast selection

Phase 0.1 adds one regression test for import behavior without the optional
MySQL connector.  A post-change collection found 382 tests in 8.69 seconds.

Focused optional-DB boundary check:

```bash
venv/bin/python -m pytest -q tests/test_db.py
```

```text
14 passed in 5.12s
```

Fast selector executed in the same incomplete local venv:

```bash
venv/bin/python -m pytest -q -m '(unit or contract) and not slow and not external_tools and not mysql and not platform'
```

```text
366 passed, 16 deselected, 1 warning in 34.23s
```

The 16 deselections are intentional and are not hidden skips:

- 10 C2 cryptographic/protocol tests marked `contract` + `slow`;
- 6 plugin worker-process tests marked `integration`.

The complete post-change suite was also rerun in that same local venv:

```bash
venv/bin/python -m pytest -q
```

```text
382 passed, 1 warning in 62.21s (0:01:02)
```

## Coverage baseline

Coverage was measured with branch tracking over the complete first-party
Python tree. Tests, the local venv, vendor submodules, and generated `data/`
content are excluded from the denominator; unexecuted first-party modules are
included at zero coverage.

```bash
venv/bin/python -m coverage erase
venv/bin/python -m coverage run --branch --source=. -m pytest -q
rg --files -g '*.py' -g '!tests/**' -g '!venv/**' -g '!vendor/**' -g '!data/**' -0 \
  | xargs -0 venv/bin/python -m coverage report --precision=2
```

```text
382 passed, 1 warning in 73.96s (0:01:13)
TOTAL  24872 statements  13919 missed  9248 branches  1121 partial  42.71%
```

This is the honest repository-wide baseline for the current checkout. There is
no coverage gate yet, and Phase 0.1 does not claim to improve this percentage.

There are currently no live `mysql`, `external_tools`, or `platform` tests in
the collected suite.  When such tests are added, they must have explicit skip
reasons if their provisioned dependency is unavailable.

## Failure and skip accounting

| Category | Count | Reason |
|---|---:|---|
| Failed | 0 | No baseline failures |
| Skipped | 0 | No implicit environment skips |
| Fast-suite deselected | 16 | Explicit marker selection described above |
| Environment collection failures | 0 | Optional integrations do not break collection |

## Clean-environment proof status

`requirements/test.txt` now defines the intended clean test environment, but a
fresh install of that file was not completed in this network-restricted macOS
session.  Therefore Phase 0.1 proves collection and test behavior with missing
optional packages, but the clean-install acceptance item remains **pending
Linux/clean-venv evidence**.  Do not relabel the local numbers above as
hermetic.

## Commands for later Linux evidence

Run these unchanged on the Linux test host and append a dated section with the
host/Python versions and exact output; do not overwrite this macOS baseline:

```bash
python -m pip install -r requirements/test.txt
python -m pip check
python -m pytest --collect-only -q
python -m pytest -q -m '(unit or contract) and not slow and not external_tools and not mysql and not platform'
python -m pytest -q
```

## Wave 6 local verification (2026-07-15)

After the domain split, report/decision contracts, benchmark harness, and
release cleanup, the complete configured suite was rerun with the repository
virtual-environment interpreter:

```bash
venv/bin/python -m pytest -q
```

```text
699 passed, 1 warning in 154.68s (0:02:34)
```

There were no failures or skips. The one warning is urllib3's
`NotOpenSSLWarning` because this macOS Python 3.9.6 build links LibreSSL 2.8.3;
it is an environment limitation, not a suppressed test failure. This result is
a local verification snapshot and does not replace the pending clean-Linux
evidence above.

Use `venv/bin/python -m pytest`, not the copied `venv/bin/pytest` console
script: the latter can retain an absolute shebang from the directory where the
virtual environment was originally created.

## Mission/assessment completion verification (2026-07-16)

After durable typed retries, bounded state-change replanning, configurable task
scoring, versioned assessment correctness, production exploit applicability,
the built-in benchmark runner, and the final pipeline extraction were
integrated, the complete configured suite was rerun:

```bash
venv/bin/python -m pytest -q
```

```text
759 passed, 1 warning in 192.22s (0:03:12)
```

There were no failures or skips. The single warning remains the environment's
documented urllib3/LibreSSL warning. The same worktree also passed repository-
wide Ruff, the configured 50-file mypy gate, compileall, `pip check`, and
`git diff --check`; all ten hermetic benchmark scenarios completed five
repetitions, and the regenerated no-op/repeat comparison was byte-identical to
the checked-in artifact.

## Competitor benchmark matrix verification (2026-07-16)

After the versioned external-system manifest, bounded command adapter, fair
matrix runner, checksummed publication writer, and CLI end-to-end contracts
were added, the complete configured suite was rerun:

```text
venv/bin/python -m pytest -q
776 passed, 1 warning in 184.17s (0:03:04)
```

The focused benchmark suite reported `28 passed`. Repository-wide Ruff,
compileall, `pip check`, and `git diff --check` remained clean; the configured
mypy ratchet reported no issues across 55 source files. The single warning is
the previously documented urllib3/LibreSSL environment warning.
