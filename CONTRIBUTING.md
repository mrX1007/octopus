# Contributing to OCTOPUS

OCTOPUS accepts changes for authorized security assessment, defensive testing,
replay, reliability, and research workflows. Contributions must preserve scope,
policy, secret, evidence, and process-lifecycle boundaries.

## Development setup

```bash
python3 -m venv venv
source venv/bin/activate
python -m pip install --upgrade pip wheel
python -m pip install -r requirements.txt
```

Use `venv/bin/python -m ...` in scripts and local checks so a relocated virtual
environment cannot select a stale console-script shebang.

## Change rules

- Do not give a planner/model direct execution authority. Final deterministic
  policy authorization stays immediately before execute.
- Add provider behavior through the existing runtime/action adapter seams; do
  not introduce a parallel dispatcher, fact store, graph authority, or result
  type.
- Facts are evidence, assessments are judgements, and graph/model/report data
  are projections. A success exit or CVE string is not verification.
- Use typed argv. Shell execution requires its explicit managed policy boundary.
- Bound process lifetime/output and preserve partial output on timeout or
  cancellation.
- Persist secret references or redacted values. Never put plaintext secrets in
  commands, fixtures, logs, exceptions, facts, events, reports, or benchmark
  artifacts.
- Keep public aliases only with a compatibility test and deprecation/removal
  condition. Usage search alone is not proof that external callers do not exist.
- Preserve unrelated working-tree and vendor/submodule changes.

## Tests

Add the narrowest test that proves the changed contract. Mark tests using the
strict taxonomy in `docs/quality/test-architecture.md`. Unit, contract, replay,
and benchmark tests must be hermetic and use injected runners/providers; they
must not contact a public target or launch an installed security scanner.

```bash
venv/bin/python -m pytest -q -m "not slow and not external and not external_tools and not mysql and not platform"
venv/bin/python -m pytest -q -m security
venv/bin/python -m pytest -q -m replay
venv/bin/python -m pytest -q tests/benchmark -m benchmark
venv/bin/python -m pytest -q
```

For parsers, adapters, report changes, persistence migrations, and benchmarks,
follow the corresponding guide under `docs/guides/`. Migration tests must
include an old-version fixture, restart/idempotency, and rollback documentation.

## Static checks

```bash
venv/bin/ruff check .
venv/bin/mypy
PYTHONPYCACHEPREFIX=/tmp/octopus-pyc venv/bin/python -m compileall -q core octopus.py msf.py
```

Do not silence a warning globally to land one change. Narrow exclusions require
a reason and owner in the baseline documentation.

## Documentation and review

Update architecture ownership, an ADR, schema/version documentation, threat
model, authoring guide, or release checklist whenever the corresponding
contract changes. Pull requests should state:

- intended behavior and authorization assumptions;
- compatibility/migration impact;
- evidence for tests and static checks;
- new subprocess, network, secret, storage, plugin, or model boundaries;
- cleanup/rollback behavior.

Avoid committing generated databases, secrets, benchmark outputs, unbounded
tool logs, or local environment files.
