# Test architecture

## Suite taxonomy

Pytest markers are strict and describe the strongest boundary a test crosses:

| Marker | Contract |
| --- | --- |
| `unit` | Hermetic in-process behavior without service, subprocess, or platform dependency. |
| `contract` | Serialization, compatibility, adapter, or protocol boundary. |
| `replay` | Deterministic recorded output or persisted snapshot. |
| `integration` | Multiple components or a real process boundary. |
| `slow` | Intentionally expensive and excluded from the fast loop. |
| `external` / `external_tools` | Separately managed service, scanner, browser, or executable. |
| `security` | Scope, authorization, policy, redaction, secret, or process boundary. |
| `benchmark` | Versioned scenario/harness/aggregation contract. |
| `mysql` / `platform` | Live MySQL/MariaDB or operating-system-specific behavior. |

Tests may carry multiple markers. An external dependency must never be hidden
inside an unmarked unit/contract test.

## Pipeline domain split

The former `tests/test_pipeline_quality.py` monolith is physically removed.
Its characterization coverage is preserved in focused modules for reporting,
planning, parser families, target-model replay, command decisions, action
providers, pipeline state, execution scope, credentials/access, follow-ups, and
miscellaneous compatibility behavior.

Shared fixtures in `tests/conftest.py` construct canonical successful and
partial execution results. Prefer those fixtures over ad-hoc result doubles.
Each test owns its temporary database/config/environment; process-global
registries must be restored by fixtures.

## Critical branches

Review emphasizes behavior, not aggregate coverage percentage. Required
branches include:

- target normalization, scope, policy, capability, and final authorization;
- secret/reference redaction through result, fact, trace, and report paths;
- assessment promotion/contradiction and verified report separation;
- mission/task transitions, crash interruption, idempotent resume, and retry;
- graph identity, provenance, projection replay, and verified-path gaps;
- provider fallback only for typed retryable/unavailable/timeout results;
- action native-result adapters, verification, and cleanup independence;
- SQLite concurrent first-write/event idempotency and bounded retention.

## Local selections

```bash
# Fast hermetic feedback
venv/bin/python -m pytest -q -m "not slow and not external and not external_tools and not mysql and not platform"

# Security and replay contracts
venv/bin/python -m pytest -q -m security
venv/bin/python -m pytest -q -m replay

# Benchmark contract only
venv/bin/python -m pytest -q tests/benchmark -m benchmark

# Complete configured suite
venv/bin/python -m pytest -q
```

Use `venv/bin/python -m pytest`; a copied virtual environment may contain stale
console-script shebangs even when its Python interpreter is valid.

External tests must state prerequisites and safe target fixtures. They are not
part of replay benchmarks and must never default to a public target.
