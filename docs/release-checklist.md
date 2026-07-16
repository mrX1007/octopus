# Release readiness checklist

## Scope and provenance

- [ ] Release revision, version, changelog, and schema/protocol versions are
      recorded independently.
- [ ] Working tree contains only intentional first-party changes; vendor
      submodule SHAs and trust-manifest hashes are reviewed.
- [ ] No generated DB, secret, raw prompt/stdout, external-tool artifact, or
      operator target data is included.
- [ ] Dependency locks reproduce in the supported clean Python/platform matrix.

## Persistence and migration

- [ ] Backups include every authoritative database and SQLite WAL/SHM files.
- [ ] Fact/assessment/mission/graph/telemetry/decision stores open from previous
      fixtures and reject unsupported explicit versions.
- [ ] Duplicate fact ingestion, assessment transition, graph projection,
      decision event, and mission resume remain idempotent after restart.
- [ ] `PRAGMA integrity_check` and relevant foreign-key checks pass.
- [ ] Forward migration, validation, rebuildable-store policy, and full restore
      rollback are documented and rehearsed.

## Security boundaries

- [ ] Scope and capability checks execute at the final action boundary.
- [ ] Security tests cover command/target normalization, active authorization,
      policy denial, cancellation/process-tree cleanup, and plugin isolation.
- [ ] A canary secret is absent from facts, missions, graph, command results,
      telemetry, decision trace, reports, logs, and benchmark aggregates.
- [ ] Verified report items all contain assessment reason, evidence chain, and
      source execution IDs; access/candidates remain separate.
- [ ] Clean-negative and contradiction scenarios emit no verified vulnerability.
- [ ] Broad exception catches in changed critical paths are narrowed or
      explicitly documented at an isolation boundary.
- [ ] Production placeholders, simulated results/payloads, and unsafe default
      targets were removed or are clearly test-only fixtures.

## Verification commands

```bash
venv/bin/ruff check .
venv/bin/mypy
PYTHONPYCACHEPREFIX=/tmp/octopus-pyc venv/bin/python -m compileall -q core octopus.py msf.py
venv/bin/python -m pytest -q
venv/bin/python -m pytest -q -m security
venv/bin/python -m pytest -q -m replay
venv/bin/python -m pytest -q tests/benchmark -m benchmark
venv/bin/python -m core.benchmarks --comparison-only
```

- [ ] The complete suite passes from the release dependency profile.
- [ ] External/MySQL/platform selections either pass in their declared
      environment or are listed as unverified release limitations.
- [ ] No new warnings or skips are unexplained.

## Benchmark evidence

- [ ] All ten schema `1.0` scenarios load with pinned lab, target, model, tool,
      strategy, seed, budgets, actions, ground truth, and artifacts.
- [ ] Each published scenario has at least five repetitions.
- [ ] Median and population variance are present; invalid/failed runs are not
      silently included in successful metrics.
- [ ] `benchmarks/results/noop-repeat-comparison-v1.json` exactly matches
      `venv/bin/python -m core.benchmarks --comparison-only`; its schema,
      scenario version, metric definitions, configured weights, selection
      records, and content-derived ID are present.
- [ ] The published no-op/repeated-task reductions are labeled as deterministic
      planner-frontier replay measurements, not external scanner performance.
- [ ] Ablations use only explicitly stable, tested toggles.

## Documentation and handoff

- [ ] System map, ownership contracts, duplication matrix, ADRs, authoring
      guides, schemas/migrations, threat model, and CONTRIBUTING match the code.
- [ ] Compatibility aliases and deprecated wrappers have an owner, telemetry or
      usage evidence, replacement, and removal condition.
- [ ] Operator-facing configuration changes and safe defaults are documented.
- [ ] Restore, cancellation, partial-result, cleanup-failure, and degraded
      provider behavior are included in the release notes.
