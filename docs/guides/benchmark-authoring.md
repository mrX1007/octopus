# Benchmark scenario authoring guide

Benchmarks are deterministic, replay-first experiments. The default harness
executes built-in in-process replays for the ten catalog categories and never
launches an external scanner. A caller can still inject a custom runner.

## Scenario contract

Add one JSON document under `benchmarks/scenarios/` conforming to
`docs/schemas/benchmark-scenario-v1.schema.json`. Use schema version `1.0` and a
stable lowercase identifier. Pin:

- lab and target version/fixture reference;
- model provider, name, and parameters;
- relevant tool/component versions;
- strategy configuration and seed;
- tool/time/output budgets;
- exact allowed actions;
- expected and forbidden findings;
- input and output artifact references.

Set at least five repetitions. The harness increments the declared seed for
each repetition and publishes median, population variance, minimum, maximum,
and count for successful-run metrics. Failed runner exceptions retain only the
exception class.

## Runner output

The built-in runner and any injected runner return a mapping with optional
`status`, `actions`, `metrics`, `reported_findings`, `verified_findings`,
`coverage_gaps`, `artifact_refs`, and `duration_seconds`. Any action outside
`allowed_actions` makes the run invalid.

Adding a new category to the default catalog also requires a hermetic handler in
`core/benchmarks/builtin_runner.py` and a contract test. A scenario intended only
for a custom integration runner should not be added to the required default
catalog.

Ablations are allowed only for toggle names explicitly passed as stable to the
harness. Do not add a speculative ablation for behavior that cannot yet be
enabled and disabled through a tested configuration contract.

## Review checklist

- Ground truth distinguishes expected, forbidden, and empty-negative results.
- Replay artifacts are immutable or content-addressed.
- No plaintext credential, raw prompt, raw exception, or unbounded stdout is
  stored.
- Budgets are realistic and enforceable by the selected built-in or injected
  runner.
- Results from different schema/tool/lab versions are not merged silently.
- A scenario test covers schema load and the relevant behavior.

Run the harness contracts with:

```bash
venv/bin/python -m pytest -q tests/benchmark -m benchmark
```

Run the default catalog and write reproducible artifacts with:

```bash
venv/bin/python -m core.benchmarks
```
