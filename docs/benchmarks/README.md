# Benchmark harness

The benchmark package provides a versioned, replay-first experiment contract.
`BenchmarkHarness()` can now run every entry in the ten-scenario catalog with a
built-in, hermetic deterministic replay. It exercises project persistence,
assessment, execution-result, planner-fallback, and mission-resume components
without a scanner, network, model provider, or external tool. Passing a custom
runner is still supported.

## Layout

- `core/benchmarks/schema.py`: schema `1.0` models and bounded validation.
- `core/benchmarks/harness.py`: repeated execution, ground-truth metrics,
  allowed-action validation, aggregation, and atomic JSON output.
- `core/benchmarks/builtin_runner.py`: in-process deterministic implementations
  of all ten catalog scenarios.
- `core/benchmarks/task_efficiency.py`: versioned baseline-versus-configured
  task-selection replay and atomic result writer.
- `benchmarks/scenarios/`: the ten required scenario definitions.
- `benchmarks/results/noop-repeat-comparison-v1.json`: reproducible published
  no-op/repeated-task comparison.
- `docs/schemas/benchmark-scenario-v1.schema.json`: portable JSON Schema.
- `tests/benchmark/`: hermetic contract tests.

The catalog covers service verification, web/API mapping, credential safe
validation, verified SSH inventory, authorized internal discovery, clean
negative behavior, timeout/partial persistence, invalid/empty model fallback,
crash/resume, and contradictory evidence.

## Programmatic use

```python
from core.benchmarks import BenchmarkHarness, load_scenario

scenario = load_scenario("benchmarks/scenarios/06-clean-negative.json")
harness = BenchmarkHarness()
aggregate = harness.run(scenario)
harness.write(aggregate, "artifacts/clean-negative.json")
```

Custom replay logic remains an explicit injection point:

```python
from core.benchmarks import BenchmarkHarness, load_scenario

scenario = load_scenario("benchmarks/scenarios/06-clean-negative.json")

def replay_runner(scenario, repetition, seed):
    return {
        "status": "succeeded",
        "actions": ["replay_negative_checks"],
        "reported_findings": [],
        "metrics": {"evidence_completeness": 1.0},
    }

harness = BenchmarkHarness(replay_runner)
aggregate = harness.run(scenario)
harness.write(aggregate, "artifacts/clean-negative.json")
```

Run all built-in scenarios and write one aggregate per scenario plus the
task-efficiency comparison:

```bash
venv/bin/python -m core.benchmarks
```

Regenerate only the checked-in comparison:

```bash
venv/bin/python -m core.benchmarks --comparison-only
```

Every aggregate contains at least five runs. Metrics from successful runs
publish median, population variance, minimum, maximum, and count. Finding
precision/recall and forbidden-finding rate are derived from ground truth.
Runner failures persist only the exception class. Results with unapproved
actions are marked invalid and excluded from metric aggregation.

## Published no-op/repeat comparison

The versioned `mission-frontier-replay-v1` comparison replays six recorded
planner frontiers with two selections per round through the real `TaskScorer`.
The risk/cost-only baseline selected 12/12 known no-op tasks and repeated 10/12
selections (rate `0.833333`). The shipped configurable scoring profile selected
0/12 known no-op tasks and repeated 0/12 selections. The absolute reductions
are therefore `1.0` for no-op rate and `0.833333` for repeated-task rate.

These measurements describe the deterministic planner-selection fixture only;
they are not presented as external scanner or live-lab performance. The
published JSON contains the weights, every selected task, the metric
definitions, and a content-derived comparison ID. A contract test regenerates
the payload from code and requires exact equality with the checked-in artifact.

Do not compare or merge results across changed scenario, lab, target, model,
tool, or schema versions without making that difference explicit. Ablations
require a tested stable toggle passed to `BenchmarkHarness`.

## Published live-system visualization

The live competitor track is separate from this hermetic harness. Its current
checked-in result has a deterministic, non-normative GitHub visualization:

![Published OCTOPUS and Strix terminal outcomes with successful-run quality ranges](linux-blackbox-small-model-v1-20260721t134205z.svg)

The normative data and full provenance remain in
`benchmarks/competitors/results/linux-blackbox-small-model-v1-20260721t134205z/`.
New live bundles generate and checksum their own `comparison.svg`; failed or
timed-out runs remain terminal outcomes and are never converted into zero
quality scores.
