# Linux black-box small-model v4

`linux-blackbox-small-model-v4` is the prospective efficiency companion to the
Benchmark v3 blinded discovery design. It keeps the same two systems, pinned
altered Qwen 9B/Ollama runtime, 12 generated read-only fixture families,
independent task evaluator, and controller request ledger. It adds a frozen
efficiency plan with 20 matched repetitions per system/scenario, randomized
scenario-block order, position-balanced adjacent system pairs, controller-
derived resource metrics, and a task-completion gate for efficiency claims.

A complete run schedules 480 scored product executions (`12 families × 2
systems × 20 paired repetitions`). At the 900-second hard wall cap, the
sequential product-time ceiling is 120 hours before reset, health, cleanup, and
publication overhead. This is an engineering small-model track, not a
vendor-representative or universal product ranking.

Use the same private environment contract as v3, including a fresh secret base
fixture seed:

```dotenv
OCTOBENCH_V3_BASE_FIXTURE_SEED=<32-to-64-hexadecimal-characters>
OCTOBENCH_V3_BATCH_ID=batch-1
OCTOBENCH_V3_HOST_ID=<lowercase-host-attestation-id>
```

Generate and inspect both immutable plans without launching a product:

```bash
./venv/bin/python -m core.benchmarks.competitors.launch \
  --campaign-id linux-blackbox-small-model-v4-check \
  --campaign-definition linux-blackbox-small-model-v4 \
  --profile core \
  --environment-file benchmarks/competitors/secrets.env \
  --prepare-only
```

Review `analysis-plan.json`, `efficiency-plan.json`, all generated neutral
scenarios, and the system manifests. A prepared ID is write-once; use a new ID
for the live campaign.

On the authorized isolated Linux host, run the full campaign with a different
fresh ID and without `--prepare-only`:

```bash
./venv/bin/python -m core.benchmarks.competitors.launch \
  --campaign-id <fresh-live-id> \
  --campaign-definition linux-blackbox-small-model-v4 \
  --profile core \
  --environment-file benchmarks/competitors/secrets.env
```

After that campaign publishes its source v3 evidence bundle, create and verify
the additive efficiency companion:

```bash
SOURCE="benchmarks/competitors/results/<fresh-live-id>"
COMPANION="benchmarks/competitors/results/<fresh-live-id>-efficiency-v4"

./venv/bin/python -m core.benchmarks.v4 publish \
  --plan ".benchmark-state/generated/<fresh-live-id>/efficiency-plan.json" \
  --source-v3 "$SOURCE" \
  --output "$COMPANION"

./venv/bin/python -m core.benchmarks.v4 verify \
  --source-v3 "$SOURCE" \
  "$COMPANION"
```

The primary resource metrics are runner-measured wall time and controller-
verified fixture HTTP requests. Tokens, cost, and native tool calls remain
secondary unless both systems expose comparable reliable measurements. Missing
telemetry is published as unavailable, never zero. If either system fails the
task in a matched pair, that pair remains in stability and all-scheduled
resource statistics but is excluded from directional efficiency claims.

See [Benchmark v4 methodology](../../../../docs/benchmarks/benchmark-v4.md) and
the parent [competitor runbook](../../README.md) before execution.
