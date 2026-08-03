# Linux black-box small-model v4

`linux-blackbox-small-model-v4` is the efficiency companion to the Benchmark v3
blinded discovery design. It keeps the same two systems, pinned abliterated
Qwen 9B/Ollama runtime, 12 generated read-only fixture families,
independent task evaluator, and controller request ledger. It adds a frozen
efficiency plan with 20 matched repetitions per system/scenario, randomized
scenario-block order, position-balanced adjacent system pairs, controller-
derived resource metrics, and a task-completion gate for efficiency claims.

A complete run schedules 480 scored product executions (`12 families × 2
systems × 20 paired repetitions`). At the 900-second hard wall cap, the
sequential product-time ceiling is 120 hours before reset, health, cleanup, and
publication overhead. The launcher therefore refuses to start it without a
successful fixed readiness calibration: 24 product runs at a 300-second cap
plus 12 fast sealed-reference checks. The calibration's product-time ceiling is
two hours. This is an engineering small-model track, not a vendor-representative
or universal product ranking.

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

Review `analysis-plan.json`, `efficiency-plan.json`, `readiness-plan.json`, all
generated neutral scenarios, and the system manifests. A preview ID is
write-once; use a new ID for calibration and the live campaign.

On the authorized isolated Linux host, use a different fresh ID for the
mandatory readiness calibration:

```bash
RUN_ID="linux-blackbox-small-model-v4-$(date -u +%Y%m%dt%H%M%Sz)"
./venv/bin/python -m core.benchmarks.competitors.launch \
  --campaign-id "$RUN_ID" \
  --campaign-definition linux-blackbox-small-model-v4 \
  --profile core \
  --environment-file benchmarks/competitors/secrets.env \
  --readiness-calibration

./venv/bin/python -m json.tool \
  ".benchmark-state/readiness-journal/$RUN_ID/readiness-evidence.json"
```

The command succeeds only when both products produce verified signal, at least
one positive evidence-bearing matched block is jointly completed, the sealed
reference is perfect for all families, and no policy violation occurs. Passing
only the clean-negative family does not satisfy this gate. The complete
append-only calibration journal is recomputed before the full run; no
successful retry can replace a failed scheduled attempt. If readiness fails,
fix the adapter/runtime and start again with a fresh ID.

After the evidence reports `"status": "ready"`, run the full campaign with the
same ID and no readiness flag:

```bash
./venv/bin/python -m core.benchmarks.competitors.launch \
  --campaign-id "$RUN_ID" \
  --campaign-definition linux-blackbox-small-model-v4 \
  --profile core \
  --environment-file benchmarks/competitors/secrets.env
```

After that campaign publishes its source v3 evidence bundle, create and verify
the additive efficiency companion:

```bash
SOURCE="benchmarks/competitors/results/$RUN_ID"
COMPANION="benchmarks/competitors/results/$RUN_ID-efficiency-v4"

./venv/bin/python -m core.benchmarks.v4 publish \
  --plan ".benchmark-state/generated/$RUN_ID/efficiency-plan.json" \
  --source-v3 "$SOURCE" \
  --output "$COMPANION"

./venv/bin/python -m core.benchmarks.v4 verify \
  --source-v3 "$SOURCE" \
  "$COMPANION"
```

Run the verifier on the execution host before copying either directory, retain
that original until publication is complete, and run the same verifier again
on the destination. A transfer that preserves the aggregate JSON/CSV but
truncates a controller-ledger shard is not a recoverable publication; do not
regenerate `SHA256SUMS` around damaged files.

The primary resource metrics are runner-measured wall time and controller-
verified fixture HTTP requests. Tokens, cost, and native tool calls remain
secondary unless both systems expose comparable reliable measurements. Missing
telemetry is published as unavailable, never zero. If either system fails the
task in a matched pair, that pair remains in stability and all-scheduled
resource statistics but is excluded from directional efficiency claims.

See [Benchmark v4 methodology](../../../../docs/benchmarks/benchmark-v4.md) and
the parent [competitor runbook](../../README.md) before execution.
