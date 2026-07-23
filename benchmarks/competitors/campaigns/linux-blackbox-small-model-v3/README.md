# Linux black-box small-model v3

`linux-blackbox-small-model-v3` is the full Benchmark v3 launcher definition
for the `core` profile: OCTOPUS and Strix 1.1.0, the pinned altered Qwen 9B
model/Ollama runtime, 12 generated blinded fixture families, and 12 paired
repetitions per system/scenario. A complete run schedules 288 product
executions (`12 families × 2 systems × 12 repetitions`). It belongs only to
the isolated `small-model-stress-v3` track. With the 900-second per-run cap,
the sequential worst-case product-time allowance is 72 hours before lifecycle
and publication overhead.

Unlike v1/v2, this directory does not contain static scenario JSON. The
launcher generates the 12 neutral scenarios, paired fixture seeds, and frozen
`analysis-plan.json` under ignored
`.benchmark-state/generated/<campaign-id>/`. Each product starts at the stable
lab root; the generated route, truth, evidence nonces, completion rule, private
manifest, and ledger remain controller-owned.

Add these v3 inputs to the otherwise complete small-model environment file:

```dotenv
OCTOBENCH_V3_BASE_FIXTURE_SEED=<32-to-64-hexadecimal-characters>
OCTOBENCH_V3_BATCH_ID=batch-1
OCTOBENCH_V3_HOST_ID=<lowercase-host-attestation-id>
```

The base seed is secret pre-closure input and is never serialized directly.
The plan contains its derived paired seeds. Batch and host IDs are attested in
every schema-2.0 run; if omitted, the launcher uses `batch-1` and a
deterministic local runtime identity.

Inspect generated inputs without starting a product:

```bash
./venv/bin/python -m core.benchmarks.competitors.launch --help
./venv/bin/python -m core.benchmarks.competitors.launch \
  --campaign-id linux-blackbox-small-model-v3-check \
  --campaign-definition linux-blackbox-small-model-v3 \
  --profile core \
  --environment-file benchmarks/competitors/secrets.env \
  --prepare-only
```

Use a different fresh campaign ID for a real run; the launcher refuses to
overwrite generated state. A publishable run also requires
Linux, a clean attested checkout, the authorization/isolation acknowledgements,
the pinned model/runtime and a working Docker Compose service. Use a fresh ID
and omit `--prepare-only`.

After all 288 scheduled executions and cleanup are sealed, the campaign path
publishes a checksum-covered v3 bundle. It includes the frozen analysis plan,
post-closure fixture reveals, full schema-2.0 run records, controller
request-ledger chains, statistics, and a deterministic `comparison.svg`
generated directly from the plan and statistics. Verify it with:

```bash
./venv/bin/python -c \
  'import json,sys; from core.benchmarks.v3 import verify_v3_results; print(json.dumps(verify_v3_results(sys.argv[1]), sort_keys=True))' \
  "benchmarks/competitors/results/<campaign-id>"
```

Successful output contains `track_id: small-model-stress-v3`, `runs: 288`,
the analysis-plan digest, and the verified file count. Verification also
rebuilds the statistics and SVG and validates every ledger chain.

There is no checked-in v3 result bundle yet. The definition and methodology do
not establish a performance result, ranking, or superiority claim.
