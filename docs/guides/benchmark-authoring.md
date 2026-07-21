# Benchmark scenario authoring guide

Benchmarks are deterministic, replay-first experiments. The default harness
executes built-in in-process replays for the ten catalog categories and never
launches an external scanner. A caller can still inject a custom runner.

System-to-system experiments are a separate authorized live/integration track
under `benchmarks/competitors/`. They use the same result aggregation contract,
but add versioned system manifests, command adapters, fairness profiles, lab
reset controls and a publication matrix. Do not place live competitor
scenarios in the built-in catalog or present hermetic replay numbers as
competitor performance.

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

The shipped Linux definitions keep reviewed scenarios under
`benchmarks/competitors/campaigns/linux-blackbox-v1/scenarios/` and
`benchmarks/competitors/campaigns/linux-blackbox-small-model-v1/scenarios/`,
with the four multi-surface contracts under
`benchmarks/competitors/campaigns/linux-blackbox-small-model-v2/scenarios/`.
The launcher selects only allowlisted checked-in contracts with
`--campaign-definition`; it never accepts an arbitrary path. For a custom
low-level campaign, start from
`benchmarks/competitors/scenarios/authorized-service-inventory.json.example`
and place the completed document in a dedicated scenario directory. Use
neutral actions and canonical finding IDs: product-specific commands must
be translated inside each adapter. Pin the authorized lab snapshot and restore
it before every repetition. Clear system state/caches and verify lab health.
The shipped launcher records a balanced forward/reverse system rotation;
custom low-level campaigns must define and publish equivalent scheduling when
infrastructure drift could systematically favor one product.

Never modify an existing live fixture after its digest has entered a scenario
or publication bundle. The v1 fixture remains under
`benchmarks/competitors/lab/`; newer fixtures use an allowlisted directory under
`benchmarks/competitors/labs/`. The v2 controller recreates the container for
every run with exactly one selected `scenario_id`, then requires health output
to attest both `discovery-lab-v2` and that scenario. This prevents a full-host
scanner from observing another scenario surface in the same repetition.

Each participating system also needs a schema `1.0` manifest conforming to
`docs/schemas/benchmark-system-v1.schema.json`. The manifest pins its exact
version/revision, model, tools, execution mode, fairness track and command
adapter. Adapter `argv` must contain `{scenario_path}` and `{output_path}`;
environment passthrough lists names only and must never contain secret values.
All manifests in one matrix must declare the same `execution_mode`: `live` and
`replay` results are never mixed.

Ablations are allowed only for toggle names explicitly passed as stable to the
harness. Do not add a speculative ablation for behavior that cannot yet be
enabled and disabled through a tested configuration contract.

## Review checklist

- Ground truth distinguishes expected, forbidden, and empty-negative results.
- Replay artifacts are immutable or content-addressed.
- No plaintext credential, raw prompt, raw exception, or unbounded stdout is
  stored.
- Hard budgets are enforceable by the selected runner; vendor-controlled soft
  budgets and missing telemetry are disclosed rather than presented as caps.
- Results from different schema/tool/lab versions are not merged silently.
- `framework_only` and `full_system` results remain separate, and only systems
  with the same fairness profile are compared directly.
- Live and replay execution modes remain separate.
- The lab is reset from the same immutable snapshot before every live run.
- Failed and invalid repetitions remain in the published result set.
- A comparison reports per-metric values and does not declare an overall
  winner unless a separate versioned scoring rule was declared in advance.
- A scenario test covers schema load and the relevant behavior.

Run the harness contracts with:

```bash
venv/bin/python -m pytest -q tests/benchmark -m benchmark
```

Run the default catalog and write reproducible artifacts with:

```bash
venv/bin/python -m core.benchmarks
```

The competitor manifest, command protocol, metrics, result layout and Git
publication checklist are documented in
`benchmarks/competitors/README.md`. Competitor campaigns require at least five
repetitions for every system/scenario pair. Publish immutable inputs, all runs,
aggregate median/variance/minimum/maximum/count, failures, execution mode,
comparison track and fairness metadata together. On Linux x86_64, use the
supported pinned launcher. Omit `--campaign-definition` for the backward-
compatible `linux-blackbox-v1` default, or select the altered-model
multi-surface contract explicitly. Pilot only one exact surface first; without
`--pilot-scenario`, a diagnostic runs every scenario in the definition:

```bash
./scripts/benchmarks/bootstrap_competitors_linux.sh --profile core
SCENARIO_ID="authorized-hypermedia-pagination-small-model-v2"
PILOT_ID="linux-blackbox-v2-pilot-strix-$(date -u +%Y%m%dt%H%M%Sz)"
./venv/bin/python -m core.benchmarks.competitors.launch \
  --campaign-id "$PILOT_ID" \
  --campaign-definition linux-blackbox-small-model-v2 \
  --profile core \
  --environment-file benchmarks/competitors/secrets.env \
  --diagnostic-pilot \
  --pilot-system strix \
  --pilot-scenario "$SCENARIO_ID" \
  --pilot-seconds 900

CAMPAIGN_ID="linux-blackbox-small-model-v2-$(date -u +%Y%m%dt%H%M%Sz)"
./venv/bin/python -m core.benchmarks.competitors.launch \
  --campaign-id "$CAMPAIGN_ID" \
  --campaign-definition linux-blackbox-small-model-v2 \
  --profile core \
  --environment-file benchmarks/competitors/secrets.env

BUNDLE="benchmarks/competitors/results/$CAMPAIGN_ID"
./venv/bin/python -c \
  'import json,sys; from core.benchmarks.competitors.publication import verify_campaign_bundle; print(json.dumps(verify_campaign_bundle(sys.argv[1]), sort_keys=True))' \
  "$BUNDLE"
```

The interface below is the low-level path for a custom, already-controlled
campaign; it does not bootstrap systems or manage the shipped Docker lab.

Run a completed two-system campaign with:

```bash
venv/bin/python -m core.benchmarks.competitors \
  --system-manifest benchmarks/competitors/systems/octopus.json \
  --system-manifest benchmarks/competitors/systems/competitor-a.json \
  --scenario-directory benchmarks/competitors/scenarios \
  --output-directory benchmarks/competitors/results/<campaign-id> \
  --repetitions 5 \
  --strict
```

The output directory must not already exist. Strict mode publishes the complete
comparison first, then exits non-zero if a run failed, timed out, was partial
or invalid, or recorded a policy violation. Timeout and partial counts remain
separate in the published completeness metadata and are included in
`error_runs`.
