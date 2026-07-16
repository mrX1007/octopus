# Competitor benchmark track

This directory defines the publication contract for comparing OCTOPUS with
other systems in an authorized, resettable lab. It is a live/integration track,
not an extension of the built-in hermetic replay catalog.

The default `python -m core.benchmarks` command remains an in-process,
deterministic OCTOPUS regression benchmark. It does not launch OCTOPUS as a
scanner, call a model provider, use a network, or run a competitor. Never cite
its results as a system-to-system comparison.

## Layout

```text
benchmarks/competitors/
├── systems/      # one versioned system manifest per system under test
├── scenarios/    # neutral authorized-lab scenarios shared by the systems
└── results/      # immutable campaign directories selected for publication
```

The checked-in files ending in `.json.example` are templates. Copy and fill
them as `.json` before running a campaign; the suffix deliberately keeps them
out of normal JSON scenario/manifest discovery.

## Comparison tracks

Every system manifest declares one execution mode, one track and one fairness
profile. `live` launches the actual system in an authorized lab; `replay` runs
only immutable recorded inputs. A matrix rejects mixed execution modes, so
live and replay results cannot be compared as though they measured the same
thing.

The comparison tracks are:

- `framework_only`: all systems in the comparison group use the same model,
  model parameters, tool versions, hardware class, lab snapshot and budgets.
  This track is intended to isolate orchestration/framework behavior.
- `full_system`: each system uses its documented recommended model and tools.
  Hardware, price and model/tool differences remain visible in the manifests
  and results.

Do not merge, rank or average results across these tracks. A fairness profile
ID identifies systems that are eligible for a direct comparison. For a
`framework_only` group, all four `same_*` fields should be true and the recorded
model/tool values must match in substance, not merely by label.

## System manifest

Each system is declared with schema `1.0` from
`docs/schemas/benchmark-system-v1.schema.json`. A manifest pins:

- system ID, display name, release version, exact source revision and
  `live | replay` execution mode;
- comparison track and fairness profile;
- model identity/parameters and external tool versions;
- a command adapter, its working directory and names of environment variables
  that may be passed through;
- bounded, non-secret publication metadata.

`environment_passthrough` contains variable names only. Never commit tokens, passwords
or environment values. Adapter `argv` is an argument vector, not a shell
command, and must contain both `{scenario_path}` and `{output_path}`. It may
also use `{repetition}`, `{seed}` and `{system_id}`. `working_directory` is resolved relative
to the directory containing the manifest and cannot escape that directory.
Names beginning with `OCTOPUS_BENCHMARK_` are reserved for runner metadata and
cannot be listed in `environment_passthrough`.

See `systems/octopus-command.json.example` for a starting point. Give every
competitor its own manifest; do not hide a competitor version or configuration
behind a generic adapter name.

## Command adapter JSON protocol

For each repetition, the matrix runner materializes the exact benchmark
scenario JSON, allocates a fresh output path and starts the manifest's command
adapter. It also exposes repetition, seed, system and track through bounded
`OCTOPUS_BENCHMARK_*` environment metadata. The adapter must:

1. read the UTF-8 JSON scenario from `{scenario_path}`;
2. enforce its target scope, allowed actions, seed, time/tool/output/model/cost
   budgets, and the campaign's reset contract;
3. write exactly one bounded UTF-8 JSON object to `{output_path}`;
4. exit with status zero only after that object has been completely written.

The output object uses the existing `BenchmarkRunner` mapping:

```json
{
  "status": "succeeded",
  "actions": ["observe_authorized_target", "verify_observed_service"],
  "reported_findings": ["service.https.443"],
  "verified_findings": ["service.https.443"],
  "coverage_gaps": [],
  "metrics": {
    "time_to_first_verified_seconds": 12.4,
    "evidence_completeness": 1.0,
    "no_op_task_rate": 0.0,
    "repeated_task_rate": 0.0,
    "tool_calls": 2,
    "model_calls": 1,
    "api_cost_usd": 0.12
  },
  "duration_seconds": 18.7,
  "artifact_refs": ["sha256:replace-with-content-digest"]
}
```

Action and finding IDs must be canonical campaign IDs. The adapter performs
product-specific translation; a marketing label or free-form report sentence
is not a finding ID. The harness derives precision, recall and forbidden-hit
metrics from the scenario ground truth. An undeclared action invalidates the
run. A non-zero exit, missing/oversized/malformed output or exhausted timeout
is a failed run, not a zero score silently substituted by the adapter.

Diagnostic stdout/stderr must be bounded and scrubbed. Environment values,
manifest source paths and raw logs are execution-only data and are never
serialized into the benchmark aggregate. Published `artifact_refs` should be
content-addressed references, not raw credentials, prompts or target data.

## Neutral live scenarios

Competitor scenarios reuse benchmark scenario schema `1.0`, but live examples
belong under `benchmarks/competitors/scenarios/`, not the built-in replay
catalog. A valid campaign scenario must:

- name an explicitly authorized isolated lab and immutable target snapshot;
- use neutral objectives/actions that do not encode OCTOPUS implementation
  steps or product-specific tool names;
- define independently reviewed expected and forbidden canonical findings;
- declare identical enforceable budgets and at least five repetitions;
- include a seed and immutable/content-addressed fixture references;
- define reset-before-every-repetition behavior.

Restore the same lab snapshot before every repetition, clear product state and
caches, and verify lab health before starting the timed interval. The CLI runs
systems in manifest argument order; choose and record a counterbalanced order
when separate campaigns are needed to measure infrastructure drift. Preserve a
failed reset as a campaign failure; do not continue on a contaminated target.

`scenarios/authorized-service-inventory.json.example` is deliberately a
placeholder. Replace every `replace-with-*` value and keep public Internet
targets out of the repository.

## Repetitions, metrics and interpretation

Run at least five repetitions per system/scenario pair. Publish every run,
including failures and invalid runs, plus aggregate count, median, population
variance, minimum and maximum for successful-run metrics. At minimum retain:

- verified-finding recall and reported-finding precision;
- forbidden-finding and policy-violation rates;
- time to first verified evidence and total duration;
- evidence completeness and coverage gaps;
- no-op and repeated-task rates;
- recovery success after declared transient failures;
- tool calls, model calls/tokens and normalized monetary cost.

There is no default overall winner. The matrix must present per-metric values,
sample counts, failures, execution mode and fairness metadata. Any later
weighted score is a separate, versioned analysis whose weights and
missing-data rules must be published. Never drop failed repetitions, compare
only each product's best run, combine live with replay, or combine incompatible
fairness profiles.

## Run a matrix

Create at least two completed `.json` system manifests and one or more completed
`.json` scenarios. Example templates are not discovered because they end in
`.json.example`. Then run:

```bash
./venv/bin/python -m core.benchmarks.competitors \
  --system-manifest benchmarks/competitors/systems/octopus.json \
  --system-manifest benchmarks/competitors/systems/competitor-a.json \
  --scenario-directory benchmarks/competitors/scenarios \
  --output-directory benchmarks/competitors/results/2026-07-16-framework-v1 \
  --repetitions 5 \
  --strict
```

Use repeatable `--system-directory` instead of, or together with,
`--system-manifest` when every `*.json` file in a directory belongs to the
campaign. The destination must not already exist. Publication is atomic:
`--strict` still writes the complete result directory, then exits non-zero if
any run failed, was invalid or recorded a policy violation. Inspect and publish
that evidence rather than deleting the failed runs.

## Publication layout

Use one immutable campaign ID and keep inputs beside outputs:

```text
benchmarks/competitors/results/<campaign-id>/
├── aggregates/
│   ├── octopus-local/
│   │   └── authorized-service-inventory-v1.json
│   └── competitor-a/
│       └── authorized-service-inventory-v1.json
├── comparison.json
├── comparison.md
└── SHA256SUMS
```

`comparison.json` is the machine-readable matrix and embeds public system,
scenario, execution-mode, fairness and completeness metadata. It excludes
adapter commands, local paths, environment values and raw logs.
`comparison.md` is a non-normative rendering and deliberately declares no
winner. Every full aggregate retains its runs under `aggregates/`, and
`SHA256SUMS` covers all generated publication files. Keep the executed system
manifests and scenarios in their source directories in the same Git commit.
Published result directories are append-only: use a new campaign ID when any
input, revision or configuration changes.

## Git publication workflow

Review artifacts for secrets and authorization-sensitive target data before
staging. A typical publication flow is:

```bash
cd /path/to/Octopus

git status --short
git diff --check

git add \
  benchmarks/competitors/systems/ \
  benchmarks/competitors/scenarios/ \
  benchmarks/competitors/results/<campaign-id>/

git diff --cached --check
git diff --cached --stat
git commit -m "Publish competitor benchmark <campaign-id>"
git push -u origin "$(git branch --show-current)"
```

Do not stage adapter logs, `.env` files, credentials or mutable lab images. A
published campaign is evidence, so corrections should add a superseding
campaign or a clearly linked erratum instead of rewriting old results.
