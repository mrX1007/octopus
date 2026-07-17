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
├── catalog.json  # reviewed upstream releases, revisions, licenses and tracks
├── campaigns/    # versioned live campaign scenarios
├── lab/          # resettable OCTOBENCH-owned target fixture
├── systems/      # low-level system-manifest examples
├── scenarios/    # neutral scenario templates for the low-level matrix runner
└── results/      # immutable campaign publication bundles
```

The launcher writes generated manifests to ignored
`.benchmark-state/generated/<campaign-id>/`; it never writes them under
`systems/`.

The checked-in files ending in `.json.example` are templates. Copy and fill
them as `.json` before running a campaign; the suffix deliberately keeps them
out of normal JSON scenario/manifest discovery.

## Supported releases and comparison surfaces

`catalog.json` is the machine-readable review record for the competitor
selection as reviewed on 2026-07-17. A contract test requires its tags and
revisions to match the launcher and bootstrap pins, preventing silent drift
between those three inputs. The supported Linux black-box launcher
profiles are deliberately small:

| Profile | Systems | Surface |
| --- | --- | --- |
| `core` | OCTOPUS, Strix 1.1.0 | black-box, full-system |
| `extended` | `core` plus PentAGI 2.1.0 | black-box, full-system |

The pinned upstream releases are [Strix 1.1.0](https://github.com/usestrix/strix/releases/tag/v1.1.0),
[PentestGPT 1.0.0](https://github.com/GreyDGL/PentestGPT/releases/tag/v1.0.0),
[PentAGI 2.1.0](https://github.com/vxcontrol/pentagi/releases/tag/v2.1.0)
and [Shannon 1.9.0](https://github.com/KeygraphHQ/shannon/releases/tag/v1.9.0).
PentestGPT remains a cataloged CTF-only candidate: its v1.0.0 non-interactive
path hardcodes flag capture and retries no-flag results three times. It has no
launcher profile and must not contribute discovery results. Use the optional
bootstrap flag `--with-pentestgpt` only for a separately designed CTF campaign.
The bootstrap checks the full release commit recorded in `catalog.json`, not
only the human-readable tag.

Shannon requires the target source checkout and is therefore white-box only.
It is a cataloged candidate, not a runnable shipped campaign: no versioned
Shannon scenario or publication runbook is included yet. Do not add ad-hoc
Shannon numbers to the Linux black-box ranking. CAI is recorded only under `excluded` because
its [official license](https://github.com/aliasrobotics/cai/blob/main/LICENSE)
contains research-use restrictions and separate commercial-license terms, so
it is not part of this strict open-source comparison.

## Linux quick start

The supported launcher targets Linux x86_64 with glibc 2.34 or newer. Before
starting, install Git, Docker with Compose and an accessible running daemon,
CPython 3.12 and the model services or provider accounts you intend to use. GitHub and PyPI
egress are required during bootstrap. The bootstrap creates pinned
`uv==0.11.28`, syncs
the OCTOPUS `venv/` from the checked-in CPython 3.12 hashed runtime lock, and
then syncs the competitors from their frozen locks. It never invokes `sudo`,
never starts a target, and never performs an interactive competitor
configuration. It intentionally synchronizes an existing repo `venv/`; use a
dedicated benchmark checkout if that environment must not be changed.

Execute a live campaign only from a disposable, dedicated Linux VM on an
isolated VLAN. Give that VM no unrelated or long-lived credentials or sensitive
mounts; use only scoped, revocable benchmark provider keys. Never pass it a
Docker socket from a more privileged host. Give it no route to any
sensitive/private network other than the benchmark lab. Permit only the
Internet/provider egress required for bootstrap and the selected models.
Vendor agents can invoke their own tools or Docker workloads; process bounds
and target validation do not prove every internal tool action, so isolation is
a required safety boundary rather than optional hardening.

Prepare the default `core` competitors from exact detached source revisions:

```bash
cd /path/to/Octopus
./scripts/benchmarks/bootstrap_competitors_linux.sh --profile core
cp benchmarks/competitors/secrets.env.example benchmarks/competitors/secrets.env
chmod 600 benchmarks/competitors/secrets.env
```

Bootstrap also pulls and verifies the immutable Linux amd64 Strix sandbox
image recorded as `STRIX_IMAGE` in the template. Mutable tags and alternate
digests are rejected by the launcher.

Fill the blank model/provider fields in `secrets.env`. Set
`OCTOBENCH_ACK_AUTHORIZED=YES` yourself only when the included OCTOBENCH fixture
or another explicitly authorized target is actually in scope. Set
`OCTOBENCH_ACK_ISOLATED_HOST=YES` yourself only after establishing the isolation
boundary above. The launcher requires both acknowledgements and
fails closed for any other value. The checked-in example
contains executable paths and variable names but no credentials. The launcher
detects one private host address and binds the lab only there;
standalone lab control defaults to `127.0.0.1`. Optional explicit host, bind
and port overrides are documented as comments in the template.

Optionally inspect the exact generated manifests and campaign config without
running a system:

```bash
./venv/bin/python -m core.benchmarks.competitors.launch \
  --campaign-id linux-blackbox-v1-check \
  --profile core \
  --environment-file benchmarks/competitors/secrets.env \
  --prepare-only
```

Then run the complete reset/health/execute/resume/publish lifecycle with one
launcher command and a new immutable campaign ID:

```bash
./venv/bin/python -m core.benchmarks.competitors.launch \
  --campaign-id linux-blackbox-v1-20260716T120000Z \
  --profile core \
  --environment-file benchmarks/competitors/secrets.env
```

Use `--profile extended` only after a private/internal PentAGI endpoint is
configured as benchmark-dedicated infrastructure in the isolated segment, can
reach the private OCTOBENCH lab address, and the four
`OCTOBENCH_PENTAGI_*` fields are filled. The adapter fails closed unless the
service reports release `2.1.0`, the selected provider matches, and every model
actually used by the flow matches `OCTOBENCH_PENTAGI_MODEL`. Prepare its pinned
source checkout with `bootstrap_competitors_linux.sh --profile extended`; the
adapter also deletes its benchmark flow after capture and marks a failed
cleanup as `partial`. For a private HTTPS endpoint signed by an internal CA,
set the optional `OCTOBENCH_PENTAGI_CA_FILE`; its content digest is included in
runtime provenance. The bootstrap does not deploy or configure that service.
`--with-shannon` only
obtains a verified source candidate and does not create a publishable Shannon
campaign.

The launcher generates manifests and its campaign config under
`.benchmark-state/generated/<campaign-id>/`, resumes only matching work from
`.benchmark-state/journal/<campaign-id>/`, and publishes the complete bundle
under `benchmarks/competitors/results/<campaign-id>/`. Existing destinations,
changed fingerprints, missing executables, missing environment fields, an
unhealthy lab or an authorization acknowledgement other than `YES` fail
closed. A dirty repository is always rejected; the supported publication path
has no dirty-tree override.

Bootstrap and live execution are not free. Initial source downloads, Python
environments and container images can consume multiple gigabytes and take tens
of minutes. The balanced launcher runs six repetitions per system for both
profiles; a campaign can take tens of minutes to hours and
can incur model-provider, cloud and tool charges. The
launcher hard-bounds wall time and captured output. Vendor CLIs do not expose a
uniform enforceable token/tool/cost cutoff, so those declared budgets are
conformance targets, not spending guarantees; `same_budgets` is therefore
false for this full-system profile. Strix 1.1.0 additionally receives its
native `--max-budget-usd` limit, but that does not make the cross-system budget
contract uniform. Set independent provider-side spending
limits before a live run. Publish only the calls, tokens and cost actually
reported in the result bundle, leave unavailable values as `N/A`, and never
project one provider's price onto another system.

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
`OCTOPUS_BENCHMARK_*` environment metadata. The adapter must, for behavior it
can directly observe and control:

1. read the UTF-8 JSON scenario from `{scenario_path}`;
2. enforce target scope, hard time/output limits and the campaign reset
   contract, and report conformance only for observable action/tool/model/cost
   controls;
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

Action and finding IDs must be canonical campaign IDs. For shipped third-party
black-box agents, internal per-tool action conformance is `N/A` (`not
assessed`): the adapter must not fabricate an action stream or claim
enforcement it cannot prove. An observable adapter-controlled action may still
be checked against the scenario contract. The adapter performs product-specific
translation; a marketing label or free-form report sentence is not a finding
ID. The harness derives precision, recall and forbidden-hit metrics from the
scenario ground truth, so finding and coverage comparisons remain valid when
internal action conformance is unavailable. An observed undeclared
adapter-controlled action invalidates the run. A non-zero exit,
missing/oversized/malformed output, exhausted timeout or partial result is
published as a non-conforming run, not silently substituted with a zero score.

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
- declare hard and observational budgets explicitly, record fairness limits,
  and use at least five repetitions;
- include a seed and immutable/content-addressed fixture references;
- define reset-before-every-repetition behavior.

Restore the same lab snapshot before every repetition, clear product state and
caches, and verify lab health before starting the timed interval. The supported
launcher records a deterministic forward/reverse rotation: six repetitions in
either profile give every system every schedule position equally often.
Custom low-level campaigns must publish their own counterbalancing policy.
Preserve a failed reset as a campaign failure; do not continue on a
contaminated target.

`scenarios/authorized-service-inventory.json.example` is deliberately a
placeholder. Replace every `replace-with-*` value and keep public Internet
targets out of the repository.

## Repetitions, metrics and interpretation

Run at least five repetitions per system/scenario pair. Publish every run,
including failures and invalid runs, plus aggregate count, median, population
variance, minimum and maximum for successful-run metrics. The shipped adapters
always retain derived finding precision/recall, evidence completeness, total
duration and terminal status. Retain these additional metrics when the product
exposes trustworthy source events:

- verified-finding recall and reported-finding precision;
- forbidden-finding and policy-violation rates;
- time to first verified evidence and total duration;
- evidence completeness and coverage gaps;
- no-op and repeated-task rates from product task events;
- recovery success after declared transient failures;
- tool calls, model calls/tokens and normalized monetary cost.

Missing vendor telemetry remains `N/A`; it is never inferred from prose or
replaced with zero. In particular, no-op/repeated-task and recovery metrics are
not cross-system claims in the shipped black-box campaign because the selected
competitors do not expose a common task-event contract. OCTOPUS's separate
hermetic no-op/repeat comparison remains documented in the root README.
Third-party internal action conformance is likewise `N/A` (`not assessed`),
not a fabricated pass and not a launcher-enforced claim. This does not prevent
comparison of findings, verified evidence, precision/recall or coverage gaps
against the common ground truth.

There is no default overall winner. The matrix must present per-metric values,
sample counts, failures, execution mode and fairness metadata. Any later
weighted score is a separate, versioned analysis whose weights and
missing-data rules must be published. Never drop failed repetitions, compare
only each product's best run, combine live with replay, or combine incompatible
fairness profiles.

## Low-level matrix runner

The supported Linux runbook above should be used for the versioned
`linux-blackbox-v1` campaign. The lower-level matrix interface remains useful
for authoring or replaying a custom, already-controlled campaign. Create at
least two completed `.json` system manifests and one or more completed `.json`
scenarios. Example templates are not discovered because they end in
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
any run failed, timed out, was partial or invalid, or recorded a policy
violation. Timeout and partial counts are published separately and included in
`error_runs`. Inspect and publish that evidence rather than deleting the runs.

## Publication layout

Use one immutable campaign ID and keep inputs beside outputs:

```text
benchmarks/competitors/results/<campaign-id>/
├── aggregates/
│   ├── octopus/
│   ├── strix/
│   └── pentagi/               # extended profile only
├── attestations/             # reset/health evidence for every scheduled run
├── inputs/
│   ├── campaign.json
│   ├── scenarios/
│   └── systems/
├── campaign-status.json
├── comparison.json
├── comparison.md
├── preflight.json
├── provenance.json
├── schedule.json
└── SHA256SUMS
```

`comparison.json` is the machine-readable matrix and embeds public system,
scenario, execution-mode, fairness and completeness metadata. It excludes
adapter commands, local paths, environment values and raw logs.
`comparison.md` is a non-normative rendering and deliberately declares no
winner. Every full aggregate retains its runs under `aggregates/`; the bundle
also includes public input copies, the exact schedule, preflight, provenance,
per-run reset attestations and campaign status. `SHA256SUMS` covers every
publication file and the campaign verifies it before returning. Generated
runtime manifests remain under ignored `.benchmark-state/`; their sanitized
public forms are already preserved under `inputs/systems/`. Published result
directories are append-only: use a new campaign ID when any input, revision or
configuration changes.

## Git publication workflow

Review artifacts for secrets and authorization-sensitive target data before
staging. A typical publication flow is:

```bash
cd /path/to/Octopus

git status --short
git diff --check

git add \
  benchmarks/competitors/results/<campaign-id>/

git diff --cached --check
git diff --cached --stat
git commit -m "Publish competitor benchmark <campaign-id>"
git push -u origin "$(git branch --show-current)"
```

Do not stage adapter logs, `.env` files, credentials or mutable lab images. A
published campaign is evidence, so corrections should add a superseding
campaign or a clearly linked erratum instead of rewriting old results.
