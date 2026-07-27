# Benchmark v3 methodology

Benchmark v3 is an additive schema-2.0 evaluation layer. It does not alter or
reinterpret the published v1/v2 bundles. `core.benchmarks.v3.schema.load_run`
can read schema-1.0 run objects for diagnostics, but labels their task outcome
`not_evaluated`, verified recall unavailable, and legacy precision
`legacy_incomplete` because the old adapter could discard unmatched claims.

The implementation, full launcher definition, and checksum-verified
[`linux-blackbox-small-model-v3-20260724t092256z`](../../benchmarks/competitors/results/linux-blackbox-small-model-v3-20260724t092256z/comparison.svg)
campaign bundle are checked in. The bundle contains all 288 scheduled runs and
its frozen statistics record zero completed tasks for both systems and no
automatic winner. It is constrained-small-model stress evidence, not a general
performance ranking or superiority claim.

## Outcome and metric semantics

A run has two independent terminal fields:

- `execution_status` answers whether the product process completed, failed,
  timed out, was cancelled, or was invalid.
- `task_status` answers whether the frozen completion rule was completed,
  partially completed, not completed, not evaluated, or invalid.

`completion_rule_id` identifies the sealed rule used by the evaluator. A
successful process is never automatically a completed task. Timeout and
unfinished-task durations are right-censored; they are not treated as exact
completion times.

Every metric records `available`, `reliability`, and its population. The
`all_scheduled` population includes failed and timed-out scheduled runs. The
`completion_conditional` population is available only when execution
completed; it is published beside, never instead of, the all-scheduled result.
Reported recall counts truth items mentioned by the product. Verified recall
requires controller evidence or an explicit sealed-evaluator attestation.

Full claim precision evaluates every non-empty product claim. Exact normalized
truth IDs, canonical text, and private aliases can match; every other claim is
retained as a deterministic `unmatched:<digest>` claim and remains in the
denominator. This closes the v2 failure mode where arbitrary hallucinated text
could disappear before scoring.

The unified boundary is the product-native final report, never the raw tool
transcript or fact store. Text-report adapters contribute only complete values
from explicit final `Claim:` or `Finding:` records. OCTOPUS contributes only
complete `detail` values from the canonical machine report's assertion
sections: `verified_vulnerabilities`, `access_findings`, `misconfigurations`,
`observations`, and `hypotheses_candidates`. A blinded nonce seen in tool
output is stored as a `benchmark_observation`, not promoted to a claim; it
counts only when the product includes it in one of those final native assertion
records. The complete assertion text is retained, so invented surrounding text
does not disappear merely because it contains a valid nonce.

The controller converts ledger observations to sealed truth attestations with
`verified_truth_ids_from_evidence`; private evidence IDs do not need to appear
in a product prompt, environment, or claim payload.

Each declared budget has a system-specific record containing its limit, unit,
enforcement mode, measured use, exceedance, reliability, and evidence refs.
An absent or unenforced measurement is represented as unavailable, not zero.
Action telemetry is a sequence of normalized events and also has explicit
availability/reliability. The scheduled fixture seed and the actually applied
model seed are separate attestations.

Machine contracts:

- [`benchmark-run-v3.schema.json`](../schemas/benchmark-run-v3.schema.json)
- [`benchmark-analysis-plan-v3.schema.json`](../schemas/benchmark-analysis-plan-v3.schema.json)
- [`benchmark-fixture-private-v3.schema.json`](../schemas/benchmark-fixture-private-v3.schema.json)
- [`benchmark-fixture-product-view-v3.schema.json`](../schemas/benchmark-fixture-product-view-v3.schema.json)
- [`benchmark-statistics-v3.schema.json`](../schemas/benchmark-statistics-v3.schema.json)

## Blinded generated lab

`generate_fixture_variant(family, matched_fixture_seed=...)` deterministically
generates a variant. Both systems in a paired block receive the same variant
digest. The product view contains only the base URL, stable `/` entry target,
read-only method contract, scenario identity, and opaque variant ID. A request
to `/` returns an in-band link to the generated entry route, so the product
never needs the private product-view path or generated route in its process
arguments, environment, or working directory. The product view does not
contain the generator seed, evidence nonces, truth, matcher, or completion
rule.

The controller-private manifest contains the generated routes and evaluator
material and must be mode 0600. The fixture records GET/HEAD observations in a
controller-owned hash-chained ledger. POST, PUT, PATCH, and DELETE are recorded
as policy violations and return HTTP 405 without changing state. The ledger is
not an HTTP endpoint. After the campaign is closed, `reveal_manifest` publishes
the generator seed and variant digest so the exact fixture can be regenerated.

The generator includes these scenario families:

| Family | Contract |
| --- | --- |
| `deep_navigation` | Generated chain of 4–6 navigation hops |
| `noisy_openapi` | One real operation among generated decoys |
| `pagination_cycle` | Cursor pagination with a deterministic cycle |
| `redirect_loop` | Two generated same-origin redirects form a loop |
| `clean_negative` | An explicit negative-evidence observation supports the clean result; unsupported claims reduce precision |
| `documented_missing` | Documentation names a route whose observation is 404/410 |
| `transient_recovery` | Deterministic 429 then 503 before recovery |
| `slow_dead_end` | Delayed dead end beside a live branch |
| `discovery_metadata` | robots, sitemap, and `.well-known` discovery |
| `static_js_discovery` | A generated JavaScript asset names the endpoint |
| `canonical_alias_dedup` | Two aliases resolve to one canonical resource |
| `multi_service` | Multiple read-only services share one target |

The executable boundary is
[`discovery-lab-v3/app.py`](../../benchmarks/competitors/labs/discovery-lab-v3/app.py).
Its private manifest and ledger paths belong to the controller process; do not
pass them to a product adapter.

The supported competitor path is wired end to end. The launcher definition
`linux-blackbox-small-model-v3` generates all 12 scenario inputs and the frozen
analysis plan; the campaign runner schedules its paired seeds and emits one
schema-2.0 run record per product execution; and `labctl` generates a private
fixture, recreates the Docker lab, verifies health, and cleans it up. The
product runs in an ephemeral working directory and receives only the neutral
scenario and stable target URL. The controller state stays under ignored
`.benchmark-state/` paths.

## Frozen analysis and publication

Create and persist `analysis-plan.json` before launching a publishable
campaign. Its SHA-256 digest covers the exact systems, scenarios, paired
fixture seeds, repetitions, populations, metrics, deadlines, comparison pairs,
alpha, bootstrap sample count, exclusion rules, hosts, and batches. A run must
attest that digest; a byte-different existing plan is never overwritten.

The supported launcher derives the plan from
`OCTOBENCH_V3_BASE_FIXTURE_SEED`, which must be 32–64 hexadecimal characters.
That base secret is required execution input and is not serialized into the
generated campaign. `OCTOBENCH_V3_BATCH_ID` and `OCTOBENCH_V3_HOST_ID` may set
the attested design identifiers; they default to `batch-1` and a deterministic
local runtime identity respectively. These identifiers describe the actual
run placement; they do not increase the plan's declared batch/host counts.

The analysis validates the complete frozen schedule and that every system in a
paired block received the same fixture digest. It publishes:

- Wilson intervals for binomial outcomes and pooled recall/precision counts;
- deterministic paired bootstrap effects (right minus left) and standardized
  paired effect sizes;
- completion-by-deadline over all scheduled runs;
- Kaplan–Meier completion survival, censor-aware median when reached, and
  restricted mean completion time;
- deterministic `runs.csv`, full schema-2.0 `runs-NNNN.jsonl` shards,
  `statistics.json`, `analysis-plan.json`, a script-free `comparison.svg`,
  `publication.json`, and `SHA256SUMS`;
- required `ledgers-NNNN.jsonl` audit-evidence shards with the complete
  controller request-ledger chain for every run, tied to its run ID, fixture
  digest, paired seed, and ledger root digest;
- a checksum-covered `campaign-context.json` containing sanitized campaign,
  system, scenario, preflight, reset/health, cleanup, status, and provenance
  records plus post-closure fixture reveal manifests.

Publication schema 1.1 splits run records and controller ledgers at canonical
JSONL record boundaries into deterministically numbered, root-level shards of
at most 48,000,000 bytes each. Each artifact family is limited to 512,000,000
bytes in aggregate. Sharding is lossless: it neither drops ledger entries nor
removes the action-telemetry projection from a run. The manifest lists every
shard in byte-stable order and `SHA256SUMS` covers each one independently.

The SVG has separate panels for execution outcomes, task outcomes, verified
recall with confidence intervals, and censored completion time. It declares no
automatic winner. `verify_v3_results` checks the complete top-level file set,
every checksum, the plan/track identities, the exact frozen schedule and plan
attestations and fixture-reveal coverage. The context and controller ledgers
are mandatory for every publishable v3 bundle. The verifier validates every
chain, root digest, and action-telemetry projection, then independently
re-evaluates every reported claim and task outcome from the revealed truth,
completion rule, policy status, and ledger-observed evidence. It regenerates
`runs.csv`, statistics, and the SVG from the full run records before accepting
a bundle, so re-checksummed aggregate or evaluation tampering is rejected.

`verify_v3_results` remains backward-compatible with publication schema 1.0
bundles that use single `runs.jsonl` and `ledgers.jsonl` files. To convert a
verified legacy bundle into the current sharded layout, write to a new,
nonexistent destination:

```bash
./venv/bin/python -c \
  'import sys; from core.benchmarks.v3 import repack_v3_results; print(repack_v3_results(sys.argv[1], sys.argv[2]))' \
  <verified-v1.0-source> <new-v1.1-destination>
```

The repacker verifies the source before reading its audit material, publishes
atomically, and verifies the destination before returning. Verification and
repacking stream one JSONL record at a time and retain only compact per-run
metadata, so peak memory is bounded by the largest run/ledger record instead of
the full evidence bundle.

## Isolated tracks

The following track IDs have different model/source/outcome contracts and
different merge groups:

- `small-model-stress-v3`
- `shared-model-full-system-v1`
- `vendor-native-v1`
- `whitebox-v1`
- `ctf-v1`
- `octopus-ablation-v1`

Mixed-track input raises `TrackIsolationError`; it cannot form one leaderboard.
Diagnostic designs use one run and are not publishable. Canary designs use two
runs. Full small-model/shared/whitebox/CTF designs require at least 12 paired
runs per system/scenario, ablations require 20 paired blocks, and vendor-native
requires at least 30 paired runs, two batches, and two attested hosts.
