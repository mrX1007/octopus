# Benchmark v4 methodology

Benchmark v4 is an additive efficiency companion to Benchmark v3. It consumes
a checksum-verified v3 bundle and never changes the v3 run, fixture, analysis,
or publication contracts. The source v3 bundle remains the normative evidence
for execution stability, task outcome, claims, and the controller request
ledger. V4 freezes a separate plan before a live campaign and derives resource
and quality-on-resource statistics from that evidence.

V4 is deliberately not a single-score leaderboard. It publishes quality,
stability, resource use, telemetry coverage, paired effects, and Pareto results
as separate estimands. `automatic_winner` is always `false`.

## Primary questions

The benchmark answers four different questions without merging them:

1. Did the product process remain stable?
2. Did the independently sealed task completion rule pass?
3. How much controller-observed work did the product consume?
4. Among matched pairs where both products completed the task, did either
   product retain quality while using less of a comparable resource?

This separation prevents a product that exits quickly without completing the
task from appearing efficient.

## Frozen design

Under efficiency plan schema 1.1, `efficiency-plan.json` is write-once and
content-addressed. It binds the source
v3 analysis-plan digest, systems, scenarios, matched fixture seeds, comparison
pairs, resource definitions, optimization direction, quality gate,
non-inferiority margin, telemetry coverage gates, bootstrap design, and an
explicit block schedule. It also freezes an all-scheduled joint-completion
population gate for every directional efficiency claim.

The schedule pseudo-randomizes scenario blocks using a frozen schedule seed.
The two system runs for one fixture seed remain adjacent, receive the same
fixture variant, and use a position-balanced system order. The source v3 plan
continues to validate the complete set of runs; v4 additionally validates the
actual chronological order against its frozen schedule.

The shipped live definition uses 20 repetitions for each of 12 scenario
families (240 matched pairs). This increases within-family precision over v3,
but it is not presented as a universal power guarantee: the 12 families remain
the generalization boundary, uncertainty is reported explicitly, and a wide
interval yields an inconclusive result rather than a post-hoc sample increase.

A publishable v4 campaign attests the efficiency-plan digest in every source
run. A retrospective diagnostic may omit that attestation, but it is labelled
diagnostic and cannot be presented as a pre-registered efficiency result.

## Mandatory readiness calibration

The full 480-run evaluation cannot start until a separate prospective
readiness calibration passes. Its write-once plan uses calibration-only fixture
seeds that do not overlap the evaluation schedule. It runs one fixed
repetition across all 12 families: 24 scored product executions (Octopus and
Strix) plus 12 controller-owned sealed-reference checks. Product runs have a
300-second hard cap, so the product-time ceiling is two hours rather than the
full campaign's 120 hours.

The gate is functional, not a leaderboard and not part of the evaluation
sample. It requires the exact predeclared run set, a perfect sealed reference
for every family, verified-recall coverage for every product run, all scheduled
product tasks completed, and every matched product block jointly claim-eligible
for both products. Claim eligibility requires positive verified-recall
numerators and denominators, available verified claim precision, positive wall
time, and a positive verified controller-ledger count that matches action
telemetry. Policy violations remain zero-tolerance.
Missing runs, extra runs, selective retries, evaluation-track runs, mismatched
fixture variants, or a modified attestation fail closed. The shipped profile
requires 12/12 completed runs per product, a 100% system completion rate, and
12/12 jointly claim-eligible blocks; readiness therefore
cannot open from a favorable one-family subset when the full efficiency claim
requires the complete scheduled population.

Calibration runs and evidence remain owner-only under
`.benchmark-state/readiness-journal/<campaign-id>/`. Immediately before the
first full evaluation run, the launcher reloads the complete journal,
recomputes the evidence, and verifies its binding to the same immutable
analysis and efficiency plans. A failed readiness run is not repaired by
selecting successful attempts; fix the cause and use a fresh campaign ID.

### Interpreting a blocked calibration

A blocked calibration establishes only that one or more prospective gates were
not met. It remains owner-only, is not an evaluation sample, and must not be
published as a product ranking or efficiency result. Its controller-private
`request-ledger.jsonl` files remain the source for individual method, status,
violation, route and timestamp records.

Before retrying readiness, run one fixed, positive
`canonical-alias-dedup-v3` diagnostic pilot for each product with the same
300-second per-product cap. Pilot IDs are disposable and must differ from the
future readiness ID. Diagnostic schema 1.1 records claim-shape fields plus
`ledger_contract_status`, `ledger_entry_count`, `evidence_event_count`, and
`policy_violation_count` in each run summary. A v3 pilot exits zero only when
the product/lifecycle finishes cleanly, the reported claim list is nonempty
and contains only complete, exact `OCTOBENCH_V3_*` values, at least one
controller-verified evidence event occurred, and the verified ledger contains
no mutation violation.

Inspect the owner-only `adapter.log`, `process.log`, and `product.log` files below
`.benchmark-state/diagnostics/<pilot-id>/raw/<system>/<scenario>/` when the
automatic check fails, and inspect the matching private fixture ledger below
`.benchmark-state/lab-v3/<pilot-id>/`. The pilot verifies the ledger hash chain,
but its claim-shape and evidence-contact checks still do not establish claim
correctness or recall. Do not whitelist a mutation, relax the zero-tolerance
gate, or copy a token into the final report in the adapter. These raw logs must
never be staged, published, or attached; create a separate manually reviewed
sanitized excerpt if support analysis is required.

The full source v3 campaign context and every source run publish only the same
non-sensitive, exact `readiness_attestation`: `campaign_id`, `status` (`ready`),
`profile_digest`, `plan_digest`, `evidence_digest`, `source_run_digest`,
`reset_attestation_set_digest`, and `cleanup_attestation_digest`. The v4
companion copies that eight-field commitment into `source-attestation.json`;
both verifiers reject a missing, extra, or mismatched field. Raw calibration
runs, reset and cleanup records, evidence summaries, and the readiness journal
remain private and owner-only.

## Quality and stability

V4 reuses v3's sealed task outcome and verified claim evaluation. Per-run
quality is verified F1, the harmonic mean of `verified_recall` and
`verified_claim_precision` from the `all_scheduled` population. Both original
components remain published; F1 is not used to hide either one.

Execution success, task completion, policy violations, and v3's censor-aware
time-to-completion remain separate stability/outcome fields. The v3
`duration_censored` flag still describes time to successful task completion.
For resource accounting, the runner-measured elapsed time is exact consumed
wall time up to normal exit or enforced termination, including for failed and
timed-out runs.

## Resource measurements

The primary resources are intentionally limited to measurements with a common
controller boundary:

| Resource | Source | Reliability |
| --- | --- | --- |
| `wall_time_seconds` | command runner monotonic clock | measured |
| `fixture_http_requests` | hash-chained controller lab ledger | verified |

The same ledger also derives `unique_fixture_targets`,
`repeated_fixture_requests`, `unsuccessful_fixture_requests`, and
`evidence_bearing_requests`. These are diagnostic resource-shape metrics; a
repeated request is not automatically labelled waste because retries and
cycles can be part of a scenario.

`tool_calls`, `output_bytes`, `model_tokens`, and `api_cost_usd` are secondary
budget observations. They retain the source record's availability and
reliability. Missing or non-comparable telemetry is `unavailable`, never zero,
and cannot enter a paired efficiency claim.

CPU, RSS, GPU, energy, and provider-token figures are not inferred from the
adapter process. A future campaign may add them only through a common
controller-owned cgroup/model-gateway ledger. Until then they are outside the
primary v4 contract; this avoids undercounting container or shared-model work
for one system.

## Efficiency estimands

Every system receives all-scheduled resource summaries, even when a run fails.
Quality-on-resource and resource-superiority analysis uses only matched blocks
where both systems have `task_status == completed`. Exclusion counts and
reasons are published for every comparison and resource. Schema 1.1 prevents
that conditional denominator from becoming a favorable selected subset: a
directional claim additionally requires every scheduled pair, across the exact
frozen scenario-family set, to be jointly completed and quality-qualified.

For each scenario and then as an equal-weight macro result across scenarios,
v4 publishes:

- raw quality and raw resource distributions;
- completed tasks and verified-F1 yield per unit of available resource;
- deterministic hierarchical paired bootstrap quality differences;
- geometric mean resource ratios for strictly positive measurements;
- paired quality-per-resource differences;
- right-dominates, left-dominates, trade-off, and tie counts.

The hierarchical bootstrap resamples scenario families and then matched blocks
inside the sampled family. The plan freezes alpha, sample count, and seed.
Zero denominators are unavailable rather than replaced with an epsilon. A
directional claim is suppressed if any jointly completed, quality-qualified
pair lacks a strictly positive resource observation; v4 never selects only the
positive subset. For directional claims, the nominal alpha is divided by the
number of frozen comparison-pair/resource combinations (Bonferroni);
descriptive intervals do not become an overall family-wise ranking.

A directional per-resource efficiency claim is eligible only when all of the
following were frozen and pass:

- both products completed the task in the contributing pairs;
- the contributing population equals all scheduled pairs and covers the exact
  frozen scenario-family set; one or a few favorable completed pairs cannot
  support a directional claim;
- verified F1 is available for every all-scheduled pair and every jointly
  completed pair;
- primary telemetry coverage and balance gates pass;
- on all scheduled pairs, completion and verified-F1 differences both pass
  their frozen non-inferiority gates (the lower confidence bound is above the
  negative margin);
- within the jointly completed subset, the lower confidence bound for the
  quality difference is also above the negative frozen margin;
- the resource-ratio confidence interval supports lower consumption;
- the relevant model, hardware, fixture, host/batch, ordering, and policy
  checks pass.

Even then the claim applies only to that resource and track. Conflicting
resource results are a trade-off, not an overall winner. If any scheduled pair
is not jointly completed and quality-qualified, v4 still publishes stability,
resource consumption, exclusions and descriptive paired effects, but its
directional result is `inconclusive`.

## Fairness and missing data

The v4 verifier requires the complete verified v3 schedule and one matching
controller ledger per run. It checks paired fixture digests, same paired seed,
plan attestation, system-order balance, chronological block order, per-pair
host and batch identity, and the common fairness profile. The shipped v4
definition also pins the same model weights, Ollama server, context, hardware,
neutral backend preload, concurrency declarations, wall deadline, output cap,
and generated read-only fixture contract.

Native prompts and tool stacks remain different because this is a full-system
comparison. Consequently tool-call counts are secondary and the track is an
engineering small-model efficiency comparison, not a causal framework-only or
vendor-representative ranking.

Product failures, timeouts, invalid results, and policy violations are never
trimmed or retried selectively. Infrastructure-invalid pairs remain visible and
may be replaced only by a future protocol that freezes pair-level replacement
rules before execution. V4 performs no imputation, winsorization, best-run
selection, or optional stopping.

## Publication and verification

A v4 companion bundle contains:

- `efficiency-plan.json`;
- `efficiency-runs.csv` and canonical `efficiency-runs.jsonl` projections;
- `efficiency-statistics.json`;
- a script-free `efficiency.svg`;
- `source-attestation.json` containing the digest of the source v3
  `SHA256SUMS` file and, for a full campaign, its exact eight-field public
  readiness commitment;
- `publication.json` and `SHA256SUMS`.

The companion does not duplicate the potentially large v3 bundle. Verification
therefore takes both directories, verifies v3 first, checks the source digest,
re-derives every ledger/resource projection, recomputes the statistics, CSV,
JSONL, and SVG, and then compares them byte-for-byte. Re-checksumming a modified
aggregate is insufficient to pass.

Verify both bundles on the execution host and again after transfer. Keep the
original source until the destination passes `core.benchmarks.v4 verify`;
copying only aggregates or regenerating a checksum manifest cannot recover
missing controller evidence.

The supported workflow for the next live campaign is:

```bash
set -euo pipefail

PREVIEW_ID="linux-blackbox-small-model-v4-check-$(date -u +%Y%m%dt%H%M%Sz)"
./venv/bin/python -m core.benchmarks.competitors.launch \
  --campaign-id "$PREVIEW_ID" \
  --campaign-definition linux-blackbox-small-model-v4 \
  --profile core \
  --environment-file benchmarks/competitors/secrets.env \
  --prepare-only
```

Stop after this command and manually review the generated
`analysis-plan.json`, `efficiency-plan.json`, `readiness-plan.json`, neutral
scenarios, and system manifests beneath
`.benchmark-state/generated/$PREVIEW_ID/`. Do not turn preview, pilots,
readiness, full execution, and publication into one unattended shell block.
After review, follow the separately bounded diagnostic, readiness, full-run,
verification, and exact-two-directory Git steps in the
[campaign runbook](../../benchmarks/competitors/campaigns/linux-blackbox-small-model-v4/README.md).
Each section has its own fail-closed checks and deliberate operator boundary.

Run the live campaign only in the authorized, isolated Linux environment
described by the competitor benchmark runbook. A prepare-only preview is not a
live measurement and its campaign ID must not be reused for calibration.
