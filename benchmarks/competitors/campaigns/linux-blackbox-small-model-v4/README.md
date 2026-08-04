# Linux black-box small-model v4

`linux-blackbox-small-model-v4` is the efficiency companion to the Benchmark v3
blinded discovery design. It keeps the same two systems, pinned abliterated
Qwen 9B/Ollama runtime, 12 generated read-only fixture families,
independent task evaluator, and controller request ledger. It adds a frozen
efficiency plan with 20 matched repetitions per system/scenario, randomized
scenario-block order, position-balanced adjacent system pairs, controller-
derived resource metrics, and a task-completion gate for efficiency claims.
This runnable definition is not itself an efficiency result.

Efficiency plan/statistics schema 1.1 permits a directional resource claim
only when all 240 frozen matched pairs, across the exact 12-family scenario
set, are jointly completed and quality-qualified. Any incomplete pair keeps
the descriptive measurements and exclusions but makes the directional result
`inconclusive`; shared failures cannot create a smaller favorable denominator.

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
PREVIEW_ID="linux-blackbox-small-model-v4-check-$(date -u +%Y%m%dt%H%M%Sz)"
./venv/bin/python -m core.benchmarks.competitors.launch \
  --campaign-id "$PREVIEW_ID" \
  --campaign-definition linux-blackbox-small-model-v4 \
  --profile core \
  --environment-file benchmarks/competitors/secrets.env \
  --prepare-only
```

Review `analysis-plan.json`, `efficiency-plan.json`, `readiness-plan.json`, all
generated neutral scenarios, and the system manifests. A preview ID is
write-once; use a new ID for calibration and the live campaign.

## Required short diagnostic before readiness

A blocked calibration remains owner-only. It establishes only that one or more
prospective readiness gates were not met; it is not published and establishes
no quality ranking or efficiency result.

Before spending another complete readiness schedule, run the same fixed
positive diagnostic once for each product. Use disposable IDs that will never
be reused for readiness:

```bash
PILOT_SCENARIO="canonical-alias-dedup-v3"
for SYSTEM_ID in octopus strix; do
  PILOT_ID="linux-blackbox-small-model-v4-pilot-${SYSTEM_ID}-$(date -u +%Y%m%dt%H%M%Sz)"
  PILOT_EXIT=0
  SUMMARY_EXIT=0
  ./venv/bin/python -m core.benchmarks.competitors.launch \
    --campaign-id "$PILOT_ID" \
    --campaign-definition linux-blackbox-small-model-v4 \
    --profile core \
    --environment-file benchmarks/competitors/secrets.env \
    --diagnostic-pilot \
    --pilot-system "$SYSTEM_ID" \
    --pilot-scenario "$PILOT_SCENARIO" \
    --pilot-seconds 300 || PILOT_EXIT=$?

  ./venv/bin/python -m json.tool \
    ".benchmark-state/diagnostics/$PILOT_ID/summary.json" || SUMMARY_EXIT=$?
  find ".benchmark-state/diagnostics/$PILOT_ID/raw/$SYSTEM_ID/$PILOT_SCENARIO" \
    -type f \( -name adapter.log -o -name product.log -o -name process.log \) -print
  find ".benchmark-state/lab-v3/$PILOT_ID" \
    -name request-ledger.jsonl -print
  if [ "$PILOT_EXIT" -ne 0 ] || [ "$SUMMARY_EXIT" -ne 0 ]; then
    EXIT_CODE="$PILOT_EXIT"
    if [ "$EXIT_CODE" -eq 0 ]; then
      EXIT_CODE="$SUMMARY_EXIT"
    fi
    echo "diagnostic pilot or summary validation failed for $SYSTEM_ID; readiness is blocked" >&2
    exit "$EXIT_CODE"
  fi
done
```

The diagnostic summary and raw `adapter.log`, `product.log`, and `process.log`
files are owner-only, ignored by Git and `publishable: false`. Never stage,
publish, or attach a raw log, even after editing it in place. When support
context must be shared, create a separate sanitized excerpt or sanitized
summary outside the raw directory, review that new file, and share only that
copy; it must not enter a benchmark result bundle.

The pilot prints flushed `diagnostic` start/finish progress to stderr around
every run, so a long model invocation is distinguishable from a launcher hang
while stdout remains reserved for the final summary path.
Diagnostic schema 1.1 writes `claim_contract_status`,
`reported_claim_count`, `exact_claim_count`, `ledger_contract_status`,
`ledger_entry_count`, `evidence_event_count`, and `policy_violation_count` for
every run. The command returns nonzero unless all of the following hold for
each v3 product:

- process `status` is `succeeded`, `error_class` is empty, reset is healthy and
  cleanup succeeded;
- `claim_contract_status` is `satisfied`;
- `reported_claim_count == exact_claim_count` and both counts are greater than
  zero;
- `ledger_contract_status` is `satisfied`, `ledger_entry_count` and
  `evidence_event_count` are greater than zero, and `policy_violation_count` is
  zero.

The automatic check verifies the ledger's hash chain, evidence contact and
read-only policy, but claim shape plus evidence contact still do not establish
claim correctness or recall. Use `adapter.log`, `product.log`, `process.log`,
and the ledger to diagnose a failed pilot. Do not copy controller truth into a
product report, ignore mutation requests, loosen thresholds or select a
friendlier pilot scenario.

Only after both disposable pilots satisfy those criteria, use a different
fresh ID for the mandatory readiness calibration:

```bash
RUN_ID="linux-blackbox-small-model-v4-$(date -u +%Y%m%dt%H%M%Sz)"
READINESS_EVIDENCE=".benchmark-state/readiness-journal/$RUN_ID/readiness-evidence.json"
READINESS_EXIT=0
EVIDENCE_EXIT=0
./venv/bin/python -m core.benchmarks.competitors.launch \
  --campaign-id "$RUN_ID" \
  --campaign-definition linux-blackbox-small-model-v4 \
  --profile core \
  --environment-file benchmarks/competitors/secrets.env \
  --readiness-calibration || READINESS_EXIT=$?

./venv/bin/python -m json.tool \
  "$READINESS_EVIDENCE" || EVIDENCE_EXIT=$?

if [ "$READINESS_EXIT" -ne 0 ] || [ "$EVIDENCE_EXIT" -ne 0 ]; then
  EXIT_CODE="$READINESS_EXIT"
  if [ "$EXIT_CODE" -eq 0 ]; then
    EXIT_CODE="$EVIDENCE_EXIT"
  fi
  echo "readiness calibration or evidence validation failed; full campaign is blocked" >&2
  exit "$EXIT_CODE"
fi

if ! ./venv/bin/python -c \
  'import json,sys; payload=json.load(open(sys.argv[1], encoding="utf-8")); raise SystemExit(0 if payload.get("status") == "ready" else 1)' \
  "$READINESS_EVIDENCE"
then
  echo "readiness evidence status is not ready; full campaign is blocked" >&2
  exit 1
fi
```

The calibration prints a flushed `run_start` to stderr before each
reset/execution and a `run_finish` after that run is durably journaled,
including its safe status and duration but no seed, claim, token, artifact or
error text. Stdout remains reserved for the final evidence path. A visible
start without a finish means that exact run (or its reset) is still active.

The command succeeds only when both products complete all 12 scheduled runs;
all 12 matched blocks carry verified recall and claim precision, positive wall
time, and a positive verified controller-ledger count for both products; the
sealed reference is perfect for all families; and no policy violation occurs.
Passing only a subset of families does not satisfy this gate. The complete
append-only calibration journal is recomputed before the full run; no
successful retry can replace a failed scheduled attempt. If readiness fails,
fix the adapter/runtime, repeat both disposable diagnostic pilots, and then
start readiness again with a fresh ID. A blocked calibration remains private
diagnostic evidence and must not be presented or published as an efficiency
result.

After the evidence reports `"status": "ready"`, run the full campaign with the
same ID and no readiness flag:

```bash
if [ -z "${RUN_ID:-}" ]; then
  echo "RUN_ID is not set; full campaign is blocked" >&2
  exit 1
fi
READINESS_EVIDENCE=".benchmark-state/readiness-journal/$RUN_ID/readiness-evidence.json"
if ! ./venv/bin/python -c \
  'import json,sys; payload=json.load(open(sys.argv[1], encoding="utf-8")); raise SystemExit(0 if payload.get("status") == "ready" else 1)' \
  "$READINESS_EVIDENCE"
then
  echo "readiness evidence status is not ready; full campaign is blocked" >&2
  exit 1
fi

if ! ./venv/bin/python -m core.benchmarks.competitors.launch \
  --campaign-id "$RUN_ID" \
  --campaign-definition linux-blackbox-small-model-v4 \
  --profile core \
  --environment-file benchmarks/competitors/secrets.env
then
  echo "full campaign failed; v4 publication is blocked" >&2
  exit 1
fi
```

After that campaign publishes its source v3 evidence bundle, create and verify
the additive efficiency companion:

```bash
SOURCE="benchmarks/competitors/results/$RUN_ID"
COMPANION="benchmarks/competitors/results/$RUN_ID-efficiency-v4"

if ! ./venv/bin/python -m core.benchmarks.v4 publish \
  --plan ".benchmark-state/generated/$RUN_ID/efficiency-plan.json" \
  --source-v3 "$SOURCE" \
  --output "$COMPANION"
then
  echo "v4 companion publication failed; verification and Git publication are blocked" >&2
  exit 1
fi

if ! ./venv/bin/python -m core.benchmarks.v4 verify \
  --source-v3 "$SOURCE" \
  "$COMPANION"
then
  echo "v4 source/companion verification failed; Git publication is blocked" >&2
  exit 1
fi
```

After both directories pass verification on the destination host, stage the
source evidence and its companion together. Never use `git add .` for a
benchmark publication:

```bash
if [ -z "${RUN_ID:-}" ]; then
  echo "RUN_ID is not set; Git publication is blocked" >&2
  exit 1
fi
SOURCE="benchmarks/competitors/results/$RUN_ID"
COMPANION="benchmarks/competitors/results/$RUN_ID-efficiency-v4"
test -d "$SOURCE" && test -d "$COMPANION" || {
  echo "verified source or v4 companion is missing; publication is blocked" >&2
  exit 1
}

if ! ./venv/bin/python -m core.benchmarks.v4 verify \
  --source-v3 "$SOURCE" \
  "$COMPANION"
then
  echo "destination verification failed; Git publication is blocked" >&2
  exit 1
fi

if ! git diff --cached --quiet; then
  echo "Git index already contains staged changes; publication is blocked" >&2
  exit 1
fi
git add -- "$SOURCE" "$COMPANION" || exit $?
git diff --cached --check || exit $?
git diff --cached --stat || exit $?
git commit -m "Publish competitor benchmark $RUN_ID with efficiency v4" || exit $?
git push -u origin "$(git branch --show-current)"
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
resource statistics, while every directional efficiency claim becomes
`inconclusive` for the campaign comparison.

See [Benchmark v4 methodology](../../../../docs/benchmarks/benchmark-v4.md) and
the parent [competitor runbook](../../README.md) before execution.
