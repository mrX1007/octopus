# Cancellation, cleanup, and recovery

Status: implemented runtime reliability boundary  
Cancellation contract: `1.0` (in-process)  
Durable mission schema: `1.4`

## Cooperative cancellation

Every `ExecutionContext` carries a thread-safe `CancellationContext`. A token
can be cancelled once with a bounded reason code or can expire at a monotonic
deadline. `ExecutionCancelled` is control flow (a `BaseException`), so broad
provider `except Exception` handlers cannot accidentally convert cancellation
to an ordinary failure. Its string contains only the reason code; optional
partial stdout/stderr are attributes consumed and redacted at the canonical
result boundary.

`AIPipeline` owns one token per scan and exposes `cancel()`. The scan loop checks
it between iterations and tasks, and every command context shares it. Policy
fails a cancelled context closed. `PipelineRuntime` and `ActionExecutor`
normalize cancellation separately from failure; an action that was attempted
still runs its declared cleanup phase.

## Process lifetime and tree cleanup

The canonical direct/shell runner and the legacy `run_tool()` compatibility
runner now enforce both `ExecutionContext.max_runtime_seconds` and
`max_output_bytes`. `timeout=0` no longer means unlimited. POSIX children start
in a new session; timeout, cancellation, output exhaustion, and
`KeyboardInterrupt` send `SIGTERM` to the process group, wait a short grace
period, then use `SIGKILL`. The non-POSIX fallback terminates then kills the
child. The Metasploit adapter path uses the same bounded tree cleanup and
checks cancellation once per second.

Plugin workers already use a fresh process group, bounded IPC, TERM/KILL, and a
cleanup marker. Long-lived C2 is a separately supervised application service,
not a tool subprocess. Local build helpers now have explicit wall-clock
timeouts as a final guard.

## Ctrl+C and partial output

`OctopusCLIApplication.run()` installs the compatibility handler only for the
interactive lifecycle and restores the previous SIGINT handler on exit. The
handler requests cancellation on the currently bound execution, marks the scan
session interrupted, stops the supervisor, and raises `KeyboardInterrupt`. It
does not call `os._exit`; Python can unwind mission transactions and process
`finally` blocks.

Process cancellation raises `ExecutionCancelled` with already captured bounded
output. Runtime normalization redacts it and marks the result `cancelled` and
`partial`. The pipeline persists derived safe facts, the canonical command
result, execution/fact provenance, and decision trace before re-raising control
flow to `ScanLifecycle`, which interrupts the durable mission.

## Retry and circuit breaker

Retry classification remains limited to `unavailable`, `timeout`, and typed or
explicitly marked transient failures. Three consecutive recent `unavailable`
events open a provider/capability/target-class circuit for five minutes by
default. An open provider is rejected with a trace reason. After cooldown it is
half-open and may be probed with a ranking penalty; any newer non-unavailable
result closes the circuit.

Task-level retries are separately bounded by the persisted `TaskRetryPolicy`.
Attempt terminalization, budget consumption, and the command-key retry grant
commit in one mission-store transaction. The scheduler reauthorizes every
retry, consumes each grant once before dispatch, bypasses duplicate suppression
and only matching timeout-degraded suppression, and reloads pending grants from
SQLite after restart.

MissionStore schema `1.4` also persists the retry's absolute `not_before`, a
bounded typed fixed/exponential `TaskBackoff`, and the provider-circuit
reference that caused a longer deferral. Recovery never reconstructs or sleeps
through this delay in memory: deferred tasks are omitted from resumable plans,
`begin_attempt()` rejects early dispatch until the durable timestamp has
elapsed, and a scan with only deferred work is interrupted as `tasks_deferred`
rather than incorrectly completed.

## Transaction and idempotency boundaries

- mission/task/attempt transitions use `BEGIN IMMEDIATE`, owner fencing, one
  running attempt per task, monotonic attempt numbers, and idempotent terminal
  completion; eligible typed retries commit their bounded dispatch allowlist in
  the same transaction as the failed attempt;
- canonical fact insertion uses an immediate transaction and a unique fact
  identity, while graph projection has its own fact/assessment/version ledger;
- provider telemetry writes and pruning share one immediate transaction and
  deduplicate by execution ID;
- production completion hashes its idempotency key and reserves a durable
  claim before parsing or callbacks. Scope plus the versioned result envelope
  form a keyed request fingerprint: conflicting reuse fails closed before
  evidence writes, while exact replay returns the original result/fact IDs,
  repairs pending graph projection and advances only missing attempt
  provenance. Pending ownership has a bounded lease so a crash cannot fence
  the completion forever. Ownership is validated and renewed atomically with
  each fact write; scan clearing fails closed while a live claim exists and
  advances a retained keyed scan generation before removing expired claims and
  evidence. Production captures the generation before dispatch, so even a
  result that returns after reset but before creating its claim is rejected.
  The canonical completion ingress requires the bound scan/generation token and
  fails before parsing when it is absent;
- completed command-result execution IDs are attached to the durable attempt
  before downstream terminalization. A pre-dispatch `running` check marker is
  not treated as proof of execution during recovery; a crash in that window
  leaves the command eligible rather than permanently suppressing work that
  may never have reached the provider.

There is no false claim of an atomic transaction across SQLite, MariaDB, plugin
processes, or external targets. Recovery fences abandoned mission ownership,
retains completed evidence/result rows, interrupts the old attempt, and starts
a new monotonic attempt only for unfinished work.

Runtime completion callbacks are explicitly idempotent, at-least-once
projection hooks. A crash after an external callback effect but before result
finalization can repeat that callback after lease recovery. A future
non-idempotent consumer requires a transactional outbox and its own durable
idempotency marker; a lease heartbeat alone cannot provide exactly-once
delivery.

Exceptions are normalized through the runtime redactor before persistence or
audit. Free-form cancellation reasons are reduced to codes, idempotency keys
are hashed, and live process error messages are bounded and command-redacted.

Contract coverage is in `tests/test_execution_reliability.py`,
`tests/test_pipeline_mission_lifecycle.py`, and
`tests/test_pipeline_mission_resume.py`, plus
`tests/test_durable_retry_execution.py`.
