# Cancellation, cleanup, and recovery

Status: implemented runtime reliability boundary  
Cancellation contract: `1.0` (in-process)  
Durable mission schema: `1.2`

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

The CLI signal handler requests cancellation on the currently bound execution,
marks the scan session interrupted, stops the supervisor, and raises
`KeyboardInterrupt`. It no longer calls `os._exit`; Python can unwind mission
transactions and process `finally` blocks.

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

## Transaction and idempotency boundaries

- mission/task/attempt transitions use `BEGIN IMMEDIATE`, owner fencing, one
  running attempt per task, monotonic attempt numbers, and idempotent terminal
  completion; eligible typed retries commit their bounded dispatch allowlist in
  the same transaction as the failed attempt;
- canonical fact insertion uses an immediate transaction and a unique fact
  identity, while graph projection has its own fact/assessment/version ledger;
- provider telemetry writes and pruning share one immediate transaction and
  deduplicate by execution ID;
- production command results use a SHA-256 idempotency key derived from the
  execution ID. Repeating persistence returns the original row without storing
  the raw key;
- command execution ID is attached to the durable attempt before downstream
  parsing. Fact and result writes are separately committed and idempotent, so
  restart recovery is deliberately at-most-once for execution rather than
  risking an unapproved duplicate side effect.

There is no false claim of an atomic transaction across SQLite, MariaDB, plugin
processes, or external targets. Recovery fences abandoned mission ownership,
retains completed evidence/result rows, interrupts the old attempt, and starts
a new monotonic attempt only for unfinished work.

Exceptions are normalized through the runtime redactor before persistence or
audit. Free-form cancellation reasons are reduced to codes, idempotency keys
are hashed, and live process error messages are bounded and command-redacted.

Contract coverage is in `tests/test_execution_reliability.py`,
`tests/test_pipeline_mission_lifecycle.py`, and
`tests/test_pipeline_mission_resume.py`, plus
`tests/test_durable_retry_execution.py`.
