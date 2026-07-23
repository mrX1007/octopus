# Durable mission and task lifecycle

Snapshot date: 2026-07-23

`MissionStore` is the control-plane authority for AI mission, planner-task, and
task-attempt state. It uses the same SQLite database file as `FactStore`, but
facts remain the evidence authority and C2 delivery tasks remain a separate
protocol domain.

## Identity and schema

The additive schema is exposed by `core.ai.mission_store` and declares version
`1.4` in `mission_lifecycle_schema`. It does not use SQLite `user_version`, so
it can coexist with the existing FactStore tables.

The public import remains a compatibility facade. Persistence responsibilities
are split without changing the API or schema:

- `mission_store_models.py` owns lifecycle enums, immutable records, typed task
  definitions, validation limits, and public exceptions;
- `mission_store_schema.py` owns table/index creation, version checks, additive
  migrations, and legacy task-identity backfill;
- `mission_store_tasks.py` owns task, dependency, attempt, retry, and progress
  repository transitions;
- `mission_store_replans.py` owns evaluated-snapshot and durable replan rows;
- `mission_store_codecs.py` owns bounded/redacted JSON and SQLite row codecs;
- `mission_store_maintenance.py` owns connections, short transactions, close,
  and abandoned-running-work recovery maintenance.

`MissionStore` composes those layers and retains the existing methods and
return types. None of the layers opens a second database authority or changes
transaction boundaries.

Opening a `1.0`, `1.1`, `1.2`, or `1.3` store performs one transactional,
additive migration. Durable state-replan columns and the typed task-definition
columns are added with compatibility defaults. Existing mission rows are
advanced to `1.4`, and the component version changes only after every row has a
valid typed identity. Unknown versions still fail closed before lifecycle
tables are created or changed. Operational backup, validation, compatibility,
and rollback steps are in `docs/migrations/mission-store-1.4.md`.

- `missions` has one opaque `mission_id`; a keyed digest of the raw scan ID is
  the unique lookup identity, while the bounded/redacted scan ID is display
  data only. It also owns the consumed state-change replan count and deduplicated
  transition signatures, so a restart cannot restore spent replan budget.
- `mission_tasks` has one opaque `task_id`. Its unique identity includes the
  mission, legacy-compatible `agent/task` key, versioned `TaskScope`, and task
  definition version. A scope is a sorted set of canonical graph entity IDs;
  legacy string-only scopes use a keyed digest instead. This permits the same
  agent/capability task for multiple assets, services, or endpoints without a
  collision. The row retains bounded/redacted string `scope` and `capability`
  fields for old readers while also persisting the typed scope, canonical
  capability ID, `not_before`, typed backoff, provider-circuit reference, and
  evaluated-fact snapshot reference.
- `mission_task_dependencies` stores same-mission task dependencies with
  foreign keys.
- `mission_task_attempts` has one opaque `attempt_id` and a monotonic
  `(task_id, attempt_number)` identity. A partial unique index permits at most
  one running attempt per task.
- `mission_task_retry_commands` stores the bounded command-key allowlist for
  each consumed task retry number and whether each grant has been consumed.
- `mission_evaluated_fact_snapshots` stores complete content-addressed
  `EvaluatedFactSnapshot` payloads by mission/reference. Task rows retain the
  compact reference; resolution verifies the digest and derived metadata.

Task outcomes store the existing legacy-compatible `TaskOutcome` shape after
redaction. Execution IDs and FactStore fact IDs are persisted separately as
bounded provenance links; neither is interpreted as proof by this store.

## State transitions

Mission states are deliberately small:

| From | To | Cause |
|---|---|---|
| absent | `running` | first `open_mission()` |
| `running` | `interrupted` | exception, operator interruption, or a bounded run limit |
| `interrupted` | `running` | resume through `open_mission()` |
| `running` | `completed` | a normal deterministic scan-loop stop |

`completed` is terminal. Repeating the same completion reason is idempotent;
a conflicting completion or later interruption fails closed.

Task and attempt states preserve the current pipeline vocabulary:
`pending`, `running`, `interrupted`, `blocked`, `skipped`, `failed`,
`no_new_facts`, and `completed`. A new attempt may start from `pending` or
`interrupted`. Dependencies must be `completed` or `no_new_facts`. A mission
cannot complete while any task remains `pending`, `running`, or `interrupted`.

`failed` is terminal unless the task was registered with an explicit
`TaskRetryPolicy`. The pipeline calls
`complete_attempt_and_schedule_retry(..., retry_error_class=...,
retry_command_keys=...)`: terminal attempt data, the `failed → pending`
transition, one consumed budget unit, and the bounded command allowlist commit
in the same transaction. A crash therefore cannot leave a committed eligible
failure without its retry grant. Non-allowlisted and exhausted retries remain
terminal with stable rejection reasons. The lower-level
`schedule_retry(..., error_class=...)` transition remains for control-plane
callers and preserves its typed exceptions and idempotency. Crash recovery from
`interrupted` remains separate and does not consume a failure retry.

`not_before` is an absolute durable timestamp. `begin_attempt()` fails with
`TaskNotReady` before that instant, and the pipeline omits deferred work from a
resumable plan. If deferred work is the only unfinished work, the scan lifecycle
interrupts the mission with `tasks_deferred` instead of attempting normal
completion; a later run reopens it after the durable timestamp has elapsed. A
`TaskBackoff` is either `none`, `fixed`, or `exponential`; its
bounded deterministic delay is calculated in the same transaction that moves
an eligible failed task back to `pending`. Starting the granted attempt clears
the elapsed gate. Provider-circuit references may advance when the retry is
scheduled, while the evaluated snapshot reference continues to identify the
immutable fact view on which the task definition was accepted.

The scan loop captures one `EvaluatedFactSnapshot` for each planning pass. The
same object supplies ContextBuilder and the plan compiler's decision facts, and
its full payload and reference are persisted before accepted mission-task
definitions are registered. Dispatch resolves the active task's accepted
snapshot, including after restart, and supplies its decision facts to scheduler
and exploit applicability. This prevents a later FactStore mutation from
changing the evidence view between task acceptance and execution.

At retry dispatch, the scheduler re-runs `ExecutionPolicy` first. An
unconsumed grant may bypass the ordinary duplicate-command gate and only the
matching nuclei/nikto timeout-degraded suppression; completed checks, confirmed
negative surface facts, and every other state/policy gate still apply. The
grant is atomically consumed before the runner call, so a retry number can
execute each allowlisted failed command at most once. Pending grants are read
from SQLite when a task begins after restart rather than reconstructed from
process memory.

After a registered plan finishes, the pipeline compares a deterministic state
signature (resolved state, next capability, stage gates, and assessment
counts) with the signature used to plan it. A material transition requests an
immediate planner pass without consuming the caller's ordinary iteration
budget. Identical transitions are deduplicated, and
`strategy.mission.max_state_replans` bounds the extra passes; after exhaustion
the normal iteration and stop rules resume. Accepted and budget-exhausted
transition signatures are both persisted, so repeating a rejected transition
after restart is idempotent. Every first accepted or rejected request is
recorded in the decision trace.

The typed registration surfaces are:

- `register_task(..., scope=..., capability=..., capability_id=...,
  task_definition_version=..., retry_policy=..., not_before=..., backoff=...,
  provider_circuit_ref=..., evaluated_snapshot_ref=...)`;
- `register_plan()` with either legacy `(agent, task, dependencies)` tuples or
  `MissionTaskDefinition` values; scoped plans use `TaskDependencyRef(task_id=...)`
  for persisted prerequisites or a full agent/task/scope/definition-version
  identity for new prerequisites in the same atomic plan. Position-keyed blocked
  reasons keep same-name scoped definitions unambiguous inside that transaction;
- `TaskDependencyRef(task_id=...)` or a full
  `agent/task/scope/task_definition_version` selector for dependencies between
  same-name scoped tasks; legacy `(agent, task)` pairs remain valid only when
  they resolve unambiguously;
- `register_plan(..., blocked_reasons_by_position=...)` for committing planner
  rejection state in the same transaction as task definitions and dependency
  edges;
- `TaskScope(entity_ids=(canonical_entity_id, ...), legacy_scope=...)` with
  schema `1.0`; `entity_ids` are strictly validated by the graph identity
  module, while free-form input remains supported only through the explicit
  legacy string/`TaskScope.from_legacy(...)` adapter;
- `store_evaluated_fact_snapshot(...)` and
  `resolve_evaluated_fact_snapshot(...)` for durable task decision views;
- `TaskRetryPolicy(retry_budget=N,
  retryable_error_classes=(RetryErrorClass.TIMEOUT, ...))`;
- `TaskBackoff(strategy=BackoffStrategy.FIXED|EXPONENTIAL, ...)`;
- `schedule_retry(mission_id, agent, task, error_class=...)`;
- `complete_attempt_and_schedule_retry(..., retry_error_class=...,
  retry_command_keys=...)` for the atomic pipeline transition;
- `pending_retry_command_keys(...)` and `consume_retry_command(...)` for the
  durable dispatch allowlist.

Omitting optional metadata on a repeated legacy registration preserves the
stored definition while `agent/task` resolves to exactly one task. Repeating
matching typed metadata is idempotent. If multiple scoped definitions share
`agent/task`, mutation and attempt APIs require `scope` or `task_id` and fail
closed instead of selecting one arbitrarily. A different scope or task
definition version creates a distinct task; conflicting capability, retry, or
backoff metadata for the same typed identity fails closed. Empty migrated
metadata may be populated once so recovered legacy tasks can adopt the typed
definition.

## Crash recovery and idempotency

Each running mission has an opaque owner token. A different owner must request
explicit recovery; that transaction changes every abandoned running task and
attempt to `interrupted`, transfers ownership, and fences the old writer.
The next attempt number is derived under `BEGIN IMMEDIATE`, so a restart cannot
reuse the abandoned attempt ID or number. Store instances that cooperate inside
one live run share the owner token.

The current pipeline requests recovery while opening an unfinished mission.
Owner fencing prevents the previous writer from committing afterward, but no
durable lease or heartbeat yet distinguishes a crashed writer from another
still-live pipeline process. Concurrent processes targeting the same scan can
therefore interrupt and take ownership from one another; adding an expiring
owner lease is a remaining correctness item.

Budget exhaustion is a control-flow stop, not a synthetic task result. If a
tool budget is reached inside a command batch, the active attempt remains
non-terminal until the mission interruption atomically marks it `interrupted`;
later plan tasks remain `pending` for the next run.

`register_plan()` commits every task definition and dependency edge in one
transaction; recovery therefore cannot observe a half-registered plan.
`begin_attempt()` is get-or-create while an attempt is running. Concurrent
store instances serialize through SQLite and observe the same task and active
attempt. `complete_attempt()` is exactly-once: repeating the same redacted
outcome plus the same execution/fact IDs returns the terminal record, while a
conflicting second completion raises `MissionStoreError`. Keyed hashes of the
raw terminal reason/outcome make this idempotency stable even when the redactor
learns another secret between the original write and its replay.
`complete_attempt_and_schedule_retry()` preserves that completion idempotency
while committing the eligible retry transition and grants in the same
transaction.

Retry-command grants currently provide at-most-once dispatch: a grant is
consumed immediately before calling the provider. A process crash in that
interval leaves no reusable grant. Closing that window requires an
attempt-bound dispatch lease plus provider idempotency (or a provider-owned
request key); MissionStore alone cannot promise exactly-once external side
effects.

The scan plan is registered before task execution. On resume, `AIPipeline`
topologically drains every persisted `pending`/`interrupted` task before asking
Director or Planner for new work. A dependent remains pending while any
prerequisite is `pending`, `running`, or `interrupted`; only a terminally
unsatisfied dependency produces a durable `blocked` outcome. Resumable steps
reuse the stored dependency, typed scope, canonical capability ID, definition
version, retry/backoff schedule, circuit reference, and evaluated snapshot
reference instead of recomputing them from current configuration. The pipeline
also rebuilds its legacy `completed_tasks`, `blocked_tasks`, `task_outcomes`,
failure/no-fact indexes, fact count, executed command keys, and tool count from
the durable snapshot, terminal check facts, and FactStore command records. A
pre-dispatch `check_result(status=running)` is intentionally not restored as an
executed command key: after a crash it cannot prove the provider ran, so the
unfinished command remains eligible for recovery. Public report dictionaries
retain their existing shape.

## Security and transaction boundary

Targets, reasons, task labels, outcomes, commands, and execution identifiers
pass through the FactStore `Redactor` before SQLite persistence. Raw scan and
target lookup identities use namespaced keyed digests in production, so the
database does not contain a plain hash oracle. Control fields such as status
and raw identity comparisons are never derived from redacted display text.
Outcome size and individual text fields are bounded; truncation adds a digest
suffix to avoid prefix collisions. Raw subprocess output is not stored in the
mission tables. Direct standalone construction creates its own encrypted
redaction store; `PipelineRuntime` reuses FactStore's store.

Mission transitions are transactional within their tables. After every command
dispatch, execution IDs are attached to the running attempt immediately; fact
IDs are appended after ingestion, and terminal completion seals the outcome.
Fact insertion and lifecycle progress remain ordered, separate SQLite
transactions. Recovery therefore never fabricates evidence, but a crash between
those commits can leave durable facts or execution provenance on an interrupted
attempt. A future reliability phase may add a shared transaction coordinator;
it must not make task state the source of truth for facts. `FactStore.clear_scan`
deletes the matching mission graph as well as evidence so a deliberate clean
restart cannot fast-return through stale completed state.

## Non-goals

- Mission status is not execution authorization. Every command still reaches
  `ExecutionPolicy` immediately before dispatch.
- Task success is not vulnerability verification. The implemented
  `FactAssessmentStore` owns that distinction; mission state only links its
  evidence and assessment references.
- C2 task IDs, scan-session rows in MariaDB, evidence session IDs, and remote
  session IDs are not interchangeable with mission task IDs.
