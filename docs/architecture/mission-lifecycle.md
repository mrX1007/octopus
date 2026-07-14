# Durable mission and task lifecycle

Snapshot date: 2026-07-14

`MissionStore` is the control-plane authority for AI mission, planner-task, and
task-attempt state. It uses the same SQLite database file as `FactStore`, but
facts remain the evidence authority and C2 delivery tasks remain a separate
protocol domain.

## Identity and schema

The additive schema is owned by `core.ai.mission_store` and declares version
`1.0` in `mission_lifecycle_schema`. It does not use SQLite `user_version`, so
it can coexist with the existing FactStore tables.

- `missions` has one opaque `mission_id`; a keyed digest of the raw scan ID is
  the unique lookup identity, while the bounded/redacted scan ID is display
  data only.
- `mission_tasks` has one opaque `task_id` and a unique
  `(mission_id, hash(agent, task))` definition.
- `mission_task_dependencies` stores same-mission task dependencies with
  foreign keys.
- `mission_task_attempts` has one opaque `attempt_id` and a monotonic
  `(task_id, attempt_number)` identity. A partial unique index permits at most
  one running attempt per task.

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
`interrupted`; `failed` is terminal until the typed retry-policy phase adds an
explicit retry transition. Dependencies must be `completed` or
`no_new_facts`. A mission cannot complete while any task remains `pending`,
`running`, or `interrupted`.

## Crash recovery and idempotency

Each running mission has an opaque owner token. A different owner must request
explicit recovery; that transaction changes every abandoned running task and
attempt to `interrupted`, transfers ownership, and fences the old writer.
The next attempt number is derived under `BEGIN IMMEDIATE`, so a restart cannot
reuse the abandoned attempt ID or number. Store instances that cooperate inside
one live run share the owner token.

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

The scan plan is registered before task execution. On resume, `AIPipeline`
topologically drains every persisted `pending`/`interrupted` task before asking
Director or Planner for new work. A terminally unsatisfied dependency produces
a durable `blocked` outcome instead of aborting the mission. The pipeline also
rebuilds its legacy `completed_tasks`, `blocked_tasks`, `task_outcomes`,
failure/no-fact indexes, fact count, executed command keys, and tool count from
the durable snapshot, running check facts, and FactStore command records. The public report
dictionaries therefore retain their existing shape.

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
- Task success is not vulnerability verification. Fact assessment owns that
  distinction in the next roadmap phase.
- C2 task IDs, scan-session rows in MariaDB, evidence session IDs, and remote
  session IDs are not interchangeable with mission task IDs.
