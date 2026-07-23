# MissionStore 1.4 typed task-scope migration

Schema `1.4` is a forward, transactional migration from MissionStore `1.0`
through `1.3`. It adds typed task-definition identity and durable scheduling
metadata without changing mission, task, attempt, dependency, or retry-grant
IDs.

## Changes

`mission_tasks` gains:

- `task_compat_key`, `task_scope_json`, and `task_scope_key`;
- `capability_id` and its keyed comparison field;
- `task_definition_version`;
- `not_before` and typed `backoff_json`;
- provider-circuit and evaluated-fact snapshot references, each with a keyed
  comparison field.

Schema `1.4` also adds `mission_evaluated_fact_snapshots`. Task rows keep the
content-addressed reference, while this mission-owned table stores the complete
immutable payload needed to resolve it after restart. Resolution recomputes the
snapshot digest and derived provenance/coverage metadata.

The previous `task_key = hash(agent, task)` becomes `task_compat_key`. A new
unique `task_key` includes that compatibility key, TaskScope identity, and the
task-definition version. Existing string scopes are adapted to TaskScope `1.0`
and contribute through the already keyed legacy scope identity. Existing
`task_id` values and all foreign-key links remain unchanged.

New typed `TaskScope.entity_ids` accept only versioned canonical graph IDs.
Free-form or historical labels are not auto-promoted into typed identity; they
must use the explicit `TaskScope.from_legacy(...)` path.

## Compatibility

- `TaskRecord.scope` and `TaskRecord.capability` remain strings for legacy
  readers. Typed consumers use `task_scope` and `capability_id`.
- `register_task(..., scope="...")` remains supported. Repeating the same
  string scope resolves the migrated task.
- Three-item `(agent, task, dependencies)` plan definitions remain supported.
- Typed plans may use `TaskDependencyRef` with `task_id` or a full scoped task
  identity. Legacy dependency pairs fail closed when same-name scoped tasks make
  the reference ambiguous.
- Planner-side blocked reasons can be passed by task position so definitions,
  dependencies, and rejection state commit or roll back together.
- Calls that provide only `agent/task` remain supported when exactly one task
  matches. They fail closed after multiple scoped definitions exist; callers
  then pass `scope` or `task_id`.
- MissionStore binaries that only understand schema `1.3` reject `1.4`; they
  must not write an upgraded database.

## Backup and upgrade

Stop all MissionStore writers. Copy the SQLite database together with its
`-wal` and `-shm` files, or take an SQLite online backup. Keep the matching
secret-store database because keyed identities depend on its key material.
Open the database once with the new application. Schema alteration, row
backfill, task-key replacement, and component-version advancement occur under
one `BEGIN IMMEDIATE` transaction; an identity collision or invalid persisted
codec rolls the entire migration back.

## Validation

After upgrade:

1. Run `PRAGMA integrity_check` and confirm `ok`.
2. Confirm `mission_lifecycle_schema.version = '1.4'`.
3. Confirm task, dependency, attempt, and retry-grant row counts match the
   backup.
4. Verify every task has non-empty `task_compat_key`, `task_scope_json`,
   `task_scope_key`, and `task_definition_version`.
5. Reopen an interrupted mission and verify an unfinished scoped task resumes
   with the same `task_id` and a monotonic attempt number.
6. Resolve every non-empty task `evaluated_snapshot_ref` created by a `1.4`
   planning pass and verify the returned digest equals the task reference.

## Rollback

Rollback is restore-only: stop writers, restore the database plus WAL/SHM and
the matching secret-store backup, then run the previous binary. Do not delete
the `1.4` version row or strip columns in place. A `1.3` binary cannot safely
interpret the new task identity after two same-name tasks have been registered
for different scopes.
