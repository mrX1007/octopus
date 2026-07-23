"""Task, attempt, dependency, and retry repository operations."""

from __future__ import annotations

import json
import math
import sqlite3
import time
from collections.abc import Mapping, Sequence
from typing import Any
from uuid import uuid4

from core.ai.mission_store_models import (
    _MAX_IDENTIFIER_BYTES,
    _MAX_REASON_BYTES,
    _OUTCOME_STATUSES,
    _RETRYABLE_TASK_STATUSES,
    TASK_DEFINITION_SCHEMA_VERSION,
    AttemptCompletionResult,
    MissionStatus,
    MissionStoreError,
    MissionTaskDefinition,
    RetryErrorClass,
    TaskAttemptRecord,
    TaskBackoff,
    TaskDependenciesIncomplete,
    TaskDependencyRef,
    TaskNotReady,
    TaskRecord,
    TaskRetryBudgetExhausted,
    TaskRetryError,
    TaskRetryNotAllowed,
    TaskRetryPolicy,
    TaskScope,
    TaskStatus,
    canonical_capability_id,
)
from core.ai.outcomes import TaskOutcome

# mypy: disable-error-code="attr-defined"


class MissionTaskRepositoryMixin:
    def register_task(
        self,
        mission_id: str,
        agent: str,
        task: str,
        depends_on: Sequence[str] = (),
        *,
        scope: TaskScope | str | Mapping[str, Any] | Sequence[str] | None = None,
        capability: str | None = None,
        capability_id: str | None = None,
        task_definition_version: str = TASK_DEFINITION_SCHEMA_VERSION,
        retry_policy: TaskRetryPolicy | None = None,
        not_before: float | None = None,
        backoff: TaskBackoff | None = None,
        provider_circuit_ref: str | None = None,
        evaluated_snapshot_ref: str | None = None,
    ) -> TaskRecord:
        raw_agent = str(agent or "")
        raw_task = str(task or "")
        if not raw_agent or not raw_task:
            raise MissionStoreError("agent and task are required")
        compat_key = self._task_compat_key(raw_agent, raw_task)
        safe_agent = self._safe_text(raw_agent, "mission_task_agent", _MAX_IDENTIFIER_BYTES)
        safe_task = self._safe_text(raw_task, "mission_task_name", _MAX_IDENTIFIER_BYTES)
        dependency_ids = tuple(sorted(dict.fromkeys(str(item) for item in depends_on)))
        metadata = self._prepare_task_metadata(
            scope,
            capability,
            retry_policy,
            capability_id=capability_id,
            task_definition_version=task_definition_version,
            not_before=not_before,
            backoff=backoff,
            provider_circuit_ref=provider_circuit_ref,
            evaluated_snapshot_ref=evaluated_snapshot_ref,
        )
        task_key = self._task_identity_key(
            compat_key,
            metadata["task_scope_key"],
            metadata["task_definition_version"],
        )
        now = time.time()

        with self._transaction() as conn:
            self._require_mutable_mission(conn, mission_id)
            row = conn.execute(
                """
                SELECT * FROM mission_tasks
                WHERE mission_id = ? AND task_key = ?
                """,
                (mission_id, task_key),
            ).fetchone()
            if row is None and not metadata["scope_supplied"]:
                compatible = self._task_rows_by_compat_key(
                    conn,
                    mission_id,
                    compat_key,
                )
                if len(compatible) == 1:
                    row = compatible[0]
                elif len(compatible) > 1:
                    raise MissionStoreError("task scope is required because agent/task is ambiguous")
            if row is None:
                task_id = f"task_{uuid4().hex}"
                self._insert_task_definition_row(
                    conn,
                    task_id=task_id,
                    mission_id=mission_id,
                    task_key=task_key,
                    compat_key=compat_key,
                    safe_agent=safe_agent,
                    safe_task=safe_task,
                    created_at=now,
                    metadata=metadata,
                )
                row = conn.execute(
                    "SELECT * FROM mission_tasks WHERE task_id = ?",
                    (task_id,),
                ).fetchone()
            else:
                row = self._reconcile_task_metadata(conn, row, metadata)

            current_dependencies = self._dependency_ids(conn, row["task_id"])
            if row["attempt_count"] > 0 and current_dependencies != dependency_ids:
                raise MissionStoreError("cannot change dependencies after a task has started")
            if current_dependencies and current_dependencies != dependency_ids:
                raise MissionStoreError("task dependencies conflict with the persisted definition")
            if not current_dependencies and dependency_ids:
                self._set_dependencies(conn, mission_id, row["task_id"], dependency_ids)

            current = conn.execute(
                "SELECT * FROM mission_tasks WHERE task_id = ?",
                (row["task_id"],),
            ).fetchone()
            return self._task_from_row(conn, current)

    def register_plan(
        self,
        mission_id: str,
        definitions: Sequence[
            MissionTaskDefinition
            | tuple[
                str,
                str,
                Sequence[TaskDependencyRef | tuple[str, str]],
            ]
        ],
        *,
        blocked_reasons: Mapping[tuple[str, str], str] | None = None,
        blocked_reasons_by_position: Mapping[int, str] | None = None,
    ) -> tuple[TaskRecord, ...]:
        """Atomically register a plan and all dependency edges."""
        prepared = []
        seen_keys: set[str] = set()
        for definition in definitions:
            if isinstance(definition, MissionTaskDefinition):
                agent = definition.agent
                task = definition.task
                dependencies = definition.depends_on
                metadata = self._prepare_task_metadata(
                    definition.scope,
                    definition.capability,
                    definition.retry_policy,
                    capability_id=definition.capability_id or None,
                    task_definition_version=definition.task_definition_version,
                    not_before=definition.not_before,
                    backoff=definition.backoff,
                    provider_circuit_ref=definition.provider_circuit_ref,
                    evaluated_snapshot_ref=definition.evaluated_snapshot_ref,
                )
            else:
                try:
                    agent, task, raw_dependencies = definition
                    dependencies = tuple(raw_dependencies)
                except (TypeError, ValueError) as exc:
                    raise MissionStoreError(
                        "plan definitions must be MissionTaskDefinition or (agent, task, dependencies) tuples"
                    ) from exc
                metadata = self._prepare_task_metadata(None, None, None)
            raw_agent = str(agent or "")
            raw_task = str(task or "")
            if not raw_agent or not raw_task:
                raise MissionStoreError("agent and task are required")
            compat_key = self._task_compat_key(raw_agent, raw_task)
            task_key = self._task_identity_key(
                compat_key,
                metadata["task_scope_key"],
                metadata["task_definition_version"],
            )
            if task_key in seen_keys:
                raise MissionStoreError("duplicate task definition in mission plan")
            seen_keys.add(task_key)
            prepared.append(
                (
                    raw_agent,
                    raw_task,
                    task_key,
                    compat_key,
                    self._safe_text(
                        raw_agent,
                        "mission_task_agent",
                        _MAX_IDENTIFIER_BYTES,
                    ),
                    self._safe_text(
                        raw_task,
                        "mission_task_name",
                        _MAX_IDENTIFIER_BYTES,
                    ),
                    tuple(self._coerce_task_dependency(dependency) for dependency in dependencies),
                    metadata,
                )
            )
        if not prepared:
            return ()

        keys_by_compat: dict[str, list[str]] = {}
        for _, _, task_key, compat_key, _, _, _, _ in prepared:
            keys_by_compat.setdefault(compat_key, []).append(task_key)
        safe_blocked_reasons: dict[str, tuple[str, str]] = {}
        for (agent, task), reason in (blocked_reasons or {}).items():
            raw_reason = str(reason or "")
            compat_key = self._task_compat_key(str(agent or ""), str(task or ""))
            matching_keys = keys_by_compat.get(compat_key, [])
            if len(matching_keys) != 1:
                raise MissionStoreError("blocked plan task identity is missing or scope-ambiguous")
            safe_blocked_reasons[matching_keys[0]] = (
                self._safe_text(
                    raw_reason,
                    "mission_task_reason",
                    _MAX_REASON_BYTES,
                ),
                self._stable_key("mission_task_reason", raw_reason),
            )
        for position, reason in (blocked_reasons_by_position or {}).items():
            if isinstance(position, bool) or not isinstance(position, int) or position < 0 or position >= len(prepared):
                raise MissionStoreError("blocked plan position is out of range")
            task_key = prepared[position][2]
            if task_key in safe_blocked_reasons:
                raise MissionStoreError("blocked plan task has more than one reason selector")
            raw_reason = str(reason or "")
            safe_blocked_reasons[task_key] = (
                self._safe_text(
                    raw_reason,
                    "mission_task_reason",
                    _MAX_REASON_BYTES,
                ),
                self._stable_key("mission_task_reason", raw_reason),
            )
        if any(not value[0] for value in safe_blocked_reasons.values()):
            raise MissionStoreError("terminal task reason is required")

        now = time.time()
        with self._transaction() as conn:
            self._require_mutable_mission(conn, mission_id)
            rows_by_key: dict[str, sqlite3.Row] = {}
            for position, (
                _,
                _,
                task_key,
                compat_key,
                safe_agent,
                safe_task,
                _,
                metadata,
            ) in enumerate(prepared):
                row = conn.execute(
                    """
                    SELECT * FROM mission_tasks
                    WHERE mission_id = ? AND task_key = ?
                    """,
                    (mission_id, task_key),
                ).fetchone()
                if row is None:
                    task_id = f"task_{uuid4().hex}"
                    self._insert_task_definition_row(
                        conn,
                        task_id=task_id,
                        mission_id=mission_id,
                        task_key=task_key,
                        compat_key=compat_key,
                        safe_agent=safe_agent,
                        safe_task=safe_task,
                        created_at=now + (position * 0.000001),
                        metadata=metadata,
                    )
                    row = conn.execute(
                        "SELECT * FROM mission_tasks WHERE task_id = ?",
                        (task_id,),
                    ).fetchone()
                else:
                    row = self._reconcile_task_metadata(conn, row, metadata)
                rows_by_key[task_key] = row

            for _, _, task_key, _, _, _, dependencies, _ in prepared:
                row = rows_by_key[task_key]
                dependency_ids = []
                for dependency_ref in dependencies:
                    dependency = self._resolve_dependency_row(
                        conn,
                        mission_id,
                        dependency_ref,
                    )
                    dependency_ids.append(dependency["task_id"])
                normalized_ids = tuple(sorted(dict.fromkeys(dependency_ids)))
                current_dependencies = self._dependency_ids(conn, row["task_id"])
                if row["attempt_count"] > 0 and current_dependencies != normalized_ids:
                    raise MissionStoreError("cannot change dependencies after a task has started")
                if current_dependencies and current_dependencies != normalized_ids:
                    raise MissionStoreError("task dependencies conflict with the persisted definition")
                if not current_dependencies and normalized_ids:
                    self._set_dependencies(
                        conn,
                        mission_id,
                        row["task_id"],
                        normalized_ids,
                    )

            for raw_agent, raw_task, task_key, _, _, _, _, _ in prepared:
                safe_reason_data = safe_blocked_reasons.get(task_key)
                if safe_reason_data is None:
                    continue
                safe_reason, reason_key = safe_reason_data
                rows_by_key[task_key], _ = self._terminalize_task_row(
                    conn,
                    mission_id,
                    rows_by_key[task_key],
                    raw_agent,
                    raw_task,
                    TaskStatus.BLOCKED.value,
                    safe_reason,
                    reason_key,
                    now,
                )

            return tuple(self._task_from_row(conn, rows_by_key[task_key]) for _, _, task_key, _, _, _, _, _ in prepared)

    def begin_attempt(
        self,
        mission_id: str,
        agent: str,
        task: str,
        *,
        scope: TaskScope | str | Mapping[str, Any] | Sequence[str] | None = None,
        task_definition_version: str | None = None,
        task_id: str | None = None,
    ) -> TaskAttemptRecord:
        raw_agent = str(agent or "")
        raw_task = str(task or "")
        if not raw_agent or not raw_task:
            raise MissionStoreError("agent and task are required")
        now = time.time()

        with self._transaction() as conn:
            self._require_running_mission(conn, mission_id)
            try:
                task_row = self._resolve_task_row(
                    conn,
                    mission_id,
                    raw_agent,
                    raw_task,
                    scope=scope,
                    task_definition_version=task_definition_version,
                    task_id=task_id,
                )
            except MissionStoreError as exc:
                if "unknown mission task" not in str(exc):
                    raise
                raise MissionStoreError("task must be registered before an attempt begins") from exc

            if task_row["status"] == TaskStatus.RUNNING.value:
                existing = conn.execute(
                    """
                    SELECT * FROM mission_task_attempts
                    WHERE task_id = ? AND status = 'running'
                    """,
                    (task_row["task_id"],),
                ).fetchone()
                if existing:
                    return self._attempt_from_row(existing)

            if task_row["status"] not in _RETRYABLE_TASK_STATUSES:
                raise MissionStoreError(f"task {task_row['task_id']} cannot start from {task_row['status']}")
            self._require_dependencies_completed(conn, task_row["task_id"])
            if task_row["not_before"] is not None and now < float(task_row["not_before"]):
                raise TaskNotReady(
                    task_row["task_id"],
                    float(task_row["not_before"]),
                    now,
                )

            attempt_number = int(task_row["attempt_count"]) + 1
            attempt_id = f"attempt_{uuid4().hex}"
            try:
                conn.execute(
                    """
                    INSERT INTO mission_task_attempts(
                        attempt_id, task_id, mission_id, attempt_number,
                        status, reason, started_at
                    ) VALUES (?, ?, ?, ?, 'running', '', ?)
                    """,
                    (
                        attempt_id,
                        task_row["task_id"],
                        mission_id,
                        attempt_number,
                        now,
                    ),
                )
            except sqlite3.IntegrityError:
                existing = conn.execute(
                    """
                    SELECT * FROM mission_task_attempts
                    WHERE task_id = ? AND status = 'running'
                    """,
                    (task_row["task_id"],),
                ).fetchone()
                if existing:
                    return self._attempt_from_row(existing)
                raise
            conn.execute(
                """
                UPDATE mission_tasks
                SET status = 'running', reason = '', reason_key = '', updated_at = ?,
                    started_at = COALESCE(started_at, ?), finished_at = NULL,
                    attempt_count = ?, not_before = NULL
                WHERE task_id = ?
                """,
                (now, now, attempt_number, task_row["task_id"]),
            )
            conn.execute(
                "UPDATE missions SET updated_at = ? WHERE mission_id = ?",
                (now, mission_id),
            )
            row = conn.execute(
                "SELECT * FROM mission_task_attempts WHERE attempt_id = ?",
                (attempt_id,),
            ).fetchone()
            return self._attempt_from_row(row)

    def complete_attempt(
        self,
        attempt_id: str,
        outcome: TaskOutcome,
        execution_ids: Sequence[str] = (),
        fact_ids: Sequence[int] = (),
    ) -> TaskAttemptRecord:
        """Terminalize an attempt without requesting a retry."""
        return self.complete_attempt_and_schedule_retry(
            attempt_id,
            outcome,
            execution_ids=execution_ids,
            fact_ids=fact_ids,
        ).attempt

    def complete_attempt_and_schedule_retry(
        self,
        attempt_id: str,
        outcome: TaskOutcome,
        execution_ids: Sequence[str] = (),
        fact_ids: Sequence[int] = (),
        *,
        retry_error_class: RetryErrorClass | str | None = None,
        retry_command_keys: Sequence[str] = (),
        not_before: float | None = None,
        provider_circuit_ref: str | None = None,
    ) -> AttemptCompletionResult:
        """Atomically terminalize an attempt and schedule an eligible retry.

        A failed attempt and its retry grant are committed in one SQLite
        transaction.  Therefore a process crash can observe either the running
        attempt or the fully persisted terminal attempt plus bounded retry
        allowlist, never a failed task that lost an otherwise eligible retry.
        """
        if outcome.status not in _OUTCOME_STATUSES:
            raise MissionStoreError(f"unsupported terminal task status: {outcome.status}")
        normalized_retry_error = self._retry_error_class(retry_error_class) if retry_error_class is not None else None
        if normalized_retry_error is not None and outcome.status != TaskStatus.FAILED.value:
            raise MissionStoreError("only failed task attempts can request a retry")
        safe_retry_keys = self._safe_retry_command_keys(retry_command_keys)
        requested_not_before = self._not_before(not_before)
        raw_provider_circuit_ref = None if provider_circuit_ref is None else str(provider_circuit_ref)
        raw_execution_ids = tuple(dict.fromkeys(str(item) for item in execution_ids if str(item)))
        requested_execution_ids = self._safe_execution_ids(execution_ids)
        requested_fact_ids = self._safe_fact_ids(fact_ids)
        completion_key = self._stable_payload_key(
            "task_completion",
            {
                "outcome": outcome.to_legacy_dict(),
                "execution_ids": raw_execution_ids,
                "fact_ids": requested_fact_ids,
            },
        )
        reason_key = self._stable_key("mission_task_reason", outcome.reason)
        now = time.time()

        with self._transaction() as conn:
            row = conn.execute(
                "SELECT * FROM mission_task_attempts WHERE attempt_id = ?",
                (attempt_id,),
            ).fetchone()
            if row is None:
                raise MissionStoreError(f"unknown task attempt: {attempt_id}")
            task_row = conn.execute(
                "SELECT * FROM mission_tasks WHERE task_id = ?",
                (row["task_id"],),
            ).fetchone()
            if task_row is None or task_row["task_compat_key"] != self._task_compat_key(outcome.agent, outcome.task):
                raise MissionStoreError("task outcome identity does not match the persisted attempt")
            if row["status"] != TaskStatus.RUNNING.value and row["outcome_key"] == completion_key:
                persisted_keys = self._retry_command_keys_for_row(conn, task_row)
                retry_scheduled = bool(
                    normalized_retry_error is not None
                    and task_row["last_error_class"] == normalized_retry_error.value
                    and int(task_row["retry_count"]) > 0
                    and persisted_keys
                )
                return AttemptCompletionResult(
                    attempt=self._attempt_from_row(row),
                    task=self._task_from_row(conn, task_row),
                    retry_scheduled=retry_scheduled,
                    retry_command_keys=persisted_keys,
                )
            safe_outcome = self._safe_outcome(
                outcome,
                agent=task_row["agent"],
                task=task_row["task"],
            )
            outcome_json = self._encode_outcome(safe_outcome)
            safe_reason = safe_outcome.reason
            merged_execution_ids = tuple(
                dict.fromkeys((*self._load_string_tuple(row["execution_ids_json"]), *requested_execution_ids))
            )
            merged_fact_ids = tuple(dict.fromkeys((*self._load_int_tuple(row["fact_ids_json"]), *requested_fact_ids)))
            execution_json = json.dumps(merged_execution_ids, separators=(",", ":"))
            fact_json = json.dumps(merged_fact_ids, separators=(",", ":"))
            if row["status"] != TaskStatus.RUNNING.value:
                if (
                    row["status"] == outcome.status
                    and row["outcome_json"] == outcome_json
                    and row["execution_ids_json"] == execution_json
                    and row["fact_ids_json"] == fact_json
                ):
                    persisted_keys = self._retry_command_keys_for_row(conn, task_row)
                    return AttemptCompletionResult(
                        attempt=self._attempt_from_row(row),
                        task=self._task_from_row(conn, task_row),
                        retry_scheduled=bool(persisted_keys),
                        retry_command_keys=persisted_keys,
                    )
                raise MissionStoreError(f"attempt {attempt_id} already ended as {row['status']}")

            mission = conn.execute(
                "SELECT * FROM missions WHERE mission_id = ?",
                (row["mission_id"],),
            ).fetchone()
            if not mission or mission["status"] != MissionStatus.RUNNING.value:
                raise MissionStoreError("cannot complete an attempt outside a running mission")
            self._require_owner(mission)
            conn.execute(
                """
                UPDATE mission_task_attempts
                SET status = ?, reason = ?, reason_key = ?, finished_at = ?,
                    outcome_json = ?, outcome_key = ?,
                    execution_ids_json = ?, fact_ids_json = ?
                WHERE attempt_id = ? AND status = 'running'
                """,
                (
                    outcome.status,
                    safe_reason,
                    reason_key,
                    now,
                    outcome_json,
                    completion_key,
                    execution_json,
                    fact_json,
                    attempt_id,
                ),
            )
            conn.execute(
                """
                UPDATE mission_tasks
                SET status = ?, reason = ?, reason_key = ?,
                    updated_at = ?, finished_at = ?
                WHERE task_id = ?
                """,
                (
                    outcome.status,
                    safe_reason,
                    reason_key,
                    now,
                    now,
                    row["task_id"],
                ),
            )
            conn.execute(
                "UPDATE missions SET updated_at = ? WHERE mission_id = ?",
                (now, row["mission_id"]),
            )
            retry_scheduled = False
            retry_rejection = ""
            if normalized_retry_error is not None:
                task_row = conn.execute(
                    "SELECT * FROM mission_tasks WHERE task_id = ?",
                    (row["task_id"],),
                ).fetchone()
                retryable = self._load_retry_error_classes(task_row["retryable_error_classes_json"])
                retry_count = int(task_row["retry_count"])
                retry_budget = int(task_row["retry_budget"])
                if normalized_retry_error not in retryable:
                    retry_rejection = TaskRetryNotAllowed.__name__
                elif retry_count >= retry_budget:
                    retry_rejection = TaskRetryBudgetExhausted.__name__
                elif not safe_retry_keys:
                    retry_rejection = "retry_command_allowlist_empty"
                else:
                    next_retry = retry_count + 1
                    backoff = self._decode_backoff(task_row["backoff_json"])
                    retry_not_before = self._retry_not_before(
                        now,
                        next_retry,
                        backoff,
                        requested_not_before,
                    )
                    conn.execute(
                        """
                        UPDATE mission_tasks
                        SET status = 'pending', reason = '', reason_key = '',
                            updated_at = ?, finished_at = NULL,
                            retry_count = ?, last_error_class = ?, not_before = ?
                        WHERE task_id = ? AND status = 'failed'
                        """,
                        (
                            now,
                            next_retry,
                            normalized_retry_error.value,
                            retry_not_before,
                            row["task_id"],
                        ),
                    )
                    if raw_provider_circuit_ref is not None:
                        self._set_provider_circuit_ref(
                            conn,
                            row["task_id"],
                            raw_provider_circuit_ref,
                        )
                    self._insert_retry_command_grants(
                        conn,
                        row["task_id"],
                        next_retry,
                        normalized_retry_error,
                        safe_retry_keys,
                        now,
                    )
                    retry_scheduled = True
            current = conn.execute(
                "SELECT * FROM mission_task_attempts WHERE attempt_id = ?",
                (attempt_id,),
            ).fetchone()
            current_task = conn.execute(
                "SELECT * FROM mission_tasks WHERE task_id = ?",
                (row["task_id"],),
            ).fetchone()
            return AttemptCompletionResult(
                attempt=self._attempt_from_row(current),
                task=self._task_from_row(conn, current_task),
                retry_scheduled=retry_scheduled,
                retry_rejection=retry_rejection,
                retry_command_keys=safe_retry_keys if retry_scheduled else (),
            )

    def schedule_retry(
        self,
        mission_id: str,
        agent: str,
        task: str,
        *,
        error_class: RetryErrorClass | str,
        scope: TaskScope | str | Mapping[str, Any] | Sequence[str] | None = None,
        task_definition_version: str | None = None,
        task_id: str | None = None,
        not_before: float | None = None,
        provider_circuit_ref: str | None = None,
    ) -> TaskRecord:
        """Transition a failed task back to pending under its durable policy.

        The transition consumes one retry only after the error class and budget
        checks pass. Repeating the same request while the retry is pending is
        idempotent and does not consume another retry.
        """
        raw_agent = str(agent or "")
        raw_task = str(task or "")
        if not raw_agent or not raw_task:
            raise MissionStoreError("agent and task are required")
        normalized_error = self._retry_error_class(error_class)
        requested_not_before = self._not_before(not_before)
        now = time.time()

        with self._transaction() as conn:
            self._require_running_mission(conn, mission_id)
            try:
                task_row = self._resolve_task_row(
                    conn,
                    mission_id,
                    raw_agent,
                    raw_task,
                    scope=scope,
                    task_definition_version=task_definition_version,
                    task_id=task_id,
                )
            except MissionStoreError as exc:
                if "unknown mission task" not in str(exc):
                    raise
                raise MissionStoreError("task must be registered before it can retry") from exc

            if (
                task_row["status"] == TaskStatus.PENDING.value
                and int(task_row["retry_count"]) > 0
                and task_row["last_error_class"] == normalized_error.value
            ):
                return self._task_from_row(conn, task_row)
            if task_row["status"] != TaskStatus.FAILED.value:
                raise TaskRetryError(f"task {task_row['task_id']} cannot retry from {task_row['status']}")

            retryable = self._load_retry_error_classes(task_row["retryable_error_classes_json"])
            if normalized_error not in retryable:
                raise TaskRetryNotAllowed(f"{normalized_error.value} is not retryable for task {task_row['task_id']}")
            retry_count = int(task_row["retry_count"])
            retry_budget = int(task_row["retry_budget"])
            if retry_count >= retry_budget:
                raise TaskRetryBudgetExhausted(
                    f"retry budget exhausted for task {task_row['task_id']}: {retry_count}/{retry_budget}"
                )

            next_retry = retry_count + 1
            retry_not_before = self._retry_not_before(
                now,
                next_retry,
                self._decode_backoff(task_row["backoff_json"]),
                requested_not_before,
            )
            conn.execute(
                """
                UPDATE mission_tasks
                SET status = 'pending', reason = '', reason_key = '',
                    updated_at = ?, finished_at = NULL,
                    retry_count = ?, last_error_class = ?, not_before = ?
                WHERE task_id = ? AND status = 'failed'
                """,
                (
                    now,
                    next_retry,
                    normalized_error.value,
                    retry_not_before,
                    task_row["task_id"],
                ),
            )
            if provider_circuit_ref is not None:
                self._set_provider_circuit_ref(
                    conn,
                    task_row["task_id"],
                    str(provider_circuit_ref),
                )
            conn.execute(
                "UPDATE missions SET updated_at = ? WHERE mission_id = ?",
                (now, mission_id),
            )
            current = conn.execute(
                "SELECT * FROM mission_tasks WHERE task_id = ?",
                (task_row["task_id"],),
            ).fetchone()
            return self._task_from_row(conn, current)

    def pending_retry_command_keys(
        self,
        mission_id: str,
        agent: str,
        task: str,
        *,
        scope: TaskScope | str | Mapping[str, Any] | Sequence[str] | None = None,
        task_definition_version: str | None = None,
        task_id: str | None = None,
    ) -> tuple[str, ...]:
        """Return the unconsumed allowlist for a task's current retry number."""
        with self._connection() as conn:
            row = self._resolve_task_row(
                conn,
                mission_id,
                str(agent or ""),
                str(task or ""),
                scope=scope,
                task_definition_version=task_definition_version,
                task_id=task_id,
            )
            return self._retry_command_keys_for_row(conn, row, pending_only=True)

    def consume_retry_command(
        self,
        mission_id: str,
        agent: str,
        task: str,
        command_key: str,
        *,
        scope: TaskScope | str | Mapping[str, Any] | Sequence[str] | None = None,
        task_definition_version: str | None = None,
        task_id: str | None = None,
    ) -> bool:
        """Atomically consume one current retry grant before dispatch."""
        safe_keys = self._safe_retry_command_keys((command_key,))
        if not safe_keys:
            return False
        now = time.time()
        with self._transaction() as conn:
            self._require_running_mission(conn, mission_id)
            row = self._resolve_task_row(
                conn,
                mission_id,
                str(agent or ""),
                str(task or ""),
                scope=scope,
                task_definition_version=task_definition_version,
                task_id=task_id,
            )
            if row["status"] != TaskStatus.RUNNING.value:
                return False
            cursor = conn.execute(
                """
                UPDATE mission_task_retry_commands
                SET consumed_at = ?
                WHERE task_id = ? AND retry_number = ? AND command_key = ?
                  AND consumed_at IS NULL
                """,
                (
                    now,
                    row["task_id"],
                    int(row["retry_count"]),
                    safe_keys[0],
                ),
            )
            return cursor.rowcount == 1

    def record_attempt_progress(
        self,
        attempt_id: str,
        *,
        execution_ids: Sequence[str] = (),
        fact_ids: Sequence[int] = (),
    ) -> TaskAttemptRecord:
        """Persist command/fact provenance before the enclosing task is terminal."""
        requested_execution_ids = self._safe_execution_ids(execution_ids)
        requested_fact_ids = self._safe_fact_ids(fact_ids)
        with self._transaction() as conn:
            row = conn.execute(
                "SELECT * FROM mission_task_attempts WHERE attempt_id = ?",
                (attempt_id,),
            ).fetchone()
            if row is None:
                raise MissionStoreError(f"unknown task attempt: {attempt_id}")
            if row["status"] != TaskStatus.RUNNING.value:
                raise MissionStoreError(f"attempt {attempt_id} is not running: {row['status']}")
            mission = self._require_running_mission(conn, row["mission_id"])
            execution_values = tuple(
                dict.fromkeys((*self._load_string_tuple(row["execution_ids_json"]), *requested_execution_ids))
            )
            fact_values = tuple(dict.fromkeys((*self._load_int_tuple(row["fact_ids_json"]), *requested_fact_ids)))
            conn.execute(
                """
                UPDATE mission_task_attempts
                SET execution_ids_json = ?, fact_ids_json = ?
                WHERE attempt_id = ? AND status = 'running'
                """,
                (
                    json.dumps(execution_values, separators=(",", ":")),
                    json.dumps(fact_values, separators=(",", ":")),
                    attempt_id,
                ),
            )
            conn.execute(
                "UPDATE missions SET updated_at = ? WHERE mission_id = ?",
                (time.time(), mission["mission_id"]),
            )
            current = conn.execute(
                "SELECT * FROM mission_task_attempts WHERE attempt_id = ?",
                (attempt_id,),
            ).fetchone()
            return self._attempt_from_row(current)

    def block_task(
        self,
        mission_id: str,
        agent: str,
        task: str,
        reason: str,
        *,
        scope: TaskScope | str | Mapping[str, Any] | Sequence[str] | None = None,
        task_definition_version: str | None = None,
        task_id: str | None = None,
    ) -> TaskAttemptRecord:
        """Terminally block a registered task without opening a running attempt."""
        return self._terminalize_unstarted_task(
            mission_id,
            agent,
            task,
            TaskStatus.BLOCKED.value,
            reason,
            scope=scope,
            task_definition_version=task_definition_version,
            task_id=task_id,
        )

    def skip_task(
        self,
        mission_id: str,
        agent: str,
        task: str,
        reason: str,
        *,
        scope: TaskScope | str | Mapping[str, Any] | Sequence[str] | None = None,
        task_definition_version: str | None = None,
        task_id: str | None = None,
    ) -> TaskAttemptRecord:
        """Terminally skip a registered task without opening a running attempt."""
        return self._terminalize_unstarted_task(
            mission_id,
            agent,
            task,
            TaskStatus.SKIPPED.value,
            reason,
            scope=scope,
            task_definition_version=task_definition_version,
            task_id=task_id,
        )

    def _terminalize_unstarted_task(
        self,
        mission_id: str,
        agent: str,
        task: str,
        status: str,
        reason: str,
        *,
        scope: TaskScope | str | Mapping[str, Any] | Sequence[str] | None = None,
        task_definition_version: str | None = None,
        task_id: str | None = None,
    ) -> TaskAttemptRecord:
        raw_agent = str(agent or "")
        raw_task = str(task or "")
        if not raw_agent or not raw_task:
            raise MissionStoreError("agent and task are required")
        raw_reason = str(reason or "")
        safe_reason = self._safe_text(
            raw_reason,
            "mission_task_reason",
            _MAX_REASON_BYTES,
        )
        reason_key = self._stable_key("mission_task_reason", raw_reason)
        if not safe_reason:
            raise MissionStoreError("terminal task reason is required")
        now = time.time()
        with self._transaction() as conn:
            self._require_running_mission(conn, mission_id)
            try:
                task_row = self._resolve_task_row(
                    conn,
                    mission_id,
                    raw_agent,
                    raw_task,
                    scope=scope,
                    task_definition_version=task_definition_version,
                    task_id=task_id,
                )
            except MissionStoreError as exc:
                if "unknown mission task" not in str(exc):
                    raise
                raise MissionStoreError("task must be registered before it can be blocked") from exc
            _, attempt_row = self._terminalize_task_row(
                conn,
                mission_id,
                task_row,
                raw_agent,
                raw_task,
                status,
                safe_reason,
                reason_key,
                now,
            )
            return self._attempt_from_row(attempt_row)

    def _terminalize_task_row(
        self,
        conn: sqlite3.Connection,
        mission_id: str,
        task_row: sqlite3.Row,
        raw_agent: str,
        raw_task: str,
        status: str,
        safe_reason: str,
        reason_key: str,
        now: float,
    ) -> tuple[sqlite3.Row, sqlite3.Row]:
        if task_row["status"] == status:
            existing = conn.execute(
                """
                SELECT * FROM mission_task_attempts
                WHERE task_id = ? AND status = ?
                ORDER BY attempt_number DESC LIMIT 1
                """,
                (task_row["task_id"], status),
            ).fetchone()
            if existing and (
                existing["reason_key"] == reason_key
                or (not existing["reason_key"] and existing["reason"] == safe_reason)
            ):
                return task_row, existing
            raise MissionStoreError(f"task is already {status} for another reason")
        if task_row["status"] not in _RETRYABLE_TASK_STATUSES:
            raise MissionStoreError(f"task {task_row['task_id']} cannot become {status} from {task_row['status']}")
        attempt_number = int(task_row["attempt_count"]) + 1
        attempt_id = f"attempt_{uuid4().hex}"
        outcome = self._safe_outcome(
            TaskOutcome(
                agent=raw_agent,
                task=raw_task,
                status=status,
                reason=safe_reason,
                new_facts=0,
                parsed_facts=0,
                commands=(),
                duration=0.0,
            ),
            agent=task_row["agent"],
            task=task_row["task"],
        )
        conn.execute(
            """
            INSERT INTO mission_task_attempts(
                attempt_id, task_id, mission_id, attempt_number, status,
                reason, reason_key, started_at, finished_at, outcome_json,
                outcome_key
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                attempt_id,
                task_row["task_id"],
                mission_id,
                attempt_number,
                status,
                safe_reason,
                reason_key,
                now,
                now,
                self._encode_outcome(outcome),
                self._stable_payload_key(
                    "task_completion",
                    {
                        "outcome": TaskOutcome(
                            agent=raw_agent,
                            task=raw_task,
                            status=status,
                            reason=safe_reason,
                            new_facts=0,
                            parsed_facts=0,
                            commands=(),
                            duration=0.0,
                        ).to_legacy_dict(),
                        "execution_ids": [],
                        "fact_ids": [],
                    },
                ),
            ),
        )
        conn.execute(
            """
            UPDATE mission_tasks
            SET status = ?, reason = ?, reason_key = ?, updated_at = ?,
                started_at = COALESCE(started_at, ?), finished_at = ?,
                attempt_count = ?
            WHERE task_id = ?
            """,
            (
                status,
                safe_reason,
                reason_key,
                now,
                now,
                now,
                attempt_number,
                task_row["task_id"],
            ),
        )
        conn.execute(
            "UPDATE missions SET updated_at = ? WHERE mission_id = ?",
            (now, mission_id),
        )
        current_task = conn.execute(
            "SELECT * FROM mission_tasks WHERE task_id = ?",
            (task_row["task_id"],),
        ).fetchone()
        current_attempt = conn.execute(
            "SELECT * FROM mission_task_attempts WHERE attempt_id = ?",
            (attempt_id,),
        ).fetchone()
        return current_task, current_attempt

    def _require_mission(self, conn: sqlite3.Connection, mission_id: str) -> sqlite3.Row:
        row = conn.execute(
            "SELECT * FROM missions WHERE mission_id = ?",
            (mission_id,),
        ).fetchone()
        if row is None:
            raise MissionStoreError(f"unknown mission: {mission_id}")
        return row

    def _require_mutable_mission(
        self,
        conn: sqlite3.Connection,
        mission_id: str,
    ) -> sqlite3.Row:
        row = self._require_mission(conn, mission_id)
        if row["status"] != MissionStatus.RUNNING.value:
            raise MissionStoreError(f"mission {mission_id} is not running: {row['status']}")
        self._require_owner(row)
        return row

    def _require_running_mission(
        self,
        conn: sqlite3.Connection,
        mission_id: str,
    ) -> sqlite3.Row:
        row = self._require_mission(conn, mission_id)
        if row["status"] != MissionStatus.RUNNING.value:
            raise MissionStoreError(f"mission {mission_id} is not running: {row['status']}")
        self._require_owner(row)
        return row

    def _require_owner(self, row: sqlite3.Row) -> None:
        if row["owner_id"] != self._owner_id:
            raise MissionStoreError("mission owner changed; stale writer is fenced")

    def _prepare_task_metadata(
        self,
        scope: TaskScope | str | Mapping[str, Any] | Sequence[str] | None,
        capability: str | None,
        retry_policy: TaskRetryPolicy | None,
        *,
        capability_id: str | None = None,
        task_definition_version: str = TASK_DEFINITION_SCHEMA_VERSION,
        not_before: float | None = None,
        backoff: TaskBackoff | None = None,
        provider_circuit_ref: str | None = None,
        evaluated_snapshot_ref: str | None = None,
    ) -> dict[str, Any]:
        if retry_policy is not None and not isinstance(retry_policy, TaskRetryPolicy):
            raise MissionStoreError("retry_policy must be a TaskRetryPolicy")
        if backoff is not None and not isinstance(backoff, TaskBackoff):
            raise MissionStoreError("backoff must be a TaskBackoff")

        scope_supplied = scope is not None
        raw_task_scope = self._coerce_task_scope(scope)
        raw_legacy_scope = raw_task_scope.legacy_scope
        safe_entity_ids = tuple(
            self._safe_text(
                entity_id,
                "mission_task_entity_id",
                _MAX_IDENTIFIER_BYTES,
            )
            for entity_id in raw_task_scope.entity_ids
        )
        safe_legacy_scope = self._safe_text(
            raw_legacy_scope,
            "mission_task_scope",
            _MAX_IDENTIFIER_BYTES,
        )
        safe_task_scope = TaskScope(
            entity_ids=safe_entity_ids,
            legacy_scope=safe_legacy_scope,
            schema_version=raw_task_scope.schema_version,
        )
        legacy_scope_key = self._stable_key("mission_task_scope", raw_legacy_scope) if raw_legacy_scope else ""
        task_scope_key = self._task_scope_key(
            raw_task_scope,
            legacy_scope_key=legacy_scope_key,
        )
        safe_scope = safe_legacy_scope or (
            self._encode_task_scope(safe_task_scope) if safe_task_scope.entity_ids else ""
        )
        raw_capability = None if capability is None else str(capability)
        raw_capability_id = (
            self._capability_id(capability_id)
            if capability_id not in (None, "")
            else (canonical_capability_id(raw_capability) if raw_capability else None)
        )
        safe_capability = (
            ""
            if raw_capability is None
            else self._safe_text(
                raw_capability,
                "mission_task_capability",
                _MAX_IDENTIFIER_BYTES,
            )
        )
        safe_capability_id = (
            ""
            if raw_capability_id is None
            else self._safe_text(
                raw_capability_id,
                "mission_task_capability_id",
                _MAX_IDENTIFIER_BYTES,
            )
        )
        definition_version = self._task_definition_version(task_definition_version)
        policy = retry_policy or TaskRetryPolicy()
        retryable_json = self._encode_retry_error_classes(policy.retryable_error_classes)
        policy_payload = {
            "retry_budget": policy.retry_budget,
            "retryable_error_classes": [item.value for item in policy.retryable_error_classes],
        }
        normalized_not_before = self._not_before(not_before)
        typed_backoff = backoff or TaskBackoff()
        backoff_json = self._encode_backoff(typed_backoff)
        raw_provider_ref = None if provider_circuit_ref is None else str(provider_circuit_ref)
        raw_snapshot_ref = None if evaluated_snapshot_ref is None else str(evaluated_snapshot_ref)
        return {
            "scope_supplied": scope_supplied,
            "scope": safe_scope,
            "scope_key": (None if not scope_supplied else legacy_scope_key),
            "task_scope_json": self._encode_task_scope(safe_task_scope),
            "task_scope_key": task_scope_key,
            "capability": safe_capability,
            "capability_key": (
                None if raw_capability is None else self._stable_key("mission_task_capability", raw_capability)
            ),
            "capability_id": safe_capability_id,
            "capability_id_key": (
                None
                if raw_capability_id is None
                else self._stable_key(
                    "mission_task_capability_id",
                    raw_capability_id,
                )
            ),
            "task_definition_version": definition_version,
            "retry_budget": policy.retry_budget,
            "retryable_error_classes_json": retryable_json,
            "retry_policy_key": (
                None if retry_policy is None else self._stable_payload_key("mission_task_retry_policy", policy_payload)
            ),
            "not_before": normalized_not_before,
            "backoff_json": backoff_json,
            "backoff_key": (
                None
                if backoff is None
                else self._stable_payload_key(
                    "mission_task_backoff",
                    typed_backoff.to_dict(),
                )
            ),
            "provider_circuit_ref": (
                ""
                if raw_provider_ref is None
                else self._safe_text(
                    raw_provider_ref,
                    "mission_task_provider_circuit_ref",
                    _MAX_IDENTIFIER_BYTES,
                )
            ),
            "provider_circuit_ref_key": (
                None
                if raw_provider_ref is None
                else self._stable_key(
                    "mission_task_provider_circuit_ref",
                    raw_provider_ref,
                )
            ),
            "evaluated_snapshot_ref": (
                ""
                if raw_snapshot_ref is None
                else self._safe_text(
                    raw_snapshot_ref,
                    "mission_task_evaluated_snapshot_ref",
                    _MAX_IDENTIFIER_BYTES,
                )
            ),
            "evaluated_snapshot_ref_key": (
                None
                if raw_snapshot_ref is None
                else self._stable_key(
                    "mission_task_evaluated_snapshot_ref",
                    raw_snapshot_ref,
                )
            ),
        }

    def _reconcile_task_metadata(
        self,
        conn: sqlite3.Connection,
        row: sqlite3.Row,
        requested: Mapping[str, Any],
    ) -> sqlite3.Row:
        updates: dict[str, Any] = {}
        if requested["scope_supplied"]:
            if row["task_scope_key"] != requested["task_scope_key"]:
                raise MissionStoreError("task scope conflicts with the persisted definition")
            if not row["task_scope_json"]:
                updates["scope"] = requested["scope"]
                updates["scope_key"] = requested["scope_key"] or ""
                updates["task_scope_json"] = requested["task_scope_json"]
                updates["task_scope_key"] = requested["task_scope_key"]

        for field_name in ("capability", "capability_id"):
            requested_key = requested[f"{field_name}_key"]
            if requested_key is None:
                continue
            current_key = row[f"{field_name}_key"]
            current_value = row[field_name]
            requested_value = requested[field_name]
            if current_key and current_key != requested_key:
                raise MissionStoreError(f"task {field_name} conflicts with the persisted definition")
            if not current_key and current_value and current_value != requested_value:
                raise MissionStoreError(f"task {field_name} conflicts with the persisted definition")
            if not current_key:
                updates[field_name] = requested_value
                updates[f"{field_name}_key"] = requested_key

        if row["task_definition_version"] != requested["task_definition_version"]:
            raise MissionStoreError("task definition version conflicts with the persisted definition")

        requested_policy_key = requested["retry_policy_key"]
        if requested_policy_key is not None:
            current_policy_key = row["retry_policy_key"]
            current_classes = self._load_retry_error_classes(row["retryable_error_classes_json"])
            requested_classes = self._load_retry_error_classes(requested["retryable_error_classes_json"])
            same_policy = (
                int(row["retry_budget"]) == int(requested["retry_budget"]) and current_classes == requested_classes
            )
            if current_policy_key and current_policy_key != requested_policy_key:
                raise MissionStoreError("task retry policy conflicts with the persisted definition")
            if not current_policy_key and (int(row["retry_budget"]) or current_classes) and not same_policy:
                raise MissionStoreError("task retry policy conflicts with the persisted definition")
            if not current_policy_key:
                updates["retry_budget"] = int(requested["retry_budget"])
                updates["retryable_error_classes_json"] = requested["retryable_error_classes_json"]
                updates["retry_policy_key"] = requested_policy_key

        requested_backoff_key = requested["backoff_key"]
        if requested_backoff_key is not None:
            current_backoff_key = row["backoff_key"]
            if current_backoff_key and current_backoff_key != requested_backoff_key:
                raise MissionStoreError("task backoff conflicts with the persisted definition")
            if not current_backoff_key:
                current_backoff = self._decode_backoff(row["backoff_json"])
                requested_backoff = self._decode_backoff(requested["backoff_json"])
                if current_backoff != TaskBackoff() and current_backoff != requested_backoff:
                    raise MissionStoreError("task backoff conflicts with the persisted definition")
                updates["backoff_json"] = requested["backoff_json"]
                updates["backoff_key"] = requested_backoff_key

        for field_name in (
            "provider_circuit_ref",
            "evaluated_snapshot_ref",
        ):
            requested_key = requested[f"{field_name}_key"]
            if requested_key is None:
                continue
            current_key = row[f"{field_name}_key"]
            if current_key and current_key != requested_key:
                raise MissionStoreError(f"task {field_name} conflicts with the persisted definition")
            if not current_key:
                updates[field_name] = requested[field_name]
                updates[f"{field_name}_key"] = requested_key

        if requested["not_before"] is not None:
            current_not_before = float(row["not_before"]) if row["not_before"] is not None else None
            if current_not_before is None:
                updates["not_before"] = requested["not_before"]
            elif int(row["attempt_count"]) == 0 and not math.isclose(
                current_not_before,
                float(requested["not_before"]),
                rel_tol=0.0,
                abs_tol=1e-6,
            ):
                raise MissionStoreError("task not_before conflicts with the persisted definition")

        if not updates:
            return row
        assignments = ", ".join(f"{name} = ?" for name in updates)
        conn.execute(
            f"UPDATE mission_tasks SET {assignments} WHERE task_id = ?",
            (*updates.values(), row["task_id"]),
        )
        return conn.execute(
            "SELECT * FROM mission_tasks WHERE task_id = ?",
            (row["task_id"],),
        ).fetchone()

    @staticmethod
    def _insert_task_definition_row(
        conn: sqlite3.Connection,
        *,
        task_id: str,
        mission_id: str,
        task_key: str,
        compat_key: str,
        safe_agent: str,
        safe_task: str,
        created_at: float,
        metadata: Mapping[str, Any],
    ) -> None:
        conn.execute(
            """
            INSERT INTO mission_tasks(
                task_id, mission_id, task_key, task_compat_key,
                agent, task, status, reason, created_at, updated_at,
                attempt_count, scope, scope_key, task_scope_json,
                task_scope_key, capability, capability_key, capability_id,
                capability_id_key, task_definition_version, retry_budget,
                retryable_error_classes_json, retry_policy_key, not_before,
                backoff_json, backoff_key, provider_circuit_ref,
                provider_circuit_ref_key, evaluated_snapshot_ref,
                evaluated_snapshot_ref_key
            ) VALUES (
                ?, ?, ?, ?, ?, ?, 'pending', '', ?, ?, 0, ?, ?, ?, ?, ?, ?,
                ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
            )
            """,
            (
                task_id,
                mission_id,
                task_key,
                compat_key,
                safe_agent,
                safe_task,
                created_at,
                created_at,
                metadata["scope"],
                metadata["scope_key"] or "",
                metadata["task_scope_json"],
                metadata["task_scope_key"],
                metadata["capability"],
                metadata["capability_key"] or "",
                metadata["capability_id"],
                metadata["capability_id_key"] or "",
                metadata["task_definition_version"],
                metadata["retry_budget"],
                metadata["retryable_error_classes_json"],
                metadata["retry_policy_key"] or "",
                metadata["not_before"],
                metadata["backoff_json"],
                metadata["backoff_key"] or "",
                metadata["provider_circuit_ref"],
                metadata["provider_circuit_ref_key"] or "",
                metadata["evaluated_snapshot_ref"],
                metadata["evaluated_snapshot_ref_key"] or "",
            ),
        )

    def _set_provider_circuit_ref(
        self,
        conn: sqlite3.Connection,
        task_id: str,
        raw_reference: str,
    ) -> None:
        conn.execute(
            """
            UPDATE mission_tasks
            SET provider_circuit_ref = ?, provider_circuit_ref_key = ?
            WHERE task_id = ?
            """,
            (
                self._safe_text(
                    raw_reference,
                    "mission_task_provider_circuit_ref",
                    _MAX_IDENTIFIER_BYTES,
                ),
                self._stable_key(
                    "mission_task_provider_circuit_ref",
                    raw_reference,
                ),
                task_id,
            ),
        )

    @staticmethod
    def _coerce_task_dependency(
        value: TaskDependencyRef | tuple[str, str],
    ) -> TaskDependencyRef:
        if isinstance(value, TaskDependencyRef):
            return value
        if isinstance(value, (str, bytes)):
            raise MissionStoreError("task dependencies must be TaskDependencyRef or (agent, task) pairs")
        try:
            agent, task = value
        except (TypeError, ValueError) as exc:
            raise MissionStoreError("task dependencies must be TaskDependencyRef or (agent, task) pairs") from exc
        return TaskDependencyRef(agent=str(agent or ""), task=str(task or ""))

    def _resolve_dependency_row(
        self,
        conn: sqlite3.Connection,
        mission_id: str,
        reference: TaskDependencyRef,
    ) -> sqlite3.Row:
        task_id = str(reference.task_id or "")
        agent = str(reference.agent or "")
        task = str(reference.task or "")
        if task_id:
            row = conn.execute(
                """
                SELECT * FROM mission_tasks
                WHERE mission_id = ? AND task_id = ?
                """,
                (mission_id, task_id),
            ).fetchone()
            if row is None:
                raise MissionStoreError(f"unknown dependency task_id {task_id!r}")
            if bool(agent) != bool(task):
                raise MissionStoreError("dependency agent and task must be supplied together")
            if agent and row["task_compat_key"] != self._task_compat_key(agent, task):
                raise MissionStoreError("dependency identity does not match task_id")
            if reference.task_definition_version is not None:
                version = self._task_definition_version(reference.task_definition_version)
                if row["task_definition_version"] != version:
                    raise MissionStoreError("dependency definition version does not match task_id")
            if reference.scope is not None:
                metadata = self._prepare_task_metadata(
                    reference.scope,
                    None,
                    None,
                    task_definition_version=row["task_definition_version"],
                )
                if row["task_scope_key"] != metadata["task_scope_key"]:
                    raise MissionStoreError("dependency scope does not match task_id")
            return row

        if not agent or not task:
            raise MissionStoreError("dependency agent and task are required")
        compat_key = self._task_compat_key(agent, task)
        if reference.scope is not None:
            metadata = self._prepare_task_metadata(
                reference.scope,
                None,
                None,
                task_definition_version=(reference.task_definition_version or TASK_DEFINITION_SCHEMA_VERSION),
            )
            identity_key = self._task_identity_key(
                compat_key,
                metadata["task_scope_key"],
                metadata["task_definition_version"],
            )
            row = conn.execute(
                """
                SELECT * FROM mission_tasks
                WHERE mission_id = ? AND task_key = ?
                """,
                (mission_id, identity_key),
            ).fetchone()
            if row is None:
                raise MissionStoreError(f"unknown dependency scope {agent}:{task}")
            return row

        candidates = self._task_rows_by_compat_key(conn, mission_id, compat_key)
        if reference.task_definition_version is not None:
            version = self._task_definition_version(reference.task_definition_version)
            candidates = tuple(row for row in candidates if row["task_definition_version"] == version)
        if not candidates:
            raise MissionStoreError(f"unknown dependency {agent}:{task}")
        if len(candidates) > 1:
            raise MissionStoreError(f"scope-ambiguous dependency {agent}:{task}")
        return candidates[0]

    @staticmethod
    def _task_rows_by_compat_key(
        conn: sqlite3.Connection,
        mission_id: str,
        compat_key: str,
    ) -> tuple[sqlite3.Row, ...]:
        return tuple(
            conn.execute(
                """
                SELECT * FROM mission_tasks
                WHERE mission_id = ? AND task_compat_key = ?
                ORDER BY created_at, task_id
                """,
                (mission_id, compat_key),
            ).fetchall()
        )

    def _resolve_task_row(
        self,
        conn: sqlite3.Connection,
        mission_id: str,
        agent: str,
        task: str,
        *,
        scope: TaskScope | str | Mapping[str, Any] | Sequence[str] | None = None,
        task_definition_version: str | None = None,
        task_id: str | None = None,
    ) -> sqlite3.Row:
        compat_key = self._task_compat_key(agent, task)
        if task_id:
            row = conn.execute(
                """
                SELECT * FROM mission_tasks
                WHERE mission_id = ? AND task_id = ?
                """,
                (mission_id, str(task_id)),
            ).fetchone()
            if row is None or row["task_compat_key"] != compat_key:
                raise MissionStoreError("unknown mission task")
            if task_definition_version is not None:
                requested_version = self._task_definition_version(task_definition_version)
                if row["task_definition_version"] != requested_version:
                    raise MissionStoreError("task definition version does not match task_id")
            if scope is not None:
                requested_scope = self._prepare_task_metadata(
                    scope,
                    None,
                    None,
                    task_definition_version=row["task_definition_version"],
                )
                if row["task_scope_key"] != requested_scope["task_scope_key"]:
                    raise MissionStoreError("task scope does not match task_id")
            return row
        if scope is not None:
            metadata = self._prepare_task_metadata(
                scope,
                None,
                None,
                task_definition_version=(task_definition_version or TASK_DEFINITION_SCHEMA_VERSION),
            )
            identity_key = self._task_identity_key(
                compat_key,
                metadata["task_scope_key"],
                metadata["task_definition_version"],
            )
            row = conn.execute(
                """
                SELECT * FROM mission_tasks
                WHERE mission_id = ? AND task_key = ?
                """,
                (mission_id, identity_key),
            ).fetchone()
            if row is None:
                raise MissionStoreError("unknown mission task scope")
            return row
        candidates = self._task_rows_by_compat_key(conn, mission_id, compat_key)
        if task_definition_version is not None:
            requested_version = self._task_definition_version(task_definition_version)
            candidates = tuple(row for row in candidates if row["task_definition_version"] == requested_version)
        if not candidates:
            raise MissionStoreError("unknown mission task")
        if len(candidates) > 1:
            raise MissionStoreError("task scope or task_id is required because agent/task is ambiguous")
        return candidates[0]

    def _set_dependencies(
        self,
        conn: sqlite3.Connection,
        mission_id: str,
        task_id: str,
        dependency_ids: Sequence[str],
    ) -> None:
        for dependency_id in dependency_ids:
            dependency = conn.execute(
                """
                SELECT task_id FROM mission_tasks
                WHERE task_id = ? AND mission_id = ?
                """,
                (dependency_id, mission_id),
            ).fetchone()
            if dependency is None:
                raise MissionStoreError(f"unknown dependency {dependency_id!r} for mission {mission_id}")
            if dependency_id == task_id:
                raise MissionStoreError("a task cannot depend on itself")
            creates_cycle = conn.execute(
                """
                WITH RECURSIVE dependencies(task_id) AS (
                    SELECT dependency_task_id
                    FROM mission_task_dependencies
                    WHERE task_id = ?
                    UNION
                    SELECT link.dependency_task_id
                    FROM mission_task_dependencies link
                    JOIN dependencies current ON link.task_id = current.task_id
                )
                SELECT 1 FROM dependencies WHERE task_id = ? LIMIT 1
                """,
                (dependency_id, task_id),
            ).fetchone()
            if creates_cycle:
                raise MissionStoreError("task dependency cycle detected")
            conn.execute(
                """
                INSERT INTO mission_task_dependencies(task_id, dependency_task_id)
                VALUES (?, ?)
                """,
                (task_id, dependency_id),
            )

    @staticmethod
    def _dependency_ids(conn: sqlite3.Connection, task_id: str) -> tuple[str, ...]:
        return tuple(
            row["dependency_task_id"]
            for row in conn.execute(
                """
                SELECT dependency_task_id FROM mission_task_dependencies
                WHERE task_id = ? ORDER BY dependency_task_id
                """,
                (task_id,),
            ).fetchall()
        )

    def _require_dependencies_completed(
        self,
        conn: sqlite3.Connection,
        task_id: str,
    ) -> None:
        incomplete = conn.execute(
            """
            SELECT dep.task_id, dep.status
            FROM mission_task_dependencies link
            JOIN mission_tasks dep ON dep.task_id = link.dependency_task_id
            WHERE link.task_id = ?
              AND dep.status NOT IN ('completed', 'no_new_facts')
            ORDER BY dep.task_id
            """,
            (task_id,),
        ).fetchall()
        if incomplete:
            raise TaskDependenciesIncomplete(tuple((row["task_id"], row["status"]) for row in incomplete))

    @staticmethod
    def _insert_retry_command_grants(
        conn: sqlite3.Connection,
        task_id: str,
        retry_number: int,
        error_class: RetryErrorClass,
        command_keys: Sequence[str],
        created_at: float,
    ) -> None:
        for command_key in command_keys:
            conn.execute(
                """
                INSERT INTO mission_task_retry_commands(
                    task_id, retry_number, command_key,
                    error_class, consumed_at, created_at
                ) VALUES (?, ?, ?, ?, NULL, ?)
                """,
                (
                    task_id,
                    retry_number,
                    command_key,
                    error_class.value,
                    created_at,
                ),
            )

    @staticmethod
    def _retry_command_keys_for_row(
        conn: sqlite3.Connection,
        task_row: sqlite3.Row,
        *,
        pending_only: bool = False,
    ) -> tuple[str, ...]:
        retry_number = int(task_row["retry_count"])
        if retry_number < 1:
            return ()
        if pending_only:
            rows = conn.execute(
                """
                SELECT command_key FROM mission_task_retry_commands
                WHERE task_id = ? AND retry_number = ? AND consumed_at IS NULL
                ORDER BY command_key
                """,
                (task_row["task_id"], retry_number),
            ).fetchall()
        else:
            rows = conn.execute(
                """
                SELECT command_key FROM mission_task_retry_commands
                WHERE task_id = ? AND retry_number = ?
                ORDER BY command_key
                """,
                (task_row["task_id"], retry_number),
            ).fetchall()
        return tuple(str(row["command_key"]) for row in rows)
