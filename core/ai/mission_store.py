"""Durable mission, task, and attempt lifecycle for the AI pipeline.

The store is a control-plane projection.  Facts remain authoritative evidence,
and C2 delivery tasks remain a separate protocol domain.  Every mutation is a
short SQLite transaction so a restarted process can recover abandoned work
without replaying a terminal task attempt.
"""

from __future__ import annotations

import os
import sqlite3
import threading
import time
from typing import Any
from uuid import uuid4

from core.ai.mission_store_codecs import MissionStoreCodecMixin
from core.ai.mission_store_maintenance import MissionStoreMaintenanceMixin
from core.ai.mission_store_models import (
    _MAX_IDENTIFIER_BYTES,
    _MAX_REASON_BYTES,
    MISSION_LIFECYCLE_SCHEMA_VERSION,
    TASK_DEFINITION_SCHEMA_VERSION,
    TASK_SCOPE_SCHEMA_VERSION,
    AttemptCompletionResult,
    BackoffStrategy,
    MissionRecord,
    MissionSnapshot,
    MissionStatus,
    MissionStoreError,
    MissionTaskDefinition,
    RetryErrorClass,
    StateReplanResult,
    TaskAttemptRecord,
    TaskBackoff,
    TaskBackoffPolicy,
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
from core.ai.mission_store_replans import MissionStoreReplanRepositoryMixin
from core.ai.mission_store_schema import MissionStoreSchemaMixin
from core.ai.mission_store_tasks import MissionTaskRepositoryMixin
from core.secrets import Redactor, SecretStore, default_secret_store_path


class MissionStore(
    MissionStoreSchemaMixin,
    MissionTaskRepositoryMixin,
    MissionStoreReplanRepositoryMixin,
    MissionStoreCodecMixin,
    MissionStoreMaintenanceMixin,
):
    """SQLite authority for mission/task/attempt state transitions."""

    def __init__(
        self,
        db_path: str,
        redactor: Any | None = None,
        *,
        owner_id: str | None = None,
    ) -> None:
        self.db_path = db_path
        self._owned_secret_store: SecretStore | None = None
        if redactor is None:
            if db_path == ":memory:":
                secret_path = ":memory:"
            elif os.path.normpath(db_path) == os.path.normpath("data/facts.db"):
                secret_path = default_secret_store_path()
            else:
                secret_path = f"{db_path}.secrets"
            self._owned_secret_store = SecretStore(secret_path)
            redactor = Redactor(self._owned_secret_store)
        self.redactor = redactor
        self._lock = threading.RLock()
        self._owner_id = owner_id or uuid4().hex
        self._memory_conn: sqlite3.Connection | None = None
        if db_path == ":memory:":
            self._memory_conn = sqlite3.connect(
                ":memory:",
                timeout=30,
                check_same_thread=False,
            )
            self._memory_conn.row_factory = sqlite3.Row
        else:
            os.makedirs(os.path.dirname(os.path.abspath(db_path)), exist_ok=True)
        self._init_db()

    @property
    def owner_id(self) -> str:
        """Opaque run-owner token used to fence a superseded pipeline."""
        return self._owner_id

    def open_mission(
        self,
        scan_id: str,
        target: str,
        *,
        recover: bool = False,
    ) -> MissionRecord:
        raw_scan_id = str(scan_id or "")
        raw_target = str(target or "")
        if not raw_scan_id or not raw_target:
            raise MissionStoreError("scan_id and target are required")
        scan_key = self._stable_key("scan", raw_scan_id)
        target_key = self._stable_key("target", raw_target)
        safe_scan_id = self._safe_text(raw_scan_id, "mission_scan_id", _MAX_IDENTIFIER_BYTES)
        safe_target = self._safe_text(raw_target, "mission_target", _MAX_IDENTIFIER_BYTES)

        now = time.time()
        with self._transaction() as conn:
            row = conn.execute(
                "SELECT * FROM missions WHERE scan_key = ?",
                (scan_key,),
            ).fetchone()
            if row is None:
                legacy_candidates = conn.execute(
                    """
                    SELECT * FROM missions
                    WHERE scan_id IN (?, ?)
                    ORDER BY created_at, mission_id
                    """,
                    (raw_scan_id, safe_scan_id),
                ).fetchall()
                legacy_rows = [
                    candidate
                    for candidate in legacy_candidates
                    if candidate["target"] in {raw_target, safe_target}
                    or self._safe_text(
                        candidate["target"],
                        "mission_target",
                        _MAX_IDENTIFIER_BYTES,
                    )
                    == safe_target
                ]
                if len(legacy_rows) == 1:
                    legacy = legacy_rows[0]
                    conn.execute(
                        """
                        UPDATE missions
                        SET scan_key = ?, scan_id = ?, target_key = ?, target = ?
                        WHERE mission_id = ?
                        """,
                        (
                            scan_key,
                            safe_scan_id,
                            target_key,
                            safe_target,
                            legacy["mission_id"],
                        ),
                    )
                    row = conn.execute(
                        "SELECT * FROM missions WHERE mission_id = ?",
                        (legacy["mission_id"],),
                    ).fetchone()
            if row is None:
                mission_id = f"mis_{uuid4().hex}"
                conn.execute(
                    """
                    INSERT INTO missions(
                        mission_id, scan_key, scan_id, target_key, target,
                        status, reason, owner_id,
                        created_at, updated_at, started_at, finished_at,
                        run_count, schema_version
                    ) VALUES (?, ?, ?, ?, ?, 'running', '', ?, ?, ?, ?, NULL, 1, ?)
                    """,
                    (
                        mission_id,
                        scan_key,
                        safe_scan_id,
                        target_key,
                        safe_target,
                        self._owner_id,
                        now,
                        now,
                        now,
                        MISSION_LIFECYCLE_SCHEMA_VERSION,
                    ),
                )
            else:
                if row["target_key"] != target_key:
                    legacy_target_matches = (
                        row["target"]
                        in {
                            raw_target,
                            safe_target,
                        }
                        or self._safe_text(
                            row["target"],
                            "mission_target",
                            _MAX_IDENTIFIER_BYTES,
                        )
                        == safe_target
                    )
                    if not legacy_target_matches:
                        raise MissionStoreError(f"scan_id {safe_scan_id!r} already belongs to a different target")
                    conn.execute(
                        """
                        UPDATE missions SET target_key = ?, target = ?
                        WHERE mission_id = ?
                        """,
                        (target_key, safe_target, row["mission_id"]),
                    )
                    row = conn.execute(
                        "SELECT * FROM missions WHERE mission_id = ?",
                        (row["mission_id"],),
                    ).fetchone()
                status = row["status"]
                if status == MissionStatus.COMPLETED.value:
                    return self._mission_from_row(row)
                if status == MissionStatus.RUNNING.value and row["owner_id"] != self._owner_id:
                    if not recover:
                        raise MissionStoreError("mission is owned by another run; explicit recovery is required")
                    self._interrupt_running_work(
                        conn,
                        row["mission_id"],
                        "recovered_after_process_restart",
                        now,
                        self._stable_key(
                            "mission_reason",
                            "recovered_after_process_restart",
                        ),
                    )
                if status != MissionStatus.RUNNING.value or row["owner_id"] != self._owner_id:
                    conn.execute(
                        """
                        UPDATE missions
                        SET status = 'running', reason = '', reason_key = '', owner_id = ?,
                            updated_at = ?, finished_at = NULL, run_count = run_count + 1
                        WHERE mission_id = ?
                        """,
                        (self._owner_id, now, row["mission_id"]),
                    )
            current = conn.execute(
                "SELECT * FROM missions WHERE scan_key = ?",
                (scan_key,),
            ).fetchone()
            return self._mission_from_row(current)

    def get_mission_by_scan_id(self, scan_id: str) -> MissionRecord | None:
        scan_key = self._stable_key("scan", str(scan_id or ""))
        with self._connection() as conn:
            row = conn.execute(
                "SELECT * FROM missions WHERE scan_key = ?",
                (scan_key,),
            ).fetchone()
            return self._mission_from_row(row) if row else None

    def interrupt_mission(self, mission_id: str, reason: str) -> MissionRecord:
        raw_reason = str(reason or "")
        safe_reason = self._safe_text(raw_reason, "mission_reason", _MAX_REASON_BYTES)
        reason_key = self._stable_key("mission_reason", raw_reason)
        if not safe_reason:
            raise MissionStoreError("interrupt reason is required")
        now = time.time()
        with self._transaction() as conn:
            row = self._require_mission(conn, mission_id)
            if row["status"] == MissionStatus.COMPLETED.value:
                raise MissionStoreError("completed missions cannot be interrupted")
            if row["status"] == MissionStatus.INTERRUPTED.value:
                if row["reason_key"] not in {"", reason_key} or (
                    not row["reason_key"] and row["reason"] != safe_reason
                ):
                    raise MissionStoreError("mission is already interrupted for another reason")
                return self._mission_from_row(row)
            self._require_owner(row)
            self._interrupt_running_work(
                conn,
                mission_id,
                safe_reason,
                now,
                reason_key,
            )
            conn.execute(
                """
                UPDATE missions
                SET status = 'interrupted', reason = ?, reason_key = ?, owner_id = '',
                    updated_at = ?, finished_at = ?
                WHERE mission_id = ?
                """,
                (safe_reason, reason_key, now, now, mission_id),
            )
            current = conn.execute(
                "SELECT * FROM missions WHERE mission_id = ?",
                (mission_id,),
            ).fetchone()
            return self._mission_from_row(current)

    def complete_mission(self, mission_id: str, reason: str) -> MissionRecord:
        raw_reason = str(reason or "")
        safe_reason = self._safe_text(raw_reason, "mission_reason", _MAX_REASON_BYTES)
        reason_key = self._stable_key("mission_reason", raw_reason)
        if not safe_reason:
            raise MissionStoreError("completion reason is required")
        now = time.time()
        with self._transaction() as conn:
            row = self._require_mission(conn, mission_id)
            if row["status"] == MissionStatus.COMPLETED.value:
                if row["reason_key"] not in {"", reason_key} or (
                    not row["reason_key"] and row["reason"] != safe_reason
                ):
                    raise MissionStoreError("mission already completed for another reason")
                return self._mission_from_row(row)
            if row["status"] != MissionStatus.RUNNING.value:
                raise MissionStoreError(f"mission cannot complete from {row['status']}")
            self._require_owner(row)
            unfinished = conn.execute(
                """
                SELECT task_id, status FROM mission_tasks
                WHERE mission_id = ?
                  AND status IN ('pending', 'running', 'interrupted')
                ORDER BY task_id LIMIT 1
                """,
                (mission_id,),
            ).fetchone()
            if unfinished:
                raise MissionStoreError(f"mission has unfinished task {unfinished['task_id']}:{unfinished['status']}")
            conn.execute(
                """
                UPDATE missions
                SET status = 'completed', reason = ?, reason_key = ?, owner_id = '',
                    updated_at = ?, finished_at = ?
                WHERE mission_id = ?
                """,
                (safe_reason, reason_key, now, now, mission_id),
            )
            current = conn.execute(
                "SELECT * FROM missions WHERE mission_id = ?",
                (mission_id,),
            ).fetchone()
            return self._mission_from_row(current)

    def snapshot(self, mission_id: str) -> MissionSnapshot:
        with self._connection() as conn:
            conn.execute("BEGIN")
            try:
                mission_row = self._require_mission(conn, mission_id)
                task_rows = conn.execute(
                    """
                    SELECT * FROM mission_tasks
                    WHERE mission_id = ? ORDER BY created_at, task_id
                    """,
                    (mission_id,),
                ).fetchall()
                attempt_rows = conn.execute(
                    """
                    SELECT * FROM mission_task_attempts
                    WHERE mission_id = ? ORDER BY started_at, task_id, attempt_number
                    """,
                    (mission_id,),
                ).fetchall()
                return MissionSnapshot(
                    mission=self._mission_from_row(mission_row),
                    tasks=tuple(self._task_from_row(conn, row) for row in task_rows),
                    attempts=tuple(self._attempt_from_row(row) for row in attempt_rows),
                )
            finally:
                conn.rollback()


__all__ = [
    "MISSION_LIFECYCLE_SCHEMA_VERSION",
    "TASK_DEFINITION_SCHEMA_VERSION",
    "TASK_SCOPE_SCHEMA_VERSION",
    "AttemptCompletionResult",
    "BackoffStrategy",
    "MissionRecord",
    "MissionSnapshot",
    "MissionStatus",
    "MissionStore",
    "MissionStoreError",
    "MissionTaskDefinition",
    "RetryErrorClass",
    "StateReplanResult",
    "TaskAttemptRecord",
    "TaskBackoff",
    "TaskBackoffPolicy",
    "TaskDependenciesIncomplete",
    "TaskDependencyRef",
    "TaskNotReady",
    "TaskRecord",
    "TaskRetryBudgetExhausted",
    "TaskRetryError",
    "TaskRetryNotAllowed",
    "TaskRetryPolicy",
    "TaskScope",
    "TaskStatus",
    "canonical_capability_id",
]
