"""Durable mission, task, and attempt lifecycle for the AI pipeline.

The store is a control-plane projection.  Facts remain authoritative evidence,
and C2 delivery tasks remain a separate protocol domain.  Every mutation is a
short SQLite transaction so a restarted process can recover abandoned work
without replaying a terminal task attempt.
"""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import threading
import time
from collections.abc import Iterator, Mapping, Sequence
from contextlib import contextmanager
from dataclasses import dataclass, field
from enum import Enum
from typing import Any
from uuid import uuid4

from core.ai.outcomes import TaskOutcome
from core.secrets import Redactor, SecretStore, default_secret_store_path

MISSION_LIFECYCLE_SCHEMA_VERSION = "1.2"
_MIGRATABLE_SCHEMA_VERSIONS = frozenset(
    {"1.0", "1.1", MISSION_LIFECYCLE_SCHEMA_VERSION}
)
_MAX_IDENTIFIER_BYTES = 4096
_MAX_REASON_BYTES = 16 * 1024
_MAX_OUTCOME_BYTES = 4 * 1024 * 1024
_MAX_RETRY_BUDGET = 100
_MAX_RETRY_COMMAND_KEYS = 64


class MissionStatus(str, Enum):
    RUNNING = "running"
    INTERRUPTED = "interrupted"
    COMPLETED = "completed"


class TaskStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    INTERRUPTED = "interrupted"
    BLOCKED = "blocked"
    SKIPPED = "skipped"
    FAILED = "failed"
    NO_NEW_FACTS = "no_new_facts"
    COMPLETED = "completed"


class RetryErrorClass(str, Enum):
    """Stable error taxonomy used by durable retry policies."""

    TIMEOUT = "timeout"
    RATE_LIMIT = "rate_limit"
    TRANSIENT_NETWORK = "transient_network"
    PROVIDER_UNAVAILABLE = "provider_unavailable"
    TOOL_UNAVAILABLE = "tool_unavailable"
    EXECUTION_ERROR = "execution_error"


_RETRYABLE_TASK_STATUSES = {
    TaskStatus.PENDING.value,
    TaskStatus.INTERRUPTED.value,
}
_OUTCOME_STATUSES = {
    TaskStatus.BLOCKED.value,
    TaskStatus.SKIPPED.value,
    TaskStatus.FAILED.value,
    TaskStatus.NO_NEW_FACTS.value,
    TaskStatus.COMPLETED.value,
}


class MissionStoreError(ValueError):
    """Raised when a lifecycle mutation conflicts with persisted state."""


class TaskDependenciesIncomplete(MissionStoreError):
    """Raised when durable task prerequisites have not completed."""

    def __init__(self, incomplete: Sequence[tuple[str, str]]) -> None:
        self.incomplete = tuple(incomplete)
        details = ",".join(
            f"{task_id}:{status}" for task_id, status in self.incomplete
        )
        super().__init__(f"task dependencies are incomplete: {details}")


class TaskRetryError(MissionStoreError):
    """Base error for an invalid durable retry transition."""


class TaskRetryNotAllowed(TaskRetryError):
    """Raised when a failure class is not retryable for a task."""


class TaskRetryBudgetExhausted(TaskRetryError):
    """Raised when a task has consumed its explicit retry budget."""


@dataclass(frozen=True)
class TaskRetryPolicy:
    """Bounded retry policy persisted with a mission task definition."""

    retry_budget: int = 0
    retryable_error_classes: tuple[RetryErrorClass, ...] = ()

    def __post_init__(self) -> None:
        if isinstance(self.retry_budget, bool) or not isinstance(self.retry_budget, int):
            raise MissionStoreError("retry_budget must be an integer")
        if not 0 <= self.retry_budget <= _MAX_RETRY_BUDGET:
            raise MissionStoreError(
                f"retry_budget must be between 0 and {_MAX_RETRY_BUDGET}"
            )
        try:
            normalized = tuple(
                dict.fromkeys(
                    item
                    if isinstance(item, RetryErrorClass)
                    else RetryErrorClass(str(item))
                    for item in self.retryable_error_classes
                )
            )
        except ValueError as exc:
            raise MissionStoreError(f"unsupported retry error class: {exc}") from exc
        if self.retry_budget and not normalized:
            raise MissionStoreError(
                "a positive retry_budget requires retryable_error_classes"
            )
        if not self.retry_budget and normalized:
            raise MissionStoreError(
                "retryable_error_classes require a positive retry_budget"
            )
        object.__setattr__(self, "retryable_error_classes", normalized)


@dataclass(frozen=True)
class MissionTaskDefinition:
    """Typed planner-task definition accepted by :meth:`register_plan`."""

    agent: str
    task: str
    depends_on: tuple[tuple[str, str], ...] = ()
    scope: str = ""
    capability: str = ""
    retry_policy: TaskRetryPolicy = field(default_factory=TaskRetryPolicy)


@dataclass(frozen=True)
class MissionRecord:
    mission_id: str
    scan_id: str
    target: str
    status: str
    reason: str
    created_at: float
    updated_at: float
    started_at: float
    finished_at: float | None
    run_count: int
    schema_version: str = MISSION_LIFECYCLE_SCHEMA_VERSION


@dataclass(frozen=True)
class TaskRecord:
    task_id: str
    mission_id: str
    agent: str
    task: str
    status: str
    reason: str
    depends_on: tuple[str, ...]
    created_at: float
    updated_at: float
    started_at: float | None
    finished_at: float | None
    attempt_count: int
    scope: str = ""
    capability: str = ""
    retry_budget: int = 0
    retry_count: int = 0
    retryable_error_classes: tuple[RetryErrorClass, ...] = ()
    last_error_class: RetryErrorClass | None = None


@dataclass(frozen=True)
class TaskAttemptRecord:
    attempt_id: str
    task_id: str
    mission_id: str
    attempt_number: int
    status: str
    reason: str
    started_at: float
    finished_at: float | None
    outcome: TaskOutcome | None
    execution_ids: tuple[str, ...]
    fact_ids: tuple[int, ...]


@dataclass(frozen=True)
class AttemptCompletionResult:
    """Atomic result of terminalizing an attempt and evaluating its retry."""

    attempt: TaskAttemptRecord
    task: TaskRecord
    retry_scheduled: bool = False
    retry_rejection: str = ""
    retry_command_keys: tuple[str, ...] = ()


@dataclass(frozen=True)
class MissionSnapshot:
    mission: MissionRecord
    tasks: tuple[TaskRecord, ...]
    attempts: tuple[TaskAttemptRecord, ...]

    @property
    def task_outcomes(self) -> tuple[dict[str, Any], ...]:
        """Return completed attempt outcomes in legacy report order."""
        return tuple(
            attempt.outcome.to_legacy_dict()
            for attempt in self.attempts
            if attempt.outcome is not None
        )


class MissionStore:
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

    def close(self) -> None:
        with self._lock:
            if self._memory_conn is not None:
                self._memory_conn.close()
                self._memory_conn = None
            if self._owned_secret_store is not None:
                self._owned_secret_store.close()
                self._owned_secret_store = None

    @contextmanager
    def _connection(self) -> Iterator[sqlite3.Connection]:
        with self._lock:
            if self._memory_conn is not None:
                conn = self._memory_conn
                close = False
            else:
                conn = sqlite3.connect(self.db_path, timeout=30)
                conn.row_factory = sqlite3.Row
                close = True
            conn.execute("PRAGMA foreign_keys=ON")
            conn.execute("PRAGMA busy_timeout=30000")
            try:
                yield conn
            finally:
                if close:
                    conn.close()

    @contextmanager
    def _transaction(self) -> Iterator[sqlite3.Connection]:
        with self._connection() as conn:
            conn.execute("BEGIN IMMEDIATE")
            try:
                yield conn
                conn.commit()
            except BaseException:
                conn.rollback()
                raise

    def _init_db(self) -> None:
        last_error: sqlite3.OperationalError | None = None
        for attempt in range(12):
            try:
                self._init_db_once()
                return
            except sqlite3.OperationalError as exc:
                if "locked" not in str(exc).lower() and "busy" not in str(exc).lower():
                    raise
                last_error = exc
                time.sleep(min(0.01 * (2 ** attempt), 0.25))
        if last_error is not None:
            raise last_error

    def _init_db_once(self) -> None:
        with self._connection() as conn:
            if self._memory_conn is None:
                conn.execute("PRAGMA journal_mode=WAL")
                conn.execute("PRAGMA synchronous=FULL")
            conn.execute("BEGIN IMMEDIATE")
            try:
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS mission_lifecycle_schema (
                        component TEXT PRIMARY KEY,
                        version TEXT NOT NULL
                    )
                    """
                )
                existing = conn.execute(
                    """
                    SELECT version FROM mission_lifecycle_schema
                    WHERE component = 'mission_store'
                    """
                ).fetchone()
                if existing and existing["version"] not in _MIGRATABLE_SCHEMA_VERSIONS:
                    raise MissionStoreError(
                        "unsupported mission lifecycle schema version: "
                        f"{existing['version']}"
                    )
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS missions (
                        mission_id TEXT PRIMARY KEY,
                        scan_key TEXT NOT NULL UNIQUE,
                        scan_id TEXT NOT NULL,
                        target_key TEXT NOT NULL,
                        target TEXT NOT NULL,
                        status TEXT NOT NULL,
                        reason TEXT NOT NULL DEFAULT '',
                        reason_key TEXT NOT NULL DEFAULT '',
                        owner_id TEXT NOT NULL DEFAULT '',
                        created_at REAL NOT NULL,
                        updated_at REAL NOT NULL,
                        started_at REAL NOT NULL,
                        finished_at REAL,
                        run_count INTEGER NOT NULL DEFAULT 1,
                        schema_version TEXT NOT NULL
                    )
                    """
                )
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS mission_tasks (
                        task_id TEXT PRIMARY KEY,
                        mission_id TEXT NOT NULL,
                        task_key TEXT NOT NULL,
                        agent TEXT NOT NULL,
                        task TEXT NOT NULL,
                        status TEXT NOT NULL,
                        reason TEXT NOT NULL DEFAULT '',
                        reason_key TEXT NOT NULL DEFAULT '',
                        created_at REAL NOT NULL,
                        updated_at REAL NOT NULL,
                        started_at REAL,
                        finished_at REAL,
                        attempt_count INTEGER NOT NULL DEFAULT 0,
                        scope TEXT NOT NULL DEFAULT '',
                        scope_key TEXT NOT NULL DEFAULT '',
                        capability TEXT NOT NULL DEFAULT '',
                        capability_key TEXT NOT NULL DEFAULT '',
                        retry_budget INTEGER NOT NULL DEFAULT 0,
                        retry_count INTEGER NOT NULL DEFAULT 0,
                        retryable_error_classes_json TEXT NOT NULL DEFAULT '[]',
                        retry_policy_key TEXT NOT NULL DEFAULT '',
                        last_error_class TEXT NOT NULL DEFAULT '',
                        UNIQUE(mission_id, task_key),
                        FOREIGN KEY(mission_id) REFERENCES missions(mission_id)
                            ON DELETE CASCADE
                    )
                    """
                )
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS mission_task_dependencies (
                        task_id TEXT NOT NULL,
                        dependency_task_id TEXT NOT NULL,
                        PRIMARY KEY(task_id, dependency_task_id),
                        CHECK(task_id <> dependency_task_id),
                        FOREIGN KEY(task_id) REFERENCES mission_tasks(task_id)
                            ON DELETE CASCADE,
                        FOREIGN KEY(dependency_task_id) REFERENCES mission_tasks(task_id)
                            ON DELETE CASCADE
                    )
                    """
                )
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS mission_task_attempts (
                        attempt_id TEXT PRIMARY KEY,
                        task_id TEXT NOT NULL,
                        mission_id TEXT NOT NULL,
                        attempt_number INTEGER NOT NULL,
                        status TEXT NOT NULL,
                        reason TEXT NOT NULL DEFAULT '',
                        reason_key TEXT NOT NULL DEFAULT '',
                        started_at REAL NOT NULL,
                        finished_at REAL,
                        outcome_json TEXT NOT NULL DEFAULT '',
                        outcome_key TEXT NOT NULL DEFAULT '',
                        execution_ids_json TEXT NOT NULL DEFAULT '[]',
                        fact_ids_json TEXT NOT NULL DEFAULT '[]',
                        UNIQUE(task_id, attempt_number),
                        FOREIGN KEY(task_id) REFERENCES mission_tasks(task_id)
                            ON DELETE CASCADE,
                        FOREIGN KEY(mission_id) REFERENCES missions(mission_id)
                            ON DELETE CASCADE
                    )
                    """
                )
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS mission_task_retry_commands (
                        task_id TEXT NOT NULL,
                        retry_number INTEGER NOT NULL,
                        command_key TEXT NOT NULL,
                        error_class TEXT NOT NULL,
                        consumed_at REAL,
                        created_at REAL NOT NULL,
                        PRIMARY KEY(task_id, retry_number, command_key),
                        FOREIGN KEY(task_id) REFERENCES mission_tasks(task_id)
                            ON DELETE CASCADE
                    )
                    """
                )
                conn.execute(
                    """
                    CREATE UNIQUE INDEX IF NOT EXISTS idx_one_running_attempt_per_task
                    ON mission_task_attempts(task_id) WHERE status = 'running'
                    """
                )
                conn.execute(
                    """
                    CREATE INDEX IF NOT EXISTS idx_mission_tasks_status
                    ON mission_tasks(mission_id, status)
                    """
                )
                conn.execute(
                    """
                    CREATE INDEX IF NOT EXISTS idx_mission_attempts_status
                    ON mission_task_attempts(mission_id, status)
                    """
                )
                conn.execute(
                    """
                    CREATE INDEX IF NOT EXISTS idx_mission_retry_commands_pending
                    ON mission_task_retry_commands(task_id, retry_number, consumed_at)
                    """
                )
                self._ensure_column(
                    conn,
                    "missions",
                    "scan_key",
                    "TEXT NOT NULL DEFAULT ''",
                )
                self._ensure_column(
                    conn,
                    "missions",
                    "target_key",
                    "TEXT NOT NULL DEFAULT ''",
                )
                self._ensure_column(
                    conn,
                    "missions",
                    "reason_key",
                    "TEXT NOT NULL DEFAULT ''",
                )
                self._ensure_column(
                    conn,
                    "mission_tasks",
                    "reason_key",
                    "TEXT NOT NULL DEFAULT ''",
                )
                self._ensure_column(
                    conn,
                    "mission_tasks",
                    "scope",
                    "TEXT NOT NULL DEFAULT ''",
                )
                self._ensure_column(
                    conn,
                    "mission_tasks",
                    "scope_key",
                    "TEXT NOT NULL DEFAULT ''",
                )
                self._ensure_column(
                    conn,
                    "mission_tasks",
                    "capability",
                    "TEXT NOT NULL DEFAULT ''",
                )
                self._ensure_column(
                    conn,
                    "mission_tasks",
                    "capability_key",
                    "TEXT NOT NULL DEFAULT ''",
                )
                self._ensure_column(
                    conn,
                    "mission_tasks",
                    "retry_budget",
                    "INTEGER NOT NULL DEFAULT 0",
                )
                self._ensure_column(
                    conn,
                    "mission_tasks",
                    "retry_count",
                    "INTEGER NOT NULL DEFAULT 0",
                )
                self._ensure_column(
                    conn,
                    "mission_tasks",
                    "retryable_error_classes_json",
                    "TEXT NOT NULL DEFAULT '[]'",
                )
                self._ensure_column(
                    conn,
                    "mission_tasks",
                    "retry_policy_key",
                    "TEXT NOT NULL DEFAULT ''",
                )
                self._ensure_column(
                    conn,
                    "mission_tasks",
                    "last_error_class",
                    "TEXT NOT NULL DEFAULT ''",
                )
                self._ensure_column(
                    conn,
                    "mission_task_attempts",
                    "reason_key",
                    "TEXT NOT NULL DEFAULT ''",
                )
                self._ensure_column(
                    conn,
                    "mission_task_attempts",
                    "outcome_key",
                    "TEXT NOT NULL DEFAULT ''",
                )
                for row in conn.execute(
                    """
                    SELECT mission_id, scan_id, target, scan_key, target_key
                    FROM missions
                    """
                ).fetchall():
                    scan_key = row["scan_key"] or self._stable_key(
                        "scan",
                        row["scan_id"],
                    )
                    target_key = row["target_key"] or self._stable_key(
                        "target",
                        row["target"],
                    )
                    conn.execute(
                        """
                        UPDATE missions SET scan_key = ?, target_key = ?
                        WHERE mission_id = ?
                        """,
                        (scan_key, target_key, row["mission_id"]),
                    )
                conn.execute(
                    """
                    CREATE UNIQUE INDEX IF NOT EXISTS idx_missions_scan_key
                    ON missions(scan_key)
                    """
                )
                if existing is None:
                    conn.execute(
                        """
                        INSERT INTO mission_lifecycle_schema(component, version)
                        VALUES ('mission_store', ?)
                        """,
                        (MISSION_LIFECYCLE_SCHEMA_VERSION,),
                    )
                elif existing["version"] != MISSION_LIFECYCLE_SCHEMA_VERSION:
                    conn.execute(
                        """
                        UPDATE mission_lifecycle_schema SET version = ?
                        WHERE component = 'mission_store' AND version = ?
                        """,
                        (MISSION_LIFECYCLE_SCHEMA_VERSION, existing["version"]),
                    )
                    conn.execute(
                        "UPDATE missions SET schema_version = ?",
                        (MISSION_LIFECYCLE_SCHEMA_VERSION,),
                    )
                current = conn.execute(
                    """
                    SELECT version FROM mission_lifecycle_schema
                    WHERE component = 'mission_store'
                    """
                ).fetchone()
                if (
                    current is None
                    or current["version"] != MISSION_LIFECYCLE_SCHEMA_VERSION
                ):
                    raise MissionStoreError("mission lifecycle schema version race")
                conn.commit()
            except BaseException:
                conn.rollback()
                raise

    @staticmethod
    def _ensure_column(
        conn: sqlite3.Connection,
        table: str,
        column: str,
        definition: str,
    ) -> None:
        columns = {
            row["name"] for row in conn.execute(f"PRAGMA table_info({table})").fetchall()
        }
        if column not in columns:
            conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")

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
                    legacy_target_matches = row["target"] in {
                        raw_target,
                        safe_target,
                    } or self._safe_text(
                        row["target"],
                        "mission_target",
                        _MAX_IDENTIFIER_BYTES,
                    ) == safe_target
                    if not legacy_target_matches:
                        raise MissionStoreError(
                            f"scan_id {safe_scan_id!r} already belongs to a different target"
                        )
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
                        raise MissionStoreError(
                            "mission is owned by another run; explicit recovery is required"
                        )
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

    def register_task(
        self,
        mission_id: str,
        agent: str,
        task: str,
        depends_on: Sequence[str] = (),
        *,
        scope: str | None = None,
        capability: str | None = None,
        retry_policy: TaskRetryPolicy | None = None,
    ) -> TaskRecord:
        raw_agent = str(agent or "")
        raw_task = str(task or "")
        if not raw_agent or not raw_task:
            raise MissionStoreError("agent and task are required")
        task_key = self._task_key(raw_agent, raw_task)
        safe_agent = self._safe_text(raw_agent, "mission_task_agent", _MAX_IDENTIFIER_BYTES)
        safe_task = self._safe_text(raw_task, "mission_task_name", _MAX_IDENTIFIER_BYTES)
        dependency_ids = tuple(sorted(dict.fromkeys(str(item) for item in depends_on)))
        metadata = self._prepare_task_metadata(scope, capability, retry_policy)
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
            if row is None:
                task_id = f"task_{uuid4().hex}"
                conn.execute(
                    """
                    INSERT INTO mission_tasks(
                        task_id, mission_id, task_key, agent, task, status,
                        reason, created_at, updated_at, attempt_count,
                        scope, scope_key, capability, capability_key,
                        retry_budget, retryable_error_classes_json,
                        retry_policy_key
                    ) VALUES (?, ?, ?, ?, ?, 'pending', '', ?, ?, 0,
                              ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        task_id,
                        mission_id,
                        task_key,
                        safe_agent,
                        safe_task,
                        now,
                        now,
                        metadata["scope"],
                        metadata["scope_key"] or "",
                        metadata["capability"],
                        metadata["capability_key"] or "",
                        metadata["retry_budget"],
                        metadata["retryable_error_classes_json"],
                        metadata["retry_policy_key"] or "",
                    ),
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
            MissionTaskDefinition | tuple[str, str, Sequence[tuple[str, str]]]
        ],
        *,
        blocked_reasons: Mapping[tuple[str, str], str] | None = None,
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
                )
            else:
                try:
                    agent, task, raw_dependencies = definition
                    dependencies = tuple(raw_dependencies)
                except (TypeError, ValueError) as exc:
                    raise MissionStoreError(
                        "plan definitions must be MissionTaskDefinition or "
                        "(agent, task, dependencies) tuples"
                    ) from exc
                metadata = self._prepare_task_metadata(None, None, None)
            raw_agent = str(agent or "")
            raw_task = str(task or "")
            if not raw_agent or not raw_task:
                raise MissionStoreError("agent and task are required")
            task_key = self._task_key(raw_agent, raw_task)
            if task_key in seen_keys:
                raise MissionStoreError("duplicate task definition in mission plan")
            seen_keys.add(task_key)
            prepared.append(
                (
                    raw_agent,
                    raw_task,
                    task_key,
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
                    tuple(
                        (str(dep_agent or ""), str(dep_task or ""))
                        for dep_agent, dep_task in dependencies
                    ),
                    metadata,
                )
            )
        if not prepared:
            return ()

        safe_blocked_reasons = {}
        for (agent, task), reason in (blocked_reasons or {}).items():
            raw_reason = str(reason or "")
            safe_blocked_reasons[
                self._task_key(str(agent or ""), str(task or ""))
            ] = (
                self._safe_text(
                    raw_reason,
                    "mission_task_reason",
                    _MAX_REASON_BYTES,
                ),
                self._stable_key("mission_task_reason", raw_reason),
            )
        unknown_blocked = set(safe_blocked_reasons) - seen_keys
        if unknown_blocked:
            raise MissionStoreError("blocked plan tasks must have definitions")
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
                    conn.execute(
                        """
                        INSERT INTO mission_tasks(
                            task_id, mission_id, task_key, agent, task, status,
                            reason, created_at, updated_at, attempt_count,
                            scope, scope_key, capability, capability_key,
                            retry_budget, retryable_error_classes_json,
                            retry_policy_key
                        ) VALUES (?, ?, ?, ?, ?, 'pending', '', ?, ?, 0,
                                  ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            task_id,
                            mission_id,
                            task_key,
                            safe_agent,
                            safe_task,
                            now + (position * 0.000001),
                            now + (position * 0.000001),
                            metadata["scope"],
                            metadata["scope_key"] or "",
                            metadata["capability"],
                            metadata["capability_key"] or "",
                            metadata["retry_budget"],
                            metadata["retryable_error_classes_json"],
                            metadata["retry_policy_key"] or "",
                        ),
                    )
                    row = conn.execute(
                        "SELECT * FROM mission_tasks WHERE task_id = ?",
                        (task_id,),
                    ).fetchone()
                else:
                    row = self._reconcile_task_metadata(conn, row, metadata)
                rows_by_key[task_key] = row

            for _, _, task_key, _, _, dependencies, _ in prepared:
                row = rows_by_key[task_key]
                dependency_ids = []
                for dep_agent, dep_task in dependencies:
                    if not dep_agent or not dep_task:
                        raise MissionStoreError("dependency agent and task are required")
                    dependency_key = self._task_key(dep_agent, dep_task)
                    dependency = rows_by_key.get(dependency_key)
                    if dependency is None:
                        dependency = conn.execute(
                            """
                            SELECT * FROM mission_tasks
                            WHERE mission_id = ? AND task_key = ?
                            """,
                            (mission_id, dependency_key),
                        ).fetchone()
                    if dependency is None:
                        raise MissionStoreError(
                            f"unknown dependency {dep_agent}:{dep_task}"
                        )
                    dependency_ids.append(dependency["task_id"])
                normalized_ids = tuple(sorted(dict.fromkeys(dependency_ids)))
                current_dependencies = self._dependency_ids(conn, row["task_id"])
                if (
                    row["attempt_count"] > 0
                    and current_dependencies != normalized_ids
                ):
                    raise MissionStoreError(
                        "cannot change dependencies after a task has started"
                    )
                if current_dependencies and current_dependencies != normalized_ids:
                    raise MissionStoreError(
                        "task dependencies conflict with the persisted definition"
                    )
                if not current_dependencies and normalized_ids:
                    self._set_dependencies(
                        conn,
                        mission_id,
                        row["task_id"],
                        normalized_ids,
                    )

            for raw_agent, raw_task, task_key, _, _, _, _ in prepared:
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

            return tuple(
                self._task_from_row(conn, rows_by_key[task_key])
                for _, _, task_key, _, _, _, _ in prepared
            )

    def begin_attempt(self, mission_id: str, agent: str, task: str) -> TaskAttemptRecord:
        raw_agent = str(agent or "")
        raw_task = str(task or "")
        if not raw_agent or not raw_task:
            raise MissionStoreError("agent and task are required")
        task_key = self._task_key(raw_agent, raw_task)
        now = time.time()

        with self._transaction() as conn:
            self._require_running_mission(conn, mission_id)
            task_row = conn.execute(
                """
                SELECT * FROM mission_tasks
                WHERE mission_id = ? AND task_key = ?
                """,
                (mission_id, task_key),
            ).fetchone()
            if task_row is None:
                raise MissionStoreError("task must be registered before an attempt begins")

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
                raise MissionStoreError(
                    f"task {task_row['task_id']} cannot start from {task_row['status']}"
                )
            self._require_dependencies_completed(conn, task_row["task_id"])

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
                    attempt_count = ?
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
    ) -> AttemptCompletionResult:
        """Atomically terminalize an attempt and schedule an eligible retry.

        A failed attempt and its retry grant are committed in one SQLite
        transaction.  Therefore a process crash can observe either the running
        attempt or the fully persisted terminal attempt plus bounded retry
        allowlist, never a failed task that lost an otherwise eligible retry.
        """
        if outcome.status not in _OUTCOME_STATUSES:
            raise MissionStoreError(f"unsupported terminal task status: {outcome.status}")
        normalized_retry_error = (
            self._retry_error_class(retry_error_class)
            if retry_error_class is not None
            else None
        )
        if normalized_retry_error is not None and outcome.status != TaskStatus.FAILED.value:
            raise MissionStoreError("only failed task attempts can request a retry")
        safe_retry_keys = self._safe_retry_command_keys(retry_command_keys)
        raw_execution_ids = tuple(
            dict.fromkeys(str(item) for item in execution_ids if str(item))
        )
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
            if (
                task_row is None
                or task_row["task_key"] != self._task_key(outcome.agent, outcome.task)
            ):
                raise MissionStoreError(
                    "task outcome identity does not match the persisted attempt"
                )
            if (
                row["status"] != TaskStatus.RUNNING.value
                and row["outcome_key"] == completion_key
            ):
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
                dict.fromkeys(
                    (*self._load_string_tuple(row["execution_ids_json"]), *requested_execution_ids)
                )
            )
            merged_fact_ids = tuple(
                dict.fromkeys(
                    (*self._load_int_tuple(row["fact_ids_json"]), *requested_fact_ids)
                )
            )
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
                raise MissionStoreError(
                    f"attempt {attempt_id} already ended as {row['status']}"
                )

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
                retryable = self._load_retry_error_classes(
                    task_row["retryable_error_classes_json"]
                )
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
                    conn.execute(
                        """
                        UPDATE mission_tasks
                        SET status = 'pending', reason = '', reason_key = '',
                            updated_at = ?, finished_at = NULL,
                            retry_count = ?, last_error_class = ?
                        WHERE task_id = ? AND status = 'failed'
                        """,
                        (
                            now,
                            next_retry,
                            normalized_retry_error.value,
                            row["task_id"],
                        ),
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
        task_key = self._task_key(raw_agent, raw_task)
        now = time.time()

        with self._transaction() as conn:
            self._require_running_mission(conn, mission_id)
            task_row = conn.execute(
                """
                SELECT * FROM mission_tasks
                WHERE mission_id = ? AND task_key = ?
                """,
                (mission_id, task_key),
            ).fetchone()
            if task_row is None:
                raise MissionStoreError("task must be registered before it can retry")

            if (
                task_row["status"] == TaskStatus.PENDING.value
                and int(task_row["retry_count"]) > 0
                and task_row["last_error_class"] == normalized_error.value
            ):
                return self._task_from_row(conn, task_row)
            if task_row["status"] != TaskStatus.FAILED.value:
                raise TaskRetryError(
                    f"task {task_row['task_id']} cannot retry from "
                    f"{task_row['status']}"
                )

            retryable = self._load_retry_error_classes(
                task_row["retryable_error_classes_json"]
            )
            if normalized_error not in retryable:
                raise TaskRetryNotAllowed(
                    f"{normalized_error.value} is not retryable for "
                    f"task {task_row['task_id']}"
                )
            retry_count = int(task_row["retry_count"])
            retry_budget = int(task_row["retry_budget"])
            if retry_count >= retry_budget:
                raise TaskRetryBudgetExhausted(
                    f"retry budget exhausted for task {task_row['task_id']}: "
                    f"{retry_count}/{retry_budget}"
                )

            conn.execute(
                """
                UPDATE mission_tasks
                SET status = 'pending', reason = '', reason_key = '',
                    updated_at = ?, finished_at = NULL,
                    retry_count = ?, last_error_class = ?
                WHERE task_id = ? AND status = 'failed'
                """,
                (
                    now,
                    retry_count + 1,
                    normalized_error.value,
                    task_row["task_id"],
                ),
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
    ) -> tuple[str, ...]:
        """Return the unconsumed allowlist for a task's current retry number."""
        task_key = self._task_key(str(agent or ""), str(task or ""))
        with self._connection() as conn:
            row = conn.execute(
                """
                SELECT * FROM mission_tasks
                WHERE mission_id = ? AND task_key = ?
                """,
                (mission_id, task_key),
            ).fetchone()
            if row is None:
                raise MissionStoreError("unknown mission task")
            return self._retry_command_keys_for_row(conn, row, pending_only=True)

    def consume_retry_command(
        self,
        mission_id: str,
        agent: str,
        task: str,
        command_key: str,
    ) -> bool:
        """Atomically consume one current retry grant before dispatch."""
        safe_keys = self._safe_retry_command_keys((command_key,))
        if not safe_keys:
            return False
        task_key = self._task_key(str(agent or ""), str(task or ""))
        now = time.time()
        with self._transaction() as conn:
            self._require_running_mission(conn, mission_id)
            row = conn.execute(
                """
                SELECT * FROM mission_tasks
                WHERE mission_id = ? AND task_key = ?
                """,
                (mission_id, task_key),
            ).fetchone()
            if row is None:
                raise MissionStoreError("unknown mission task")
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
                raise MissionStoreError(
                    f"attempt {attempt_id} is not running: {row['status']}"
                )
            mission = self._require_running_mission(conn, row["mission_id"])
            execution_values = tuple(
                dict.fromkeys(
                    (*self._load_string_tuple(row["execution_ids_json"]), *requested_execution_ids)
                )
            )
            fact_values = tuple(
                dict.fromkeys(
                    (*self._load_int_tuple(row["fact_ids_json"]), *requested_fact_ids)
                )
            )
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
    ) -> TaskAttemptRecord:
        """Terminally block a registered task without opening a running attempt."""
        return self._terminalize_unstarted_task(
            mission_id,
            agent,
            task,
            TaskStatus.BLOCKED.value,
            reason,
        )

    def skip_task(
        self,
        mission_id: str,
        agent: str,
        task: str,
        reason: str,
    ) -> TaskAttemptRecord:
        """Terminally skip a registered task without opening a running attempt."""
        return self._terminalize_unstarted_task(
            mission_id,
            agent,
            task,
            TaskStatus.SKIPPED.value,
            reason,
        )

    def _terminalize_unstarted_task(
        self,
        mission_id: str,
        agent: str,
        task: str,
        status: str,
        reason: str,
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
        task_key = self._task_key(raw_agent, raw_task)
        now = time.time()
        with self._transaction() as conn:
            self._require_running_mission(conn, mission_id)
            task_row = conn.execute(
                """
                SELECT * FROM mission_tasks
                WHERE mission_id = ? AND task_key = ?
                """,
                (mission_id, task_key),
            ).fetchone()
            if task_row is None:
                raise MissionStoreError("task must be registered before it can be blocked")
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
                or (
                    not existing["reason_key"]
                    and existing["reason"] == safe_reason
                )
            ):
                return task_row, existing
            raise MissionStoreError(
                f"task is already {status} for another reason"
            )
        if task_row["status"] not in _RETRYABLE_TASK_STATUSES:
            raise MissionStoreError(
                f"task {task_row['task_id']} cannot become {status} "
                f"from {task_row['status']}"
            )
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
                raise MissionStoreError(
                    f"mission cannot complete from {row['status']}"
                )
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
                raise MissionStoreError(
                    "mission has unfinished task "
                    f"{unfinished['task_id']}:{unfinished['status']}"
                )
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
                    tasks=tuple(
                        self._task_from_row(conn, row) for row in task_rows
                    ),
                    attempts=tuple(
                        self._attempt_from_row(row) for row in attempt_rows
                    ),
                )
            finally:
                conn.rollback()

    def _interrupt_running_work(
        self,
        conn: sqlite3.Connection,
        mission_id: str,
        reason: str,
        now: float,
        reason_key: str,
    ) -> None:
        conn.execute(
            """
            UPDATE mission_task_attempts
            SET status = 'interrupted', reason = ?, reason_key = ?, finished_at = ?
            WHERE mission_id = ? AND status = 'running'
            """,
            (reason, reason_key, now, mission_id),
        )
        conn.execute(
            """
            UPDATE mission_tasks
            SET status = 'interrupted', reason = ?, reason_key = ?,
                updated_at = ?, finished_at = ?
            WHERE mission_id = ? AND status = 'running'
            """,
            (reason, reason_key, now, now, mission_id),
        )

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
            raise MissionStoreError(
                f"mission {mission_id} is not running: {row['status']}"
            )
        self._require_owner(row)
        return row

    def _require_running_mission(
        self,
        conn: sqlite3.Connection,
        mission_id: str,
    ) -> sqlite3.Row:
        row = self._require_mission(conn, mission_id)
        if row["status"] != MissionStatus.RUNNING.value:
            raise MissionStoreError(
                f"mission {mission_id} is not running: {row['status']}"
            )
        self._require_owner(row)
        return row

    def _require_owner(self, row: sqlite3.Row) -> None:
        if row["owner_id"] != self._owner_id:
            raise MissionStoreError("mission owner changed; stale writer is fenced")

    def _prepare_task_metadata(
        self,
        scope: str | None,
        capability: str | None,
        retry_policy: TaskRetryPolicy | None,
    ) -> dict[str, Any]:
        if retry_policy is not None and not isinstance(retry_policy, TaskRetryPolicy):
            raise MissionStoreError("retry_policy must be a TaskRetryPolicy")

        raw_scope = None if scope is None else str(scope)
        raw_capability = None if capability is None else str(capability)
        safe_scope = (
            ""
            if raw_scope is None
            else self._safe_text(
                raw_scope,
                "mission_task_scope",
                _MAX_IDENTIFIER_BYTES,
            )
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
        policy = retry_policy or TaskRetryPolicy()
        retryable_json = self._encode_retry_error_classes(
            policy.retryable_error_classes
        )
        policy_payload = {
            "retry_budget": policy.retry_budget,
            "retryable_error_classes": [
                item.value for item in policy.retryable_error_classes
            ],
        }
        return {
            "scope": safe_scope,
            "scope_key": (
                None
                if raw_scope is None
                else self._stable_key("mission_task_scope", raw_scope)
            ),
            "capability": safe_capability,
            "capability_key": (
                None
                if raw_capability is None
                else self._stable_key("mission_task_capability", raw_capability)
            ),
            "retry_budget": policy.retry_budget,
            "retryable_error_classes_json": retryable_json,
            "retry_policy_key": (
                None
                if retry_policy is None
                else self._stable_payload_key("mission_task_retry_policy", policy_payload)
            ),
        }

    def _reconcile_task_metadata(
        self,
        conn: sqlite3.Connection,
        row: sqlite3.Row,
        requested: Mapping[str, Any],
    ) -> sqlite3.Row:
        updates: dict[str, Any] = {}
        for field_name in ("scope", "capability"):
            requested_key = requested[f"{field_name}_key"]
            if requested_key is None:
                continue
            current_key = row[f"{field_name}_key"]
            current_value = row[field_name]
            requested_value = requested[field_name]
            if current_key and current_key != requested_key:
                raise MissionStoreError(
                    f"task {field_name} conflicts with the persisted definition"
                )
            if not current_key and current_value and current_value != requested_value:
                raise MissionStoreError(
                    f"task {field_name} conflicts with the persisted definition"
                )
            if not current_key:
                updates[field_name] = requested_value
                updates[f"{field_name}_key"] = requested_key

        requested_policy_key = requested["retry_policy_key"]
        if requested_policy_key is not None:
            current_policy_key = row["retry_policy_key"]
            current_classes = self._load_retry_error_classes(
                row["retryable_error_classes_json"]
            )
            requested_classes = self._load_retry_error_classes(
                requested["retryable_error_classes_json"]
            )
            same_policy = (
                int(row["retry_budget"]) == int(requested["retry_budget"])
                and current_classes == requested_classes
            )
            if current_policy_key and current_policy_key != requested_policy_key:
                raise MissionStoreError(
                    "task retry policy conflicts with the persisted definition"
                )
            if not current_policy_key and (
                int(row["retry_budget"]) or current_classes
            ) and not same_policy:
                raise MissionStoreError(
                    "task retry policy conflicts with the persisted definition"
                )
            if not current_policy_key:
                updates["retry_budget"] = int(requested["retry_budget"])
                updates["retryable_error_classes_json"] = requested[
                    "retryable_error_classes_json"
                ]
                updates["retry_policy_key"] = requested_policy_key

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
                raise MissionStoreError(
                    f"unknown dependency {dependency_id!r} for mission {mission_id}"
                )
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
            raise TaskDependenciesIncomplete(
                tuple((row["task_id"], row["status"]) for row in incomplete)
            )

    def _stable_key(self, kind: str, value: str) -> str:
        secret_store = getattr(self.redactor, "store", None)
        keyed_digest = getattr(secret_store, "keyed_digest", None)
        if not callable(keyed_digest):
            raise MissionStoreError(
                "mission redactor must provide a keyed identity digest"
            )
        return str(keyed_digest(value, kind=f"mission:{kind}"))

    def _stable_payload_key(self, kind: str, value: Any) -> str:
        encoded = json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            default=str,
        )
        return self._stable_key(kind, encoded)

    @staticmethod
    def _task_key(agent: str, task: str) -> str:
        payload = json.dumps(
            ["task", agent, task],
            separators=(",", ":"),
            ensure_ascii=False,
        )
        return hashlib.sha256(payload.encode("utf-8", "replace")).hexdigest()

    def _safe_text(self, value: Any, kind: str, limit: int) -> str:
        text = str(value or "")
        if self.redactor is not None:
            try:
                text = str(self.redactor.redact_text(text, kind=kind))
            except TypeError:
                text = str(self.redactor.redact_text(text))
        encoded = text.encode("utf-8", "replace")
        if len(encoded) > limit:
            digest = hashlib.sha256(encoded).hexdigest()[:16]
            suffix = f"~sha256:{digest}".encode()
            prefix_limit = max(0, limit - len(suffix))
            prefix = encoded[:prefix_limit].decode("utf-8", "ignore")
            return prefix + suffix.decode()
        return text

    def _safe_data(self, value: Any) -> Any:
        if self.redactor is None:
            return value
        try:
            return self.redactor.redact_data(value, field="mission_task_outcome")
        except TypeError:
            return self.redactor.redact_data(value)

    def _safe_execution_ids(self, values: Sequence[str]) -> tuple[str, ...]:
        return tuple(
            dict.fromkeys(
                self._safe_text(item, "mission_execution_id", _MAX_IDENTIFIER_BYTES)
                for item in values
                if str(item)
            )
        )

    def _safe_retry_command_keys(self, values: Sequence[str]) -> tuple[str, ...]:
        keys = tuple(
            dict.fromkeys(
                self._safe_text(item, "mission_retry_command", _MAX_IDENTIFIER_BYTES)
                for item in values
                if str(item).strip()
            )
        )
        if len(keys) > _MAX_RETRY_COMMAND_KEYS:
            raise MissionStoreError(
                f"retry command allowlist exceeds {_MAX_RETRY_COMMAND_KEYS} keys"
            )
        return keys

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

    @staticmethod
    def _safe_fact_ids(values: Sequence[int]) -> tuple[int, ...]:
        result: list[int] = []
        for item in values:
            try:
                fact_id = int(item)
            except (TypeError, ValueError) as exc:
                raise MissionStoreError("fact ids must be integers") from exc
            if fact_id < 1:
                raise MissionStoreError("fact ids must be positive")
            result.append(fact_id)
        return tuple(dict.fromkeys(result))

    def _safe_outcome(
        self,
        outcome: TaskOutcome,
        *,
        agent: str,
        task: str,
    ) -> TaskOutcome:
        raw_commands = [dict(command) for command in outcome.commands]
        commands = self._safe_data(raw_commands)
        if not isinstance(commands, list):
            raise MissionStoreError("redacted task commands must remain a list")
        return TaskOutcome(
            agent=agent,
            task=task,
            status=outcome.status,
            reason=self._safe_text(
                outcome.reason,
                "mission_task_reason",
                _MAX_REASON_BYTES,
            ),
            new_facts=int(outcome.new_facts),
            parsed_facts=int(outcome.parsed_facts),
            commands=tuple(
                dict(command) if isinstance(command, Mapping) else {"value": str(command)}
                for command in commands
            ),
            duration=float(outcome.duration),
        )

    @staticmethod
    def _encode_outcome(outcome: TaskOutcome) -> str:
        encoded = json.dumps(
            outcome.to_legacy_dict(),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        )
        if len(encoded.encode("utf-8", "replace")) > _MAX_OUTCOME_BYTES:
            raise MissionStoreError("task outcome exceeds the durable payload limit")
        return encoded

    @staticmethod
    def _decode_outcome(value: str) -> TaskOutcome | None:
        if not value:
            return None
        try:
            payload = json.loads(value)
        except (TypeError, ValueError, json.JSONDecodeError) as exc:
            raise MissionStoreError("corrupt persisted task outcome") from exc
        if not isinstance(payload, Mapping):
            raise MissionStoreError("corrupt persisted task outcome")
        commands = []
        for raw_command in payload.get("commands") or ():
            command = dict(raw_command) if isinstance(raw_command, Mapping) else {"value": str(raw_command)}
            fact_pairs = command.get("fact_pairs")
            if isinstance(fact_pairs, list):
                command["fact_pairs"] = [
                    tuple(item) if isinstance(item, list) and len(item) == 2 else item
                    for item in fact_pairs
                ]
            commands.append(command)
        return TaskOutcome(
            agent=str(payload.get("agent", "")),
            task=str(payload.get("task", "")),
            status=str(payload.get("status", "")),
            reason=str(payload.get("reason", "")),
            new_facts=int(payload.get("new_facts", 0) or 0),
            parsed_facts=int(payload.get("parsed_facts", 0) or 0),
            commands=tuple(commands),
            duration=float(payload.get("duration", 0.0) or 0.0),
        )

    @staticmethod
    def _load_string_tuple(value: str) -> tuple[str, ...]:
        try:
            loaded = json.loads(value or "[]")
        except (TypeError, ValueError, json.JSONDecodeError):
            return ()
        return tuple(str(item) for item in loaded) if isinstance(loaded, list) else ()

    @staticmethod
    def _load_int_tuple(value: str) -> tuple[int, ...]:
        try:
            loaded = json.loads(value or "[]")
        except (TypeError, ValueError, json.JSONDecodeError):
            return ()
        if not isinstance(loaded, list):
            return ()
        result = []
        for item in loaded:
            try:
                result.append(int(item))
            except (TypeError, ValueError):
                continue
        return tuple(result)

    @staticmethod
    def _retry_error_class(value: RetryErrorClass | str) -> RetryErrorClass:
        try:
            return (
                value
                if isinstance(value, RetryErrorClass)
                else RetryErrorClass(str(value))
            )
        except ValueError as exc:
            raise TaskRetryNotAllowed(f"unsupported retry error class: {value}") from exc

    @staticmethod
    def _encode_retry_error_classes(
        values: Sequence[RetryErrorClass],
    ) -> str:
        return json.dumps(
            [item.value for item in values],
            separators=(",", ":"),
        )

    @staticmethod
    def _load_retry_error_classes(value: str) -> tuple[RetryErrorClass, ...]:
        try:
            loaded = json.loads(value or "[]")
            if not isinstance(loaded, list):
                raise TypeError("retry error classes must be a list")
            return tuple(
                dict.fromkeys(RetryErrorClass(str(item)) for item in loaded)
            )
        except (TypeError, ValueError, json.JSONDecodeError) as exc:
            raise MissionStoreError("invalid persisted retry error classes") from exc

    @staticmethod
    def _mission_from_row(row: sqlite3.Row) -> MissionRecord:
        return MissionRecord(
            mission_id=row["mission_id"],
            scan_id=row["scan_id"],
            target=row["target"],
            status=row["status"],
            reason=row["reason"],
            created_at=float(row["created_at"]),
            updated_at=float(row["updated_at"]),
            started_at=float(row["started_at"]),
            finished_at=float(row["finished_at"]) if row["finished_at"] is not None else None,
            run_count=int(row["run_count"]),
            schema_version=row["schema_version"],
        )

    def _task_from_row(self, conn: sqlite3.Connection, row: sqlite3.Row) -> TaskRecord:
        return TaskRecord(
            task_id=row["task_id"],
            mission_id=row["mission_id"],
            agent=row["agent"],
            task=row["task"],
            status=row["status"],
            reason=row["reason"],
            depends_on=self._dependency_ids(conn, row["task_id"]),
            created_at=float(row["created_at"]),
            updated_at=float(row["updated_at"]),
            started_at=float(row["started_at"]) if row["started_at"] is not None else None,
            finished_at=float(row["finished_at"]) if row["finished_at"] is not None else None,
            attempt_count=int(row["attempt_count"]),
            scope=row["scope"],
            capability=row["capability"],
            retry_budget=int(row["retry_budget"]),
            retry_count=int(row["retry_count"]),
            retryable_error_classes=self._load_retry_error_classes(
                row["retryable_error_classes_json"]
            ),
            last_error_class=(
                self._retry_error_class(row["last_error_class"])
                if row["last_error_class"]
                else None
            ),
        )

    def _attempt_from_row(self, row: sqlite3.Row) -> TaskAttemptRecord:
        return TaskAttemptRecord(
            attempt_id=row["attempt_id"],
            task_id=row["task_id"],
            mission_id=row["mission_id"],
            attempt_number=int(row["attempt_number"]),
            status=row["status"],
            reason=row["reason"],
            started_at=float(row["started_at"]),
            finished_at=float(row["finished_at"]) if row["finished_at"] is not None else None,
            outcome=self._decode_outcome(row["outcome_json"]),
            execution_ids=self._load_string_tuple(row["execution_ids_json"]),
            fact_ids=self._load_int_tuple(row["fact_ids_json"]),
        )


__all__ = [
    "MISSION_LIFECYCLE_SCHEMA_VERSION",
    "AttemptCompletionResult",
    "MissionRecord",
    "MissionSnapshot",
    "MissionStatus",
    "MissionStore",
    "MissionStoreError",
    "MissionTaskDefinition",
    "RetryErrorClass",
    "TaskAttemptRecord",
    "TaskDependenciesIncomplete",
    "TaskRecord",
    "TaskRetryBudgetExhausted",
    "TaskRetryError",
    "TaskRetryNotAllowed",
    "TaskRetryPolicy",
    "TaskStatus",
]
