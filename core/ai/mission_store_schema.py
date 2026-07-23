"""MissionStore SQLite schema creation and in-place migrations."""

from __future__ import annotations

import sqlite3
import time

from core.ai.mission_store_models import (
    _MIGRATABLE_SCHEMA_VERSIONS,
    MISSION_LIFECYCLE_SCHEMA_VERSION,
    TASK_DEFINITION_SCHEMA_VERSION,
    MissionStoreError,
    TaskBackoff,
    TaskScope,
    canonical_capability_id,
)

# Mixin methods intentionally depend on the composed store's connection and
# codec APIs; keeping the dependency structural avoids a runtime import cycle.
# mypy: disable-error-code="attr-defined"


class MissionStoreSchemaMixin:
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
                time.sleep(min(0.01 * (2**attempt), 0.25))
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
                    raise MissionStoreError(f"unsupported mission lifecycle schema version: {existing['version']}")
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
                        state_replan_count INTEGER NOT NULL DEFAULT 0,
                        state_replan_signatures_json TEXT NOT NULL DEFAULT '[]',
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
                        task_compat_key TEXT NOT NULL DEFAULT '',
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
                        task_scope_json TEXT NOT NULL DEFAULT '',
                        task_scope_key TEXT NOT NULL DEFAULT '',
                        capability TEXT NOT NULL DEFAULT '',
                        capability_key TEXT NOT NULL DEFAULT '',
                        capability_id TEXT NOT NULL DEFAULT '',
                        capability_id_key TEXT NOT NULL DEFAULT '',
                        task_definition_version TEXT NOT NULL DEFAULT '1.0',
                        retry_budget INTEGER NOT NULL DEFAULT 0,
                        retry_count INTEGER NOT NULL DEFAULT 0,
                        retryable_error_classes_json TEXT NOT NULL DEFAULT '[]',
                        retry_policy_key TEXT NOT NULL DEFAULT '',
                        last_error_class TEXT NOT NULL DEFAULT '',
                        not_before REAL,
                        backoff_json TEXT NOT NULL DEFAULT '{}',
                        backoff_key TEXT NOT NULL DEFAULT '',
                        provider_circuit_ref TEXT NOT NULL DEFAULT '',
                        provider_circuit_ref_key TEXT NOT NULL DEFAULT '',
                        evaluated_snapshot_ref TEXT NOT NULL DEFAULT '',
                        evaluated_snapshot_ref_key TEXT NOT NULL DEFAULT '',
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
                    CREATE TABLE IF NOT EXISTS mission_evaluated_fact_snapshots (
                        mission_id TEXT NOT NULL,
                        snapshot_ref TEXT NOT NULL,
                        payload_json TEXT NOT NULL,
                        created_at REAL NOT NULL,
                        PRIMARY KEY(mission_id, snapshot_ref),
                        FOREIGN KEY(mission_id) REFERENCES missions(mission_id)
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
                conn.execute(
                    """
                    CREATE INDEX IF NOT EXISTS idx_mission_evaluated_snapshots_ref
                    ON mission_evaluated_fact_snapshots(snapshot_ref)
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
                    "missions",
                    "state_replan_count",
                    "INTEGER NOT NULL DEFAULT 0",
                )
                self._ensure_column(
                    conn,
                    "missions",
                    "state_replan_signatures_json",
                    "TEXT NOT NULL DEFAULT '[]'",
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
                    "task_compat_key",
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
                    "task_scope_json",
                    "TEXT NOT NULL DEFAULT ''",
                )
                self._ensure_column(
                    conn,
                    "mission_tasks",
                    "task_scope_key",
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
                    "capability_id",
                    "TEXT NOT NULL DEFAULT ''",
                )
                self._ensure_column(
                    conn,
                    "mission_tasks",
                    "capability_id_key",
                    "TEXT NOT NULL DEFAULT ''",
                )
                self._ensure_column(
                    conn,
                    "mission_tasks",
                    "task_definition_version",
                    f"TEXT NOT NULL DEFAULT '{TASK_DEFINITION_SCHEMA_VERSION}'",
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
                    "mission_tasks",
                    "not_before",
                    "REAL",
                )
                self._ensure_column(
                    conn,
                    "mission_tasks",
                    "backoff_json",
                    "TEXT NOT NULL DEFAULT '{}'",
                )
                self._ensure_column(
                    conn,
                    "mission_tasks",
                    "backoff_key",
                    "TEXT NOT NULL DEFAULT ''",
                )
                self._ensure_column(
                    conn,
                    "mission_tasks",
                    "provider_circuit_ref",
                    "TEXT NOT NULL DEFAULT ''",
                )
                self._ensure_column(
                    conn,
                    "mission_tasks",
                    "provider_circuit_ref_key",
                    "TEXT NOT NULL DEFAULT ''",
                )
                self._ensure_column(
                    conn,
                    "mission_tasks",
                    "evaluated_snapshot_ref",
                    "TEXT NOT NULL DEFAULT ''",
                )
                self._ensure_column(
                    conn,
                    "mission_tasks",
                    "evaluated_snapshot_ref_key",
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
                self._migrate_task_identity_rows(conn)
                conn.execute(
                    """
                    CREATE UNIQUE INDEX IF NOT EXISTS idx_missions_scan_key
                    ON missions(scan_key)
                    """
                )
                conn.execute(
                    """
                    CREATE INDEX IF NOT EXISTS idx_mission_tasks_compat
                    ON mission_tasks(mission_id, task_compat_key)
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
                if current is None or current["version"] != MISSION_LIFECYCLE_SCHEMA_VERSION:
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
        columns = {row["name"] for row in conn.execute(f"PRAGMA table_info({table})").fetchall()}
        if column not in columns:
            conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")

    def _migrate_task_identity_rows(self, conn: sqlite3.Connection) -> None:
        """Backfill the 1.4 task-definition identity without losing task IDs."""

        rows = conn.execute("SELECT * FROM mission_tasks ORDER BY task_id").fetchall()
        for row in rows:
            compat_key = row["task_compat_key"] or row["task_key"]
            raw_scope = str(row["scope"] or "")
            legacy_scope_key = row["scope_key"] or (
                self._stable_key("mission_task_scope", raw_scope) if raw_scope else ""
            )
            if row["task_scope_json"]:
                task_scope = self._decode_task_scope(row["task_scope_json"])
            else:
                task_scope = TaskScope.from_legacy(raw_scope)
            scope_json = self._encode_task_scope(task_scope)
            scope_identity_key = row["task_scope_key"] or self._task_scope_key(
                task_scope,
                legacy_scope_key=legacy_scope_key,
            )
            definition_version = self._task_definition_version(
                row["task_definition_version"] or TASK_DEFINITION_SCHEMA_VERSION
            )
            task_key = self._task_identity_key(
                compat_key,
                scope_identity_key,
                definition_version,
            )
            capability_id = str(row["capability_id"] or "")
            if not capability_id and row["capability"]:
                capability_id = canonical_capability_id(str(row["capability"]))
            capability_id_key = str(row["capability_id_key"] or "")
            if capability_id and not capability_id_key:
                capability_id_key = self._stable_key(
                    "mission_task_capability_id",
                    capability_id,
                )
            backoff_json = str(row["backoff_json"] or "")
            if not backoff_json:
                backoff_json = self._encode_backoff(TaskBackoff())
            else:
                # Validate persisted typed state before advancing the version.
                self._decode_backoff(backoff_json)
            try:
                conn.execute(
                    """
                    UPDATE mission_tasks
                    SET task_key = ?, task_compat_key = ?, scope_key = ?,
                        task_scope_json = ?, task_scope_key = ?,
                        capability_id = ?, capability_id_key = ?,
                        task_definition_version = ?, backoff_json = ?
                    WHERE task_id = ?
                    """,
                    (
                        task_key,
                        compat_key,
                        legacy_scope_key,
                        scope_json,
                        scope_identity_key,
                        capability_id,
                        capability_id_key,
                        definition_version,
                        backoff_json,
                        row["task_id"],
                    ),
                )
            except sqlite3.IntegrityError as exc:
                raise MissionStoreError("task identity collision while migrating mission schema 1.4") from exc
