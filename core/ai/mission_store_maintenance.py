"""Connection, transaction, recovery, and close maintenance helpers."""

from __future__ import annotations

import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any

from core.secrets import SecretStore

# mypy: disable-error-code="attr-defined"


class MissionStoreMaintenanceMixin:
    db_path: str
    _lock: Any
    _memory_conn: sqlite3.Connection | None
    _owned_secret_store: SecretStore | None

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
