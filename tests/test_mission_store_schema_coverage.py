"""Retry, race, and migration edge coverage for MissionStore schema setup."""

from __future__ import annotations

import sqlite3

import pytest

import core.ai.mission_store_schema as schema_module
from core.ai.mission_store import MissionStore
from core.ai.mission_store_models import MissionStoreError
from core.ai.mission_store_schema import MissionStoreSchemaMixin

pytestmark = pytest.mark.contract


def test_schema_init_retries_lock_and_propagates_nonlock_errors(monkeypatch):
    class StoreDouble(MissionStoreSchemaMixin):
        def __init__(self, errors):
            self.errors = list(errors)
            self.calls = 0

        def _init_db_once(self):
            self.calls += 1
            if self.errors:
                raise self.errors.pop(0)

    sleeps = []
    monkeypatch.setattr(schema_module.time, "sleep", lambda value: sleeps.append(value))
    retrying = StoreDouble([sqlite3.OperationalError("database is locked")])
    retrying._init_db()
    assert retrying.calls == 2
    assert sleeps == [0.01]

    nonlocking = StoreDouble([sqlite3.OperationalError("disk error")])
    with pytest.raises(sqlite3.OperationalError, match="disk error"):
        nonlocking._init_db()
    assert nonlocking.calls == 1

    exhausted = StoreDouble([sqlite3.OperationalError("database is busy") for _ in range(12)])
    with pytest.raises(sqlite3.OperationalError, match="busy"):
        exhausted._init_db()
    assert exhausted.calls == 12
    assert sleeps[-1] == 0.25


def test_memory_schema_path_and_schema_version_race(monkeypatch):
    store = MissionStore(":memory:")
    assert store._memory_conn is not None

    def delete_schema_row(conn):
        conn.execute("DELETE FROM mission_lifecycle_schema WHERE component = 'mission_store'")

    monkeypatch.setattr(store, "_migrate_task_identity_rows", delete_schema_row)
    with pytest.raises(MissionStoreError, match="schema version race"):
        store._init_db_once()


def test_task_identity_migration_initializes_backoff_and_detects_collision():
    store = MissionStore(":memory:")
    conn = store._memory_conn
    assert conn is not None
    conn.execute(
        """
        INSERT INTO missions(
            mission_id, scan_key, scan_id, target_key, target, status,
            created_at, updated_at, started_at, schema_version
        ) VALUES ('mission', 'scan-key', 'scan', 'target-key', 'target',
                  'running', 1, 1, 1, '1.4')
        """
    )
    for index in (1, 2):
        conn.execute(
            """
            INSERT INTO mission_tasks(
                task_id, mission_id, task_key, task_compat_key,
                agent, task, status, created_at, updated_at, backoff_json
            ) VALUES (?, 'mission', ?, 'shared-compat',
                      'DiscoveryAgent', 'task', 'pending', 1, 1, '')
            """,
            (f"task-{index}", f"legacy-{index}"),
        )
    conn.commit()

    with pytest.raises(MissionStoreError, match="task identity collision"):
        store._migrate_task_identity_rows(conn)
