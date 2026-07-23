"""Architecture and persistence parity tests for the MissionStore split."""

from __future__ import annotations

import pickle
import sqlite3

import pytest

from core.ai import mission_store
from core.ai.mission_store_codecs import MissionStoreCodecMixin
from core.ai.mission_store_maintenance import MissionStoreMaintenanceMixin
from core.ai.mission_store_replans import MissionStoreReplanRepositoryMixin
from core.ai.mission_store_schema import MissionStoreSchemaMixin
from core.ai.mission_store_tasks import MissionTaskRepositoryMixin

pytestmark = pytest.mark.contract


def _schema_signature(path) -> tuple[tuple[str, str], ...]:
    with sqlite3.connect(path) as conn:
        return tuple(
            conn.execute(
                """
                SELECT type, name FROM sqlite_master
                WHERE name LIKE 'mission%'
                ORDER BY type, name
                """
            ).fetchall()
        )


def test_public_store_composes_focused_persistence_layers():
    assert issubclass(mission_store.MissionStore, MissionStoreSchemaMixin)
    assert issubclass(mission_store.MissionStore, MissionTaskRepositoryMixin)
    assert issubclass(mission_store.MissionStore, MissionStoreReplanRepositoryMixin)
    assert issubclass(mission_store.MissionStore, MissionStoreCodecMixin)
    assert issubclass(mission_store.MissionStore, MissionStoreMaintenanceMixin)

    expected = {
        "MissionStore",
        "MissionStoreError",
        "MissionTaskDefinition",
        "MissionSnapshot",
        "TaskScope",
        "TaskRetryPolicy",
        "TaskBackoff",
        "canonical_capability_id",
    }
    assert expected <= set(mission_store.__all__)
    assert mission_store.TaskScope.__module__ == "core.ai.mission_store"
    assert mission_store.MissionRecord.__module__ == "core.ai.mission_store"
    scope = mission_store.TaskScope.from_legacy("compatibility-scope")
    assert pickle.loads(pickle.dumps(scope)) == scope


def test_reopen_preserves_schema_and_public_records(tmp_path):
    path = tmp_path / "missions.db"
    first = mission_store.MissionStore(str(path), owner_id="owner-one")
    mission = first.open_mission("scan-decomposition", "192.0.2.44")
    task = first.register_task(mission.mission_id, "recon", "inventory")
    attempt = first.begin_attempt(mission.mission_id, "recon", "inventory")
    first.record_attempt_progress(
        attempt.attempt_id,
        execution_ids=("execution-1",),
        fact_ids=(1,),
    )
    before = first.snapshot(mission.mission_id)
    schema_before = _schema_signature(path)
    first.close()

    reopened = mission_store.MissionStore(str(path), owner_id="owner-two")
    reopened.open_mission(
        "scan-decomposition",
        "192.0.2.44",
        recover=True,
    )
    after = reopened.snapshot(mission.mission_id)
    schema_after = _schema_signature(path)

    assert before.mission.mission_id == after.mission.mission_id
    assert before.tasks[0].task_id == task.task_id == after.tasks[0].task_id
    assert before.attempts[0].attempt_id == after.attempts[0].attempt_id
    assert after.attempts[0].execution_ids == ("execution-1",)
    assert after.attempts[0].fact_ids == (1,)
    assert after.tasks[0].status == "interrupted"
    assert after.attempts[0].status == "interrupted"
    assert schema_before == schema_after
    reopened.close()


def test_schema_version_migration_survives_reopen(tmp_path):
    path = tmp_path / "legacy.db"
    seed = mission_store.MissionStore(str(path))
    mission = seed.open_mission("scan-migrate", "example.test")
    seed.close()

    with sqlite3.connect(path) as conn:
        conn.execute(
            """
            UPDATE mission_lifecycle_schema SET version = '1.0'
            WHERE component = 'mission_store'
            """
        )
        conn.execute(
            "UPDATE missions SET schema_version = '1.0' WHERE mission_id = ?",
            (mission.mission_id,),
        )

    migrated = mission_store.MissionStore(str(path))
    snapshot = migrated.snapshot(mission.mission_id)
    with sqlite3.connect(path) as conn:
        version = conn.execute(
            """
            SELECT version FROM mission_lifecycle_schema
            WHERE component = 'mission_store'
            """
        ).fetchone()[0]

    assert version == mission_store.MISSION_LIFECYCLE_SCHEMA_VERSION
    assert snapshot.mission.schema_version == mission_store.MISSION_LIFECYCLE_SCHEMA_VERSION
    migrated.close()
