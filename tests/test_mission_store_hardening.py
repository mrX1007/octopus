"""Focused hardening regressions for the durable mission lifecycle store."""

import sqlite3
import threading
from concurrent.futures import ThreadPoolExecutor

import pytest

from core.ai.mission_store import (
    MISSION_LIFECYCLE_SCHEMA_VERSION,
    MissionStore,
    MissionStoreError,
)
from core.ai.outcomes import TaskOutcome
from core.secrets import Redactor, SecretStore

pytestmark = pytest.mark.contract


def _outcome(agent: str, task: str, status: str = "completed") -> TaskOutcome:
    return TaskOutcome(
        agent=agent,
        task=task,
        status=status,
        reason="done",
        new_facts=0,
        parsed_facts=0,
        commands=(),
        duration=0.01,
    )


def test_recovery_is_explicit_and_fences_the_stale_owner(tmp_path):
    db_path = tmp_path / "missions.db"
    original = MissionStore(str(db_path), owner_id="owner-original")
    mission = original.open_mission("scan-owner-fence", "10.0.0.5")
    task = original.register_task(
        mission.mission_id,
        "DiscoveryAgent",
        "service_discovery",
    )
    abandoned = original.begin_attempt(
        mission.mission_id,
        "DiscoveryAgent",
        "service_discovery",
    )

    replacement = MissionStore(str(db_path), owner_id="owner-replacement")
    with pytest.raises(MissionStoreError, match="explicit recovery is required"):
        replacement.open_mission("scan-owner-fence", "10.0.0.5")

    before_recovery = original.snapshot(mission.mission_id)
    assert before_recovery.mission.status == "running"
    assert before_recovery.attempts[0].status == "running"

    recovered = replacement.open_mission(
        "scan-owner-fence",
        "10.0.0.5",
        recover=True,
    )
    recovered_snapshot = replacement.snapshot(recovered.mission_id)
    recovered_task = next(
        item for item in recovered_snapshot.tasks if item.task_id == task.task_id
    )
    recovered_attempt = next(
        item
        for item in recovered_snapshot.attempts
        if item.attempt_id == abandoned.attempt_id
    )

    assert recovered.run_count == 2
    assert recovered_task.status == "interrupted"
    assert recovered_attempt.status == "interrupted"

    with pytest.raises(MissionStoreError, match="stale writer is fenced"):
        original.begin_attempt(
            mission.mission_id,
            "DiscoveryAgent",
            "service_discovery",
        )

    retry = replacement.begin_attempt(
        mission.mission_id,
        "DiscoveryAgent",
        "service_discovery",
    )
    with pytest.raises(MissionStoreError, match="stale writer is fenced"):
        original.complete_attempt(
            retry.attempt_id,
            _outcome("DiscoveryAgent", "service_discovery"),
        )

    completed = replacement.complete_attempt(
        retry.attempt_id,
        _outcome("DiscoveryAgent", "service_discovery"),
    )
    assert completed.status == "completed"


def test_complete_mission_rejects_pending_and_interrupted_tasks(tmp_path):
    store = MissionStore(str(tmp_path / "missions.db"), owner_id="owner")
    mission = store.open_mission("scan-unfinished", "10.0.0.5")
    task = store.register_task(
        mission.mission_id,
        "DiscoveryAgent",
        "service_discovery",
    )

    with pytest.raises(MissionStoreError, match=r"unfinished task .*:pending"):
        store.complete_mission(mission.mission_id, "goal_reached")

    store.begin_attempt(
        mission.mission_id,
        "DiscoveryAgent",
        "service_discovery",
    )
    store.interrupt_mission(mission.mission_id, "operator_requested")
    store.open_mission("scan-unfinished", "10.0.0.5")

    interrupted = store.snapshot(mission.mission_id)
    interrupted_task = next(
        item for item in interrupted.tasks if item.task_id == task.task_id
    )
    assert interrupted_task.status == "interrupted"
    with pytest.raises(MissionStoreError, match=r"unfinished task .*:interrupted"):
        store.complete_mission(mission.mission_id, "goal_reached")


def test_redactor_learning_task_and_status_does_not_mutate_control_fields(tmp_path):
    secret_store = SecretStore(":memory:", key=b"mission-hardening-redactor")
    store = MissionStore(
        str(tmp_path / "missions.db"),
        redactor=Redactor(secret_store),
        owner_id="owner",
    )
    task_name = "service_discovery_control_identity"
    mission = store.open_mission("scan-control-fields", "10.0.0.5")
    task = store.register_task(
        mission.mission_id,
        "DiscoveryAgent",
        task_name,
    )
    attempt = store.begin_attempt(
        mission.mission_id,
        "DiscoveryAgent",
        task_name,
    )

    secret_store.store(task_name, kind="learned_task_name")
    secret_store.store("completed", kind="learned_task_status")

    completed = store.complete_attempt(
        attempt.attempt_id,
        _outcome("DiscoveryAgent", task_name),
    )
    hydrated = store.snapshot(mission.mission_id)
    hydrated_task = next(item for item in hydrated.tasks if item.task_id == task.task_id)
    hydrated_attempt = next(
        item for item in hydrated.attempts if item.attempt_id == attempt.attempt_id
    )

    assert completed.status == "completed"
    assert completed.outcome is not None
    assert completed.outcome.task == task_name
    assert completed.outcome.status == "completed"
    assert hydrated_task.task == task_name
    assert hydrated_task.status == "completed"
    assert hydrated_attempt.outcome is not None
    assert hydrated_attempt.outcome.task == task_name
    assert hydrated_attempt.outcome.status == "completed"
    secret_store.close()


def test_scan_and_task_display_truncation_avoids_collisions(tmp_path):
    store = MissionStore(str(tmp_path / "missions.db"), owner_id="owner")
    identifier_limit = 4096
    scan_prefix = "scan-" + ("s" * (identifier_limit + 128))
    raw_scan_one = scan_prefix + "-one"
    raw_scan_two = scan_prefix + "-two"

    mission_one = store.open_mission(raw_scan_one, "10.0.0.5")
    mission_two = store.open_mission(raw_scan_two, "10.0.0.5")

    assert mission_one.mission_id != mission_two.mission_id
    assert mission_one.scan_id != mission_two.scan_id
    assert mission_one.scan_id != raw_scan_one
    assert mission_two.scan_id != raw_scan_two
    assert len(mission_one.scan_id.encode("utf-8")) <= identifier_limit
    assert len(mission_two.scan_id.encode("utf-8")) <= identifier_limit
    assert store.get_mission_by_scan_id(raw_scan_one).mission_id == mission_one.mission_id
    assert store.get_mission_by_scan_id(raw_scan_two).mission_id == mission_two.mission_id

    task_prefix = "task-" + ("t" * (identifier_limit + 128))
    raw_task_one = task_prefix + "-one"
    raw_task_two = task_prefix + "-two"
    task_one = store.register_task(mission_one.mission_id, "DiscoveryAgent", raw_task_one)
    task_two = store.register_task(mission_one.mission_id, "DiscoveryAgent", raw_task_two)

    assert task_one.task_id != task_two.task_id
    assert task_one.task != task_two.task
    assert task_one.task != raw_task_one
    assert task_two.task != raw_task_two
    assert len(task_one.task.encode("utf-8")) <= identifier_limit
    assert len(task_two.task.encode("utf-8")) <= identifier_limit


def test_concurrent_first_time_schema_initialization_is_serialized(tmp_path):
    db_path = tmp_path / "missions.db"
    worker_count = 8
    barrier = threading.Barrier(worker_count)

    def initialize(index):
        barrier.wait(timeout=10)
        store = MissionStore(str(db_path), owner_id=f"initializer-{index}")
        store.close()
        return True

    with ThreadPoolExecutor(max_workers=worker_count) as pool:
        results = tuple(pool.map(initialize, range(worker_count)))

    assert all(results)
    with sqlite3.connect(db_path) as conn:
        tables = {
            row[0]
            for row in conn.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            ).fetchall()
        }
        version = conn.execute(
            """
            SELECT version FROM mission_lifecycle_schema
            WHERE component = 'mission_store'
            """
        ).fetchone()

    assert {
        "mission_lifecycle_schema",
        "missions",
        "mission_tasks",
        "mission_task_dependencies",
        "mission_task_attempts",
    }.issubset(tables)
    assert version == (MISSION_LIFECYCLE_SCHEMA_VERSION,)


def test_v12_migration_adds_backward_compatible_state_replan_state(tmp_path):
    db_path = tmp_path / "missions.db"
    with sqlite3.connect(db_path) as conn:
        conn.execute(
            """
            CREATE TABLE mission_lifecycle_schema (
                component TEXT PRIMARY KEY,
                version TEXT NOT NULL
            )
            """
        )
        conn.execute(
            """
            INSERT INTO mission_lifecycle_schema(component, version)
            VALUES ('mission_store', '1.2')
            """
        )
        conn.execute(
            """
            CREATE TABLE missions (
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
            INSERT INTO missions(
                mission_id, scan_key, scan_id, target_key, target, status,
                owner_id, created_at, updated_at, started_at, run_count,
                schema_version
            ) VALUES (
                'mis-v12', 'scan-key', 'scan-v12', 'target-key', '10.0.0.5',
                'running', 'owner', 1.0, 1.0, 1.0, 1, '1.2'
            )
            """
        )

    store = MissionStore(str(db_path), owner_id="owner")
    migrated = store.snapshot("mis-v12").mission
    assert migrated.state_replan_count == 0
    assert migrated.state_replan_signatures == ()

    reserved = store.record_state_replan("mis-v12", "transition-one", 1)
    assert reserved.requested is True
    duplicate = store.record_state_replan("mis-v12", "transition-one", 1)
    exhausted = store.record_state_replan("mis-v12", "transition-two", 1)
    assert duplicate.requested is False
    assert duplicate.reason == "duplicate_transition"
    assert exhausted.requested is False
    assert exhausted.reason == "budget_exhausted"
    assert exhausted.count == 1
    reopened = MissionStore(str(db_path), owner_id="observer").snapshot(
        "mis-v12"
    ).mission

    with sqlite3.connect(db_path) as conn:
        version = conn.execute(
            """
            SELECT version FROM mission_lifecycle_schema
            WHERE component = 'mission_store'
            """
        ).fetchone()
        columns = {
            row[1] for row in conn.execute("PRAGMA table_info(missions)")
        }

    assert version == (MISSION_LIFECYCLE_SCHEMA_VERSION,)
    assert {
        "state_replan_count",
        "state_replan_signatures_json",
    }.issubset(columns)
    assert reopened.state_replan_count == 1
    assert reopened.state_replan_signatures == (
        "transition-one",
        "transition-two",
    )


def test_unsupported_schema_version_does_not_create_v1_tables(tmp_path):
    db_path = tmp_path / "missions.db"
    unsupported_version = "999.0"
    with sqlite3.connect(db_path) as conn:
        conn.execute(
            """
            CREATE TABLE mission_lifecycle_schema (
                component TEXT PRIMARY KEY,
                version TEXT NOT NULL
            )
            """
        )
        conn.execute(
            """
            INSERT INTO mission_lifecycle_schema(component, version)
            VALUES ('mission_store', ?)
            """,
            (unsupported_version,),
        )

    with pytest.raises(MissionStoreError, match="unsupported mission lifecycle schema"):
        MissionStore(str(db_path))

    with sqlite3.connect(db_path) as conn:
        tables = {
            row[0]
            for row in conn.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            ).fetchall()
        }
        version = conn.execute(
            """
            SELECT version FROM mission_lifecycle_schema
            WHERE component = 'mission_store'
            """
        ).fetchone()

    assert tables == {"mission_lifecycle_schema"}
    assert version == (unsupported_version,)


def test_lossy_legacy_display_keys_are_adopted_by_raw_identity(tmp_path):
    db_path = tmp_path / "missions.db"
    secret_store = SecretStore(":memory:", key=b"mission-legacy-adoption-key")
    store = MissionStore(
        str(db_path),
        redactor=Redactor(secret_store),
        owner_id="owner",
    )
    raw_scan_id = "token=SCAN_ID_SECRET_123456789"
    raw_target = "https://admin:TargetPassword_123456789@10.0.0.5/"
    mission = store.open_mission(raw_scan_id, raw_target)

    with sqlite3.connect(db_path) as conn:
        conn.execute(
            """
            UPDATE missions SET scan_key = ?, target_key = ?
            WHERE mission_id = ?
            """,
            (
                secret_store.keyed_digest(
                    mission.scan_id,
                    kind="mission:scan",
                ),
                secret_store.keyed_digest(
                    mission.target,
                    kind="mission:target",
                ),
                mission.mission_id,
            ),
        )

    adopted = store.open_mission(raw_scan_id, raw_target)

    assert adopted.mission_id == mission.mission_id
    with sqlite3.connect(db_path) as conn:
        keys = conn.execute(
            """
            SELECT scan_key, target_key FROM missions WHERE mission_id = ?
            """,
            (mission.mission_id,),
        ).fetchone()
    assert keys == (
        secret_store.keyed_digest(raw_scan_id, kind="mission:scan"),
        secret_store.keyed_digest(raw_target, kind="mission:target"),
    )

    with sqlite3.connect(db_path) as conn:
        conn.execute(
            "UPDATE missions SET target_key = ? WHERE mission_id = ?",
            (
                secret_store.keyed_digest(
                    adopted.target,
                    kind="mission:target",
                ),
                mission.mission_id,
            ),
        )
    reopened = store.open_mission(raw_scan_id, raw_target)
    assert reopened.mission_id == mission.mission_id
    with sqlite3.connect(db_path) as conn:
        target_key = conn.execute(
            "SELECT target_key FROM missions WHERE mission_id = ?",
            (mission.mission_id,),
        ).fetchone()[0]
    assert target_key == secret_store.keyed_digest(
        raw_target,
        kind="mission:target",
    )
    secret_store.close()


def test_plan_registration_rolls_back_tasks_and_edges_as_one_unit(
    tmp_path,
    monkeypatch,
):
    store = MissionStore(str(tmp_path / "missions.db"), owner_id="owner")
    mission = store.open_mission("scan-atomic-plan", "10.0.0.5")
    original = store._set_dependencies

    def crash_after_dependency_write(conn, mission_id, task_id, dependency_ids):
        original(conn, mission_id, task_id, dependency_ids)
        raise RuntimeError("simulated registration crash")

    monkeypatch.setattr(store, "_set_dependencies", crash_after_dependency_write)
    with pytest.raises(RuntimeError, match="simulated registration crash"):
        store.register_plan(
            mission.mission_id,
            [
                ("DiscoveryAgent", "parent", ()),
                (
                    "DiscoveryAgent",
                    "child",
                    (("DiscoveryAgent", "parent"),),
                ),
            ],
        )

    snapshot = store.snapshot(mission.mission_id)
    assert snapshot.tasks == ()
    assert snapshot.attempts == ()


def test_idempotent_terminal_replays_ignore_later_redactor_learning(tmp_path):
    secret_store = SecretStore(":memory:", key=b"mission-idempotency-key")
    store = MissionStore(
        str(tmp_path / "missions.db"),
        redactor=Redactor(secret_store),
        owner_id="owner",
    )

    mission_reason = "goal_reached_after_assessment"
    empty = store.open_mission("scan-idempotent-mission", "10.0.0.5")
    completed = store.complete_mission(empty.mission_id, mission_reason)
    secret_store.store(mission_reason, kind="learned_mission_reason")
    repeated = store.complete_mission(empty.mission_id, mission_reason)
    assert repeated.mission_id == completed.mission_id

    attempt_reason = "stable_attempt_reason"
    command_secret = "opaque-command-value-123456"
    active = store.open_mission("scan-idempotent-attempt", "10.0.0.6")
    store.register_task(active.mission_id, "DiscoveryAgent", "task-one")
    attempt = store.begin_attempt(
        active.mission_id,
        "DiscoveryAgent",
        "task-one",
    )
    outcome = TaskOutcome(
        agent="DiscoveryAgent",
        task="task-one",
        status="completed",
        reason=attempt_reason,
        new_facts=0,
        parsed_facts=0,
        commands=({"command": command_secret, "failed": False},),
        duration=0.01,
    )
    ended = store.complete_attempt(attempt.attempt_id, outcome)
    secret_store.store(attempt_reason, kind="learned_attempt_reason")
    secret_store.store(command_secret, kind="learned_command")
    replayed = store.complete_attempt(attempt.attempt_id, outcome)
    assert replayed.attempt_id == ended.attempt_id

    block_reason = "stable_block_reason"
    blocked_mission = store.open_mission("scan-idempotent-block", "10.0.0.7")
    store.register_task(
        blocked_mission.mission_id,
        "DiscoveryAgent",
        "task-two",
    )
    blocked = store.block_task(
        blocked_mission.mission_id,
        "DiscoveryAgent",
        "task-two",
        block_reason,
    )
    secret_store.store(block_reason, kind="learned_block_reason")
    blocked_replay = store.block_task(
        blocked_mission.mission_id,
        "DiscoveryAgent",
        "task-two",
        block_reason,
    )
    assert blocked_replay.attempt_id == blocked.attempt_id
    secret_store.close()
