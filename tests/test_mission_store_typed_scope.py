"""Schema 1.4 contracts for scoped mission-task identity and scheduling."""

from __future__ import annotations

import hashlib
import json
import sqlite3
import time

import pytest

from core.ai import mission_store as mission_store_module
from core.ai.mission_store import (
    MISSION_LIFECYCLE_SCHEMA_VERSION,
    TASK_DEFINITION_SCHEMA_VERSION,
    BackoffStrategy,
    MissionStore,
    MissionStoreError,
    MissionTaskDefinition,
    RetryErrorClass,
    TaskBackoff,
    TaskDependencyRef,
    TaskNotReady,
    TaskRetryPolicy,
    TaskScope,
    canonical_capability_id,
)
from core.ai.outcomes import TaskOutcome
from core.knowledge.identity import canonical_asset, canonical_service

pytestmark = pytest.mark.contract


def test_task_scope_rejects_noncanonical_entity_ids_but_legacy_is_explicit() -> None:
    with pytest.raises(
        MissionStoreError,
        match="canonical graph identities",
    ):
        TaskScope(entity_ids=("asset:10.0.0.5",))
    with pytest.raises(
        MissionStoreError,
        match="canonical graph identities",
    ):
        TaskScope(entity_ids=("asset:v1:" + "A" * 32,))

    assert TaskScope.from_legacy("asset:10.0.0.5") == TaskScope(
        legacy_scope="asset:10.0.0.5"
    )


def _outcome(agent: str, task: str, status: str = "completed") -> TaskOutcome:
    return TaskOutcome(
        agent=agent,
        task=task,
        status=status,
        reason="test_outcome",
        new_facts=0,
        parsed_facts=0,
        commands=(),
        duration=0.01,
    )


def test_same_capability_for_two_entity_scopes_survives_crash_recovery(tmp_path):
    db_path = tmp_path / "typed-scope.db"
    first = MissionStore(str(db_path), owner_id="owner-before-crash")
    mission = first.open_mission("scan-typed-scope", "10.0.0.5")
    asset_scope = TaskScope(
        entity_ids=(canonical_asset("10.0.0.5").entity_id,),
        legacy_scope="asset:10.0.0.5",
    )
    service_scope = TaskScope(
        entity_ids=(canonical_service("10.0.0.5", 443).entity_id,),
        legacy_scope="service:10.0.0.5:443/tcp",
    )
    capability = "service.verification"
    snapshot_ref = "evaluated-facts://sha256/" + ("a" * 64)

    asset_task, service_task = first.register_plan(
        mission.mission_id,
        (
            MissionTaskDefinition(
                agent="VerificationAgent",
                task="verify_service",
                scope=asset_scope,
                capability=capability,
                task_definition_version="2.0",
                evaluated_snapshot_ref=snapshot_ref,
            ),
            MissionTaskDefinition(
                agent="VerificationAgent",
                task="verify_service",
                scope=service_scope,
                capability=capability,
                task_definition_version="2.0",
                evaluated_snapshot_ref=snapshot_ref,
            ),
        ),
    )

    assert asset_task.task_id != service_task.task_id
    assert asset_task.capability_id == service_task.capability_id
    assert asset_task.capability_id == canonical_capability_id(capability)
    assert asset_task.scope == "asset:10.0.0.5"
    assert service_task.scope_entity_ids == service_scope.entity_ids
    with pytest.raises(MissionStoreError, match="scope or task_id is required"):
        first.begin_attempt(
            mission.mission_id,
            "VerificationAgent",
            "verify_service",
        )

    completed = first.begin_attempt(
        mission.mission_id,
        "VerificationAgent",
        "verify_service",
        scope=asset_scope,
        task_definition_version="2.0",
    )
    first.complete_attempt(
        completed.attempt_id,
        _outcome("VerificationAgent", "verify_service"),
    )
    abandoned = first.begin_attempt(
        mission.mission_id,
        "VerificationAgent",
        "verify_service",
        task_id=service_task.task_id,
    )
    first.close()

    recovered = MissionStore(str(db_path), owner_id="owner-after-crash")
    recovered.open_mission(
        "scan-typed-scope",
        "10.0.0.5",
        recover=True,
    )
    crash_snapshot = recovered.snapshot(mission.mission_id)
    by_id = {task.task_id: task for task in crash_snapshot.tasks}
    attempts = {attempt.attempt_id: attempt for attempt in crash_snapshot.attempts}

    assert by_id[asset_task.task_id].status == "completed"
    assert by_id[service_task.task_id].status == "interrupted"
    assert attempts[abandoned.attempt_id].status == "interrupted"
    assert by_id[service_task.task_id].task_scope == service_scope
    assert by_id[service_task.task_id].evaluated_snapshot_ref == snapshot_ref

    resumed = recovered.begin_attempt(
        mission.mission_id,
        "VerificationAgent",
        "verify_service",
        scope=service_scope,
        task_definition_version="2.0",
    )
    assert resumed.task_id == service_task.task_id
    assert resumed.attempt_number == 2

    new_definition = recovered.register_task(
        mission.mission_id,
        "VerificationAgent",
        "verify_service",
        scope=service_scope,
        capability=capability,
        task_definition_version="2.1",
    )
    assert new_definition.task_id not in {asset_task.task_id, service_task.task_id}


def test_legacy_string_scope_and_tuple_plan_contracts_remain_available(tmp_path):
    store = MissionStore(str(tmp_path / "legacy.db"), owner_id="owner")
    mission = store.open_mission("scan-legacy-scope", "10.0.0.5")
    legacy = store.register_task(
        mission.mission_id,
        "DiscoveryAgent",
        "service_discovery",
        scope="target:10.0.0.5",
    )
    repeated = store.register_task(
        mission.mission_id,
        "DiscoveryAgent",
        "service_discovery",
        scope="target:10.0.0.5",
    )
    second_scope = store.register_task(
        mission.mission_id,
        "DiscoveryAgent",
        "service_discovery",
        scope="target:10.0.0.6",
    )
    tuple_task = store.register_plan(
        mission.mission_id,
        (("AnalysisAgent", "analyze", ()),),
    )[0]

    assert repeated.task_id == legacy.task_id
    assert second_scope.task_id != legacy.task_id
    assert legacy.scope == legacy.task_scope.legacy_scope == "target:10.0.0.5"
    assert tuple_task.scope == ""
    assert tuple_task.task_scope == TaskScope()
    assert tuple_task.task_definition_version == TASK_DEFINITION_SCHEMA_VERSION


def test_task_id_rejects_conflicting_scope_or_definition_version(tmp_path):
    store = MissionStore(str(tmp_path / "selector-consistency.db"), owner_id="owner")
    mission = store.open_mission("scan-selector-consistency", "10.0.0.5")
    asset_scope = TaskScope(entity_ids=(canonical_asset("10.0.0.5").entity_id,))
    service_scope = TaskScope(
        entity_ids=(canonical_service("10.0.0.5", 443).entity_id,)
    )
    task = store.register_task(
        mission.mission_id,
        "VerificationAgent",
        "verify_service",
        scope=asset_scope,
        task_definition_version="2.0",
    )
    next_version = store.register_task(
        mission.mission_id,
        "VerificationAgent",
        "verify_service",
        scope=asset_scope,
        task_definition_version="3.0",
    )

    with pytest.raises(MissionStoreError, match="scope does not match task_id"):
        store.begin_attempt(
            mission.mission_id,
            task.agent,
            task.task,
            task_id=task.task_id,
            scope=service_scope,
        )
    with pytest.raises(
        MissionStoreError,
        match="definition version does not match task_id",
    ):
        store.begin_attempt(
            mission.mission_id,
            task.agent,
            task.task,
            task_id=task.task_id,
            task_definition_version="3.0",
        )
    with pytest.raises(MissionStoreError, match="registered before an attempt"):
        store.begin_attempt(
            mission.mission_id,
            task.agent,
            task.task,
            task_definition_version="4.0",
        )

    version_selected = store.begin_attempt(
        mission.mission_id,
        next_version.agent,
        next_version.task,
        task_definition_version="3.0",
    )
    assert version_selected.task_id == next_version.task_id

    matching = store.begin_attempt(
        mission.mission_id,
        task.agent,
        task.task,
        task_id=task.task_id,
        scope=asset_scope,
        task_definition_version="2.0",
    )
    assert matching.task_id == task.task_id


def test_scoped_dependency_ref_selects_one_same_name_definition(tmp_path):
    store = MissionStore(str(tmp_path / "scoped-dependency.db"), owner_id="owner")
    mission = store.open_mission("scan-scoped-dependency", "10.0.0.5")
    asset_scope = TaskScope(entity_ids=(canonical_asset("10.0.0.5").entity_id,))
    service_scope = TaskScope(
        entity_ids=(canonical_service("10.0.0.5", 443).entity_id,)
    )

    asset_parent, service_parent, child = store.register_plan(
        mission.mission_id,
        (
            MissionTaskDefinition(
                agent="DiscoveryAgent",
                task="discover",
                scope=asset_scope,
                task_definition_version="2.0",
            ),
            MissionTaskDefinition(
                agent="DiscoveryAgent",
                task="discover",
                scope=service_scope,
                task_definition_version="2.0",
            ),
            MissionTaskDefinition(
                agent="VerificationAgent",
                task="verify",
                depends_on=(
                    TaskDependencyRef(
                        agent="DiscoveryAgent",
                        task="discover",
                        scope=service_scope,
                        task_definition_version="2.0",
                    ),
                ),
                scope=service_scope,
                task_definition_version="2.0",
            ),
        ),
    )

    assert child.depends_on == (service_parent.task_id,)
    assert asset_parent.task_id not in child.depends_on
    service_attempt = store.begin_attempt(
        mission.mission_id,
        service_parent.agent,
        service_parent.task,
        task_id=service_parent.task_id,
    )
    store.complete_attempt(
        service_attempt.attempt_id,
        _outcome(service_parent.agent, service_parent.task),
    )
    child_attempt = store.begin_attempt(
        mission.mission_id,
        child.agent,
        child.task,
        task_id=child.task_id,
    )
    assert child_attempt.task_id == child.task_id


def test_scoped_blocked_positions_rollback_with_plan_transaction(
    tmp_path,
    monkeypatch,
):
    store = MissionStore(str(tmp_path / "scoped-block-rollback.db"), owner_id="owner")
    mission = store.open_mission("scan-scoped-block-rollback", "10.0.0.5")
    asset_scope = TaskScope(entity_ids=(canonical_asset("10.0.0.5").entity_id,))
    service_scope = TaskScope(
        entity_ids=(canonical_service("10.0.0.5", 443).entity_id,)
    )
    definitions = (
        MissionTaskDefinition(
            agent="DiscoveryAgent",
            task="discover",
            scope=asset_scope,
        ),
        MissionTaskDefinition(
            agent="DiscoveryAgent",
            task="discover",
            scope=service_scope,
        ),
    )
    original = store._terminalize_task_row

    def crash_after_terminalization(*args, **kwargs):
        original(*args, **kwargs)
        raise RuntimeError("simulated scoped block crash")

    monkeypatch.setattr(store, "_terminalize_task_row", crash_after_terminalization)
    with pytest.raises(RuntimeError, match="simulated scoped block crash"):
        store.register_plan(
            mission.mission_id,
            definitions,
            blocked_reasons_by_position={0: "invalid_dependency"},
        )

    assert store.snapshot(mission.mission_id).tasks == ()


def test_typed_backoff_not_before_and_references_survive_restart(
    tmp_path,
    monkeypatch,
):
    db_path = tmp_path / "backoff.db"
    store = MissionStore(str(db_path), owner_id="owner-one")
    mission = store.open_mission("scan-backoff", "10.0.0.5")
    snapshot_ref = "evaluated-facts://sha256/" + ("b" * 64)
    task = store.register_task(
        mission.mission_id,
        "DiscoveryAgent",
        "service_verification",
        scope="service:https",
        capability="service.verification",
        retry_policy=TaskRetryPolicy(
            retry_budget=1,
            retryable_error_classes=(RetryErrorClass.TIMEOUT,),
        ),
        backoff=TaskBackoff(
            strategy=BackoffStrategy.FIXED,
            base_delay_seconds=30,
        ),
        provider_circuit_ref="provider-circuit://initial",
        evaluated_snapshot_ref=snapshot_ref,
    )
    first_attempt = store.begin_attempt(
        mission.mission_id,
        task.agent,
        task.task,
        task_id=task.task_id,
    )
    store.complete_attempt(
        first_attempt.attempt_id,
        _outcome(task.agent, task.task, status="failed"),
    )
    before_schedule = time.time()
    scheduled = store.schedule_retry(
        mission.mission_id,
        task.agent,
        task.task,
        task_id=task.task_id,
        error_class=RetryErrorClass.TIMEOUT,
        provider_circuit_ref="provider-circuit://open/selection-1",
    )
    assert scheduled.not_before is not None
    assert scheduled.not_before >= before_schedule + 29
    assert scheduled.provider_circuit_ref == "provider-circuit://open/selection-1"
    store.interrupt_mission(mission.mission_id, "restart")

    resumed_store = MissionStore(str(db_path), owner_id="owner-two")
    resumed_store.open_mission("scan-backoff", "10.0.0.5")
    hydrated = resumed_store.snapshot(mission.mission_id).tasks[0]
    assert hydrated.backoff.strategy is BackoffStrategy.FIXED
    assert hydrated.backoff.base_delay_seconds == 30
    assert hydrated.not_before == scheduled.not_before
    assert hydrated.evaluated_snapshot_ref == snapshot_ref
    with pytest.raises(TaskNotReady) as deferred:
        resumed_store.begin_attempt(
            mission.mission_id,
            hydrated.agent,
            hydrated.task,
            task_id=hydrated.task_id,
        )
    assert deferred.value.not_before == hydrated.not_before

    monkeypatch.setattr(
        mission_store_module.time,
        "time",
        lambda: float(hydrated.not_before) + 1,
    )
    second_attempt = resumed_store.begin_attempt(
        mission.mission_id,
        hydrated.agent,
        hydrated.task,
        task_id=hydrated.task_id,
    )
    assert second_attempt.attempt_number == 2
    current = resumed_store.snapshot(mission.mission_id).tasks[0]
    assert current.not_before is None


def test_v13_task_rows_migrate_to_typed_identity_without_changing_task_id(tmp_path):
    db_path = tmp_path / "missions-v13.db"
    old_task_key = hashlib.sha256(
        json.dumps(
            ["task", "DiscoveryAgent", "service_discovery"],
            separators=(",", ":"),
        ).encode()
    ).hexdigest()
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
            VALUES ('mission_store', '1.3')
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
                state_replan_count INTEGER NOT NULL DEFAULT 0,
                state_replan_signatures_json TEXT NOT NULL DEFAULT '[]',
                schema_version TEXT NOT NULL
            )
            """
        )
        conn.execute(
            """
            INSERT INTO missions(
                mission_id, scan_key, scan_id, target_key, target, status,
                owner_id, created_at, updated_at, started_at, schema_version
            ) VALUES (
                'mis-v13', 'scan-key', 'scan-v13', 'target-key', '10.0.0.5',
                'running', 'owner', 1.0, 1.0, 1.0, '1.3'
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE mission_tasks (
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
                UNIQUE(mission_id, task_key)
            )
            """
        )
        conn.execute(
            """
            INSERT INTO mission_tasks(
                task_id, mission_id, task_key, agent, task, status,
                created_at, updated_at, scope, capability
            ) VALUES (
                'task-v13', 'mis-v13', ?, 'DiscoveryAgent',
                'service_discovery', 'pending', 1.0, 1.0,
                'target:10.0.0.5', 'network.service_discovery'
            )
            """,
            (old_task_key,),
        )

    store = MissionStore(str(db_path), owner_id="owner")
    migrated = store.snapshot("mis-v13").tasks[0]
    repeated = store.register_task(
        "mis-v13",
        "DiscoveryAgent",
        "service_discovery",
        scope="target:10.0.0.5",
        capability="network.service_discovery",
    )

    assert migrated.task_id == repeated.task_id == "task-v13"
    assert migrated.task_scope == TaskScope.from_legacy("target:10.0.0.5")
    assert migrated.capability_id == canonical_capability_id(
        "network.service_discovery"
    )
    assert migrated.task_definition_version == TASK_DEFINITION_SCHEMA_VERSION
    assert migrated.not_before is None
    assert migrated.backoff == TaskBackoff()

    with sqlite3.connect(db_path) as conn:
        version = conn.execute(
            """
            SELECT version FROM mission_lifecycle_schema
            WHERE component = 'mission_store'
            """
        ).fetchone()
        row = conn.execute(
            """
            SELECT task_key, task_compat_key FROM mission_tasks
            WHERE task_id = 'task-v13'
            """
        ).fetchone()
        columns = {
            item[1] for item in conn.execute("PRAGMA table_info(mission_tasks)")
        }

    assert version == (MISSION_LIFECYCLE_SCHEMA_VERSION,)
    assert row is not None
    assert row[0] != old_task_key
    assert row[1] == old_task_key
    assert {
        "task_scope_json",
        "capability_id",
        "task_definition_version",
        "not_before",
        "backoff_json",
        "provider_circuit_ref",
        "evaluated_snapshot_ref",
    }.issubset(columns)
