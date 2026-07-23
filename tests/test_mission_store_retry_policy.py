"""Contracts for durable task metadata and bounded retry transitions."""

import sqlite3

import pytest

from core.ai.mission_store import (
    MISSION_LIFECYCLE_SCHEMA_VERSION,
    MissionStore,
    MissionStoreError,
    MissionTaskDefinition,
    RetryErrorClass,
    TaskRetryBudgetExhausted,
    TaskRetryNotAllowed,
    TaskRetryPolicy,
)
from core.ai.outcomes import TaskOutcome

pytestmark = pytest.mark.contract


def _failed(agent: str, task: str, reason: str = "transient_failure") -> TaskOutcome:
    return TaskOutcome(
        agent=agent,
        task=task,
        status="failed",
        reason=reason,
        new_facts=0,
        parsed_facts=0,
        commands=(),
        duration=0.01,
    )


def test_task_metadata_and_retry_policy_survive_reopen(tmp_path):
    db_path = tmp_path / "missions.db"
    store = MissionStore(str(db_path), owner_id="owner")
    mission = store.open_mission("scan-metadata", "10.0.0.5")
    policy = TaskRetryPolicy(
        retry_budget=2,
        retryable_error_classes=(
            RetryErrorClass.TIMEOUT,
            RetryErrorClass.TRANSIENT_NETWORK,
        ),
    )

    registered = store.register_task(
        mission.mission_id,
        "DiscoveryAgent",
        "service_discovery",
        scope="target:10.0.0.5",
        capability="network.service_discovery",
        retry_policy=policy,
    )
    repeated_without_optional_metadata = store.register_task(
        mission.mission_id,
        "DiscoveryAgent",
        "service_discovery",
    )
    hydrated = MissionStore(
        str(db_path),
        owner_id="observer",
    ).snapshot(mission.mission_id).tasks[0]

    assert repeated_without_optional_metadata.task_id == registered.task_id
    assert hydrated.scope == "target:10.0.0.5"
    assert hydrated.capability == "network.service_discovery"
    assert hydrated.retry_budget == 2
    assert hydrated.retry_count == 0
    assert hydrated.retryable_error_classes == policy.retryable_error_classes
    assert hydrated.last_error_class is None

    second_scope = store.register_task(
        mission.mission_id,
        "DiscoveryAgent",
        "service_discovery",
        scope="target:10.0.0.6",
    )
    assert second_scope.task_id != registered.task_id
    with pytest.raises(MissionStoreError, match="capability conflicts"):
        store.register_task(
            mission.mission_id,
            "DiscoveryAgent",
            "service_discovery",
            scope="target:10.0.0.5",
            capability="conflicting.capability",
        )
    with pytest.raises(MissionStoreError, match="retry policy conflicts"):
        store.register_task(
            mission.mission_id,
            "DiscoveryAgent",
            "service_discovery",
            scope="target:10.0.0.5",
            retry_policy=TaskRetryPolicy(
                retry_budget=1,
                retryable_error_classes=(RetryErrorClass.TIMEOUT,),
            ),
        )


def test_typed_plan_definitions_coexist_with_legacy_tuples(tmp_path):
    store = MissionStore(str(tmp_path / "missions.db"), owner_id="owner")
    mission = store.open_mission("scan-typed-plan", "10.0.0.5")
    tasks = store.register_plan(
        mission.mission_id,
        (
            ("DiscoveryAgent", "service_discovery", ()),
            MissionTaskDefinition(
                agent="VerificationAgent",
                task="service_verification",
                depends_on=(("DiscoveryAgent", "service_discovery"),),
                scope="service:ssh",
                capability="service.verification",
                retry_policy=TaskRetryPolicy(
                    retry_budget=1,
                    retryable_error_classes=(RetryErrorClass.TIMEOUT,),
                ),
            ),
        ),
    )

    discovery, verification = tasks
    assert discovery.scope == ""
    assert discovery.retry_budget == 0
    assert verification.scope == "service:ssh"
    assert verification.capability == "service.verification"
    assert verification.depends_on == (discovery.task_id,)
    assert verification.retryable_error_classes == (RetryErrorClass.TIMEOUT,)


def test_retry_transition_is_bounded_typed_and_idempotent(tmp_path):
    store = MissionStore(str(tmp_path / "missions.db"), owner_id="owner")
    mission = store.open_mission("scan-retry", "10.0.0.5")
    task = store.register_task(
        mission.mission_id,
        "DiscoveryAgent",
        "service_discovery",
        retry_policy=TaskRetryPolicy(
            retry_budget=2,
            retryable_error_classes=(
                RetryErrorClass.TIMEOUT,
                RetryErrorClass.TRANSIENT_NETWORK,
            ),
        ),
    )

    first = store.begin_attempt(mission.mission_id, task.agent, task.task)
    store.complete_attempt(first.attempt_id, _failed(task.agent, task.task))
    with pytest.raises(TaskRetryNotAllowed, match="not retryable"):
        store.schedule_retry(
            mission.mission_id,
            task.agent,
            task.task,
            error_class=RetryErrorClass.EXECUTION_ERROR,
        )

    scheduled = store.schedule_retry(
        mission.mission_id,
        task.agent,
        task.task,
        error_class=RetryErrorClass.TIMEOUT,
    )
    repeated = store.schedule_retry(
        mission.mission_id,
        task.agent,
        task.task,
        error_class="timeout",
    )
    assert scheduled.status == repeated.status == "pending"
    assert scheduled.retry_count == repeated.retry_count == 1
    assert scheduled.last_error_class is RetryErrorClass.TIMEOUT

    second = store.begin_attempt(mission.mission_id, task.agent, task.task)
    store.complete_attempt(second.attempt_id, _failed(task.agent, task.task))
    scheduled_again = store.schedule_retry(
        mission.mission_id,
        task.agent,
        task.task,
        error_class=RetryErrorClass.TRANSIENT_NETWORK,
    )
    assert scheduled_again.retry_count == 2

    third = store.begin_attempt(mission.mission_id, task.agent, task.task)
    store.complete_attempt(third.attempt_id, _failed(task.agent, task.task))
    with pytest.raises(TaskRetryBudgetExhausted, match="2/2"):
        store.schedule_retry(
            mission.mission_id,
            task.agent,
            task.task,
            error_class=RetryErrorClass.TIMEOUT,
        )

    final = store.snapshot(mission.mission_id).tasks[0]
    assert final.status == "failed"
    assert final.attempt_count == 3
    assert final.retry_count == 2


def test_v1_schema_is_migrated_additively_before_use(tmp_path):
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
            VALUES ('mission_store', '1.0')
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
                UNIQUE(mission_id, task_key)
            )
            """
        )

    store = MissionStore(str(db_path), owner_id="owner")
    mission = store.open_mission("scan-migrated", "10.0.0.5")
    task = store.register_task(
        mission.mission_id,
        "DiscoveryAgent",
        "service_discovery",
        scope="target",
        capability="network.discovery",
        retry_policy=TaskRetryPolicy(
            retry_budget=1,
            retryable_error_classes=(RetryErrorClass.TIMEOUT,),
        ),
    )

    with sqlite3.connect(db_path) as conn:
        version = conn.execute(
            """
            SELECT version FROM mission_lifecycle_schema
            WHERE component = 'mission_store'
            """
        ).fetchone()
        columns = {
            row[1] for row in conn.execute("PRAGMA table_info(mission_tasks)")
        }

    assert version == (MISSION_LIFECYCLE_SCHEMA_VERSION,)
    assert {
        "scope",
        "capability",
        "retry_budget",
        "retry_count",
        "retryable_error_classes_json",
        "last_error_class",
    }.issubset(columns)
    assert task.scope == "target"
    assert task.retry_budget == 1


@pytest.mark.parametrize(
    "policy",
    (
        pytest.param(TaskRetryPolicy(), id="disabled"),
        pytest.param(
            TaskRetryPolicy(
                retry_budget=1,
                retryable_error_classes=(RetryErrorClass.RATE_LIMIT,),
            ),
            id="bounded",
        ),
    ),
)
def test_retry_policy_is_hashable_and_normalized(policy):
    assert hash(policy)
