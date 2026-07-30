"""Hermetic edge coverage for mission task repository transitions."""

from __future__ import annotations

import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace

import pytest

from core.ai import mission_store_tasks as tasks_module
from core.ai.mission_store import (
    BackoffStrategy,
    MissionStore,
    MissionStoreError,
    MissionTaskDefinition,
    RetryErrorClass,
    TaskBackoff,
    TaskDependenciesIncomplete,
    TaskDependencyRef,
    TaskRetryBudgetExhausted,
    TaskRetryError,
    TaskRetryNotAllowed,
    TaskRetryPolicy,
)
from core.ai.outcomes import TaskOutcome

pytestmark = pytest.mark.unit


def _store(tmp_path: Path, name: str = "tasks") -> MissionStore:
    return MissionStore(str(tmp_path / f"{name}.db"), owner_id="owner")


def _mission(store: MissionStore, name: str = "mission"):
    return store.open_mission(f"scan-{name}", "10.0.0.1")


def _outcome(
    agent: str,
    task: str,
    *,
    status: str = "completed",
    reason: str = "done",
) -> TaskOutcome:
    return TaskOutcome(
        agent=agent,
        task=task,
        status=status,
        reason=reason,
        new_facts=1 if status == "completed" else 0,
        parsed_facts=1 if status == "completed" else 0,
        commands=(),
        duration=0.1,
    )


def _update_task(store: MissionStore, task_id: str, **values) -> None:
    assignments = ", ".join(f"{name} = ?" for name in values)
    with store._transaction() as conn:
        conn.execute(
            f"UPDATE mission_tasks SET {assignments} WHERE task_id = ?",
            (*values.values(), task_id),
        )


def _task_row(store: MissionStore, task_id: str):
    with store._connection() as conn:
        return conn.execute(
            "SELECT * FROM mission_tasks WHERE task_id = ?",
            (task_id,),
        ).fetchone()


def test_register_task_validates_identity_ambiguity_and_started_dependencies(
    tmp_path: Path,
) -> None:
    store = _store(tmp_path)
    mission = _mission(store)
    with pytest.raises(MissionStoreError, match="agent and task are required"):
        store.register_task(mission.mission_id, "", "task")

    store.register_task(mission.mission_id, "agent", "ambiguous", scope="one")
    store.register_task(mission.mission_id, "agent", "ambiguous", scope="two")
    with pytest.raises(MissionStoreError, match="task scope is required"):
        store.register_task(mission.mission_id, "agent", "ambiguous")

    first = store.register_task(mission.mission_id, "agent", "first")
    second = store.register_task(mission.mission_id, "agent", "second")
    dependent = store.register_task(
        mission.mission_id,
        "agent",
        "dependent",
        depends_on=(first.task_id,),
    )
    _update_task(store, dependent.task_id, attempt_count=1)
    with pytest.raises(MissionStoreError, match="cannot change dependencies"):
        store.register_task(
            mission.mission_id,
            dependent.agent,
            dependent.task,
            depends_on=(second.task_id,),
        )


def test_register_plan_validation_blocked_selectors_and_empty_plan(
    tmp_path: Path,
) -> None:
    store = _store(tmp_path, "plan-validation")
    mission = _mission(store, "plan-validation")
    assert store.register_plan(mission.mission_id, ()) == ()
    with pytest.raises(MissionStoreError, match="plan definitions"):
        store.register_plan(mission.mission_id, (("agent", "task"),))
    with pytest.raises(MissionStoreError, match="agent and task are required"):
        store.register_plan(mission.mission_id, (("", "task", ()),))
    with pytest.raises(MissionStoreError, match="duplicate task definition"):
        store.register_plan(
            mission.mission_id,
            (("agent", "task", ()), ("agent", "task", ())),
        )

    blocked = store.register_plan(
        mission.mission_id,
        (("agent", "blocked", ()),),
        blocked_reasons={("agent", "blocked"): "policy gate"},
    )
    assert blocked[0].status == "blocked"
    repeated = store.register_plan(
        mission.mission_id,
        (("agent", "blocked", ()),),
        blocked_reasons={("agent", "blocked"): "policy gate"},
    )
    assert repeated[0].task_id == blocked[0].task_id

    with pytest.raises(MissionStoreError, match="identity is missing"):
        store.register_plan(
            mission.mission_id,
            (("agent", "known", ()),),
            blocked_reasons={("agent", "unknown"): "reason"},
        )
    with pytest.raises(MissionStoreError, match="position is out of range"):
        store.register_plan(
            mission.mission_id,
            (("agent", "position", ()),),
            blocked_reasons_by_position={True: "reason"},
        )
    with pytest.raises(MissionStoreError, match="more than one reason selector"):
        store.register_plan(
            mission.mission_id,
            (("agent", "duplicate-reason", ()),),
            blocked_reasons={("agent", "duplicate-reason"): "one"},
            blocked_reasons_by_position={0: "two"},
        )
    with pytest.raises(MissionStoreError, match="terminal task reason is required"):
        store.register_plan(
            mission.mission_id,
            (("agent", "empty-reason", ()),),
            blocked_reasons_by_position={0: ""},
        )

    ambiguous = (
        MissionTaskDefinition(agent="agent", task="same", scope="one"),
        MissionTaskDefinition(agent="agent", task="same", scope="two"),
    )
    with pytest.raises(MissionStoreError, match="scope-ambiguous"):
        store.register_plan(
            mission.mission_id,
            ambiguous,
            blocked_reasons={("agent", "same"): "reason"},
        )


def test_register_plan_dependency_conflicts_before_and_after_start(
    tmp_path: Path,
) -> None:
    store = _store(tmp_path, "plan-dependencies")
    mission = _mission(store, "plan-dependencies")
    definitions = (
        ("agent", "first", ()),
        ("agent", "second", ()),
        ("agent", "child", (("agent", "first"),)),
    )
    first, second, child = store.register_plan(mission.mission_id, definitions)
    with pytest.raises(MissionStoreError, match="dependencies conflict"):
        store.register_plan(
            mission.mission_id,
            (
                ("agent", "first", ()),
                ("agent", "second", ()),
                ("agent", "child", (("agent", "second"),)),
            ),
        )

    standalone = store.register_task(mission.mission_id, "agent", "started")
    store.begin_attempt(mission.mission_id, standalone.agent, standalone.task)
    with pytest.raises(MissionStoreError, match="cannot change dependencies"):
        store.register_plan(
            mission.mission_id,
            (
                ("agent", "first", ()),
                ("agent", "started", (("agent", "first"),)),
            ),
        )

    assert first.task_id != second.task_id != child.task_id


def test_begin_attempt_validation_nonretryable_and_deferred_paths(
    tmp_path: Path,
) -> None:
    store = _store(tmp_path, "begin")
    mission = _mission(store, "begin")
    with pytest.raises(MissionStoreError, match="agent and task are required"):
        store.begin_attempt(mission.mission_id, "", "task")

    inconsistent = store.register_task(mission.mission_id, "agent", "inconsistent")
    _update_task(store, inconsistent.task_id, status="running")
    with pytest.raises(MissionStoreError, match="cannot start from running"):
        store.begin_attempt(mission.mission_id, inconsistent.agent, inconsistent.task)

    completed = store.register_task(mission.mission_id, "agent", "completed")
    attempt = store.begin_attempt(mission.mission_id, completed.agent, completed.task)
    store.complete_attempt(attempt.attempt_id, _outcome(completed.agent, completed.task))
    with pytest.raises(MissionStoreError, match="cannot start from completed"):
        store.begin_attempt(mission.mission_id, completed.agent, completed.task)


def test_completion_validation_idempotence_and_mission_state(
    tmp_path: Path,
) -> None:
    store = _store(tmp_path, "completion")
    mission = _mission(store, "completion")
    task = store.register_task(mission.mission_id, "agent", "task")
    attempt = store.begin_attempt(mission.mission_id, task.agent, task.task)
    with pytest.raises(MissionStoreError, match="unsupported terminal"):
        store.complete_attempt(
            attempt.attempt_id,
            _outcome(task.agent, task.task, status="running"),
        )
    with pytest.raises(MissionStoreError, match="only failed"):
        store.complete_attempt_and_schedule_retry(
            attempt.attempt_id,
            _outcome(task.agent, task.task),
            retry_error_class=RetryErrorClass.TIMEOUT,
        )
    with pytest.raises(MissionStoreError, match="unknown task attempt"):
        store.complete_attempt("missing", _outcome(task.agent, task.task))

    outcome = _outcome(task.agent, task.task)
    completed = store.complete_attempt(attempt.attempt_id, outcome)
    with store._transaction() as conn:
        conn.execute(
            "UPDATE mission_task_attempts SET outcome_key = 'legacy' WHERE attempt_id = ?",
            (completed.attempt_id,),
        )
    repeated = store.complete_attempt(attempt.attempt_id, outcome)
    assert repeated.attempt_id == completed.attempt_id

    outside = store.register_task(mission.mission_id, "agent", "outside")
    outside_attempt = store.begin_attempt(mission.mission_id, outside.agent, outside.task)
    with store._transaction() as conn:
        conn.execute(
            "UPDATE missions SET status = 'completed' WHERE mission_id = ?",
            (mission.mission_id,),
        )
    with pytest.raises(MissionStoreError, match="outside a running mission"):
        store.complete_attempt(
            outside_attempt.attempt_id,
            _outcome(outside.agent, outside.task),
        )


def test_atomic_retry_rejections_success_and_provider_reference(
    tmp_path: Path,
) -> None:
    def create(name: str, retryable=(RetryErrorClass.TIMEOUT,)):
        store = _store(tmp_path, name)
        mission = _mission(store, name)
        task = store.register_task(
            mission.mission_id,
            "agent",
            "task",
            retry_policy=TaskRetryPolicy(
                retry_budget=1,
                retryable_error_classes=retryable,
            ),
        )
        attempt = store.begin_attempt(mission.mission_id, task.agent, task.task)
        return store, mission, task, attempt

    store, _mission_record, task, attempt = create("atomic-not-allowed")
    rejected = store.complete_attempt_and_schedule_retry(
        attempt.attempt_id,
        _outcome(task.agent, task.task, status="failed"),
        retry_error_class=RetryErrorClass.EXECUTION_ERROR,
        retry_command_keys=("command",),
    )
    assert rejected.retry_rejection == TaskRetryNotAllowed.__name__

    store, _mission_record, task, attempt = create("atomic-exhausted")
    _update_task(store, task.task_id, retry_count=1)
    exhausted = store.complete_attempt_and_schedule_retry(
        attempt.attempt_id,
        _outcome(task.agent, task.task, status="failed"),
        retry_error_class=RetryErrorClass.TIMEOUT,
        retry_command_keys=("command",),
    )
    assert exhausted.retry_rejection == TaskRetryBudgetExhausted.__name__

    store, _mission_record, task, attempt = create("atomic-empty")
    empty = store.complete_attempt_and_schedule_retry(
        attempt.attempt_id,
        _outcome(task.agent, task.task, status="failed"),
        retry_error_class=RetryErrorClass.TIMEOUT,
    )
    assert empty.retry_rejection == "retry_command_allowlist_empty"

    store, mission_record, task, attempt = create("atomic-success")
    successful = store.complete_attempt_and_schedule_retry(
        attempt.attempt_id,
        _outcome(task.agent, task.task, status="failed"),
        retry_error_class=RetryErrorClass.TIMEOUT,
        retry_command_keys=("command",),
        provider_circuit_ref="provider://circuit",
    )
    assert successful.retry_scheduled
    assert successful.task.provider_circuit_ref == "provider://circuit"
    assert store.pending_retry_command_keys(
        mission_record.mission_id,
        task.agent,
        task.task,
    ) == ("command",)


def test_schedule_retry_errors_and_provider_reference(tmp_path: Path) -> None:
    store = _store(tmp_path, "schedule")
    mission = _mission(store, "schedule")
    with pytest.raises(MissionStoreError, match="agent and task are required"):
        store.schedule_retry(
            mission.mission_id,
            "",
            "task",
            error_class=RetryErrorClass.TIMEOUT,
        )
    with pytest.raises(MissionStoreError, match="registered before"):
        store.schedule_retry(
            mission.mission_id,
            "agent",
            "missing",
            error_class=RetryErrorClass.TIMEOUT,
        )

    pending = store.register_task(
        mission.mission_id,
        "agent",
        "pending",
        retry_policy=TaskRetryPolicy(
            retry_budget=1,
            retryable_error_classes=(RetryErrorClass.TIMEOUT,),
        ),
    )
    with pytest.raises(TaskRetryError, match="cannot retry from pending"):
        store.schedule_retry(
            mission.mission_id,
            pending.agent,
            pending.task,
            error_class=RetryErrorClass.TIMEOUT,
        )

    task = store.register_task(
        mission.mission_id,
        "agent",
        "failed",
        retry_policy=TaskRetryPolicy(
            retry_budget=1,
            retryable_error_classes=(RetryErrorClass.TIMEOUT,),
        ),
    )
    attempt = store.begin_attempt(mission.mission_id, task.agent, task.task)
    store.complete_attempt(attempt.attempt_id, _outcome(task.agent, task.task, status="failed"))
    scheduled = store.schedule_retry(
        mission.mission_id,
        task.agent,
        task.task,
        error_class=RetryErrorClass.TIMEOUT,
        provider_circuit_ref="provider://scheduled",
    )
    assert scheduled.provider_circuit_ref == "provider://scheduled"

    store.register_task(mission.mission_id, "agent", "ambiguous", scope="one")
    store.register_task(mission.mission_id, "agent", "ambiguous", scope="two")
    with pytest.raises(MissionStoreError, match="scope or task_id"):
        store.schedule_retry(
            mission.mission_id,
            "agent",
            "ambiguous",
            error_class=RetryErrorClass.TIMEOUT,
        )


def test_retry_command_consumption_and_progress_validation(tmp_path: Path) -> None:
    store = _store(tmp_path, "commands")
    mission = _mission(store, "commands")
    task = store.register_task(
        mission.mission_id,
        "agent",
        "task",
        retry_policy=TaskRetryPolicy(
            retry_budget=1,
            retryable_error_classes=(RetryErrorClass.TIMEOUT,),
        ),
    )
    assert not store.consume_retry_command(mission.mission_id, task.agent, task.task, "")
    assert not store.consume_retry_command(mission.mission_id, task.agent, task.task, "command")
    with pytest.raises(MissionStoreError, match="unknown task attempt"):
        store.record_attempt_progress("missing")

    first = store.begin_attempt(mission.mission_id, task.agent, task.task)
    progressed = store.record_attempt_progress(
        first.attempt_id,
        execution_ids=("exec", "exec"),
        fact_ids=(1, 1),
    )
    assert progressed.execution_ids == ("exec",)
    store.complete_attempt(first.attempt_id, _outcome(task.agent, task.task, status="failed"))
    with pytest.raises(MissionStoreError, match="is not running"):
        store.record_attempt_progress(first.attempt_id)

    scheduled = store.schedule_retry(
        mission.mission_id,
        task.agent,
        task.task,
        error_class=RetryErrorClass.TIMEOUT,
    )
    with store._transaction() as conn:
        tasks_module.MissionTaskRepositoryMixin._insert_retry_command_grants(
            conn,
            task.task_id,
            scheduled.retry_count,
            RetryErrorClass.TIMEOUT,
            ("command",),
            1.0,
        )
        row = conn.execute(
            "SELECT * FROM mission_tasks WHERE task_id = ?",
            (task.task_id,),
        ).fetchone()
        assert store._retry_command_keys_for_row(conn, row, pending_only=False) == ("command",)
    retry_attempt = store.begin_attempt(mission.mission_id, task.agent, task.task)
    assert store.consume_retry_command(mission.mission_id, task.agent, task.task, "command")
    assert not store.consume_retry_command(mission.mission_id, task.agent, task.task, "command")
    assert retry_attempt.status == "running"


def test_terminal_unstarted_paths_are_validated_and_idempotent(tmp_path: Path) -> None:
    store = _store(tmp_path, "terminal")
    mission = _mission(store, "terminal")
    with pytest.raises(MissionStoreError, match="agent and task are required"):
        store.block_task(mission.mission_id, "", "task", "reason")
    with pytest.raises(MissionStoreError, match="reason is required"):
        store.block_task(mission.mission_id, "agent", "task", "")
    with pytest.raises(MissionStoreError, match="registered before"):
        store.block_task(mission.mission_id, "agent", "missing", "reason")

    store.register_task(mission.mission_id, "agent", "ambiguous", scope="one")
    store.register_task(mission.mission_id, "agent", "ambiguous", scope="two")
    with pytest.raises(MissionStoreError, match="scope or task_id"):
        store.block_task(mission.mission_id, "agent", "ambiguous", "reason")

    blocked_task = store.register_task(mission.mission_id, "agent", "blocked")
    first = store.block_task(mission.mission_id, blocked_task.agent, blocked_task.task, "reason")
    assert store.block_task(mission.mission_id, blocked_task.agent, blocked_task.task, "reason") == first
    with pytest.raises(MissionStoreError, match="another reason"):
        store.block_task(mission.mission_id, blocked_task.agent, blocked_task.task, "other")

    skipped_task = store.register_task(mission.mission_id, "agent", "skipped")
    assert store.skip_task(mission.mission_id, skipped_task.agent, skipped_task.task, "skip").status == "skipped"

    completed_task = store.register_task(mission.mission_id, "agent", "completed")
    attempt = store.begin_attempt(mission.mission_id, completed_task.agent, completed_task.task)
    store.complete_attempt(attempt.attempt_id, _outcome(completed_task.agent, completed_task.task))
    with pytest.raises(MissionStoreError, match="cannot become blocked"):
        store.block_task(mission.mission_id, completed_task.agent, completed_task.task, "reason")


def test_unknown_and_immutable_mission_paths(tmp_path: Path) -> None:
    store = _store(tmp_path, "missions")
    with pytest.raises(MissionStoreError, match="unknown mission"):
        store.register_task("missing", "agent", "task")
    mission = _mission(store, "missions")
    with store._transaction() as conn:
        conn.execute(
            "UPDATE missions SET status = 'completed' WHERE mission_id = ?",
            (mission.mission_id,),
        )
    with pytest.raises(MissionStoreError, match="is not running"):
        store.register_task(mission.mission_id, "agent", "task")


def test_prepare_metadata_rejects_untyped_retry_and_backoff(tmp_path: Path) -> None:
    store = _store(tmp_path, "metadata-types")
    with pytest.raises(MissionStoreError, match="retry_policy must"):
        store._prepare_task_metadata(None, None, "bad")
    with pytest.raises(MissionStoreError, match="backoff must"):
        store._prepare_task_metadata(None, None, None, backoff="bad")


def _reconcile(store: MissionStore, task_id: str, metadata):
    with store._transaction() as conn:
        row = conn.execute(
            "SELECT * FROM mission_tasks WHERE task_id = ?",
            (task_id,),
        ).fetchone()
        return store._reconcile_task_metadata(conn, row, metadata)


def test_reconcile_scope_capability_and_definition_legacy_paths(
    tmp_path: Path,
) -> None:
    store = _store(tmp_path, "reconcile-core")
    mission = _mission(store, "reconcile-core")

    scoped = store.register_task(mission.mission_id, "agent", "scoped", scope="one")
    with pytest.raises(MissionStoreError, match="scope conflicts"):
        _reconcile(
            store,
            scoped.task_id,
            store._prepare_task_metadata("two", None, None),
        )

    _update_task(store, scoped.task_id, task_scope_json="")
    updated = _reconcile(
        store,
        scoped.task_id,
        store._prepare_task_metadata("one", None, None),
    )
    assert updated["task_scope_json"]

    capability = store.register_task(
        mission.mission_id,
        "agent",
        "capability",
        capability="one",
    )
    _update_task(store, capability.task_id, capability_key="")
    with pytest.raises(MissionStoreError, match="capability conflicts"):
        _reconcile(
            store,
            capability.task_id,
            store._prepare_task_metadata(None, "two", None),
        )

    versioned = store.register_task(mission.mission_id, "agent", "versioned")
    with pytest.raises(MissionStoreError, match="definition version conflicts"):
        _reconcile(
            store,
            versioned.task_id,
            store._prepare_task_metadata(
                None,
                None,
                None,
                task_definition_version="2.0",
            ),
        )


def test_reconcile_legacy_retry_policy_paths(tmp_path: Path) -> None:
    store = _store(tmp_path, "reconcile-policy")
    mission = _mission(store, "reconcile-policy")
    timeout_policy = TaskRetryPolicy(
        retry_budget=1,
        retryable_error_classes=(RetryErrorClass.TIMEOUT,),
    )
    network_policy = TaskRetryPolicy(
        retry_budget=2,
        retryable_error_classes=(RetryErrorClass.TRANSIENT_NETWORK,),
    )

    mismatched = store.register_task(
        mission.mission_id,
        "agent",
        "mismatched",
        retry_policy=timeout_policy,
    )
    _update_task(store, mismatched.task_id, retry_policy_key="")
    with pytest.raises(MissionStoreError, match="retry policy conflicts"):
        _reconcile(
            store,
            mismatched.task_id,
            store._prepare_task_metadata(None, None, network_policy),
        )

    matching = store.register_task(
        mission.mission_id,
        "agent",
        "matching",
        retry_policy=timeout_policy,
    )
    _update_task(store, matching.task_id, retry_policy_key="")
    row = _reconcile(
        store,
        matching.task_id,
        store._prepare_task_metadata(None, None, timeout_policy),
    )
    assert row["retry_policy_key"]
    assert (
        _reconcile(
            store,
            matching.task_id,
            store._prepare_task_metadata(None, None, timeout_policy),
        )["retry_policy_key"]
        == row["retry_policy_key"]
    )

    empty = store.register_task(mission.mission_id, "agent", "empty")
    row = _reconcile(
        store,
        empty.task_id,
        store._prepare_task_metadata(None, None, timeout_policy),
    )
    assert row["retry_budget"] == 1


def test_reconcile_legacy_backoff_reference_and_not_before_paths(
    tmp_path: Path,
) -> None:
    store = _store(tmp_path, "reconcile-other")
    mission = _mission(store, "reconcile-other")
    fixed_two = TaskBackoff(
        strategy=BackoffStrategy.FIXED,
        base_delay_seconds=2,
    )
    fixed_three = TaskBackoff(
        strategy=BackoffStrategy.FIXED,
        base_delay_seconds=3,
    )

    keyed = store.register_task(
        mission.mission_id,
        "agent",
        "keyed-backoff",
        backoff=fixed_two,
    )
    with pytest.raises(MissionStoreError, match="backoff conflicts"):
        _reconcile(
            store,
            keyed.task_id,
            store._prepare_task_metadata(None, None, None, backoff=fixed_three),
        )

    conflicting = store.register_task(
        mission.mission_id,
        "agent",
        "conflicting-backoff",
        backoff=fixed_two,
    )
    _update_task(store, conflicting.task_id, backoff_key="")
    with pytest.raises(MissionStoreError, match="backoff conflicts"):
        _reconcile(
            store,
            conflicting.task_id,
            store._prepare_task_metadata(None, None, None, backoff=fixed_three),
        )

    matching = store.register_task(
        mission.mission_id,
        "agent",
        "matching-backoff",
        backoff=fixed_two,
    )
    _update_task(store, matching.task_id, backoff_key="")
    assert _reconcile(
        store,
        matching.task_id,
        store._prepare_task_metadata(None, None, None, backoff=fixed_two),
    )["backoff_key"]
    assert _reconcile(
        store,
        matching.task_id,
        store._prepare_task_metadata(None, None, None, backoff=fixed_two),
    )["backoff_key"]

    default = store.register_task(mission.mission_id, "agent", "default-backoff")
    assert _reconcile(
        store,
        default.task_id,
        store._prepare_task_metadata(None, None, None, backoff=fixed_two),
    )["backoff_key"]

    referenced = store.register_task(
        mission.mission_id,
        "agent",
        "referenced",
        provider_circuit_ref="provider://one",
    )
    with pytest.raises(MissionStoreError, match="provider_circuit_ref conflicts"):
        _reconcile(
            store,
            referenced.task_id,
            store._prepare_task_metadata(
                None,
                None,
                None,
                provider_circuit_ref="provider://two",
            ),
        )
    assert (
        _reconcile(
            store,
            referenced.task_id,
            store._prepare_task_metadata(
                None,
                None,
                None,
                provider_circuit_ref="provider://one",
            ),
        )["provider_circuit_ref"]
        == "provider://one"
    )

    empty_refs = store.register_task(mission.mission_id, "agent", "empty-refs")
    row = _reconcile(
        store,
        empty_refs.task_id,
        store._prepare_task_metadata(
            None,
            None,
            None,
            provider_circuit_ref="provider://one",
            evaluated_snapshot_ref="snapshot://one",
        ),
    )
    assert row["provider_circuit_ref"] == "provider://one"
    assert row["evaluated_snapshot_ref"] == "snapshot://one"

    no_gate = store.register_task(mission.mission_id, "agent", "no-gate")
    assert (
        _reconcile(
            store,
            no_gate.task_id,
            store._prepare_task_metadata(None, None, None, not_before=10),
        )["not_before"]
        == 10
    )

    gate = store.register_task(
        mission.mission_id,
        "agent",
        "gate",
        not_before=10,
    )
    with pytest.raises(MissionStoreError, match="not_before conflicts"):
        _reconcile(
            store,
            gate.task_id,
            store._prepare_task_metadata(None, None, None, not_before=20),
        )
    assert (
        _reconcile(
            store,
            gate.task_id,
            store._prepare_task_metadata(None, None, None, not_before=10),
        )["not_before"]
        == 10
    )
    _update_task(store, gate.task_id, attempt_count=1)
    assert (
        _reconcile(
            store,
            gate.task_id,
            store._prepare_task_metadata(None, None, None, not_before=20),
        )["not_before"]
        == 10
    )


def test_dependency_reference_coercion_and_task_id_validation(tmp_path: Path) -> None:
    store = _store(tmp_path, "dependency-task-id")
    mission = _mission(store, "dependency-task-id")
    scoped = store.register_task(
        mission.mission_id,
        "agent",
        "scoped",
        scope="one",
    )

    with pytest.raises(MissionStoreError, match="task dependencies must"):
        store._coerce_task_dependency("agent:task")
    with pytest.raises(MissionStoreError, match="task dependencies must"):
        store._coerce_task_dependency(object())
    assert store._coerce_task_dependency(("agent", "task")) == TaskDependencyRef(
        agent="agent",
        task="task",
    )

    with store._connection() as conn:
        with pytest.raises(MissionStoreError, match="unknown dependency task_id"):
            store._resolve_dependency_row(
                conn,
                mission.mission_id,
                TaskDependencyRef(task_id="missing"),
            )
        with pytest.raises(MissionStoreError, match="supplied together"):
            store._resolve_dependency_row(
                conn,
                mission.mission_id,
                TaskDependencyRef(agent="agent", task_id=scoped.task_id),
            )
        with pytest.raises(MissionStoreError, match="identity does not match"):
            store._resolve_dependency_row(
                conn,
                mission.mission_id,
                TaskDependencyRef(
                    agent="other",
                    task="scoped",
                    task_id=scoped.task_id,
                ),
            )
        with pytest.raises(MissionStoreError, match="definition version does not match"):
            store._resolve_dependency_row(
                conn,
                mission.mission_id,
                TaskDependencyRef(
                    task_id=scoped.task_id,
                    task_definition_version="2.0",
                ),
            )
        with pytest.raises(MissionStoreError, match="scope does not match"):
            store._resolve_dependency_row(
                conn,
                mission.mission_id,
                TaskDependencyRef(task_id=scoped.task_id, scope="two"),
            )
        resolved = store._resolve_dependency_row(
            conn,
            mission.mission_id,
            TaskDependencyRef(
                agent="agent",
                task="scoped",
                task_id=scoped.task_id,
                scope="one",
                task_definition_version="1.0",
            ),
        )
        resolved_without_selectors = store._resolve_dependency_row(
            conn,
            mission.mission_id,
            TaskDependencyRef(task_id=scoped.task_id),
        )
    assert resolved["task_id"] == scoped.task_id
    assert resolved_without_selectors["task_id"] == scoped.task_id


def test_dependency_reference_identity_scope_version_and_ambiguity(
    tmp_path: Path,
) -> None:
    store = _store(tmp_path, "dependency-selectors")
    mission = _mission(store, "dependency-selectors")
    store.register_task(mission.mission_id, "agent", "versioned")
    store.register_task(mission.mission_id, "agent", "ambiguous", scope="one")
    store.register_task(mission.mission_id, "agent", "ambiguous", scope="two")

    with store._connection() as conn:
        with pytest.raises(MissionStoreError, match="agent and task are required"):
            store._resolve_dependency_row(
                conn,
                mission.mission_id,
                TaskDependencyRef(agent="agent"),
            )
        with pytest.raises(MissionStoreError, match="unknown dependency scope"):
            store._resolve_dependency_row(
                conn,
                mission.mission_id,
                TaskDependencyRef(agent="agent", task="missing", scope="one"),
            )
        with pytest.raises(MissionStoreError, match="unknown dependency"):
            store._resolve_dependency_row(
                conn,
                mission.mission_id,
                TaskDependencyRef(
                    agent="agent",
                    task="versioned",
                    task_definition_version="2.0",
                ),
            )
        with pytest.raises(MissionStoreError, match="scope-ambiguous dependency"):
            store._resolve_dependency_row(
                conn,
                mission.mission_id,
                TaskDependencyRef(agent="agent", task="ambiguous"),
            )


def test_task_selector_and_dependency_edge_failures(tmp_path: Path) -> None:
    store = _store(tmp_path, "dependency-edges")
    mission = _mission(store, "dependency-edges")
    own = store.register_task(mission.mission_id, "agent", "own")
    store.register_task(mission.mission_id, "agent", "other")

    with store._connection() as conn:
        with pytest.raises(MissionStoreError, match="unknown mission task"):
            store._resolve_task_row(
                conn,
                mission.mission_id,
                "agent",
                "own",
                task_id="missing",
            )
        with pytest.raises(MissionStoreError, match="unknown mission task"):
            store._resolve_task_row(
                conn,
                mission.mission_id,
                "agent",
                "own",
                task_id=store.register_task(
                    mission.mission_id,
                    "agent",
                    "other",
                ).task_id,
            )
        with pytest.raises(MissionStoreError, match="unknown mission task scope"):
            store._resolve_task_row(
                conn,
                mission.mission_id,
                "agent",
                "own",
                scope="missing",
            )

    with pytest.raises(MissionStoreError, match="unknown dependency"):
        store.register_task(
            mission.mission_id,
            "agent",
            "unknown-edge",
            depends_on=("missing",),
        )
    with pytest.raises(MissionStoreError, match="cannot depend on itself"):
        store.register_task(
            mission.mission_id,
            own.agent,
            own.task,
            depends_on=(own.task_id,),
        )

    prerequisite = store.register_task(mission.mission_id, "agent", "prerequisite")
    dependent = store.register_task(
        mission.mission_id,
        "agent",
        "dependent",
        depends_on=(prerequisite.task_id,),
    )
    with pytest.raises(TaskDependenciesIncomplete) as exc_info:
        store.begin_attempt(mission.mission_id, dependent.agent, dependent.task)
    assert exc_info.value.incomplete == ((prerequisite.task_id, "pending"),)


@pytest.mark.parametrize("existing", [{"attempt_id": "existing"}, None])
def test_begin_attempt_integrity_error_race_paths(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    existing,
) -> None:
    store = _store(tmp_path, "attempt-race")
    task_row = {
        "task_id": "task-id",
        "status": "pending",
        "attempt_count": 0,
        "not_before": None,
    }

    class FakeConnection:
        def execute(self, statement: str, _parameters=()):
            if "INSERT INTO mission_task_attempts" in statement:
                raise sqlite3.IntegrityError("simulated concurrent insert")
            assert "SELECT * FROM mission_task_attempts" in statement
            return SimpleNamespace(fetchone=lambda: existing)

    @contextmanager
    def fake_transaction() -> Iterator[FakeConnection]:
        yield FakeConnection()

    monkeypatch.setattr(store, "_transaction", fake_transaction)
    monkeypatch.setattr(store, "_require_running_mission", lambda *_args: None)
    monkeypatch.setattr(store, "_resolve_task_row", lambda *_args, **_kwargs: task_row)
    monkeypatch.setattr(store, "_require_dependencies_completed", lambda *_args: None)
    monkeypatch.setattr(store, "_attempt_from_row", lambda row: row)

    if existing is None:
        with pytest.raises(sqlite3.IntegrityError, match="simulated concurrent insert"):
            store.begin_attempt("mission", "agent", "task")
    else:
        assert store.begin_attempt("mission", "agent", "task") is existing
