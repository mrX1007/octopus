"""Exact branch coverage for public mission lifecycle value objects."""

from __future__ import annotations

from dataclasses import replace

import pytest

from core.ai import mission_store_models as models
from core.ai.outcomes import TaskOutcome

pytestmark = pytest.mark.unit


def _entity(index: int = 0, *, kind: str = "asset") -> str:
    return f"{kind}:v1:{index:032x}"


def _mission() -> models.MissionRecord:
    return models.MissionRecord(
        mission_id="mission",
        scan_id="scan",
        target="target",
        status=models.MissionStatus.RUNNING.value,
        reason="",
        created_at=1.0,
        updated_at=2.0,
        started_at=1.0,
        finished_at=None,
        run_count=1,
    )


def _task(**overrides) -> models.TaskRecord:
    values = {
        "task_id": "task-id",
        "mission_id": "mission",
        "agent": "agent",
        "task": "task",
        "status": models.TaskStatus.PENDING.value,
        "reason": "",
        "depends_on": (),
        "created_at": 1.0,
        "updated_at": 2.0,
        "started_at": None,
        "finished_at": None,
        "attempt_count": 0,
    }
    values.update(overrides)
    return models.TaskRecord(**values)


def _outcome(task: str = "task") -> TaskOutcome:
    return TaskOutcome(
        agent="agent",
        task=task,
        status="completed",
        reason="done",
        new_facts=1,
        parsed_facts=1,
        commands=({"command": "fixture", "failed": False},),
        duration=1.0,
    )


def _attempt(
    *,
    attempt_id: str = "attempt",
    outcome: TaskOutcome | None = None,
) -> models.TaskAttemptRecord:
    return models.TaskAttemptRecord(
        attempt_id=attempt_id,
        task_id="task-id",
        mission_id="mission",
        attempt_number=1,
        status=models.TaskStatus.COMPLETED.value,
        reason="done",
        started_at=1.0,
        finished_at=2.0,
        outcome=outcome,
        execution_ids=(),
        fact_ids=(),
    )


def test_dependency_and_not_ready_errors_preserve_structured_details() -> None:
    empty = models.TaskDependenciesIncomplete([])
    assert empty.incomplete == ()
    assert str(empty).endswith(": ")

    error = models.TaskDependenciesIncomplete(
        [("one", models.TaskStatus.PENDING.value), ("two", models.TaskStatus.RUNNING.value)]
    )
    assert error.incomplete == (("one", "pending"), ("two", "running"))
    assert "one:pending,two:running" in str(error)

    waiting = models.TaskNotReady("task", 10.0, 4.0)
    assert waiting.task_id == "task"
    assert waiting.not_before == 10.0
    assert waiting.remaining_seconds == 6.0
    elapsed = models.TaskNotReady("task", 2.0, 4.0)
    assert elapsed.remaining_seconds == 0.0


def test_task_scope_normalizes_serializes_and_supports_legacy_values() -> None:
    first = _entity(1)
    second = _entity(2, kind="service")
    scope = models.TaskScope(
        entity_ids=(second, "", first, first),
        legacy_scope=" display ",
    )
    assert scope.entity_ids == (first, second)
    assert scope.canonical_entity_ids == (first, second)
    assert scope.legacy_scope == " display "
    assert scope.to_dict() == {
        "schema_version": models.TASK_SCOPE_SCHEMA_VERSION,
        "entity_ids": [first, second],
        "legacy_scope": " display ",
    }
    assert models.TaskScope.from_legacy("legacy").legacy_scope == "legacy"
    assert models.TaskScope.from_legacy(None).legacy_scope == ""
    assert models.TaskScope(legacy_scope=None).legacy_scope == ""


def test_task_scope_rejects_schema_identity_count_and_size_violations(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with pytest.raises(models.MissionStoreError, match="unsupported task scope"):
        models.TaskScope(schema_version="2.0")
    with pytest.raises(models.MissionStoreError, match="canonical graph identities"):
        models.TaskScope(entity_ids=("display-name",))

    too_many = tuple(_entity(index) for index in range(models._MAX_SCOPE_ENTITIES + 1))
    with pytest.raises(models.MissionStoreError, match="exceeds"):
        models.TaskScope(entity_ids=too_many)

    monkeypatch.setattr(
        models,
        "validate_canonical_entity_id",
        lambda _value: "x" * (models._MAX_IDENTIFIER_BYTES + 1),
    )
    with pytest.raises(models.MissionStoreError, match="entity id is too large"):
        models.TaskScope(entity_ids=("fixture",))

    with pytest.raises(models.MissionStoreError, match="legacy task scope is too large"):
        models.TaskScope(legacy_scope="x" * (models._MAX_IDENTIFIER_BYTES + 1))


@pytest.mark.parametrize(
    ("kwargs", "message"),
    [
        ({"strategy": "invalid"}, "invalid task backoff"),
        ({"base_delay_seconds": object()}, "invalid task backoff"),
        ({"base_delay_seconds": float("nan")}, "must be finite"),
        ({"max_delay_seconds": float("inf")}, "must be finite"),
        ({"base_delay_seconds": -1}, "cannot be negative"),
        ({"max_delay_seconds": -1}, "cannot be negative"),
        ({"base_delay_seconds": models._MAX_BACKOFF_SECONDS + 1}, "cannot exceed"),
        (
            {"strategy": models.BackoffStrategy.NONE, "base_delay_seconds": 1},
            "none backoff cannot define",
        ),
        (
            {"strategy": models.BackoffStrategy.NONE, "max_delay_seconds": 1},
            "none backoff cannot define",
        ),
        (
            {"strategy": models.BackoffStrategy.FIXED, "base_delay_seconds": 0},
            "fixed backoff requires",
        ),
        (
            {
                "strategy": models.BackoffStrategy.FIXED,
                "base_delay_seconds": 2,
                "max_delay_seconds": 3,
            },
            "fixed backoff maximum",
        ),
        (
            {"strategy": models.BackoffStrategy.EXPONENTIAL, "base_delay_seconds": 0},
            "exponential backoff requires",
        ),
        (
            {
                "strategy": models.BackoffStrategy.EXPONENTIAL,
                "base_delay_seconds": 3,
                "max_delay_seconds": 2,
            },
            "cannot be below",
        ),
        (
            {
                "strategy": models.BackoffStrategy.EXPONENTIAL,
                "base_delay_seconds": 1,
                "multiplier": 0.5,
            },
            "between 1 and 100",
        ),
        (
            {
                "strategy": models.BackoffStrategy.EXPONENTIAL,
                "base_delay_seconds": 1,
                "multiplier": 101,
            },
            "between 1 and 100",
        ),
    ],
)
def test_task_backoff_rejects_invalid_policies(kwargs: dict, message: str) -> None:
    with pytest.raises(models.MissionStoreError, match=message):
        models.TaskBackoff(**kwargs)


def test_task_backoff_normalizes_and_calculates_bounded_delays() -> None:
    none = models.TaskBackoff()
    assert none.strategy is models.BackoffStrategy.NONE
    assert none.delay_for_retry(0) == 0.0
    assert none.delay_for_retry(1) == 0.0
    assert none.to_dict() == {
        "strategy": "none",
        "base_delay_seconds": 0.0,
        "max_delay_seconds": 0.0,
        "multiplier": 2.0,
    }
    assert models.TaskBackoffPolicy is models.TaskBackoff

    fixed = models.TaskBackoff(
        strategy="fixed",
        base_delay_seconds="2",
    )
    assert fixed.strategy is models.BackoffStrategy.FIXED
    assert fixed.max_delay_seconds == 2.0
    assert fixed.multiplier == 1.0
    assert fixed.delay_for_retry(1) == 2.0

    exponential = models.TaskBackoff(
        strategy=models.BackoffStrategy.EXPONENTIAL,
        base_delay_seconds=2,
        multiplier=3,
    )
    assert exponential.max_delay_seconds == 2.0
    assert exponential.delay_for_retry(1) == 2.0
    capped = models.TaskBackoff(
        strategy="exponential",
        base_delay_seconds=1,
        max_delay_seconds=100,
        multiplier=2,
    )
    assert capped.delay_for_retry(3) == 4.0
    assert capped.delay_for_retry(1000) == 100.0


def test_canonical_capability_id_is_normalized_bounded_and_stable() -> None:
    first = models.canonical_capability_id("  Service   Discovery ")
    second = models.canonical_capability_id("service discovery")
    assert first == second
    assert first.startswith("capability:v1:")
    assert len(first.rsplit(":", 1)[1]) == 32
    with pytest.raises(models.MissionStoreError, match="source is required"):
        models.canonical_capability_id("")
    with pytest.raises(models.MissionStoreError, match="source is too large"):
        models.canonical_capability_id("x" * (models._MAX_IDENTIFIER_BYTES + 1))


@pytest.mark.parametrize("retry_budget", [True, 1.5, "1"])
def test_retry_policy_requires_integer_budget(retry_budget) -> None:
    with pytest.raises(models.MissionStoreError, match="must be an integer"):
        models.TaskRetryPolicy(retry_budget=retry_budget)


@pytest.mark.parametrize("retry_budget", [-1, models._MAX_RETRY_BUDGET + 1])
def test_retry_policy_bounds_budget(retry_budget: int) -> None:
    with pytest.raises(models.MissionStoreError, match="must be between"):
        models.TaskRetryPolicy(retry_budget=retry_budget)


def test_retry_policy_normalizes_classes_and_rejects_inconsistent_values() -> None:
    with pytest.raises(models.MissionStoreError, match="unsupported retry error class"):
        models.TaskRetryPolicy(retry_budget=1, retryable_error_classes=("unknown",))
    with pytest.raises(models.MissionStoreError, match="positive retry_budget requires"):
        models.TaskRetryPolicy(retry_budget=1)
    with pytest.raises(models.MissionStoreError, match="require a positive retry_budget"):
        models.TaskRetryPolicy(
            retryable_error_classes=(models.RetryErrorClass.TIMEOUT,),
        )

    empty = models.TaskRetryPolicy()
    assert empty.retryable_error_classes == ()
    policy = models.TaskRetryPolicy(
        retry_budget=2,
        retryable_error_classes=(
            "timeout",
            models.RetryErrorClass.TIMEOUT,
            models.RetryErrorClass.RATE_LIMIT,
        ),
    )
    assert policy.retryable_error_classes == (
        models.RetryErrorClass.TIMEOUT,
        models.RetryErrorClass.RATE_LIMIT,
    )


def test_definition_records_properties_and_result_value_objects() -> None:
    scope = models.TaskScope(entity_ids=(_entity(1),))
    dependency = models.TaskDependencyRef(
        agent="agent",
        task="parent",
        scope=scope,
        task_definition_version="1.0",
    )
    retry = models.TaskRetryPolicy(
        retry_budget=1,
        retryable_error_classes=(models.RetryErrorClass.TIMEOUT,),
    )
    definition = models.MissionTaskDefinition(
        agent="agent",
        task="task",
        depends_on=(dependency, ("legacy-agent", "legacy-task")),
        scope=scope,
        capability="Capability",
        capability_id=models.canonical_capability_id("Capability"),
        retry_policy=retry,
    )
    assert definition.scope is scope

    task = _task(task_scope=scope, task_definition_version="2.0")
    assert task.scope_entity_ids == (_entity(1),)
    assert task.definition_version == "2.0"
    assert replace(task, status=models.TaskStatus.COMPLETED.value).status == "completed"

    attempt = _attempt(outcome=_outcome())
    completion = models.AttemptCompletionResult(
        attempt=attempt,
        task=task,
        retry_scheduled=True,
        retry_command_keys=("one",),
    )
    assert completion.retry_scheduled
    replan = models.StateReplanResult(
        requested=True,
        reason="state changed",
        count=1,
        signatures=("signature",),
    )
    assert replan.signatures == ("signature",)


def test_mission_snapshot_returns_only_present_outcomes_in_attempt_order() -> None:
    first = _attempt(attempt_id="one", outcome=_outcome("one"))
    missing = _attempt(attempt_id="missing", outcome=None)
    second = _attempt(attempt_id="two", outcome=_outcome("two"))
    snapshot = models.MissionSnapshot(
        mission=_mission(),
        tasks=(_task(),),
        attempts=(first, missing, second),
    )
    assert [item["task"] for item in snapshot.task_outcomes] == ["one", "two"]
    assert models.MissionSnapshot(_mission(), (), ()).task_outcomes == ()


def test_public_types_keep_historical_import_identity() -> None:
    assert models.TaskScope.__module__ == "core.ai.mission_store"
    assert models.MissionSnapshot.__module__ == "core.ai.mission_store"
    assert models.canonical_capability_id.__module__ == "core.ai.mission_store"
    assert "TaskBackoffPolicy" in models.__all__
