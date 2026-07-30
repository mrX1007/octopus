"""Hermetic defensive-path coverage for the durable mission mixin."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest

import config
import core.ai.pipeline_mission as mission_module
from core.ai.mission_store import (
    TASK_DEFINITION_SCHEMA_VERSION,
    RetryErrorClass,
    TaskBackoff,
    TaskDependenciesIncomplete,
    TaskDependencyRef,
    TaskScope,
)
from core.ai.pipeline_mission import PipelineMissionMixin
from core.knowledge.identity import canonical_asset

pytestmark = [pytest.mark.contract, pytest.mark.security]


class Recorder:
    def __init__(self) -> None:
        self.items: list[Any] = []

    def record(self, value: Any) -> None:
        self.items.append(value)


class MissionHarness(PipelineMissionMixin):
    def __init__(self, store: Any = None, *, mission_id: str = "mission") -> None:
        self.mission_store = store
        self.mission_id = mission_id
        self._current_scan_id = "scan"
        self._current_target = "10.0.0.5"
        self._state_replan_count = 0
        self._state_replan_signatures: set[str] = set()
        self._mission_was_completed = False
        self._mission_was_resumed = False
        self._active_task_attempt_id = None
        self._active_task_id = None
        self._active_task_name = ""
        self._active_task_agent = ""
        self._active_retry_command_keys: set[str] = set()
        self.task_history: list[str] = []
        self.retry_scheduled_tasks: set[str] = set()
        self.blocked_tasks: set[str] = set()
        self.completed_tasks: set[str] = set()
        self.executed_command_keys: set[str] = set()
        self.exhausted_tasks: set[str] = set()
        self.task_outcome_store = Recorder()
        self.decision_trace = Recorder()
        self.tools_run_count = 0
        self.total_new_facts = 0

    def _task_exhausted(self, task: str) -> bool:
        return task in self.exhausted_tasks


def _record(
    task_id: str,
    task: str,
    *,
    agent: str = "Agent",
    status: str = "pending",
    depends_on: tuple[str, ...] = (),
    scope: TaskScope | None = None,
    version: str = TASK_DEFINITION_SCHEMA_VERSION,
    attempt_count: int = 0,
    retry_count: int = 0,
    not_before: float | None = None,
) -> SimpleNamespace:
    task_scope = scope or TaskScope.from_legacy("target:10.0.0.5")
    return SimpleNamespace(
        task_id=task_id,
        mission_id="mission",
        agent=agent,
        task=task,
        status=status,
        reason="",
        depends_on=depends_on,
        attempt_count=attempt_count,
        retry_count=retry_count,
        scope=task_scope.legacy_scope,
        task_scope=task_scope,
        capability=task,
        capability_id="",
        task_definition_version=version,
        retry_budget=0,
        retryable_error_classes=(),
        not_before=not_before,
        backoff=TaskBackoff(),
        provider_circuit_ref="",
        evaluated_snapshot_ref="",
    )


class CapturePlanStore:
    def __init__(self, tasks: list[Any] | None = None) -> None:
        self.initial_tasks = list(tasks or [])
        self.current_tasks = list(self.initial_tasks)
        self.attempts: list[Any] = []
        self.definitions: list[Any] = []
        self.registered = False

    def snapshot(self, _mission_id: str) -> SimpleNamespace:
        tasks = self.current_tasks if self.registered else self.initial_tasks
        return SimpleNamespace(tasks=tuple(tasks), attempts=tuple(self.attempts))

    def register_plan(
        self,
        _mission_id: str,
        definitions,
        *,
        blocked_reasons_by_position=None,
        blocked_reasons=None,
    ) -> tuple[Any, ...]:
        self.definitions = list(definitions)
        blocked_positions = set((blocked_reasons_by_position or {}).keys())
        block_all = bool(blocked_reasons)
        records = []
        for position, definition in enumerate(self.definitions):
            existing = next(
                (
                    item
                    for item in self.initial_tasks
                    if item.agent == definition.agent and item.task == definition.task
                ),
                None,
            )
            records.append(
                _record(
                    existing.task_id if existing is not None else f"new-{position}",
                    definition.task,
                    agent=definition.agent,
                    status=(
                        "blocked"
                        if block_all or position in blocked_positions
                        else "pending"
                    ),
                    scope=(
                        definition.scope
                        if isinstance(definition.scope, TaskScope)
                        else TaskScope.from_legacy(str(definition.scope))
                    ),
                    version=definition.task_definition_version,
                    not_before=definition.not_before,
                )
            )
        self.current_tasks = records
        self.registered = True
        return tuple(records)


def _registration_harness(store: CapturePlanStore) -> MissionHarness:
    pipeline = MissionHarness(store)
    pipeline._ordered_mission_plan = lambda *_args, **_kwargs: []
    return pipeline


def test_start_mission_restores_retry_counts_results_and_check_keys() -> None:
    outcome = object()
    mission = SimpleNamespace(
        mission_id="mission",
        status="running",
        run_count=2,
        state_replan_count=1,
        state_replan_signatures=("prior",),
    )
    previous = SimpleNamespace(status="interrupted")
    tasks = (
        _record(
            "retry",
            "retry-task",
            status="interrupted",
            attempt_count=1,
            retry_count=1,
        ),
        _record("blocked", "blocked-task", status="blocked"),
        _record("done", "done-task", status="completed"),
    )
    attempts = (
        SimpleNamespace(outcome=outcome, execution_ids=("exec-one", "")),
        SimpleNamespace(outcome=None, execution_ids=()),
    )
    store = SimpleNamespace(
        get_mission_by_scan_id=lambda _scan_id: previous,
        open_mission=lambda *_args, **_kwargs: mission,
        snapshot=lambda _mission_id: SimpleNamespace(tasks=tasks, attempts=attempts),
    )
    pipeline = MissionHarness(store, mission_id="")
    pipeline.fact_store = SimpleNamespace(
        get_facts=lambda *_args: [
            {"type": "other", "value": "ignored"},
            {"type": "check_result", "value": "{"},
            {
                "type": "check_result",
                "value": '{"command_key":"completed-key","status":"completed"}',
            },
            {
                "type": "check_result",
                "value": '{"command_key":"running-key","status":"running"}',
            },
        ],
        get_command_results=lambda *_args: [
            {"execution_id": "exec-one", "command_key": "result-key"},
            {"execution_id": "exec-two", "command_key": ""},
            {"execution_id": "", "command_key": "legacy-key"},
        ],
    )

    assert pipeline._start_mission("scan", "10.0.0.5") is mission
    assert pipeline.retry_scheduled_tasks == {"retry-task"}
    assert pipeline.blocked_tasks == {"blocked-task"}
    assert pipeline.completed_tasks == {"done-task"}
    assert pipeline.task_outcome_store.items == [outcome]
    assert pipeline.tools_run_count == 3
    assert pipeline.executed_command_keys == {
        "result-key",
        "legacy-key",
        "completed-key",
    }


def test_register_plan_guards_invalid_ids_missing_steps_and_duplicates() -> None:
    plan = [{"agent": "Agent", "task": "task"}]
    no_mission = MissionHarness(mission_id="")
    assert no_mission._register_mission_plan(plan) is plan

    existing = _record("known", "task")
    explicit = _registration_harness(CapturePlanStore([existing]))
    with pytest.raises(ValueError, match="ordered mission plan"):
        explicit._register_mission_plan(
            [{"agent": "Wrong", "task": "task", "task_id": "known"}]
        )

    invalid = _registration_harness(CapturePlanStore([existing]))
    with pytest.raises(ValueError, match="mission plan contains"):
        invalid._register_mission_plan(
            [
                {"agent": "Agent", "task": "task", "task_id": "missing"},
                {"agent": "Other", "task": "new"},
            ]
        )

    valid_store = CapturePlanStore([existing])
    valid = _registration_harness(valid_store)
    valid._register_mission_plan(
        [
            {"agent": "Agent", "task": "task", "task_id": "known"},
            {"agent": "Other", "task": "new"},
        ]
    )
    assert {item.task for item in valid_store.definitions} == {"task", "new"}

    deduplicated_store = CapturePlanStore()
    deduplicated = _registration_harness(deduplicated_store)
    deduplicated._register_mission_plan(
        [
            {"agent": "", "task": "ignored"},
            {"agent": "Agent", "task": ""},
            {"agent": "Agent", "task": "same"},
            {"agent": "Agent", "task": "same"},
        ]
    )
    assert [item.task for item in deduplicated_store.definitions] == ["same"]


def test_register_plan_resolves_all_dependency_shapes_and_propagates_rejection() -> None:
    scope_x = TaskScope.from_legacy("scope:x")
    scope_y = TaskScope.from_legacy("scope:y")
    existing = _record("existing-id", "existing", agent="Existing")
    store = CapturePlanStore([existing])
    pipeline = _registration_harness(store)

    pipeline._register_mission_plan(
        [
            {
                "agent": "Existing",
                "task": "existing",
                "task_id": "existing-id",
            },
            {
                "agent": "A",
                "task": "shared",
                "task_scope": scope_x,
                "task_definition_version": "older",
            },
            {"agent": "B", "task": "shared", "task_scope": scope_y},
            {
                "agent": "Child",
                "task": "by-string",
                "task_scope": scope_x,
                "depends_on": "shared",
            },
            {
                "agent": "Child",
                "task": "by-reference",
                "task_scope": scope_x,
                "depends_on": [
                    TaskDependencyRef(
                        agent="A",
                        task="shared",
                        scope=scope_x,
                        task_definition_version="older",
                    )
                ],
            },
            {
                "agent": "Child",
                "task": "by-dict",
                "depends_on": [
                    {
                        "agent": "A",
                        "task": "shared",
                        "task_scope": scope_x,
                        "task_definition_version": "older",
                    }
                ],
            },
            {
                "agent": "Child",
                "task": "by-pair",
                "depends_on": [("B", "shared")],
            },
            {
                "agent": "Child",
                "task": "by-id",
                "depends_on": ["existing-id"],
            },
            {
                "agent": "Child",
                "task": "by-colon",
                "depends_on": ["A:shared"],
            },
            {
                "agent": "Child",
                "task": "incomplete-reference",
                "depends_on": [TaskDependencyRef()],
            },
            {
                "agent": "Child",
                "task": "invalid-parent",
                "depends_on": ["missing-task"],
            },
            {
                "agent": "Child",
                "task": "invalid-child",
                "depends_on": "invalid-parent",
            },
        ]
    )

    blocked = {item.task for item in store.current_tasks if item.status == "blocked"}
    assert {"invalid-parent", "invalid-child"} <= blocked
    assert {"invalid-parent", "invalid-child"} <= pipeline.blocked_tasks


def test_scope_backoff_and_config_validation_paths(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    pipeline = MissionHarness()
    entity_id = canonical_asset("10.0.0.5").entity_id

    direct = pipeline._mission_task_scope(
        {"entity_ids": entity_id, "scope": {"kind": "host"}}
    )
    assert direct.entity_ids == (entity_id,)
    assert direct.legacy_scope == '{"kind":"host"}'
    assert pipeline._mission_task_scope(
        {"canonical_entity_ids": [entity_id]}
    ).entity_ids == (entity_id,)

    monkeypatch.setattr(
        mission_module,
        "canonical_asset",
        lambda _target: (_ for _ in ()).throw(ValueError("invalid target")),
    )
    assert pipeline._mission_task_scope({}).legacy_scope == "target:10.0.0.5"

    mapped = pipeline._mission_task_scope(
        {
            "task_scope": {
                "canonical_entity_ids": entity_id,
                "legacy_scope": "alias",
            }
        }
    )
    assert mapped.entity_ids == (entity_id,)
    assert mapped.legacy_scope == "alias"
    assert pipeline._legacy_scope_text("scalar") == "scalar"

    backoff = TaskBackoff()
    assert pipeline._mission_task_backoff({"backoff": backoff}) is backoff
    with pytest.raises(ValueError, match="must be a TaskBackoff"):
        pipeline._mission_task_backoff({"backoff": {}})

    monkeypatch.setattr(
        config,
        "CFG",
        {
            "strategy": {
                "mission": {
                    "task_retry_budget": "1",
                    "retryable_error_classes": "timeout",
                }
            }
        },
    )
    policy = pipeline._mission_task_retry_policy()
    assert policy.retry_budget == 1
    assert policy.retryable_error_classes == (RetryErrorClass.TIMEOUT,)

    monkeypatch.setattr(
        config,
        "CFG",
        {"strategy": {"mission": {"task_retry_budget": "invalid"}}},
    )
    with pytest.raises(ValueError, match="task_retry_budget must be an integer"):
        pipeline._mission_task_retry_policy()

    monkeypatch.setattr(
        config,
        "CFG",
        {"strategy": {"mission": {"max_state_replans": "500"}}},
    )
    assert pipeline._max_state_replans() == 100
    monkeypatch.setattr(
        config,
        "CFG",
        {"strategy": {"mission": {"max_state_replans": "invalid"}}},
    )
    with pytest.raises(ValueError, match="max_state_replans must be an integer"):
        pipeline._max_state_replans()


def test_state_replan_handles_memory_budget_request_and_durable_duplicate() -> None:
    previous = {"state": "old"}
    current = {"state": "new"}

    exhausted = MissionHarness(mission_id="")
    exhausted.context_builder = SimpleNamespace(
        build_context=lambda *_args: current
    )
    exhausted._max_state_replans = lambda: 0
    assert exhausted._evaluate_state_change_replan(previous, "scan", "target") is False
    assert exhausted.decision_trace.items[-1]["event_type"] == "state_replan_rejected"

    requested = MissionHarness(mission_id="")
    requested.context_builder = SimpleNamespace(
        build_context=lambda *_args: current
    )
    requested._max_state_replans = lambda: 1
    assert requested._evaluate_state_change_replan(previous, "scan", "target") is True
    assert requested._state_replan_count == 1

    def duplicate(_mission_id: str, signature: str, _maximum: int):
        return SimpleNamespace(
            count=1,
            signatures=(signature,),
            reason="duplicate_transition",
            requested=False,
        )

    durable = MissionHarness(
        SimpleNamespace(record_state_replan=duplicate),
        mission_id="mission",
    )
    durable.context_builder = SimpleNamespace(build_context=lambda *_args: current)
    durable._max_state_replans = lambda: 1
    assert durable._evaluate_state_change_replan(previous, "scan", "target") is False


def test_ordered_plan_supports_name_selection_edges_and_cycle_detection(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    no_mission = MissionHarness(mission_id="")
    assert no_mission._ordered_mission_plan() == []

    monkeypatch.setattr(mission_module.time, "time", lambda: 100.0)
    parent_one = _record("p1", "parent-one", status="completed")
    parent_two = _record("p2", "parent-two", status="completed")
    child = _record(
        "child",
        "child",
        status="pending",
        depends_on=("p1", "p2"),
    )
    pipeline = MissionHarness(
        SimpleNamespace(
            snapshot=lambda _mission_id: SimpleNamespace(
                tasks=(parent_one, parent_two, child)
            )
        )
    )
    ordered = pipeline._ordered_mission_plan(
        task_names=["parent-one", "parent-two", "child"]
    )
    assert [item["task_id"] for item in ordered] == ["p1", "p2", "child"]

    first = _record("a", "cycle-a", status="completed", depends_on=("b",))
    second = _record("b", "cycle-b", status="completed", depends_on=("a",))
    pipeline.mission_store = SimpleNamespace(
        snapshot=lambda _mission_id: SimpleNamespace(tasks=(first, second))
    )
    with pytest.raises(RuntimeError, match="dependency cycle"):
        pipeline._ordered_mission_plan(task_names=["cycle-a", "cycle-b"])


def test_deferred_exhaustion_blocking_and_plan_rejection_fallbacks() -> None:
    no_mission = MissionHarness(mission_id="")
    no_mission.exhausted_tasks.add("legacy")
    assert no_mission._next_deferred_mission_time() is None
    assert no_mission._mission_plan_step_exhausted({"task": "legacy"}) is True
    assert no_mission._block_registered_task("Agent", "task", "reason") is None
    no_mission._persist_plan_rejection("Agent", "task", "reason")

    missing = MissionHarness(
        SimpleNamespace(
            snapshot=lambda _mission_id: SimpleNamespace(tasks=(), attempts=())
        )
    )
    missing.exhausted_tasks.add("fallback")
    assert missing._mission_plan_step_exhausted(
        {"task": "fallback", "task_id": "missing"}
    ) is True

    block_store = SimpleNamespace(
        block_task=lambda *_args, **_kwargs: SimpleNamespace(outcome=None)
    )
    blocked = MissionHarness(block_store)
    attempt = blocked._block_registered_task("Agent", "task", "reason")
    assert attempt.outcome is None

    terminal_blocked = _record("blocked", "blocked-task", status="blocked")
    existing = MissionHarness(
        SimpleNamespace(
            snapshot=lambda _mission_id: SimpleNamespace(
                tasks=(terminal_blocked,), attempts=()
            )
        )
    )
    existing._persist_plan_rejection("Agent", "blocked-task", "reason")
    assert existing.blocked_tasks == {"blocked-task"}

    completed = _record("done", "done-task", status="completed")
    existing.mission_store = SimpleNamespace(
        snapshot=lambda _mission_id: SimpleNamespace(tasks=(completed,), attempts=())
    )
    existing._persist_plan_rejection("Agent", "done-task", "reason")

    rejection_store = CapturePlanStore()
    rejected = MissionHarness(rejection_store)
    rejected._persist_plan_rejection("Agent", "new-task", "unavailable")
    assert rejected.blocked_tasks == {"new-task"}
    assert rejected.task_outcome_store.items == []


def test_compatibility_terminalization_covers_ambiguity_block_and_skip_paths() -> None:
    no_mission = MissionHarness(mission_id="")
    no_mission._terminalize_compatibility_exhausted_tasks([])

    outcome = object()
    records = (
        _record("dup-1", "duplicate"),
        _record("dup-2", "duplicate"),
        _record("blocked", "blocked"),
        _record("skip-none", "skip-none"),
        _record("skip-outcome", "skip-outcome"),
        _record("terminal", "terminal", status="completed"),
    )

    class TerminalStore:
        def snapshot(self, _mission_id: str) -> SimpleNamespace:
            return SimpleNamespace(tasks=records)

        def block_task(self, *_args, **_kwargs) -> SimpleNamespace:
            return SimpleNamespace(outcome=None)

        def skip_task(
            self,
            _mission_id: str,
            _agent: str,
            task: str,
            _reason: str,
            **_kwargs,
        ) -> SimpleNamespace:
            return SimpleNamespace(
                outcome=outcome if task == "skip-outcome" else None
            )

    pipeline = MissionHarness(TerminalStore())
    pipeline.exhausted_tasks.update(
        {"duplicate", "blocked", "skip-none", "skip-outcome", "terminal", "missing"}
    )
    pipeline.blocked_tasks.add("blocked")
    pipeline._terminalize_compatibility_exhausted_tasks(
        [
            {"task": "duplicate", "task_id": "dup-1"},
            {"task": "blocked", "task_id": "blocked"},
            {"task": "skip-none", "task_id": "skip-none"},
            {"task": "skip-outcome", "task_id": "skip-outcome"},
            {"task": "terminal", "task_id": "terminal"},
            {"task": "missing", "task_id": "missing"},
        ]
    )
    assert pipeline.task_outcome_store.items == [outcome]


def test_begin_attempt_transient_dependencies_and_inactive_mission_cleanup() -> None:
    no_mission = MissionHarness(mission_id="")
    assert no_mission._begin_task_attempt("Agent", "task") is None

    active = MissionHarness()
    active._active_task_attempt_id = "already-running"
    with pytest.raises(RuntimeError, match="already active"):
        active._begin_task_attempt("Agent", "task")

    def incomplete(*_args, **_kwargs):
        raise TaskDependenciesIncomplete(
            (("parent-one", "pending"), ("parent-two", "running"))
        )

    transient = MissionHarness(SimpleNamespace(begin_attempt=incomplete))
    transient._active_retry_command_keys.add("old")
    assert transient._begin_task_attempt("Agent", "task") is None
    assert transient._active_retry_command_keys == set()

    inactive = MissionHarness(mission_id="")
    inactive._active_task_attempt_id = "attempt"
    inactive._active_task_id = "task-id"
    inactive._active_task_name = "task"
    inactive._active_task_agent = "Agent"
    inactive._active_retry_command_keys.add("retry")
    inactive._interrupt_mission("stopped")
    assert inactive._active_task_attempt_id is None
    inactive._complete_mission("done")
    assert inactive._active_task_id is None
