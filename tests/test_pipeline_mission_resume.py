"""Focused integration contracts for durable mission recovery."""

from __future__ import annotations

import copy
import json
from dataclasses import dataclass
from types import SimpleNamespace
from typing import Any

import pytest

from core.ai.mission_store import MissionStoreError
from core.ai.pipeline import AIPipeline

pytestmark = pytest.mark.contract

TARGET = "10.0.0.5"


class _RegistryStub:
    def canonical_task(self, task: str) -> str:
        return task

    def get_available_tools_summary(self) -> dict[str, list[str]]:
        return {}

    def get_unavailable_tools_summary(self) -> dict[str, list[str]]:
        return {}

    def get_discovered_plugins_summary(self) -> list[dict[str, str]]:
        return []

    def get_coverage_report(self) -> dict[str, Any]:
        return {
            "covered": 0,
            "registered": 0,
            "auto": [],
            "followup": [],
            "manual_gated": [],
            "legacy_wrappers": [],
            "unknown": [],
        }


class _StateStub:
    def resolve_state(self, _scan_id: str, _target: str) -> dict[str, str]:
        return {"state": "unknown"}


class _ContextStub:
    def build_context(self, _scan_id: str, _target: str) -> dict[str, Any]:
        return {
            "state": "unknown",
            "services": [],
            "open_questions": [],
            "stage_gates": {},
            "next_required_capability": "service_discovery",
        }


@dataclass
class _Harness:
    pipeline: AIPipeline
    director_calls: list[str]
    planner_calls: list[str]
    executed_tasks: list[str]


def _configure_pipeline(
    pipeline: AIPipeline,
    *,
    goals: list[str],
    plan: list[dict[str, Any]],
    executed_tasks: list[str] | None = None,
) -> _Harness:
    """Replace external boundaries while retaining the real durable lifecycle."""

    goal_iter = iter(goals)
    director_calls: list[str] = []
    planner_calls: list[str] = []
    task_log = executed_tasks if executed_tasks is not None else []

    def decide_goal(_context: dict[str, Any], _history: list[str]) -> dict[str, Any]:
        goal = next(goal_iter)
        director_calls.append(goal)
        return {
            "goal": goal,
            "thought": "mission resume contract",
            "llm_status": "ok",
        }

    def create_plan(
        goal: str,
        _context: dict[str, Any],
        _history: list[str],
    ) -> dict[str, Any]:
        planner_calls.append(goal)
        return {"plan": copy.deepcopy(plan), "llm_status": "ok"}

    def execute_task(task: str, _target: str) -> list[str]:
        task_log.append(task)
        return [f"probe {task}"]

    def run_task_commands(
        _scan_id: str,
        _target: str,
        commands: list[str],
        **_kwargs: Any,
    ) -> dict[str, Any]:
        return {
            "new_facts": 0,
            "parsed_facts": 0,
            "commands": [
                {
                    "command": command,
                    "failed": False,
                    "skipped": False,
                    "fact_pairs": [],
                }
                for command in commands
            ],
            "reason": "commands_ran_but_no_facts",
        }

    pipeline.tool_registry = _RegistryStub()
    pipeline.state_resolver = _StateStub()
    pipeline.context_builder = _ContextStub()
    pipeline.director = SimpleNamespace(decide_goal=decide_goal)
    pipeline.planner = SimpleNamespace(create_plan=create_plan)
    pipeline.discovery_agent = SimpleNamespace(execute_task=execute_task)
    pipeline._seed_known_credentials = lambda _scan_id, _target: 0
    pipeline._run_fact_driven_actions = lambda _scan_id, _target, _facts: {
        "commands": [],
        "new_facts": 0,
        "parsed_facts": 0,
        "facts": [],
    }
    pipeline._record_llm_health = lambda *_args, **_kwargs: None
    pipeline._update_llm_failure_counter = lambda _result: None
    pipeline._print_efficiency_report = lambda *_args, **_kwargs: None
    pipeline._extract_plan_steps = lambda result: copy.deepcopy(result["plan"])
    pipeline._normalize_plan = lambda raw_plan, _goal: raw_plan
    pipeline._optimize_plan = lambda raw_plan, _goal, _context: raw_plan
    pipeline._compile_plan = lambda raw_plan, *_args, **_kwargs: raw_plan
    pipeline._run_task_commands = run_task_commands
    pipeline._sync_runtime_credentials_from_facts = lambda *_args, **_kwargs: None
    return _Harness(pipeline, director_calls, planner_calls, task_log)


def _prime_interrupted_mission(
    harness: _Harness,
    scan_id: str,
    plan: list[dict[str, Any]],
) -> None:
    pipeline = harness.pipeline
    pipeline._reset_runtime_state()
    pipeline._start_mission(scan_id, TARGET)
    pipeline._register_mission_plan(copy.deepcopy(plan))


def test_resume_drains_interrupted_and_pending_tasks_before_director_concludes(
    tmp_path,
):
    db_path = tmp_path / "resume-drain.db"
    plan = [
        {"agent": "DiscoveryAgent", "task": "first"},
        {"agent": "DiscoveryAgent", "task": "second"},
    ]
    first = _configure_pipeline(
        AIPipeline(str(db_path)),
        goals=[],
        plan=plan,
    )
    _prime_interrupted_mission(first, "scan-resume-drain", plan)
    first.pipeline._begin_task_attempt("DiscoveryAgent", "first")
    first.pipeline._interrupt_mission("simulated_process_crash")

    interrupted = first.pipeline.mission_store.snapshot(first.pipeline.mission_id)
    assert {task.task: task.status for task in interrupted.tasks} == {
        "first": "interrupted",
        "second": "pending",
    }

    resumed = _configure_pipeline(
        AIPipeline(str(db_path)),
        goals=["conclude"],
        plan=[],
    )
    resumed.pipeline.run_scan(
        "scan-resume-drain",
        TARGET,
        max_iterations=2,
    )

    snapshot = resumed.pipeline.mission_store.snapshot(resumed.pipeline.mission_id)
    assert resumed.executed_tasks == ["first", "second"]
    assert resumed.director_calls == ["conclude"]
    assert resumed.planner_calls == []
    assert snapshot.mission.status == "completed"
    assert {task.task: task.status for task in snapshot.tasks} == {
        "first": "no_new_facts",
        "second": "no_new_facts",
    }
    assert [
        (attempt.attempt_number, attempt.status)
        for attempt in snapshot.attempts
        if attempt.task_id == next(
            task.task_id for task in snapshot.tasks if task.task == "first"
        )
    ] == [(1, "interrupted"), (2, "no_new_facts")]


def test_child_before_parent_plan_executes_in_dependency_order(tmp_path):
    plan = [
        {
            "agent": "DiscoveryAgent",
            "task": "child",
            "depends_on": ["parent"],
        },
        {"agent": "DiscoveryAgent", "task": "parent"},
    ]
    harness = _configure_pipeline(
        AIPipeline(str(tmp_path / "dependency-order.db")),
        goals=["work", "conclude"],
        plan=plan,
    )

    harness.pipeline.run_scan(
        "scan-dependency-order",
        TARGET,
        max_iterations=2,
    )

    snapshot = harness.pipeline.mission_store.snapshot(harness.pipeline.mission_id)
    tasks = {task.task: task for task in snapshot.tasks}
    assert harness.executed_tasks == ["parent", "child"]
    assert tasks["child"].depends_on == (tasks["parent"].task_id,)
    assert tasks["parent"].status == tasks["child"].status == "no_new_facts"
    assert snapshot.mission.status == "completed"


@pytest.mark.parametrize("parent_status", ["blocked", "failed"])
def test_terminally_unsatisfied_parent_durably_blocks_child_without_scan_crash(
    tmp_path,
    parent_status: str,
):
    db_path = tmp_path / f"dependency-{parent_status}.db"
    plan = [
        {"agent": "DiscoveryAgent", "task": "parent"},
        {
            "agent": "DiscoveryAgent",
            "task": "child",
            "depends_on": ["parent"],
        },
    ]
    first = _configure_pipeline(AIPipeline(str(db_path)), goals=[], plan=plan)
    _prime_interrupted_mission(first, f"scan-dependency-{parent_status}", plan)
    first.pipeline._begin_task_attempt("DiscoveryAgent", "parent")
    first.pipeline._record_task_outcome(
        "DiscoveryAgent",
        "parent",
        parent_status,
        f"parent_{parent_status}",
        0,
        0,
        [],
        0.01,
    )
    first.pipeline._interrupt_mission("simulated_restart")

    resumed = _configure_pipeline(
        AIPipeline(str(db_path)),
        goals=["conclude"],
        plan=[],
    )
    resumed.pipeline.run_scan(
        f"scan-dependency-{parent_status}",
        TARGET,
        max_iterations=2,
    )

    snapshot = resumed.pipeline.mission_store.snapshot(resumed.pipeline.mission_id)
    tasks = {task.task: task for task in snapshot.tasks}
    child_attempts = [
        attempt for attempt in snapshot.attempts
        if attempt.task_id == tasks["child"].task_id
    ]
    assert resumed.executed_tasks == []
    assert tasks["parent"].status == parent_status
    assert tasks["child"].status == "blocked"
    assert "dependency_unsatisfied:" in tasks["child"].reason
    assert len(child_attempts) == 1
    assert child_attempts[0].status == "blocked"
    assert child_attempts[0].outcome is not None
    assert child_attempts[0].outcome.reason == tasks["child"].reason
    assert snapshot.mission.status == "completed"


def test_completed_same_object_rerun_preserves_traces_and_outcomes(tmp_path):
    plan = [{"agent": "DiscoveryAgent", "task": "only_task"}]
    harness = _configure_pipeline(
        AIPipeline(str(tmp_path / "completed-rerun.db")),
        goals=["work", "conclude"],
        plan=plan,
    )
    harness.pipeline.run_scan(
        "scan-completed-rerun",
        TARGET,
        max_iterations=2,
    )
    harness.pipeline.command_trace.append({"command": "sentinel", "action": "execute"})

    goal_trace = copy.deepcopy(harness.pipeline.goal_trace)
    command_trace = copy.deepcopy(harness.pipeline.command_trace)
    task_outcomes = copy.deepcopy(harness.pipeline.task_outcomes)
    list_ids = (
        id(harness.pipeline.goal_trace),
        id(harness.pipeline.command_trace),
        id(harness.pipeline.task_outcomes),
    )
    director_calls = list(harness.director_calls)

    harness.pipeline.run_scan(
        "scan-completed-rerun",
        TARGET,
        max_iterations=2,
    )

    assert harness.pipeline.goal_trace == goal_trace
    assert harness.pipeline.command_trace == command_trace
    assert harness.pipeline.task_outcomes == task_outcomes
    assert (
        id(harness.pipeline.goal_trace),
        id(harness.pipeline.command_trace),
        id(harness.pipeline.task_outcomes),
    ) == list_ids
    assert harness.director_calls == director_calls
    assert harness.executed_tasks == ["only_task"]


def test_clear_scan_removes_mission_and_allows_a_fresh_rerun(tmp_path):
    plan = [{"agent": "DiscoveryAgent", "task": "repeatable_task"}]
    harness = _configure_pipeline(
        AIPipeline(str(tmp_path / "clear-scan.db")),
        goals=["work", "conclude", "work", "conclude"],
        plan=plan,
    )
    scan_id = "scan-clear-rerun"
    harness.pipeline.run_scan(scan_id, TARGET, max_iterations=2)
    original_mission_id = harness.pipeline.mission_id

    harness.pipeline.fact_store.clear_scan(scan_id)

    assert harness.pipeline.mission_store.get_mission_by_scan_id(scan_id) is None
    with pytest.raises(MissionStoreError, match="unknown mission"):
        harness.pipeline.mission_store.snapshot(original_mission_id)

    harness.pipeline.run_scan(scan_id, TARGET, max_iterations=2)
    replacement = harness.pipeline.mission_store.snapshot(harness.pipeline.mission_id)

    assert harness.pipeline.mission_id != original_mission_id
    assert replacement.mission.status == "completed"
    assert harness.executed_tasks == ["repeatable_task", "repeatable_task"]


def test_interrupted_attempt_provenance_restores_tool_budget_before_resume(tmp_path):
    db_path = tmp_path / "resume-budget.db"
    plan = [{"agent": "DiscoveryAgent", "task": "budgeted_task"}]
    first = _configure_pipeline(AIPipeline(str(db_path)), goals=[], plan=plan)
    _prime_interrupted_mission(first, "scan-resume-budget", plan)
    attempt = first.pipeline._begin_task_attempt(
        "DiscoveryAgent",
        "budgeted_task",
    )
    first.pipeline.mission_store.record_attempt_progress(
        attempt.attempt_id,
        execution_ids=("exec-before-crash",),
    )
    first.pipeline._interrupt_mission("simulated_process_crash")

    resumed = _configure_pipeline(
        AIPipeline(str(db_path)),
        goals=["conclude"],
        plan=[],
    )
    resumed.pipeline.run_scan(
        "scan-resume-budget",
        TARGET,
        max_iterations=2,
        max_tools=1,
    )

    snapshot = resumed.pipeline.mission_store.snapshot(resumed.pipeline.mission_id)
    interrupted_attempt = snapshot.attempts[0]
    assert resumed.executed_tasks == []
    assert resumed.director_calls == []
    assert resumed.pipeline.tools_run_count == 1
    assert snapshot.mission.status == "interrupted"
    assert snapshot.mission.reason == "max_tools_reached"
    assert snapshot.tasks[0].status == "interrupted"
    assert interrupted_attempt.execution_ids == ("exec-before-crash",)


def test_same_task_name_under_multiple_agents_has_one_durable_owner(tmp_path):
    plan = [
        {"agent": "DiscoveryAgent", "task": "shared_task"},
        {"agent": "VerificationAgent", "task": "shared_task"},
    ]
    harness = _configure_pipeline(
        AIPipeline(str(tmp_path / "task-name-owner.db")),
        goals=[],
        plan=plan,
    )
    harness.pipeline._reset_runtime_state()
    harness.pipeline._start_mission("scan-task-name-owner", TARGET)

    ordered = harness.pipeline._register_mission_plan(plan)
    snapshot = harness.pipeline.mission_store.snapshot(harness.pipeline.mission_id)

    assert ordered == [{"agent": "DiscoveryAgent", "task": "shared_task"}]
    assert len(snapshot.tasks) == 1
    assert snapshot.tasks[0].agent == "DiscoveryAgent"


def test_running_check_fact_restores_command_deduplication_after_crash(tmp_path):
    db_path = tmp_path / "resume-command-key.db"
    first = AIPipeline(str(db_path))
    first._reset_runtime_state()
    first._start_mission("scan-command-key", TARGET)
    first.fact_store.add_fact(
        "scan-command-key",
        TARGET,
        "check_result",
        json.dumps(
            {
                "tool": "probe",
                "command_key": "probe:target",
                "command": "probe target",
                "status": "running",
            },
            sort_keys=True,
        ),
        "probe target",
    )
    first._interrupt_mission("simulated_process_crash")

    resumed = AIPipeline(str(db_path))
    resumed._reset_runtime_state()
    resumed._start_mission("scan-command-key", TARGET)

    assert "probe:target" in resumed.executed_command_keys
