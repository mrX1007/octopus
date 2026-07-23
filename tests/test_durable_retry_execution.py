"""End-to-end contracts for durable task retries and dependency draining."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from core.ai.command_scheduler import CommandScheduler
from core.ai.mission_store import (
    MissionStore,
    RetryErrorClass,
    TaskRetryPolicy,
)
from core.ai.outcomes import TaskOutcome
from core.ai.pipeline import AIPipeline
from core.tools.registry import get_tool

pytestmark = pytest.mark.contract

TARGET = "10.0.0.5"
RETRY_COMMAND = f"nuclei_safe http://{TARGET}"


def _make_registered_tools_hermetic(monkeypatch, *names: str) -> None:
    for name in names:
        tool_def = get_tool(name)
        assert tool_def is not None
        monkeypatch.setattr(tool_def, "is_available", lambda: True)


def _failed(agent: str, task: str) -> TaskOutcome:
    return TaskOutcome(
        agent=agent,
        task=task,
        status="failed",
        reason="all_commands_failed",
        new_facts=0,
        parsed_facts=0,
        commands=(),
        duration=0.01,
    )


def test_attempt_terminalization_and_retry_grant_rollback_together(
    tmp_path,
    monkeypatch,
):
    store = MissionStore(str(tmp_path / "atomic-retry.db"), owner_id="owner")
    mission = store.open_mission("scan-atomic-retry", TARGET)
    task = store.register_task(
        mission.mission_id,
        "DiscoveryAgent",
        "service_verification",
        retry_policy=TaskRetryPolicy(
            retry_budget=1,
            retryable_error_classes=(RetryErrorClass.TIMEOUT,),
        ),
    )
    attempt = store.begin_attempt(mission.mission_id, task.agent, task.task)
    original = store._insert_retry_command_grants

    def crash_after_grant(*args, **kwargs):
        original(*args, **kwargs)
        raise RuntimeError("simulated_commit_window_crash")

    monkeypatch.setattr(store, "_insert_retry_command_grants", crash_after_grant)

    with pytest.raises(RuntimeError, match="simulated_commit_window_crash"):
        store.complete_attempt_and_schedule_retry(
            attempt.attempt_id,
            _failed(task.agent, task.task),
            retry_error_class=RetryErrorClass.TIMEOUT,
            retry_command_keys=(RETRY_COMMAND,),
        )

    snapshot = store.snapshot(mission.mission_id)
    assert snapshot.tasks[0].status == "running"
    assert snapshot.tasks[0].retry_count == 0
    assert snapshot.attempts[0].status == "running"
    assert store.pending_retry_command_keys(
        mission.mission_id,
        task.agent,
        task.task,
    ) == ()


def test_retry_scheduler_bypasses_only_duplicate_and_timeout_degraded_gates():
    scheduler = CommandScheduler()
    key = scheduler.command_key(RETRY_COMMAND)
    timed_out = [
        {
            "type": "service_status",
            "value": "tool_timeout:nuclei_safe",
            "source": RETRY_COMMAND,
        }
    ]
    completed = [
        {
            "type": "service_status",
            "value": f"nuclei_scan_completed:http://{TARGET}",
            "source": RETRY_COMMAND,
        }
    ]

    retry = scheduler.decide(
        RETRY_COMMAND,
        timed_out,
        {key},
        retry_command_keys={key},
    )
    terminal = scheduler.decide(
        RETRY_COMMAND,
        completed,
        {key},
        retry_command_keys={key},
    )

    assert retry.action == "execute"
    assert retry.reason == "durable_retry_command"
    assert retry.retry is True
    assert terminal.action == "skip"
    assert terminal.reason == "already_completed:nuclei_scan"


def test_retry_scheduler_reauthorizes_policy_before_using_grant():
    class _Denied:
        allowed = False
        reason = "scope_denied"

        @staticmethod
        def to_dict():
            return {"allowed": False, "reason": "scope_denied"}

    class _DenyPolicy:
        @staticmethod
        def authorize_command(_command, _context):
            return _Denied()

    scheduler = CommandScheduler(execution_policy=_DenyPolicy())
    key = scheduler.command_key(RETRY_COMMAND)

    decision = scheduler.decide(
        RETRY_COMMAND,
        [],
        {key},
        retry_command_keys={key},
    )

    assert decision.action == "skip"
    assert decision.reason == "policy_denied:scope_denied"
    assert decision.retry is False


def test_timeout_retry_allowlist_survives_restart_and_executes_command_once(
    tmp_path,
    monkeypatch,
):
    _make_registered_tools_hermetic(monkeypatch, "nuclei_safe")
    db_path = tmp_path / "restart-retry.db"
    calls = []

    def timeout_runner(command):
        calls.append(command)
        raise TimeoutError("provider timed out")

    first = AIPipeline(str(db_path))
    first.runtime._runner = timeout_runner
    first._reset_runtime_state()
    first._start_mission("scan-restart-retry", TARGET)
    first._register_mission_plan(
        [
            {
                "agent": "DiscoveryAgent",
                "task": "service_verification",
                "scope": "service:https",
                "capability": "service.verification",
            }
        ]
    )
    first._begin_task_attempt("DiscoveryAgent", "service_verification")
    failed = first._execute_pipeline_command(
        "scan-restart-retry",
        TARGET,
        RETRY_COMMAND,
        "Fact",
        "[Running]",
    )
    first.completed_tasks.add("service_verification")
    first._record_task_outcome(
        "DiscoveryAgent",
        "service_verification",
        "failed",
        "all_commands_failed",
        failed["new_facts"],
        failed["parsed_facts"],
        [failed["command_result"]],
        0.01,
    )
    pending = first.mission_store.snapshot(first.mission_id).tasks[0]
    assert pending.status == "pending"
    assert pending.retry_count == 1
    scoped_sibling = first.mission_store.register_task(
        first.mission_id,
        "DiscoveryAgent",
        "service_verification",
        scope="service:http",
        capability="service.verification",
    )
    first.mission_store.block_task(
        first.mission_id,
        scoped_sibling.agent,
        scoped_sibling.task,
        "not_selected",
        task_id=scoped_sibling.task_id,
    )
    first._interrupt_mission("simulated_restart")

    def success_runner(command):
        calls.append(command)
        return (
            f"[NUCLEI SAFE - http://{TARGET}]\n"
            "No nuclei findings detected.\n"
            f"[NUCLEI COMPLETE - http://{TARGET}]"
        )

    resumed = AIPipeline(str(db_path))
    resumed.runtime._runner = success_runner
    resumed._reset_runtime_state()
    resumed._start_mission("scan-restart-retry", TARGET)
    resume_plan = resumed._resumable_mission_plan()
    assert [
        {"agent": step["agent"], "task": step["task"]}
        for step in resume_plan
    ] == [{"agent": "DiscoveryAgent", "task": "service_verification"}]
    assert resume_plan[0]["task_id"] == pending.task_id
    assert resume_plan[0]["task_scope"] == pending.task_scope
    resumed._register_mission_plan(resume_plan)

    hydrated = next(
        task
        for task in resumed.mission_store.snapshot(resumed.mission_id).tasks
        if task.task_id == pending.task_id
    )
    assert hydrated.scope == "service:https"
    assert hydrated.capability == "service.verification"
    assert hydrated.retry_budget == 2
    assert resumed._begin_task_attempt(
        "DiscoveryAgent",
        "service_verification",
        task_id=hydrated.task_id,
    ).attempt_number == 2
    assert resumed._active_task_id == hydrated.task_id
    assert resumed._active_retry_command_keys == {
        resumed.command_scheduler.command_key(RETRY_COMMAND)
    }

    succeeded = resumed._execute_pipeline_command(
        "scan-restart-retry",
        TARGET,
        RETRY_COMMAND,
        "Fact",
        "[Retrying]",
    )
    resumed.completed_tasks.add("service_verification")
    resumed._record_task_outcome(
        "DiscoveryAgent",
        "service_verification",
        "completed",
        "retry_succeeded",
        succeeded["new_facts"],
        succeeded["parsed_facts"],
        [succeeded["command_result"]],
        0.01,
    )
    repeated = resumed._execute_pipeline_command(
        "scan-restart-retry",
        TARGET,
        RETRY_COMMAND,
        "Fact",
        "[Repeated]",
    )

    assert calls == [RETRY_COMMAND, RETRY_COMMAND]
    assert succeeded["command_result"]["status"] == "succeeded"
    assert repeated["command_result"]["skipped"] is True
    assert repeated["command_result"]["skip_reason"] == "duplicate_command_key"
    final = resumed.mission_store.snapshot(resumed.mission_id)
    assert next(
        task for task in final.tasks if task.task_id == pending.task_id
    ).status == "completed"
    assert [
        attempt.status
        for attempt in final.attempts
        if attempt.task_id == pending.task_id
    ] == ["failed", "completed"]
    assert resumed._active_task_id is None


class _Registry:
    @staticmethod
    def canonical_task(task):
        return task

    @staticmethod
    def get_available_tools_summary():
        return {}

    @staticmethod
    def get_unavailable_tools_summary():
        return {}

    @staticmethod
    def get_discovered_plugins_summary():
        return []

    @staticmethod
    def get_coverage_report():
        return {
            "covered": 0,
            "registered": 0,
            "auto": [],
            "followup": [],
            "manual_gated": [],
            "legacy_wrappers": [],
            "unknown": [],
        }


def test_retrying_prerequisite_defers_then_releases_dependent_task(
    tmp_path,
    monkeypatch,
):
    _make_registered_tools_hermetic(monkeypatch, "nuclei_safe", "nmap")
    calls = []
    parent_calls = 0

    def runner(command):
        nonlocal parent_calls
        calls.append(command)
        if command == RETRY_COMMAND:
            parent_calls += 1
            if parent_calls == 1:
                raise TimeoutError("first check timed out")
            return f"[NUCLEI COMPLETE - http://{TARGET}]"
        return f"Nmap scan report for {TARGET}\n22/tcp open ssh OpenSSH"

    pipeline = AIPipeline(str(tmp_path / "dependency-retry.db"))
    pipeline.runtime._runner = runner
    pipeline.tool_registry = _Registry()
    pipeline.discovery_agent = SimpleNamespace(
        execute_task=lambda task, _target: (
            [RETRY_COMMAND] if task == "parent" else [f"nmap {TARGET}"]
        )
    )
    context = {
        "state": "unknown",
        "services": [],
        "open_questions": [],
        "stage_gates": {},
        "next_required_capability": "service_discovery",
    }
    pipeline.state_resolver = SimpleNamespace(
        resolve_state=lambda _scan, _target: context
    )
    pipeline.context_builder = SimpleNamespace(
        build_context=lambda _scan, _target: dict(context)
    )
    goals = iter(("work", "conclude"))
    pipeline.director = SimpleNamespace(
        decide_goal=lambda _context, _history: {
            "goal": next(goals),
            "thought": "durable dependency contract",
            "llm_status": "ok",
        }
    )
    plan = [
        {"agent": "DiscoveryAgent", "task": "parent"},
        {
            "agent": "DiscoveryAgent",
            "task": "child",
            "depends_on": ["parent"],
        },
    ]
    pipeline.planner = SimpleNamespace(
        create_plan=lambda _goal, _context, _history: {
            "plan": plan,
            "llm_status": "ok",
        }
    )
    pipeline._compile_plan = lambda steps, *_args, **_kwargs: steps
    pipeline._optimize_plan = lambda steps, *_args, **_kwargs: steps
    pipeline._run_fact_driven_actions = lambda *_args, **_kwargs: {
        "commands": [],
        "new_facts": 0,
        "parsed_facts": 0,
    }
    pipeline._seed_known_credentials = lambda *_args: 0
    pipeline._record_llm_health = lambda *_args, **_kwargs: None
    pipeline._update_llm_failure_counter = lambda *_args: None
    pipeline._print_efficiency_report = lambda *_args: None

    pipeline.run_scan(
        "scan-dependency-retry",
        TARGET,
        max_iterations=3,
    )

    snapshot = pipeline.mission_store.snapshot(pipeline.mission_id)
    tasks = {task.task: task for task in snapshot.tasks}
    parent_attempts = [
        attempt for attempt in snapshot.attempts
        if attempt.task_id == tasks["parent"].task_id
    ]
    child_attempts = [
        attempt for attempt in snapshot.attempts
        if attempt.task_id == tasks["child"].task_id
    ]
    assert calls == [RETRY_COMMAND, RETRY_COMMAND, f"nmap {TARGET}"]
    assert [attempt.status for attempt in parent_attempts] == ["failed", "completed"]
    assert [attempt.status for attempt in child_attempts] == ["completed"]
    assert tasks["child"].status == "completed"
    assert tasks["child"].reason != "dependency_unsatisfied"
