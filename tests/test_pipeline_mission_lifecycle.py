"""Production-wiring contracts for the durable pipeline mission lifecycle."""

from __future__ import annotations

import sqlite3
from collections.abc import Iterable
from types import SimpleNamespace

import pytest

from core.ai.command_scheduler import CommandDecision
from core.ai.mission_store import MissionStore
from core.ai.pipeline import AIPipeline
from core.ai.planner import PlanCompilation
from core.execution import ExecutionResult, ExecutionStatus

pytestmark = pytest.mark.contract

TARGET = "10.0.0.5"
TASK = {"agent": "DiscoveryAgent", "task": "service_discovery"}


class _RegistryStub:
    def canonical_task(self, task):
        return task

    def get_available_tools_summary(self):
        return {}

    def get_unavailable_tools_summary(self):
        return {}

    def get_discovered_plugins_summary(self):
        return []

    def get_coverage_report(self):
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
    def resolve_state(self, _scan_id, _target):
        return {"state": "unknown"}


class _ContextStub:
    def build_context(self, _scan_id, _target):
        return {
            "state": "unknown",
            "services": [],
            "open_questions": [],
            "stage_gates": {},
            "next_required_capability": "service_discovery",
        }


def _only(items):
    values = tuple(items)
    assert len(values) == 1
    return values[0]


def _configure_scan(
    pipeline: AIPipeline,
    *,
    goals: Iterable[str],
    task_commands=None,
) -> AIPipeline:
    """Keep mission persistence real while replacing external/LLM boundaries."""

    goal_iter = iter(goals)

    def decide_goal(_context, _history):
        return {
            "goal": next(goal_iter),
            "thought": "mission lifecycle contract",
            "llm_status": "ok",
        }

    pipeline.tool_registry = _RegistryStub()
    pipeline.state_resolver = _StateStub()
    pipeline.context_builder = _ContextStub()
    pipeline.director = SimpleNamespace(decide_goal=decide_goal)
    pipeline.planner = SimpleNamespace(
        create_plan=lambda _goal, _context, _history: {
            "plan": [dict(TASK)],
            "llm_status": "ok",
        }
    )
    pipeline.discovery_agent = SimpleNamespace(
        execute_task=task_commands or (lambda _task, _target: ["probe target"])
    )
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
    pipeline._extract_plan_steps = lambda result: result["plan"]
    pipeline._normalize_plan = lambda plan, _goal: plan
    pipeline._optimize_plan = lambda plan, _goal, _context: plan
    pipeline._compile_plan = lambda plan, *_args, **_kwargs: plan
    pipeline._expand_command_with_context = lambda command, *_args: [command]
    pipeline._augment_command_with_context = lambda command, *_args: command
    pipeline._run_controlled_post_access_followups = lambda *_args, **_kwargs: {
        "commands": [],
        "new_facts": 0,
        "parsed_facts": 0,
        "facts": [],
    }
    pipeline._followup_commands_from_facts = lambda _facts: []
    pipeline._active_commands_from_facts = lambda _facts: []
    pipeline._sync_runtime_credentials_from_facts = lambda *_args, **_kwargs: None
    return pipeline


def _install_fake_execution(pipeline: AIPipeline, execution_id: str) -> None:
    """Exercise AIPipeline fact/result persistence without a real process."""

    pipeline.runtime.decide = lambda command, *_args, **_kwargs: CommandDecision(
        command=command,
        key="probe:target",
        action="execute",
        reason="test_execution",
    )
    pipeline.runtime.execute = lambda _decision, _context: ExecutionResult(
        status=ExecutionStatus.SUCCEEDED,
        request_id=f"request-{execution_id}",
        execution_id=execution_id,
        tool_name="probe",
        stdout="22/tcp open ssh OpenSSH",
        exit_code=0,
        duration=0.01,
    )
    pipeline.runtime.parse_output = lambda _command, _result: [
        {
            "type": "port_open",
            "value": "22/tcp (ssh) [OpenSSH]",
            "confidence": 100,
        }
    ]


def test_pipeline_runtime_owns_mission_store_in_the_fact_database(tmp_path):
    db_path = tmp_path / "pipeline.db"
    pipeline = AIPipeline(str(db_path))

    assert isinstance(pipeline.runtime.missions, MissionStore)
    assert pipeline.mission_store is pipeline.runtime.missions
    assert pipeline.runtime.missions.db_path == pipeline.fact_store.db_path == str(db_path)

    with sqlite3.connect(db_path) as conn:
        tables = {
            row[0]
            for row in conn.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            ).fetchall()
        }
    assert {"facts", "missions", "mission_tasks", "mission_task_attempts"} <= tables


def test_scan_lifecycle_persists_completed_outcome_and_provenance(tmp_path):
    pipeline = _configure_scan(
        AIPipeline(str(tmp_path / "completed.db")),
        goals=("service_discovery", "conclude"),
    )
    _install_fake_execution(pipeline, "exec-completed-1")

    pipeline.run_scan("scan-completed", TARGET, max_iterations=2)

    snapshot = pipeline.mission_store.snapshot(pipeline.mission_id)
    task = _only(snapshot.tasks)
    attempt = _only(snapshot.attempts)
    fact_ids = {
        fact["id"] for fact in pipeline.fact_store.get_facts("scan-completed", TARGET)
    }
    command_result = _only(
        pipeline.fact_store.get_command_results("scan-completed", TARGET)
    )

    assert snapshot.mission.status == "completed"
    assert snapshot.mission.reason == "director_concluded"
    assert task.status == attempt.status == "completed"
    assert attempt.attempt_number == 1
    assert attempt.outcome is not None
    assert attempt.outcome.task == "service_discovery"
    assert attempt.execution_ids == ("exec-completed-1",)
    assert attempt.fact_ids
    assert set(attempt.fact_ids) <= fact_ids
    assert command_result["execution_id"] == "exec-completed-1"


def test_task_exception_is_recovered_and_retried_as_attempt_two(tmp_path):
    db_path = tmp_path / "retry.db"

    def crash_task(_task, _target):
        raise RuntimeError("simulated task crash")

    first = _configure_scan(
        AIPipeline(str(db_path)),
        goals=("service_discovery",),
        task_commands=crash_task,
    )

    with pytest.raises(RuntimeError, match="simulated task crash"):
        first.run_scan("scan-retry", TARGET, max_iterations=2)

    interrupted = first.mission_store.snapshot(first.mission_id)
    assert interrupted.mission.status == "interrupted"
    assert interrupted.mission.reason == "scan_exception:RuntimeError"
    assert _only(interrupted.tasks).status == "interrupted"
    abandoned = _only(interrupted.attempts)
    assert abandoned.status == "interrupted"
    assert abandoned.attempt_number == 1

    resumed = _configure_scan(
        AIPipeline(str(db_path)),
        goals=("service_discovery", "conclude"),
    )
    _install_fake_execution(resumed, "exec-retry-2")
    resumed.run_scan("scan-retry", TARGET, max_iterations=2)

    recovered = resumed.mission_store.snapshot(resumed.mission_id)
    assert recovered.mission.mission_id == interrupted.mission.mission_id
    assert recovered.mission.status == "completed"
    assert [attempt.attempt_number for attempt in recovered.attempts] == [1, 2]
    assert [attempt.status for attempt in recovered.attempts] == [
        "interrupted",
        "completed",
    ]
    assert recovered.attempts[1].execution_ids == ("exec-retry-2",)


def test_max_iterations_and_tool_budget_interrupt_missions(tmp_path):
    iteration_limited = _configure_scan(
        AIPipeline(str(tmp_path / "iteration-limit.db")),
        goals=("service_discovery",),
    )
    _install_fake_execution(iteration_limited, "exec-iteration-limit")
    iteration_limited.run_scan("scan-iteration-limit", TARGET, max_iterations=1)

    iteration_snapshot = iteration_limited.mission_store.snapshot(
        iteration_limited.mission_id
    )
    assert iteration_snapshot.mission.status == "interrupted"
    assert iteration_snapshot.mission.reason == "max_iterations_reached"

    tool_limited = _configure_scan(
        AIPipeline(str(tmp_path / "tool-limit.db")),
        goals=("conclude",),
    )
    original_reset = tool_limited._reset_runtime_state

    def reset_at_budget():
        original_reset()
        tool_limited.tools_run_count = 1

    tool_limited._reset_runtime_state = reset_at_budget
    tool_limited.run_scan(
        "scan-tool-limit",
        TARGET,
        max_iterations=5,
        max_tools=1,
    )

    tool_snapshot = tool_limited.mission_store.snapshot(tool_limited.mission_id)
    assert tool_snapshot.mission.status == "interrupted"
    assert tool_snapshot.mission.reason == "max_tools_reached"


def test_material_state_change_gets_only_the_configured_extra_planner_pass(
    tmp_path,
):
    def configured(name: str, maximum: int) -> AIPipeline:
        pipeline = _configure_scan(
            AIPipeline(str(tmp_path / f"{name}.db")),
            goals=("service_discovery", "conclude"),
        )
        _install_fake_execution(pipeline, f"exec-{name}")
        contexts = iter(
            (
                {
                    "state": "initial_recon",
                    "services": [],
                    "open_questions": ["service_inventory"],
                    "stage_gates": {},
                    "next_required_capability": "service_discovery",
                },
                {
                    "state": "recon_completed",
                    "services": ["ssh"],
                    "open_questions": [],
                    "stage_gates": {"recon": True},
                    "next_required_capability": "vulnerability_assessment",
                },
            )
        )
        last_context = {}

        def build_context(_scan_id, _target):
            nonlocal last_context
            last_context = next(contexts, last_context)
            return dict(last_context)

        pipeline.context_builder = SimpleNamespace(build_context=build_context)
        pipeline._max_state_replans = lambda: maximum
        return pipeline

    enabled = configured("state-replan-enabled", 1)
    enabled.run_scan("scan-state-replan-enabled", TARGET, max_iterations=1)

    enabled_snapshot = enabled.mission_store.snapshot(enabled.mission_id)
    assert enabled_snapshot.mission.status == "completed"
    assert enabled_snapshot.mission.reason == "director_concluded"
    assert enabled._state_replan_count == 1
    assert len(
        enabled.decision_trace.list_events(
            scan_id="scan-state-replan-enabled",
            event_type="state_replan_requested",
        )
    ) == 1

    disabled = configured("state-replan-disabled", 0)
    disabled.run_scan("scan-state-replan-disabled", TARGET, max_iterations=1)

    disabled_snapshot = disabled.mission_store.snapshot(disabled.mission_id)
    assert disabled_snapshot.mission.status == "interrupted"
    assert disabled_snapshot.mission.reason == "max_iterations_reached"
    assert disabled._state_replan_count == 0
    assert len(
        disabled.decision_trace.list_events(
            scan_id="scan-state-replan-disabled",
            event_type="state_replan_rejected",
        )
    ) == 1


def test_director_conclude_completes_mission(tmp_path):
    pipeline = _configure_scan(
        AIPipeline(str(tmp_path / "conclude.db")),
        goals=("conclude",),
    )

    pipeline.run_scan("scan-conclude", TARGET, max_iterations=5)

    snapshot = pipeline.mission_store.snapshot(pipeline.mission_id)
    assert snapshot.mission.status == "completed"
    assert snapshot.mission.reason == "director_concluded"
    assert snapshot.tasks == ()
    assert snapshot.attempts == ()


def test_analysis_attempt_links_verified_claim_fact_id(tmp_path):
    pipeline = _configure_scan(
        AIPipeline(str(tmp_path / "analysis-provenance.db")),
        goals=("analyze", "conclude"),
    )
    pipeline.planner = SimpleNamespace(
        create_plan=lambda _goal, _context, _history: {
            "plan": [
                {"agent": "AnalysisAgent", "task": "analyze_vulnerabilities"}
            ],
            "llm_status": "ok",
        }
    )
    pipeline.analysis_agent = SimpleNamespace(
        analyze=lambda _scan_id, _target: {
            "hypotheses": [
                {
                    "claim": "ssh_service_active",
                    "required_evidence": ["ssh_service_active"],
                }
            ]
        }
    )
    pipeline.fact_store.add_fact(
        "scan-analysis-provenance",
        TARGET,
        "port_open",
        "22/tcp (ssh)",
        "fixture",
    )

    pipeline.run_scan("scan-analysis-provenance", TARGET, max_iterations=2)

    snapshot = pipeline.mission_store.snapshot(pipeline.mission_id)
    attempt = _only(snapshot.attempts)
    verified_claim = _only(
        fact
        for fact in pipeline.fact_store.get_facts(
            "scan-analysis-provenance",
            TARGET,
        )
        if fact["type"] == "verified_claim"
    )
    assert attempt.status == "completed"
    assert attempt.fact_ids == (verified_claim["id"],)


def test_hard_unavailable_plan_rejection_is_a_durable_blocked_outcome(tmp_path):
    pipeline = AIPipeline(str(tmp_path / "plan-rejection.db"))
    pipeline.tool_registry = _RegistryStub()
    pipeline._reset_runtime_state()
    pipeline._start_mission("scan-plan-rejection", TARGET)
    pipeline.plan_compiler = SimpleNamespace(
        compile=lambda *_args, **_kwargs: PlanCompilation(
            plan=(),
            rejected=(
                {
                    "agent": "DiscoveryAgent",
                    "task": "service_discovery",
                    "reason": "capability_unavailable",
                    "blocking_reasons": ["provider:no_provider"],
                },
            ),
        )
    )

    plan = pipeline._compile_plan(
        [dict(TASK)],
        "scan-plan-rejection",
        TARGET,
        {},
    )
    snapshot = pipeline.mission_store.snapshot(pipeline.mission_id)

    assert plan == []
    assert _only(snapshot.tasks).status == "blocked"
    attempt = _only(snapshot.attempts)
    assert attempt.status == "blocked"
    assert attempt.outcome is not None
    assert attempt.outcome.reason == (
        "capability_unavailable:provider:no_provider"
    )
    pipeline._complete_mission("planner_empty")


def test_mid_task_tool_budget_leaves_attempt_resumable(tmp_path):
    pipeline = _configure_scan(
        AIPipeline(str(tmp_path / "mid-task-budget.db")),
        goals=("service_discovery",),
        task_commands=lambda _task, _target: ["probe one", "probe two"],
    )
    _install_fake_execution(pipeline, "exec-before-budget")

    pipeline.run_scan(
        "scan-mid-task-budget",
        TARGET,
        max_iterations=5,
        max_tools=1,
    )

    snapshot = pipeline.mission_store.snapshot(pipeline.mission_id)
    task = _only(snapshot.tasks)
    attempt = _only(snapshot.attempts)
    assert snapshot.mission.status == "interrupted"
    assert snapshot.mission.reason == "max_tools_reached"
    assert task.status == "interrupted"
    assert attempt.status == "interrupted"
    assert attempt.outcome is None
    assert attempt.execution_ids == ("exec-before-budget",)
    assert pipeline._resumable_mission_plan() == [dict(TASK)]
