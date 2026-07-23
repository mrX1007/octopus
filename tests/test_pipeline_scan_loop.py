"""Characterization tests for the extracted pipeline scan lifecycle."""

from types import SimpleNamespace

import pytest

from core.ai.pipeline import AIPipeline
from core.ai.scan_loop import ScanLifecycle
from core.execution import CancellationContext, ExecutionCancelled

pytestmark = pytest.mark.contract


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
    def __init__(self):
        self.calls = 0

    def resolve_state(self, _scan_id, _target):
        self.calls += 1
        return {"state": "unknown", "calls": self.calls}


class _ContextStub:
    def build_context(self, _scan_id, _target):
        return {
            "state": "unknown",
            "services": [],
            "open_questions": [],
            "stage_gates": {},
            "next_required_capability": "service_discovery",
        }


def _configure_lifecycle(pipeline, goal="conclude"):
    pipeline.tool_registry = _RegistryStub()
    pipeline.state_resolver = _StateStub()
    pipeline.context_builder = _ContextStub()
    pipeline.director = SimpleNamespace(
        decide_goal=lambda _context, _history: {
            "goal": goal,
            "thought": "characterized",
            "llm_status": "ok",
        }
    )
    pipeline._seed_known_credentials = lambda _scan_id, _target: 0
    pipeline._run_fact_driven_actions = lambda _scan_id, _target, _facts: {
        "commands": [],
        "new_facts": 0,
    }
    pipeline._record_llm_health = lambda *_args, **_kwargs: None
    pipeline._update_llm_failure_counter = lambda _result: None
    pipeline._print_efficiency_report = lambda *_args, **_kwargs: None
    pipeline._compile_plan = lambda plan, *_args, **_kwargs: plan
    return pipeline


def test_pipeline_run_scan_delegates_arguments_to_scan_lifecycle(tmp_path, monkeypatch):
    pipeline = AIPipeline(str(tmp_path / "delegation.db"))
    expected = {"state": "delegated"}
    call = {}

    def capture_run(
        _lifecycle,
        facade,
        scan_id,
        target,
        max_iterations,
        max_tools,
        max_time_minutes,
        raw_scan,
    ):
        call.update(
            facade=facade,
            scan_id=scan_id,
            target=target,
            max_iterations=max_iterations,
            max_tools=max_tools,
            max_time_minutes=max_time_minutes,
            raw_scan=raw_scan,
        )
        return expected

    monkeypatch.setattr(ScanLifecycle, "run", capture_run)

    result = pipeline.run_scan(
        "scan-1",
        "10.0.0.5",
        max_iterations=2,
        max_tools=3,
        max_time_minutes=4,
        raw_scan="seed output",
    )

    assert result is expected
    assert call == {
        "facade": pipeline,
        "scan_id": "scan-1",
        "target": "10.0.0.5",
        "max_iterations": 2,
        "max_tools": 3,
        "max_time_minutes": 4,
        "raw_scan": "seed output",
    }


def test_pipeline_binds_explicit_scan_cancellation_to_ollama(tmp_path, monkeypatch):
    import core.ai.ollama_client as ollama

    pipeline = AIPipeline(str(tmp_path / "bounded-delegation.db"))
    cancellation = CancellationContext.with_timeout(30.0)
    observed = {}

    def capture_run(
        _lifecycle,
        _facade,
        _scan_id,
        _target,
        _max_iterations,
        _max_tools,
        _max_time_minutes,
        _raw_scan,
        *,
        cancellation=None,
    ):
        observed["argument"] = cancellation
        observed["bound"] = ollama._ACTIVE_CANCELLATION.get()
        return {"state": "bounded"}

    monkeypatch.setattr(ScanLifecycle, "run", capture_run)

    result = pipeline.run_scan(
        "scan-bounded",
        "10.0.0.5",
        cancellation=cancellation,
    )

    assert result == {"state": "bounded"}
    assert observed == {"argument": cancellation, "bound": cancellation}
    assert ollama._ACTIVE_CANCELLATION.get() is None


def test_scan_lifecycle_installs_explicit_token_after_runtime_reset():
    cancellation = CancellationContext.with_timeout(30.0)

    class MissionStore:
        @staticmethod
        def get_mission_by_scan_id(_scan_id):
            return None

    class Facade:
        mission_id = None
        mission_store = MissionStore()
        state_resolver = SimpleNamespace(
            resolve_state=lambda _scan_id, _target: {"state": "completed"}
        )

        def _reset_runtime_state(self):
            self.cancellation = CancellationContext()

        @staticmethod
        def _start_mission(_scan_id, _target):
            return SimpleNamespace(status="completed")

    facade = Facade()

    result = ScanLifecycle().run(
        facade,
        "scan-bounded",
        "10.0.0.5",
        cancellation=cancellation,
    )

    assert result == {"state": "completed"}
    assert facade.cancellation is cancellation


def test_scan_lifecycle_interrupts_if_director_fallback_concludes_after_cancellation(
    tmp_path,
):
    pipeline = _configure_lifecycle(AIPipeline(str(tmp_path / "cancelled.db")))
    cancellation = CancellationContext()

    def cancel_and_conclude(_context, _history):
        cancellation.cancel("deadline_exceeded")
        return {
            "goal": "conclude",
            "thought": "fallback after cancelled request",
            "llm_status": "failed",
        }

    pipeline.director = SimpleNamespace(decide_goal=cancel_and_conclude)

    with pytest.raises(ExecutionCancelled, match="deadline_exceeded"):
        ScanLifecycle().run(
            pipeline,
            "scan-cancelled",
            "10.0.0.5",
            cancellation=cancellation,
        )

    mission = pipeline.mission_store.get_mission_by_scan_id("scan-cancelled")
    assert mission is not None
    assert mission.status == "interrupted"
    assert mission.reason == "scan_exception:ExecutionCancelled"


def test_scan_lifecycle_checks_tool_budget_before_director(tmp_path, capsys):
    pipeline = _configure_lifecycle(AIPipeline(str(tmp_path / "budget.db")))
    original_reset = pipeline._reset_runtime_state

    def reset_at_budget():
        original_reset()
        pipeline.tools_run_count = 1

    pipeline._reset_runtime_state = reset_at_budget
    pipeline.director = SimpleNamespace(
        decide_goal=lambda *_args: (_ for _ in ()).throw(AssertionError("director called"))
    )

    result = ScanLifecycle().run(
        pipeline, "scan-budget", "10.0.0.5", max_iterations=5, max_tools=1
    )

    assert result["state"] == "unknown"
    assert pipeline.goal_history == []
    assert "BUDGET EXCEEDED: Max tools run (1)" in capsys.readouterr().out


def test_scan_lifecycle_preserves_four_observation_anti_loop_boundary(tmp_path):
    pipeline = _configure_lifecycle(AIPipeline(str(tmp_path / "anti-loop.db")), goal="map")
    original_reset = pipeline._reset_runtime_state
    director_calls = []
    planner_calls = []

    def reset_with_completed_task():
        original_reset()
        pipeline.completed_tasks.add("service_discovery")

    pipeline._reset_runtime_state = reset_with_completed_task
    pipeline.director = SimpleNamespace(
        decide_goal=lambda _context, _history: director_calls.append(1) or {
            "goal": "map",
            "thought": "repeat",
            "llm_status": "ok",
        }
    )
    pipeline.planner = SimpleNamespace(
        create_plan=lambda _goal, _context, _history: planner_calls.append(1) or {
            "plan": [{"agent": "DiscoveryAgent", "task": "service_discovery"}],
            "llm_status": "ok",
        }
    )
    pipeline._extract_plan_steps = lambda result: result["plan"]
    pipeline._normalize_plan = lambda plan, _goal: plan
    pipeline._optimize_plan = lambda plan, _goal, _context: plan

    ScanLifecycle().run(
        pipeline, "scan-loop", "10.0.0.5", max_iterations=10
    )

    assert len(director_calls) == 4
    assert len(planner_calls) == 3
    assert pipeline.fact_history_counts == [0, 0, 0, 0]


def test_scan_lifecycle_reuses_context_snapshot_for_plan_compilation(tmp_path):
    pipeline = _configure_lifecycle(
        AIPipeline(str(tmp_path / "planning-snapshot.db")),
        goal="map",
    )
    snapshot = SimpleNamespace(historical_facts=lambda: ())
    observed = {}

    class Context:
        @staticmethod
        def build_evaluated_fact_snapshot(_scan_id, _target):
            return snapshot

        @staticmethod
        def build_context(
            _scan_id,
            _target,
            *,
            evaluated_fact_snapshot=None,
        ):
            observed["context_snapshot"] = evaluated_fact_snapshot
            return {
                "state": "unknown",
                "services": [],
                "open_questions": [],
                "stage_gates": {},
                "next_required_capability": "service_discovery",
            }

    def compile_plan(
        plan,
        _scan_id,
        _target,
        _context,
        *,
        evaluated_fact_snapshot=None,
    ):
        observed["compiler_snapshot"] = evaluated_fact_snapshot
        return plan

    pipeline.context_builder = Context()
    pipeline.planner = SimpleNamespace(
        create_plan=lambda *_args: {"plan": [], "llm_status": "ok"}
    )
    pipeline._compile_plan = compile_plan

    ScanLifecycle().run(
        pipeline,
        "scan-planning-snapshot",
        "10.0.0.5",
        max_iterations=1,
    )

    assert observed == {
        "context_snapshot": snapshot,
        "compiler_snapshot": snapshot,
    }
