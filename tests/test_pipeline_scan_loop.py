"""Characterization tests for the extracted pipeline scan lifecycle."""

from types import SimpleNamespace

from core.ai.pipeline import AIPipeline
from core.ai.scan_loop import ScanLifecycle


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
