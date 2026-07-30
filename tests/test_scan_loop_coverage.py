"""Hermetic branch coverage for the extracted scan lifecycle."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from core.ai.scan_loop import ScanLifecycle, ToolBudgetReached

pytestmark = pytest.mark.unit


class _Registry:
    def __init__(self, *, detailed=False):
        self.detailed = detailed

    def get_available_tools_summary(self):
        return {"recon": ["probe"], "empty": []} if self.detailed else {}

    def get_unavailable_tools_summary(self):
        if self.detailed:
            return {"blocked": ["missing"], "recon": ["fallback"], "empty": []}
        return {}

    def get_discovered_plugins_summary(self):
        return [{"name": "plugin", "type": "python"}] if self.detailed else []

    def get_coverage_report(self):
        if self.detailed:
            return {"unknown": ["gap"]}
        return {
            "unknown": [],
            "covered": 0,
            "registered": 0,
            "auto": [],
            "followup": [],
            "manual_gated": [],
            "legacy_wrappers": [],
        }


class _Context:
    @staticmethod
    def build_context(_scan_id, _target):
        return {"state": "unknown", "services": [], "open_questions": []}


class _Facts:
    def __init__(self):
        self.hypotheses = []

    @staticmethod
    def get_facts(_scan_id, _target):
        return []

    def add_hypothesis(self, *args):
        self.hypotheses.append(args)


class _Pipeline:
    def __init__(self):
        self.cancellation = SimpleNamespace(checkpoint=lambda: None)
        self.tool_registry = _Registry()
        self.state_resolver = SimpleNamespace(resolve_state=lambda _scan_id, _target: {"state": "resolved"})
        self.context_builder = _Context()
        self.fact_store = _Facts()
        self.output_parser = SimpleNamespace(parse_tool_output=lambda *_args: [])
        self.director = SimpleNamespace(
            decide_goal=lambda *_args: {
                "goal": "conclude",
                "thought": "done",
                "llm_status": "ok",
            }
        )
        self.planner = SimpleNamespace(create_plan=lambda *_args: {"plan": []})
        self.discovery_agent = SimpleNamespace(execute_task=lambda *_args: [])
        self.analysis_agent = SimpleNamespace(analyze=lambda *_args: {"hypotheses": [], "llm_status": "ok"})
        self.verification_agent = SimpleNamespace(
            execute_task=lambda *_args: [],
            verify_hypothesis=lambda *_args: {"status": "rejected"},
        )
        self._mission_stop_reason = ""
        self._max_tools_budget = None
        self._state_replan_count = 1
        self.tools_run_count = 0
        self.total_new_facts = 0
        self.consecutive_llm_failures = 0
        self.completed_tasks = set()
        self.blocked_tasks = set()
        self.goal_history = []
        self.fact_history_counts = []
        self.task_history = []
        self.outcomes = []

    @staticmethod
    def _iteration_limit(value):
        return value

    @staticmethod
    def _tool_limit(value):
        return value

    @staticmethod
    def _runtime_limit(value):
        return value

    @staticmethod
    def _seed_known_credentials(_scan_id, _target):
        return 0

    @staticmethod
    def _run_fact_driven_actions(_scan_id, _target, _facts):
        return {"commands": [], "new_facts": 0}

    @staticmethod
    def _sync_runtime_credentials_from_facts(_target, _facts):
        return None

    @staticmethod
    def _print_stage_gates(_context):
        return None

    @staticmethod
    def _record_goal_trace(*_args):
        return None

    @staticmethod
    def _record_llm_health(*_args, **_kwargs):
        return None

    @staticmethod
    def _update_llm_failure_counter(_result):
        return None

    @staticmethod
    def _llm_fallback_only():
        return False

    @staticmethod
    def _resumable_mission_plan():
        return []

    @staticmethod
    def _next_deferred_mission_time():
        return None

    @staticmethod
    def _extract_plan_steps(result):
        return result.get("plan", [])

    @staticmethod
    def _normalize_plan(plan, _goal):
        return plan

    @staticmethod
    def _optimize_plan(plan, _goal, _context):
        return plan

    @staticmethod
    def _compile_plan(plan, *_args, **_kwargs):
        return plan

    @staticmethod
    def _register_mission_plan(plan):
        return plan

    @staticmethod
    def _terminalize_compatibility_exhausted_tasks(_plan):
        return None

    @staticmethod
    def _mission_plan_step_exhausted(step):
        return bool(step.get("exhausted"))

    @staticmethod
    def _begin_task_attempt(_agent, task, **_kwargs):
        if task == "deferred":
            return None
        if task == "dependency-blocked":
            return SimpleNamespace(status="blocked", reason="dependency")
        return SimpleNamespace(status="running", reason="")

    @staticmethod
    def _classify_task_result(result):
        return result["status"]

    def _record_task_outcome(self, *args, **kwargs):
        self.outcomes.append((args, kwargs))

    @staticmethod
    def _evaluate_state_change_replan(_context, _scan_id, _target):
        return False

    @staticmethod
    def _max_state_replans():
        return 3

    @staticmethod
    def _print_efficiency_report(*_args):
        return None


def test_run_converts_tool_budget_exception_to_interrupt(monkeypatch):
    pipeline = _Pipeline()
    pipeline.mission_id = "mission"
    pipeline.mission_store = SimpleNamespace(get_mission_by_scan_id=lambda _scan: None)
    pipeline._reset_runtime_state = lambda: None
    pipeline._start_mission = lambda *_args: SimpleNamespace(status="running")
    interrupted = []
    pipeline._interrupt_mission = interrupted.append
    pipeline._complete_mission = lambda _reason: pytest.fail("mission completed")
    monkeypatch.setattr(
        ScanLifecycle,
        "_run_active",
        staticmethod(lambda *_args: (_ for _ in ()).throw(ToolBudgetReached())),
    )

    assert ScanLifecycle.run(pipeline, "scan", "target") == {"state": "resolved"}
    assert interrupted == ["max_tools_reached"]


def test_manual_seed_registry_diagnostics_and_initial_tool_budget(capsys):
    pipeline = _Pipeline()
    pipeline.tool_registry = _Registry(detailed=True)
    pipeline.tools_run_count = 1
    pipeline.output_parser = SimpleNamespace(
        parse_tool_output=lambda *_args: [
            {"type": "service", "value": "one"},
            {"type": "service", "value": "two"},
        ]
    )
    stored = iter(
        [
            {
                "created": True,
                "new_facts": 1,
                "fact": {"type": "service", "value": "one", "confidence": 90},
            },
            {"created": False, "new_facts": 0, "fact": {}},
        ]
    )
    pipeline._store_fact = lambda *_args: next(stored)
    pipeline._seed_known_credentials = lambda *_args: 2

    result = ScanLifecycle._run_active(
        pipeline,
        "scan",
        "target",
        max_iterations=1,
        max_tools=1,
        raw_scan="manual output",
    )

    assert result == {"state": "resolved"}
    assert pipeline.total_new_facts == 1
    output = capsys.readouterr().out
    assert "Seeded 1 facts" in output
    assert "Blocked capabilities" in output
    assert "Discovered plugins" in output
    assert "Registry coverage gaps" in output


def test_startup_actions_then_time_budget_stops_before_planning():
    pipeline = _Pipeline()
    pipeline._run_fact_driven_actions = lambda *_args: {
        "commands": ["startup"],
        "new_facts": 2,
    }

    ScanLifecycle._run_active(
        pipeline,
        "scan",
        "target",
        max_iterations=2,
        max_tools=None,
        max_time_minutes=0,
    )

    assert pipeline.total_new_facts == 2
    assert pipeline._mission_stop_reason == "max_time_reached"


def test_tool_budget_can_be_reached_after_startup_actions():
    pipeline = _Pipeline()

    def startup(*_args):
        pipeline.tools_run_count = 1
        return {"commands": [], "new_facts": 0}

    pipeline._run_fact_driven_actions = startup

    ScanLifecycle._run_active(
        pipeline,
        "scan",
        "target",
        max_iterations=2,
        max_tools=1,
        max_time_minutes=None,
    )

    assert pipeline._mission_stop_reason == "max_tools_reached"


def test_zero_iteration_limit_exits_loop_and_records_stop_reason():
    pipeline = _Pipeline()

    ScanLifecycle._run_active(
        pipeline,
        "scan",
        "target",
        max_iterations=0,
        max_tools=None,
        max_time_minutes=None,
    )

    assert pipeline._mission_stop_reason == "max_iterations_reached"


def test_registered_empty_plan_with_deferred_work_stops_resumably():
    pipeline = _Pipeline()
    pipeline.director = SimpleNamespace(decide_goal=lambda *_args: {"goal": "work", "thought": "plan"})
    pipeline.planner = SimpleNamespace(create_plan=lambda *_args: {"plan": [{"agent": "Unknown", "task": "task"}]})
    pipeline._register_mission_plan = lambda _plan: []
    deferred = iter((None, 12.0))
    pipeline._next_deferred_mission_time = lambda: next(deferred)

    ScanLifecycle._run_active(
        pipeline,
        "scan",
        "target",
        max_iterations=1,
        max_tools=None,
        max_time_minutes=None,
    )

    assert pipeline._mission_stop_reason == "tasks_deferred"


def test_fallback_director_planner_and_analysis_skip_paths():
    pipeline = _Pipeline()
    pipeline.consecutive_llm_failures = 3
    pipeline._llm_fallback_only = lambda: True
    pipeline._director_fallback_result = lambda _context: {
        "goal": "work",
        "thought": "fallback",
    }
    pipeline._planner_fallback_result = lambda _goal: {"plan": [{"agent": "AnalysisAgent", "task": "analysis"}]}

    ScanLifecycle._run_active(
        pipeline,
        "scan",
        "target",
        max_iterations=1,
        max_tools=None,
        max_time_minutes=None,
    )

    assert "analysis" in pipeline.completed_tasks
    assert pipeline.outcomes[-1][0][2:4] == (
        "no_new_facts",
        "llm_unavailable_fallback_mode",
    )


def test_all_task_agent_outcomes_and_analysis_validation_paths():
    pipeline = _Pipeline()
    tasks = [
        {"agent": "DiscoveryAgent", "task": "already", "exhausted": True},
        {"agent": "DiscoveryAgent", "task": "deferred"},
        {"agent": "DiscoveryAgent", "task": "dependency-blocked"},
        {"agent": "DiscoveryAgent", "task": "discovery-empty"},
        {"agent": "DiscoveryAgent", "task": "discovery-blocked"},
        {"agent": "DiscoveryAgent", "task": "discovery-complete"},
        {"agent": "AnalysisAgent", "task": "analysis-not-dict"},
        {"agent": "AnalysisAgent", "task": "analysis-status-invalid"},
        {"agent": "AnalysisAgent", "task": "analysis-shape-invalid"},
        {"agent": "AnalysisAgent", "task": "analysis-item-invalid"},
        {"agent": "AnalysisAgent", "task": "analysis-failed"},
        {"agent": "AnalysisAgent", "task": "analysis-empty"},
        {"agent": "AnalysisAgent", "task": "analysis-accepted"},
        {"agent": "AnalysisAgent", "task": "analysis-rejected"},
        {"agent": "VerificationAgent", "task": "verification-empty"},
        {"agent": "VerificationAgent", "task": "verification-blocked"},
        {"agent": "VerificationAgent", "task": "verification-complete"},
        {"agent": "OtherAgent", "task": "unknown"},
    ]
    goals = iter(("work", "conclude"))
    pipeline.director = SimpleNamespace(
        decide_goal=lambda *_args: {
            "goal": next(goals),
            "thought": "exercise tasks",
            "llm_status": "ok",
        }
    )
    pipeline.planner = SimpleNamespace(create_plan=lambda *_args: {"plan": tasks})
    pipeline.discovery_agent = SimpleNamespace(
        execute_task=lambda task, _target: [] if task == "discovery-empty" else [task]
    )
    analyses = iter(
        (
            None,
            {"llm_status": "strange", "hypotheses": []},
            {"llm_status": "ok", "hypotheses": "bad"},
            {"llm_status": "ok", "hypotheses": [1]},
            {"llm_status": "failed", "hypotheses": [{"claim": "must-clear"}]},
            {"llm_status": "ok", "hypotheses": []},
            {
                "llm_status": "ok",
                "hypotheses": [
                    {"claim": "accepted", "required_evidence": ["proof"]},
                    {"claim": "accepted-existing"},
                    {"claim": "rejected"},
                ],
            },
            {"llm_status": "ok", "hypotheses": [{"claim": "rejected-only"}]},
        )
    )
    pipeline.analysis_agent = SimpleNamespace(analyze=lambda *_args: next(analyses))
    verification_results = iter(
        (
            {"status": "accepted", "reason": "ok", "fact_id": 42, "created": True},
            {"status": "accepted", "reason": "old", "fact_id": 0, "created": False},
            {"status": "rejected", "reason": "no"},
            {"status": "rejected", "reason": "no"},
        )
    )
    pipeline.verification_agent = SimpleNamespace(
        execute_task=lambda task, _target: [] if task == "verification-empty" else [task],
        verify_hypothesis=lambda *_args: next(verification_results),
    )

    def run_commands(_scan, _target, commands, **_kwargs):
        task = commands[0]
        blocked = task.endswith("blocked")
        return {
            "new_facts": 0 if blocked else 1,
            "parsed_facts": 0 if blocked else 1,
            "commands": [task],
            "status": "blocked" if blocked else "completed",
            "reason": "blocked" if blocked else "done",
        }

    pipeline._run_task_commands = run_commands
    replans = iter((True, False))
    pipeline._evaluate_state_change_replan = lambda *_args: next(replans)

    ScanLifecycle._run_active(
        pipeline,
        "scan",
        "target",
        max_iterations=1,
        max_tools=None,
        max_time_minutes=None,
    )

    reasons = {args[3] for args, _kwargs in pipeline.outcomes}
    assert {
        "no_available_tools",
        "blocked",
        "done",
        "analysis_failed",
        "analysis_returned_no_hypotheses",
        "2_hypotheses_accepted",
        "hypotheses_rejected_or_duplicate",
        "unknown_agent",
    } <= reasons
    assert 42 in pipeline.outcomes[-6][1].get("fact_ids", ()) or any(
        42 in kwargs.get("fact_ids", ()) for _args, kwargs in pipeline.outcomes
    )
