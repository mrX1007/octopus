"""Focused branch coverage for deterministic pipeline planning seams."""

from __future__ import annotations

import builtins
from types import SimpleNamespace
from typing import Any

import pytest

import core.ai.pipeline_planning as planning_module
from core.ai.pipeline_planning import PipelinePlanningMixin
from core.execution import CAP_ACTIVE_TOOL, ExecutionContext

pytestmark = pytest.mark.unit


class RegistryStub:
    def __init__(self) -> None:
        self.profiles: dict[str, dict[str, Any]] = {}
        self.unavailable: set[str] = set()

    def canonical_task(self, task: object) -> str:
        return str(task or "").strip().lower().replace("-", "_").replace(" ", "_")

    def has_task(self, task: str) -> bool:
        return task != "unknown_task"

    def task_has_available_tools(self, task: str) -> bool:
        return task not in self.unavailable

    def task_profile(self, task: str) -> dict[str, Any]:
        return dict(self.profiles.get(task, {}))


class CompilerStub:
    def __init__(self) -> None:
        self.result = SimpleNamespace(plan=[], rejected=[])
        self.calls: list[tuple[list[dict[str, Any]], dict[str, Any]]] = []

    def compile(self, plan: list[dict[str, Any]], **kwargs: Any) -> SimpleNamespace:
        self.calls.append((plan, kwargs))
        return self.result


class SnapshotStub:
    def __init__(self, *, snapshot_ref: str = "snapshot-ref") -> None:
        self.snapshot_ref = snapshot_ref

    def decision_facts(self) -> tuple[dict[str, str], ...]:
        return ({"type": "port_open", "value": "80/tcp (http)"},)


class PlanningHarness(PipelinePlanningMixin):
    MAX_CONSECUTIVE_LLM_FAILURES = 3

    def __init__(self) -> None:
        self.tool_registry = RegistryStub()
        self.cancellation = ExecutionContext.automatic().cancellation
        self.consecutive_llm_failures = 0
        self.goal_history: list[str] = []
        self.director = SimpleNamespace(_fallback_logic=lambda context, history: {"goal": "fallback", "seen": context})
        self.planner = SimpleNamespace(_fallback_logic=lambda goal: {"plan": [], "goal": goal})
        self.fact_store = SimpleNamespace(get_facts=lambda scan_id, target: [])
        self.mission_id = ""
        self.stored_snapshots: list[tuple[str, object]] = []
        self.mission_store = SimpleNamespace(
            store_evaluated_fact_snapshot=lambda mission_id, snapshot: self.stored_snapshots.append(
                (mission_id, snapshot)
            )
        )
        self.plan_compiler = CompilerStub()
        self.plan_rejections: list[dict[str, Any]] = []
        self.blocked_tasks: set[str] = set()
        self.completed_tasks: set[str] = set()
        self.persisted_rejections: list[tuple[str, str, str]] = []
        self.policy = SimpleNamespace(validate_plan=lambda plan, context: plan)
        self.strategy: dict[str, bool] = {}
        self.capability_resolver = SimpleNamespace(
            missing_requirements=lambda requirements, context: list(requirements)
        )
        self.task_history: list[str] = []
        self.goal_trace: list[dict[str, Any]] = []
        self._current_scan_id = "scan-current"
        self.authorized_scope = False

    def _target_in_authorized_scope(self, target: str, allowed: list[str]) -> bool:
        return self.authorized_scope and target in allowed

    def _strategy_enabled(self, name: str, default: bool) -> bool:
        return self.strategy.get(name, default)

    def _persist_plan_rejection(self, agent: str, task: str, reason: str) -> None:
        self.persisted_rejections.append((agent, task, reason))

    def _mission_task_scope(self, step: dict[str, Any]) -> object:
        return step.get("scope")

    def _mission_task_scope_identity(self, scope: object) -> str:
        return repr(scope)


def _reject_config_import(monkeypatch: pytest.MonkeyPatch) -> None:
    original_import = builtins.__import__

    def fake_import(name: str, *args: Any, **kwargs: Any) -> Any:
        if name == "config":
            raise ImportError("isolated config")
        return original_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", fake_import)


def _use_identity_enrichment(pipeline: PlanningHarness) -> None:
    pipeline._rank_candidate_tasks = lambda candidates, _context, _critical: list(dict.fromkeys(candidates))
    pipeline._plan_enrichment_limit = lambda: 100


def test_runtime_limits_handle_none_invalid_values_and_missing_config(monkeypatch: pytest.MonkeyPatch) -> None:
    pipeline = PlanningHarness()

    assert pipeline._runtime_limit(None) is None
    assert pipeline._runtime_limit(object()) is None

    _reject_config_import(monkeypatch)
    assert pipeline._iteration_limit(4) == 4
    assert pipeline._tool_limit(5) == 5
    context = pipeline._execution_context("scan-1", "example.test")
    assert context.approved is False
    assert context.target_scope == ("example.test",)


def test_execution_context_grants_active_capability_only_for_authorized_target(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import config

    pipeline = PlanningHarness()
    pipeline.authorized_scope = True
    monkeypatch.setitem(
        config.CFG,
        "strategy",
        {"active_authorized": True, "authorized_targets": ["example.test"]},
    )

    context = pipeline._execution_context("scan-active", "example.test")

    assert context.approved is True
    assert context.approval_id == "config:active_authorized:scan-active"
    assert context.has(CAP_ACTIVE_TOOL)


def test_llm_fallback_helpers_track_dead_provider_state() -> None:
    pipeline = PlanningHarness()

    assert pipeline._llm_fallback_only() is False
    pipeline.consecutive_llm_failures = 3
    assert pipeline._llm_fallback_only() is True
    assert pipeline._director_fallback_result({"state": "initial"}) == {
        "goal": "fallback",
        "seen": {"state": "initial"},
        "llm_status": "skipped",
        "llm_error": "llm_dead_fallback_only",
        "fallback": True,
    }
    assert pipeline._planner_fallback_result("service_discovery") == {
        "plan": [],
        "goal": "service_discovery",
        "llm_status": "skipped",
        "llm_error": "llm_dead_fallback_only",
        "fallback": True,
    }


def test_compile_plan_persists_snapshot_rejections_and_snapshot_references() -> None:
    pipeline = PlanningHarness()
    pipeline.mission_id = "mission-1"
    pipeline.plan_compiler.result = SimpleNamespace(
        rejected=[
            {
                "agent": "DiscoveryAgent",
                "task": "known-task",
                "reason": "provider_unavailable",
                "blocking_reasons": ["binary_missing", "policy"],
            },
            {"task": "", "blocking_reasons": []},
        ],
        plan=[{"agent": "DiscoveryAgent", "task": "known-task"}],
    )
    snapshot = SnapshotStub(snapshot_ref="snapshot://one")

    compiled = pipeline._compile_plan(
        [{"agent": "DiscoveryAgent", "task": "known-task"}],
        "scan-compile",
        "example.test",
        {"state": "recon"},
        evaluated_fact_snapshot=snapshot,
    )

    assert compiled == [
        {
            "agent": "DiscoveryAgent",
            "task": "known-task",
            "evaluated_snapshot_ref": "snapshot://one",
        }
    ]
    assert pipeline.stored_snapshots == [("mission-1", snapshot)]
    assert pipeline.blocked_tasks == {"known_task"}
    assert pipeline.persisted_rejections == [
        ("DiscoveryAgent", "known_task", "provider_unavailable:binary_missing, policy"),
        ("", "", "capability_unavailable"),
    ]


def test_compile_plan_builds_snapshot_and_allows_empty_reference(monkeypatch: pytest.MonkeyPatch) -> None:
    pipeline = PlanningHarness()
    built_snapshot = SnapshotStub(snapshot_ref="built-ref")
    build_calls: list[tuple[str, str, list[object]]] = []

    def build(scan_id: str, target: str, facts: list[object]) -> SnapshotStub:
        build_calls.append((scan_id, target, facts))
        return built_snapshot

    monkeypatch.setattr(planning_module.EvaluatedFactSnapshot, "build", staticmethod(build))
    pipeline.plan_compiler.result = SimpleNamespace(rejected=[], plan=[])

    assert pipeline._compile_plan([], "scan-built", "host", {}) == []
    assert build_calls == [("scan-built", "host", [])]

    pipeline.plan_compiler.result = SimpleNamespace(
        rejected=[],
        plan=[{"agent": "DiscoveryAgent", "task": "service_discovery"}],
    )
    assert pipeline._compile_plan(
        [],
        "scan-empty-ref",
        "host",
        {},
        evaluated_fact_snapshot=SnapshotStub(snapshot_ref=""),
    ) == [{"agent": "DiscoveryAgent", "task": "service_discovery"}]


def test_normalize_plan_covers_filtered_steps_aliases_and_commands(monkeypatch: pytest.MonkeyPatch) -> None:
    pipeline = PlanningHarness()

    monkeypatch.setattr(pipeline, "_coerce_plan_steps", lambda _plan: ["not-a-dict"])
    assert pipeline._normalize_plan([]) == []

    monkeypatch.setattr(pipeline, "_coerce_plan_steps", PipelinePlanningMixin._coerce_plan_steps.__get__(pipeline))
    with monkeypatch.context() as isolated:
        isolated.setattr(pipeline, "_task_from_planner_command", lambda _command: "")
        assert pipeline._normalize_plan([{}]) == []
    assert pipeline._normalize_plan([{"task": "verify exploit"}], "privilege_escalation")[0]["task"] == (
        "exploit_privesc"
    )
    assert pipeline._normalize_plan([{"action": "directory_bruteforce"}], "data_exfiltration")[0]["task"] == (
        "exfiltrate_data"
    )
    command_plan = pipeline._normalize_plan([{"command": "service_discovery host"}])
    assert command_plan[0]["task"] == "service_discovery"
    assert pipeline._task_from_planner_command("service_discovery host") == "service_discovery"


def test_extract_and_coerce_plan_steps_accept_all_supported_shapes() -> None:
    pipeline = PlanningHarness()
    step = {"task": "service_discovery"}

    assert pipeline._extract_plan_steps([step]) == [step]
    assert pipeline._coerce_plan_steps("invalid") == []
    assert pipeline._coerce_plan_steps({"plan": {"tasks": [step, "ignored"]}}) == [step]
    assert pipeline._coerce_plan_steps({"command": "service_discovery host"}) == [{"command": "service_discovery host"}]
    assert pipeline._coerce_plan_steps({"metadata": "only"}) == []


def test_agent_fallback_uses_goal_for_unknown_post_access_task() -> None:
    pipeline = PlanningHarness()

    assert pipeline._agent_for_task("custom_task", "cleanup") == "VerificationAgent"


def test_optimize_plan_returns_equal_forced_plan_and_filters_invalid_steps(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    pipeline = PlanningHarness()
    forced = [{"agent": "VerificationAgent", "task": "post_access_inventory"}]
    monkeypatch.setattr(pipeline, "_post_exploit_plan", lambda *_args: forced)
    assert pipeline._optimize_plan(forced, "goal", {"state": "root_access_confirmed"}) is forced

    monkeypatch.setattr(pipeline, "_post_exploit_plan", lambda *_args: None)
    steps = [
        {},
        {"agent": "DiscoveryAgent"},
        {"agent": "DiscoveryAgent", "task": "known-task", "scope": "host"},
        {"agent": "DiscoveryAgent", "task": "known-task", "scope": "host"},
        {"agent": "AnalysisAgent", "task": "known-task"},
        {"agent": "DiscoveryAgent", "task": "unknown-task"},
        {"agent": "AnalysisAgent", "task": "analyze-vulnerabilities"},
    ]

    assert pipeline._optimize_plan(steps, "other", {"state": "initial"}) == [
        {"agent": "DiscoveryAgent", "task": "known_task", "scope": "host"},
        {"agent": "AnalysisAgent", "task": "analyze_vulnerabilities"},
    ]


def test_post_exploit_plans_cover_every_guardrail(monkeypatch: pytest.MonkeyPatch) -> None:
    import core.killchain.policy as killchain_policy

    pipeline = PlanningHarness()
    allowed = {"persistence": True, "data_exfil": True, "cleanup": True}
    monkeypatch.setattr(killchain_policy, "automated_stage_enabled", lambda stage: allowed[stage])
    state = "root_access_confirmed"

    assert pipeline._post_exploit_plan("post_access_inventory", state) == [
        {"agent": "VerificationAgent", "task": "post_access_inventory"}
    ]
    assert pipeline._post_exploit_plan("persistence", state) == []

    pipeline.strategy["auto_persistence"] = True
    pipeline.strategy["auto_payload_generation"] = True
    assert pipeline._post_exploit_plan("persistence", state) == [
        {"agent": "VerificationAgent", "task": "payload_generation"},
        {"agent": "VerificationAgent", "task": "establish_persistence"},
    ]
    pipeline.strategy["auto_payload_generation"] = False
    assert pipeline._post_exploit_plan("persistence", state) == [
        {"agent": "VerificationAgent", "task": "establish_persistence"}
    ]

    pipeline.strategy["auto_internal_recon"] = False
    assert pipeline._post_exploit_plan("internal_reconnaissance", state) == []
    pipeline.strategy["auto_internal_recon"] = True
    assert pipeline._post_exploit_plan("internal_reconnaissance", state) == [
        {"agent": "VerificationAgent", "task": "internal_network_recon"}
    ]

    assert pipeline._post_exploit_plan("data_exfiltration", state) == []
    pipeline.strategy["auto_data_exfil"] = True
    assert pipeline._post_exploit_plan("data_exfiltration", state) == [
        {"agent": "VerificationAgent", "task": "exfiltrate_data"}
    ]

    assert pipeline._post_exploit_plan("cleanup", state) == []
    pipeline.strategy["auto_cleanup"] = True
    assert pipeline._post_exploit_plan("cleanup", state) == [{"agent": "VerificationAgent", "task": "stealth_cleanup"}]

    allowed.update(persistence=False, data_exfil=False, cleanup=False)
    assert pipeline._post_exploit_plan("persistence", state) == []
    assert pipeline._post_exploit_plan("data_exfiltration", state) == []
    assert pipeline._post_exploit_plan("cleanup", state) == []


def test_vulnerability_enrichment_covers_sparse_and_full_web_surfaces() -> None:
    pipeline = PlanningHarness()
    _use_identity_enrichment(pipeline)
    sparse_context = {
        "host": "app.example.test",
        "services": ["smb", "ldap"],
        "open_questions": [],
        "coverage_gaps": [
            "internal_vulnerability_assessment_pending",
            "web_app_deep_testing_pending",
        ],
        "target_model": {
            "surface_states": {
                "asm": "unknown",
                "api": "confirmed_absent",
                "web": "confirmed_present",
                "cloud": "unknown",
            },
            "assets": {
                "domains": ["app.example.test"],
                "urls": ["https://app.example.test"],
            },
        },
    }

    sparse_tasks = {item["task"] for item in pipeline._enrich_plan([], "vulnerability_assessment", sparse_context)}
    assert {
        "exploit_selection",
        "asm_discovery",
        "web_app_deep_testing",
        "web_vulnerability_testing",
        "windows_enumeration",
        "active_directory_enumeration",
        "ad_security_review",
        "template_verification",
        "cloud_security_assessment",
    }.issubset(sparse_tasks)
    assert "web_application_mapping" not in sparse_tasks
    assert "api_security_testing" not in sparse_tasks

    full_context = {
        "host": "10.0.0.5",
        "services": ["http", "https"],
        "open_questions": [],
        "coverage_gaps": [],
        "target_model": {
            "surface_states": {
                "asm": "confirmed_present",
                "api": "confirmed_present",
                "cloud": "confirmed_absent",
            }
        },
    }
    full_tasks = {item["task"] for item in pipeline._enrich_plan([], "vulnerability_assessment", full_context)}
    assert "web_application_mapping" in full_tasks
    assert "api_security_testing" in full_tasks
    assert "transport_security_assessment" in full_tasks
    assert "web_app_deep_testing" not in full_tasks


def test_credential_and_internal_recon_enrichment_cover_present_and_empty_candidates() -> None:
    pipeline = PlanningHarness()
    _use_identity_enrichment(pipeline)
    credential_context = {
        "services": ["ldap", "ssh", "smb"],
        "open_questions": ["web_credentials_unknown"],
    }

    credential_tasks = {item["task"] for item in pipeline._enrich_plan([], "credential_harvesting", credential_context)}
    assert {
        "active_directory_enumeration",
        "kerberos_assessment",
        "web_credential_testing",
        "ssh_user_enumeration",
        "windows_enumeration",
    } == credential_tasks
    assert pipeline._enrich_plan([], "credential_harvesting", {}) == []

    internal_context = {
        "coverage_gaps": [
            "internal_network_recon_pending",
            "internal_service_assessment_pending",
        ]
    }
    assert {item["task"] for item in pipeline._enrich_plan([], "internal_reconnaissance", internal_context)} == {
        "internal_network_recon",
        "internal_service_discovery",
    }
    assert pipeline._enrich_plan([], "internal_reconnaissance", {}) == []

    original = [{"agent": "DiscoveryAgent", "task": "ssh_user_enumeration"}]
    assert pipeline._enrich_plan(original, "credential_harvesting", {"services": ["ssh"]}) == original

    pipeline.completed_tasks.add("ssh_user_enumeration")
    assert pipeline._enrich_plan([], "credential_harvesting", {"services": ["ssh"]}) == []


def test_task_scoring_handles_empty_preconditions_invalid_cost_and_completed_unknown_task() -> None:
    pipeline = PlanningHarness()
    pipeline.tool_registry.profiles["novel_task"] = {
        "preconditions": [],
        "cost": object(),
        "time": "unexpected",
        "risk": "unknown",
    }
    pipeline.completed_tasks.add("novel_task")

    signals = pipeline._task_scoring_signals("novel_task", {})

    assert signals.path_value == 0.45
    assert signals.cost == 0.6
    assert signals.repeat == 1.0
    assert signals.risk == 0.8
    assert signals.uncertainty == 0.5


def test_empty_scoring_trace_and_plan_limit_error_paths(monkeypatch: pytest.MonkeyPatch) -> None:
    pipeline = PlanningHarness()
    assert pipeline._record_task_scoring_trace([], {}) is None

    with monkeypatch.context() as isolated:
        _reject_config_import(isolated)
        assert pipeline._plan_enrichment_limit() == 8

    import config

    monkeypatch.setitem(config.CFG, "strategy", {"plan_enrichment_limit": object()})
    assert pipeline._plan_enrichment_limit() == 8


def test_trim_low_priority_enrichment_handles_protected_missing_and_fallback_steps() -> None:
    pipeline = PlanningHarness()
    protected_plan = [
        {"task": "web_application_mapping"},
        {"task": "web_vulnerability_testing"},
    ]
    pipeline._trim_low_priority_enrichment(protected_plan, {"web_application_mapping"})
    assert protected_plan == [{"task": "web_application_mapping"}]

    long_plan = [{"task": f"custom_{index}"} for index in range(4)]
    pipeline._trim_low_priority_enrichment(long_plan, set())
    assert [item["task"] for item in long_plan] == ["custom_0", "custom_1", "custom_3"]

    short_plan = [{"task": "custom_0"}, {"task": "custom_1"}]
    pipeline._trim_low_priority_enrichment(short_plan, set())
    assert len(short_plan) == 2
