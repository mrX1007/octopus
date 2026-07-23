"""Acceptance contracts for the remaining Wave 2/4 orchestration work."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

from core.ai.command_scheduler import CommandDecision
from core.ai.evaluated_facts import EvaluatedFactSnapshot
from core.ai.mission_store import TaskScope
from core.ai.pipeline import AIPipeline
from core.ai.planner import PlanCompilation
from core.ai.task_scoring import TaskScorer, TaskScoringWeights
from core.execution import ExecutionResult, ExecutionStatus
from core.knowledge.identity import canonical_asset, canonical_service

pytestmark = pytest.mark.contract


def test_pipeline_facade_stays_substantially_below_original_size():
    pipeline_path = Path(__file__).parents[1] / "core" / "ai" / "pipeline.py"

    assert len(pipeline_path.read_text(encoding="utf-8").splitlines()) <= 2_400


def test_registered_pipeline_task_persists_scope_capability_and_retry_policy(
    tmp_path,
):
    pipeline = AIPipeline(str(tmp_path / "task-metadata.db"))
    pipeline._reset_runtime_state()
    pipeline._start_mission("scan-task-metadata", "10.0.0.5")

    pipeline._register_mission_plan(
        [
            {
                "agent": "DiscoveryAgent",
                "task": "service_discovery",
                "scope": {"target": "10.0.0.5", "kind": "host"},
                "capability": "network.service_discovery",
            }
        ]
    )

    task = pipeline.mission_store.snapshot(pipeline.mission_id).tasks[0]
    assert task.scope == '{"kind":"host","target":"10.0.0.5"}'
    assert task.capability == "network.service_discovery"
    assert task.retry_budget == 2
    assert {item.value for item in task.retryable_error_classes} == {
        "timeout",
        "rate_limit",
        "transient_network",
        "provider_unavailable",
        "tool_unavailable",
    }


def test_compiled_plan_carries_evaluated_snapshot_ref_into_registered_task(
    tmp_path,
):
    pipeline = AIPipeline(str(tmp_path / "task-snapshot-ref.db"))
    pipeline._reset_runtime_state()
    pipeline._start_mission("scan-task-snapshot-ref", "10.0.0.5")
    pipeline.plan_compiler = SimpleNamespace(
        compile=lambda plan, **_kwargs: PlanCompilation(
            plan=tuple(dict(step) for step in plan),
            rejected=(),
        )
    )
    snapshot = EvaluatedFactSnapshot.build(
        "scan-task-snapshot-ref",
        "10.0.0.5",
        [],
        evaluated_at=123.0,
    )

    compiled = pipeline._compile_plan(
        [
            {
                "agent": "DiscoveryAgent",
                "task": "service_discovery",
                "evaluated_snapshot_ref": "evaluated-facts://stale",
            }
        ],
        "scan-task-snapshot-ref",
        "10.0.0.5",
        {"evaluated_fact_snapshot_ref": snapshot.snapshot_ref},
        evaluated_fact_snapshot=snapshot,
    )
    pipeline._register_mission_plan(compiled)

    task = pipeline.mission_store.snapshot(pipeline.mission_id).tasks[0]
    assert compiled[0]["evaluated_snapshot_ref"] == snapshot.snapshot_ref
    assert task.evaluated_snapshot_ref == snapshot.snapshot_ref
    restored = pipeline.mission_store.resolve_evaluated_fact_snapshot(
        pipeline.mission_id,
        snapshot.snapshot_ref,
    )
    assert restored == snapshot


def test_restarted_task_execution_uses_accepted_durable_snapshot(tmp_path) -> None:
    db_path = tmp_path / "task-snapshot-restart.db"
    scan_id = "scan-task-snapshot-restart"
    target = "10.0.0.5"
    first = AIPipeline(str(db_path))
    first._reset_runtime_state()
    first._start_mission(scan_id, target)
    initial_id = first.fact_store.add_fact(
        scan_id,
        target,
        "port_open",
        "80/tcp (http)",
        "initial-probe",
    )
    snapshot = first.context_builder.build_evaluated_fact_snapshot(scan_id, target)
    first.plan_compiler = SimpleNamespace(
        compile=lambda plan, **_kwargs: PlanCompilation(
            plan=tuple(dict(step) for step in plan),
            rejected=(),
        )
    )
    compiled = first._compile_plan(
        [{"agent": "DiscoveryAgent", "task": "service_discovery"}],
        scan_id,
        target,
        {"evaluated_fact_snapshot_ref": snapshot.snapshot_ref},
        evaluated_fact_snapshot=snapshot,
    )
    task = first._register_mission_plan(compiled)[0]
    late_id = first.fact_store.add_fact(
        scan_id,
        target,
        "potential_vulnerability",
        "CVE-2099-0001 late observation",
        "late-probe",
    )
    first._interrupt_mission("simulated_restart")

    resumed = AIPipeline(str(db_path))
    resumed._reset_runtime_state()
    resumed._start_mission(scan_id, target)
    resumed_task = resumed._resumable_mission_plan()[0]
    assert resumed_task["task_id"] == task["task_id"]
    resumed._register_mission_plan([resumed_task])
    resumed._begin_task_attempt(
        resumed_task["agent"],
        resumed_task["task"],
        task_id=resumed_task["task_id"],
    )
    observed: dict[str, list[dict]] = {}

    def decide(command, facts, *_args, **_kwargs):
        observed["facts"] = list(facts)
        return CommandDecision(command, "probe:accepted-snapshot", "execute", "test")

    resumed.runtime.decide = decide
    resumed.runtime.execute = lambda _decision, _context: ExecutionResult(
        status=ExecutionStatus.SUCCEEDED,
        request_id="request-accepted-snapshot",
        execution_id="exec-accepted-snapshot",
        tool_name="probe",
        stdout="",
        exit_code=0,
    )
    resumed.runtime.parse_output = lambda _command, _result: []

    resumed._execute_pipeline_command(
        scan_id,
        target,
        "probe target",
        "Fact",
        "[Running]",
    )

    assert [fact["id"] for fact in observed["facts"]] == [initial_id]
    assert late_id not in {fact["id"] for fact in observed["facts"]}


def test_plan_compiler_uses_captured_snapshot_without_rereading_fact_store(
    tmp_path,
):
    pipeline = AIPipeline(str(tmp_path / "captured-plan-snapshot.db"))
    captured = {}
    snapshot = EvaluatedFactSnapshot.build(
        "scan-captured-plan-snapshot",
        "10.0.0.5",
        [
            {"id": 1, "type": "port_open", "value": "443/tcp"},
            {
                "id": 2,
                "type": "port_open",
                "value": "80/tcp",
                "assessment": {"status": "contradicted"},
            },
        ],
        evaluated_at=123.0,
    )

    def compile_plan(plan, **kwargs):
        captured["facts"] = kwargs["facts"]
        return PlanCompilation(
            plan=tuple(dict(step) for step in plan),
            rejected=(),
        )

    pipeline.plan_compiler = SimpleNamespace(compile=compile_plan)
    pipeline.fact_store.get_facts = lambda *_args: (_ for _ in ()).throw(
        AssertionError("FactStore was reread after snapshot capture")
    )

    compiled = pipeline._compile_plan(
        [{"agent": "DiscoveryAgent", "task": "service_discovery"}],
        "scan-captured-plan-snapshot",
        "10.0.0.5",
        {"evaluated_fact_snapshot_ref": snapshot.snapshot_ref},
        evaluated_fact_snapshot=snapshot,
    )

    assert [fact["id"] for fact in captured["facts"]] == [1]
    assert compiled[0]["evaluated_snapshot_ref"] == snapshot.snapshot_ref


def test_plan_compiler_compat_fallback_uses_evaluated_decision_facts(tmp_path):
    pipeline = AIPipeline(str(tmp_path / "fallback-plan-snapshot.db"))
    captured = {}
    pipeline.fact_store.get_facts = lambda *_args: [
        {"id": 1, "type": "port_open", "value": "443/tcp"},
        {
            "id": 2,
            "type": "port_open",
            "value": "80/tcp",
            "freshness_status": "stale",
        },
    ]

    def compile_plan(plan, **kwargs):
        captured["facts"] = kwargs["facts"]
        return PlanCompilation(
            plan=tuple(dict(step) for step in plan),
            rejected=(),
        )

    pipeline.plan_compiler = SimpleNamespace(compile=compile_plan)

    compiled = pipeline._compile_plan(
        [{"agent": "DiscoveryAgent", "task": "service_discovery"}],
        "scan-fallback-plan-snapshot",
        "10.0.0.5",
        {},
    )

    assert [fact["id"] for fact in captured["facts"]] == [1]
    assert compiled[0]["evaluated_snapshot_ref"].startswith(
        "evaluated-facts://sha256/"
    )


def test_plan_optimization_keeps_same_task_for_distinct_typed_scopes(tmp_path):
    target = "10.0.0.5"
    pipeline = AIPipeline(str(tmp_path / "typed-scope-optimization.db"))
    pipeline._current_target = target
    asset_scope = TaskScope(
        entity_ids=(canonical_asset(target).entity_id,),
        legacy_scope=f"asset:{target}",
    )
    service_scope = TaskScope(
        entity_ids=(canonical_service(target, 443).entity_id,),
        legacy_scope=f"service:{target}:443/tcp",
    )

    optimized = pipeline._optimize_plan(
        [
            {
                "agent": "DiscoveryAgent",
                "task": "service_discovery",
                "task_scope": asset_scope,
            },
            {
                "agent": "DiscoveryAgent",
                "task": "service_discovery",
                "task_scope": service_scope,
            },
            {
                "agent": "DiscoveryAgent",
                "task": "service_discovery",
                "task_scope": TaskScope(
                    entity_ids=asset_scope.entity_ids,
                    legacy_scope="display-alias-that-is-not-identity",
                ),
            },
            {
                "agent": "VerificationAgent",
                "task": "service_discovery",
                "task_scope": TaskScope(
                    entity_ids=asset_scope.entity_ids,
                    legacy_scope="different-agent-display-alias",
                ),
            },
        ],
        "service_discovery",
        {"state": "initial_recon"},
    )

    assert [step["task_scope"] for step in optimized] == [
        asset_scope,
        service_scope,
        TaskScope(
            entity_ids=asset_scope.entity_ids,
            legacy_scope="different-agent-display-alias",
        ),
    ]
    assert [step["agent"] for step in optimized] == [
        "DiscoveryAgent",
        "DiscoveryAgent",
        "VerificationAgent",
    ]


def test_pipeline_schedules_only_typed_transient_failure_for_retry(tmp_path):
    pipeline = AIPipeline(str(tmp_path / "typed-retry.db"))
    pipeline._reset_runtime_state()
    pipeline._start_mission("scan-typed-retry", "10.0.0.5")
    pipeline._register_mission_plan(
        [{"agent": "DiscoveryAgent", "task": "service_discovery"}]
    )
    pipeline._begin_task_attempt("DiscoveryAgent", "service_discovery")
    pipeline.completed_tasks.add("service_discovery")

    pipeline._record_task_outcome(
        "DiscoveryAgent",
        "service_discovery",
        "failed",
        "all_commands_failed",
        0,
        0,
        [
            {
                "command": "nmap target",
                "failed": True,
                "status": "timeout",
                "error_class": "TimeoutExpired",
                "fact_pairs": [],
            }
        ],
        0.1,
    )

    snapshot = pipeline.mission_store.snapshot(pipeline.mission_id)
    task = snapshot.tasks[0]
    assert task.status == "pending"
    assert task.retry_count == 1
    assert task.last_error_class.value == "timeout"
    assert "service_discovery" not in pipeline.completed_tasks
    assert "service_discovery" in pipeline.retry_scheduled_tasks
    events = pipeline.decision_trace.list_events(
        scan_id="scan-typed-retry",
        event_type="task_retry_scheduled",
    )
    assert len(events) == 1
    assert events[0]["retry_count"] == 1


def test_state_change_replan_is_material_deduplicated_and_bounded(tmp_path):
    pipeline = AIPipeline(str(tmp_path / "state-replan.db"))
    pipeline._reset_runtime_state()
    pipeline._start_mission("scan-state-replan", "10.0.0.5")
    pipeline._max_state_replans = lambda: 2
    contexts = iter(
        [
            {"state": "recon_completed", "next_required_capability": "verify"},
            {"state": "access_confirmed", "next_required_capability": "inventory"},
            {"state": "inventory_completed", "next_required_capability": "conclude"},
        ]
    )
    pipeline.context_builder = SimpleNamespace(
        build_context=lambda _scan, _target: next(contexts)
    )

    assert pipeline._evaluate_state_change_replan(
        {"state": "initial_recon"},
        "scan-state-replan",
        "10.0.0.5",
    ) is True
    assert pipeline._evaluate_state_change_replan(
        {"state": "recon_completed", "next_required_capability": "verify"},
        "scan-state-replan",
        "10.0.0.5",
    ) is True
    assert pipeline._evaluate_state_change_replan(
        {"state": "access_confirmed", "next_required_capability": "inventory"},
        "scan-state-replan",
        "10.0.0.5",
    ) is False
    assert pipeline._state_replan_count == 2
    assert len(
        pipeline.decision_trace.list_events(
            scan_id="scan-state-replan",
            event_type="state_replan_requested",
        )
    ) == 2
    assert len(
        pipeline.decision_trace.list_events(
            scan_id="scan-state-replan",
            event_type="state_replan_rejected",
        )
    ) == 1


def test_state_change_replan_reads_nested_fact_assessment_counts(tmp_path):
    pipeline = AIPipeline(str(tmp_path / "assessment-replan.db"))
    pipeline._reset_runtime_state()
    pipeline._start_mission("scan-assessment-replan", "10.0.0.5")
    pipeline._max_state_replans = lambda: 1
    previous = {
        "state": "recon_completed",
        "next_required_capability": "verify",
        "stage_gates": {"recon": True},
        "fact_assessments": {
            "counts": {"observed": 1, "verified": 0, "contradicted": 0}
        },
    }
    current = {
        **previous,
        "fact_assessments": {
            "counts": {"observed": 0, "verified": 1, "contradicted": 0}
        },
    }
    pipeline.context_builder = SimpleNamespace(
        build_context=lambda _scan, _target: current
    )

    assert pipeline._evaluate_state_change_replan(
        previous,
        "scan-assessment-replan",
        "10.0.0.5",
    ) is True
    assert pipeline._state_replan_count == 1
    assert (
        pipeline.mission_store.snapshot(pipeline.mission_id).mission.state_replan_count
        == 1
    )


def test_state_change_replan_budget_and_deduplication_survive_restart(tmp_path):
    db_path = tmp_path / "restart-replan.db"
    scan_id = "scan-restart-replan"
    target = "10.0.0.5"
    initial = {"state": "initial_recon"}
    recon = {"state": "recon_completed", "next_required_capability": "verify"}

    first = AIPipeline(str(db_path))
    first._reset_runtime_state()
    first._start_mission(scan_id, target)
    first._max_state_replans = lambda: 1
    first.context_builder = SimpleNamespace(
        build_context=lambda _scan, _target: recon
    )
    assert first._evaluate_state_change_replan(initial, scan_id, target) is True
    assert first._state_replan_count == 1
    first.mission_store.close()

    resumed = AIPipeline(str(db_path))
    resumed._reset_runtime_state()
    resumed._start_mission(scan_id, target)
    resumed._max_state_replans = lambda: 1

    assert resumed._state_replan_count == 1
    assert len(resumed._state_replan_signatures) == 1

    resumed.context_builder = SimpleNamespace(
        build_context=lambda _scan, _target: recon
    )
    assert resumed._evaluate_state_change_replan(initial, scan_id, target) is False
    assert len(resumed._state_replan_signatures) == 1

    verified = {
        "state": "recon_completed",
        "next_required_capability": "verify",
        "fact_assessments": {"counts": {"observed": 0, "verified": 1}},
    }
    resumed.context_builder = SimpleNamespace(
        build_context=lambda _scan, _target: verified
    )
    assert resumed._evaluate_state_change_replan(recon, scan_id, target) is False

    durable = resumed.mission_store.snapshot(resumed.mission_id).mission
    assert durable.state_replan_count == 1
    assert len(durable.state_replan_signatures) == 2
    assert len(resumed._state_replan_signatures) == 2
    assert resumed._evaluate_state_change_replan(recon, scan_id, target) is False
    assert len(resumed._state_replan_signatures) == 2
    assert len(
        resumed.decision_trace.list_events(
            scan_id=scan_id,
            event_type="state_replan_requested",
        )
    ) == 1
    assert len(
        resumed.decision_trace.list_events(
            scan_id=scan_id,
            event_type="state_replan_rejected",
        )
    ) == 1


def test_pipeline_scoring_penalizes_repeats_and_emits_explanation(tmp_path):
    pipeline = AIPipeline(str(tmp_path / "task-scoring.db"))
    pipeline._reset_runtime_state()
    pipeline._current_scan_id = "scan-task-scoring"
    pipeline.task_history.extend(
        ["DiscoveryAgent:plugin_assessment", "DiscoveryAgent:plugin_assessment"]
    )
    context = {"state": "recon_completed", "open_questions": []}

    ranked = pipeline._rank_candidate_tasks(
        ["plugin_assessment", "external_intelligence"],
        context,
    )

    assert ranked == ["external_intelligence", "plugin_assessment"]
    event = pipeline.decision_trace.list_events(
        scan_id="scan-task-scoring",
        event_type="task_scoring",
    )[0]
    assert event["chosen_action"] == "external_intelligence"
    assert event["actual_outcome"]["ranking"][0]["explanation"].startswith(
        "task_score:1.0;"
    )


def test_critical_candidate_is_a_hard_tier_above_configured_soft_score(tmp_path):
    pipeline = AIPipeline(str(tmp_path / "critical-task-scoring.db"))
    pipeline._reset_runtime_state()
    pipeline._current_scan_id = "scan-critical-task-scoring"
    pipeline.task_history.extend(
        ["DiscoveryAgent:cpanel_assessment"] * 3
    )
    pipeline.task_scorer = TaskScorer(
        TaskScoringWeights(
            information_gain=0,
            coverage_value=0,
            verification_value=0,
            path_value=0,
            cost=0,
            repeat=100,
            risk=0,
            uncertainty=0,
        )
    )

    ranked = pipeline._rank_candidate_tasks(
        ["external_intelligence", "cpanel_assessment"],
        {"state": "recon_completed", "open_questions": []},
        {"cpanel_assessment"},
    )

    assert ranked == ["cpanel_assessment", "external_intelligence"]
    event = pipeline.decision_trace.list_events(
        scan_id="scan-critical-task-scoring",
        event_type="task_scoring",
    )[0]
    assert event["expected_outcome"]["critical_candidates"] == [
        "cpanel_assessment"
    ]
    assert event["actual_outcome"]["ranking"][0]["priority_tier"] == "critical"
