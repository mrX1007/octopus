"""Acceptance contracts for the remaining Wave 2/4 orchestration work."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

from core.ai.pipeline import AIPipeline
from core.ai.task_scoring import TaskScorer, TaskScoringWeights

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
