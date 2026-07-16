"""Decision-trace durability, bounds, integration, and metric contracts."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

import pytest

from core.ai.decision_trace import (
    DecisionEvent,
    DecisionTraceStore,
    build_decision_metrics,
)
from core.ai.fact_store import FactStore

pytestmark = pytest.mark.contract


def test_decision_store_is_idempotent_bounded_and_redacted(tmp_path):
    facts = FactStore(str(tmp_path / "facts.db"))
    secret = "decision-secret-value"
    facts.secret_store.store(secret, kind="decision_test")
    store = DecisionTraceStore(
        str(tmp_path / "decision.db"),
        redactor=facts.redactor,
        max_events_per_scope=5,
        max_total_events=6,
    )

    for index in range(7):
        event_id, created = store.record({
            "event_id": f"event-{index}",
            "event_type": "goal_selection",
            "scan_id": "scan-a",
            "goal": f"goal-{index}-{secret}",
            "candidates": [f"candidate-{item}" for item in range(100)],
            "rejected": {"candidate": "unsafe", "reason": "policy_denied"},
            "supporting_fact_ids": list(range(1, 400)),
            "actual_outcome": {"status": "selected"},
            "occurred_at": float(index + 1),
        })
        assert event_id.startswith("decision://sha256/")
        assert created is True

    retained = store.list_events(scan_id="scan-a")
    assert len(retained) == 5
    assert retained[0]["goal"].startswith("goal-2-")
    assert secret not in str(retained)
    assert "secret://" in str(retained) or "[REDACTED]" in str(retained)
    assert len(retained[-1]["candidates"]) == 64
    assert retained[-1]["rejected"] == [
        {"candidate": "unsafe", "reason": "policy_denied"}
    ]
    assert len(retained[-1]["supporting_fact_ids"]) == 256

    _event_id, duplicate_created = store.record({
        "event_id": "event-6",
        "event_type": "goal_selection",
        "scan_id": "scan-a",
        "goal": f"goal-6-{secret}",
        "actual_outcome": {"status": "selected"},
        "occurred_at": 7.0,
    })
    assert duplicate_created is False
    assert store.count(scan_id="scan-a") == 5


def test_decision_store_concurrent_duplicate_writers_converge(tmp_path):
    facts = FactStore(str(tmp_path / "facts.db"))
    store = DecisionTraceStore(
        str(tmp_path / "decision.db"),
        redactor=facts.redactor,
    )
    event = DecisionEvent(
        event_id="shared-event",
        event_type="command_decision",
        scan_id="scan",
        chosen_action="safe_probe",
        actual_outcome={"status": "succeeded"},
    )

    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(lambda _index: store.record(event), range(24)))

    assert sum(1 for _event_id, created in results if created) == 1
    assert store.count(scan_id="scan") == 1


def test_decision_metrics_publish_explicit_denominators():
    facts = [
        {
            "id": 1,
            "type": "port_open",
            "timestamp": 10.0,
            "assessment_status": "observed",
        },
        {
            "id": 2,
            "type": "vulnerability_candidate",
            "timestamp": 15.0,
            "assessment_status": "verified",
            "assessment": {
                "status": "verified",
                "reason": "positive check",
                "evidence_fact_ids": [2],
                "source_execution_ids": ["exec-check"],
            },
        },
    ]
    command_results = [
        {
            "status": "succeeded",
            "timestamp": 9.0,
            "output_hash": "same",
            "parsed_facts": 4,
            "new_facts": 2,
        },
        {
            "status": "timeout",
            "timestamp": 12.0,
            "output_hash": "same",
            "parsed_facts": 1,
            "new_facts": 0,
        },
    ]
    decision_events = [
        {
            "event_type": "goal_selection",
            "occurred_at": 9.5,
            "actual_outcome": {"status": "invalid"},
            "duration": 0.2,
            "cost": {"estimated_units": 1.0},
        },
        {
            "event_type": "provider_selection",
            "occurred_at": 11.0,
            "actual_outcome": {"status": "succeeded"},
            "retry_count": 1,
            "fallback_count": 1,
            "duration": 1.8,
            "cost": {"estimated_units": 2.0},
        },
        {
            "event_type": "mission_resume_outcome",
            "occurred_at": 16.0,
            "actual_outcome": {"status": "succeeded"},
        },
    ]

    report = build_decision_metrics(
        facts,
        command_results,
        decision_events=decision_events,
        machine_report={"summary": {"evidence_completeness": 0.75}},
    )
    metrics = report["metrics"]

    assert report["schema_version"] == "1.0"
    assert metrics["time_to_first_useful_evidence_seconds"] == 1.0
    assert metrics["time_to_first_verified_evidence_seconds"] == 6.0
    assert metrics["useful_facts_per_tool"] == 1.0
    assert metrics["duplicate_rate"] == 0.5
    assert metrics["no_op_rate"] == 0.5
    assert metrics["parser_yield"] == 0.4
    assert metrics["verification_conversion_rate"] == 1.0
    assert metrics["invalid_planner_rate"] == 1.0
    assert metrics["fallback_rate"] == 1.0
    assert metrics["retry_rate"] == 1.0
    assert metrics["timeout_rate"] == 0.5
    assert metrics["resume_success_rate"] == 1.0
    assert metrics["evidence_completeness"] == 0.75
    assert metrics["decision_duration_seconds"] == 2.0
    assert metrics["estimated_cost_units"] == 3.0


def test_pipeline_command_decision_is_durable_and_visible_in_trace(tmp_path, monkeypatch):
    import core.ai.pipeline as pipeline_module
    from core.ai.pipeline import AIPipeline

    monkeypatch.setattr(
        pipeline_module,
        "run_arbitrary_cmd",
        lambda _command: "443/tcp open https nginx",
    )
    pipeline = AIPipeline(str(tmp_path / "facts.db"))
    scan_id = "scan-decision-integration"
    target = "10.0.0.5"

    pipeline._execute_pipeline_command(
        scan_id,
        target,
        f"nmap {target}",
        "Fact",
        "[Running]",
    )
    events = pipeline.decision_trace.list_events(scan_id=scan_id)
    report = pipeline.trace_report(scan_id, target)

    assert len(events) == 1
    assert events[0]["event_type"] == "command_decision"
    assert events[0]["chosen_action"] == "nmap"
    assert events[0]["actual_outcome"]["status"] == "succeeded"
    assert events[0]["supporting_fact_ids"]
    assert report["decision_trace"] == events
    assert report["decision_metrics"]["counts"]["decision_events"] == 1
