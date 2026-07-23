from __future__ import annotations

import pytest

from core.benchmarks.v3 import (
    ActionEvent,
    BenchmarkRunV3,
    BenchmarkV3SchemaError,
    CompletionRule,
    TruthClaim,
    build_budget_enforcement,
    evaluate_claims,
    load_run,
    make_run,
    verified_truth_ids_from_evidence,
)

pytestmark = [pytest.mark.benchmark, pytest.mark.contract]


def test_full_claim_precision_keeps_arbitrary_hallucinations() -> None:
    truth = TruthClaim(
        "finding-service",
        "authorized service discovered",
        aliases=("service is present",),
        required_evidence_ids=("ev-service",),
    )
    evaluation = evaluate_claims(
        execution_status="succeeded",
        reported_claims=[
            {
                "text": "authorized service discovered",
                "evidence_refs": ["ev-service"],
            },
            "database on the moon",
        ],
        truth_claims=[truth],
        completion_rule=CompletionRule("service-rule-v1", (truth.truth_id,)),
        observed_evidence_ids=["ev-service"],
    )

    precision = evaluation.metric("full_claim_precision", "all_scheduled")
    verified = evaluation.metric("verified_recall", "all_scheduled")
    assert precision.value == 0.5
    assert (precision.numerator, precision.denominator) == (1, 2)
    assert verified.value == 1.0
    assert evaluation.task_status == "partial"
    assert evaluation.claims[1].normalized_claim_id.startswith("unmatched:")
    assert not evaluation.claims[1].supported


def test_clean_negative_requires_no_unsupported_claims() -> None:
    rule = CompletionRule("clean-negative-v1", ())
    complete = evaluate_claims(
        execution_status="succeeded",
        reported_claims=[],
        truth_claims=[],
        completion_rule=rule,
    )
    hallucinated = evaluate_claims(
        execution_status="succeeded",
        reported_claims=["invented service"],
        truth_claims=[],
        completion_rule=rule,
    )

    assert complete.task_status == "completed"
    assert complete.metric("full_claim_precision", "all_scheduled").value == 1.0
    assert hallucinated.task_status == "not_completed"
    assert hallucinated.metric("full_claim_precision", "all_scheduled").value == 0.0


def test_timeout_keeps_task_and_conditional_population_separate() -> None:
    truth = TruthClaim("finding-one", "one", required_evidence_ids=("ev-one",))
    evaluation = evaluate_claims(
        execution_status="timeout",
        reported_claims=["one"],
        truth_claims=[truth],
        completion_rule=CompletionRule("rule-one", (truth.truth_id,)),
    )

    assert evaluation.task_status == "partial"
    assert evaluation.metric("reported_recall", "all_scheduled").available
    conditional = evaluation.metric("reported_recall", "completion_conditional")
    assert not conditional.available
    assert conditional.reason == "execution_did_not_complete"


def test_controller_evidence_verifies_truth_without_product_private_ids() -> None:
    truth = TruthClaim(
        "finding-one",
        "service one",
        required_evidence_ids=("ev-one", "ev-two"),
    )
    assert verified_truth_ids_from_evidence([truth], ["ev-one"]) == ()
    verified_ids = verified_truth_ids_from_evidence([truth], ["ev-two", "ev-one"])
    evaluation = evaluate_claims(
        execution_status="succeeded",
        reported_claims=["service one"],
        truth_claims=[truth],
        completion_rule=CompletionRule("rule-one", (truth.truth_id,)),
        verified_truth_ids=verified_ids,
    )

    assert evaluation.task_status == "completed"
    assert evaluation.claims[0].evidence_refs == ()
    assert evaluation.claims[0].verified


def test_complete_budget_records_and_run_round_trip() -> None:
    budgets = {"max_output_bytes": 1000, "max_seconds": 10, "max_tools": 4}
    enforcement = build_budget_enforcement(
        system_id="system-a",
        declared_budgets=budgets,
        observed_usage={
            "max_output_bytes": 400,
            "max_seconds": 3.5,
            "max_tools": 2,
        },
        enforcement_modes={
            "max_output_bytes": "hard",
            "max_seconds": "hard",
            "max_tools": "observed",
        },
        evidence_refs={"max_seconds": ["timer-attestation"]},
    )
    truth = TruthClaim("finding-one", "one", required_evidence_ids=("ev-one",))
    evaluation = evaluate_claims(
        execution_status="succeeded",
        reported_claims=["one"],
        truth_claims=[truth],
        completion_rule=CompletionRule("rule-one", (truth.truth_id,)),
        verified_truth_ids=[truth.truth_id],
    )
    action = ActionEvent(
        event_id="event-one",
        sequence=0,
        action_name="http-read",
        action_type="http",
        status="succeeded",
        method="GET",
        target_class="fixture-route",
        output_bytes=128,
        evidence_refs=("ev-one",),
    )
    run = make_run(
        track_id="small-model-stress-v3",
        system_id="system-a",
        scenario_id="scenario-one",
        repetition=1,
        execution_status="succeeded",
        evaluation=evaluation,
        matched_fixture_seed=12,
        fixture_variant_digest="a" * 64,
        applied_model_seed=91,
        model_seed_status="applied",
        budget_enforcement=enforcement,
        action_telemetry=[action],
        action_telemetry_available=True,
        action_telemetry_reliability="verified",
        duration_seconds=3.5,
        timeout_limit_seconds=10,
        started_at=100,
        finished_at=103.5,
        environment={"analysis_plan_digest": "b" * 64},
    )

    restored = BenchmarkRunV3.from_dict(run.to_dict())
    assert restored == run
    assert restored.execution_status == "succeeded"
    assert restored.task_status == "completed"
    assert not restored.duration_censored
    assert len(restored.budget_enforcement) == len(budgets)


def test_budget_enforcement_fails_closed_when_a_budget_is_missing() -> None:
    with pytest.raises(BenchmarkV3SchemaError, match="modes_incomplete"):
        build_budget_enforcement(
            system_id="system-a",
            declared_budgets={"max_seconds": 10, "max_tools": 2},
            observed_usage={"max_seconds": 1},
            enforcement_modes={"max_seconds": "hard"},
        )


def test_legacy_dual_read_never_promotes_process_success_to_task_success() -> None:
    legacy = {
        "schema_version": "1.0",
        "run_id": "legacy-1",
        "scenario_id": "old-scenario",
        "repetition": 1,
        "seed": 7,
        "status": "succeeded",
        "actions": ["http_probe"],
        "policy_violations": [],
        "metrics": {"finding_precision": 1.0, "finding_recall": 0.5},
        "result_summary": {"reported_findings": ["known-id"]},
        "artifact_refs": [],
        "duration_seconds": 2.0,
        "started_at": 1.0,
        "finished_at": 3.0,
        "environment": {
            "budgets": {"max_seconds": 10},
            "runner": {"system_id": "old-system"},
        },
        "error_class": "",
    }

    adapted = load_run(legacy)
    assert adapted.execution_status == "succeeded"
    assert adapted.task_status == "not_evaluated"
    assert adapted.source_schema_version == "1.0"
    assert not adapted.evaluation.metric("verified_recall", "all_scheduled").available
    precision = adapted.evaluation.metric("full_claim_precision", "all_scheduled")
    assert precision.reliability == "legacy_incomplete"
    assert adapted.applied_model_seed is None
