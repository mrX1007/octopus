"""Hermetic invariant and dual-read coverage for benchmark schema 2.0."""

from __future__ import annotations

import json
import math

import pytest

from core.benchmarks.v3 import schema

pytestmark = [pytest.mark.benchmark, pytest.mark.unit]


def _metric(**updates):
    values = {
        "name": "reported_recall",
        "population": "all_scheduled",
        "available": True,
        "reliability": "measured",
        "value": 0.5,
    }
    values.update(updates)
    return schema.MetricObservation(**values)


def _claim(**updates):
    values = {
        "claim_id": "claim-one",
        "text": "claim one",
        "normalized_claim_id": "normalized-one",
    }
    values.update(updates)
    return schema.ClaimAssessment(**values)


def _budget(**updates):
    values = {
        "system_id": "system-a",
        "budget_name": "max-seconds",
        "limit": 10.0,
        "unit": "seconds",
        "enforcement_mode": "hard",
        "measured": 5.0,
        "exceeded": False,
        "reliable": True,
    }
    values.update(updates)
    return schema.BudgetEnforcement(**values)


def _action(**updates):
    values = {
        "event_id": "event-one",
        "sequence": 0,
        "action_name": "http-read",
        "action_type": "http",
        "status": "succeeded",
    }
    values.update(updates)
    return schema.ActionEvent(**values)


def _evaluation(**updates):
    values = {
        "task_status": "completed",
        "completion_rule_id": "rule-one",
        "metrics": (_metric(),),
    }
    values.update(updates)
    return schema.RunEvaluation(**values)


def _run(**updates):
    values = {
        "run_id": "run-one",
        "track_id": "track-one",
        "system_id": "system-a",
        "scenario_id": "scenario-one",
        "repetition": 1,
        "execution_status": "succeeded",
        "evaluation": _evaluation(),
        "matched_fixture_seed": 1,
        "fixture_variant_digest": "a" * 64,
        "applied_model_seed": None,
        "model_seed_status": "unknown",
        "budget_enforcement": (_budget(),),
        "action_telemetry": (),
        "action_telemetry_available": False,
        "action_telemetry_reliability": "unavailable",
        "duration_seconds": 1.0,
        "duration_censored": False,
        "censor_limit_seconds": None,
        "started_at": 10.0,
        "finished_at": 11.0,
        "environment": {"nested": [1, {"ok": True}]},
    }
    values.update(updates)
    return schema.BenchmarkRunV3(**values)


def test_canonical_json_and_digest_are_stable():
    assert schema.canonical_json({"é": 1, "a": 2}) == '{"a":2,"é":1}'
    assert schema.stable_digest({"a": 1}) == schema.stable_digest({"a": 1})
    with pytest.raises(ValueError):
        schema.canonical_json({"bad": math.nan})


@pytest.mark.parametrize(
    ("updates", "error"),
    [
        ({"population": "bad"}, "invalid:metric.population"),
        ({"reliability": "bad"}, "invalid:metric.reliability"),
        ({"value": None}, "invalid:metric.value"),
        ({"value": math.inf}, "invalid:metric.value"),
        ({"value": 2.0}, "invalid:metric.rate"),
        ({"reliability": "unavailable"}, "invalid:metric.reliability"),
        (
            {"available": False, "reliability": "unavailable", "value": 1.0, "reason": "x"},
            "unavailable_metric_has_value",
        ),
        (
            {"available": False, "reliability": "measured", "value": None, "reason": "x"},
            "unavailable_metric_reliability",
        ),
        (
            {"available": False, "reliability": "unavailable", "value": None},
            "unavailable_metric_requires_reason",
        ),
        ({"numerator": 1}, "metric_fraction_incomplete"),
        ({"denominator": 1}, "metric_fraction_incomplete"),
        ({"numerator": -1, "denominator": 1}, "invalid:metric.fraction"),
        ({"numerator": 1, "denominator": -1}, "invalid:metric.fraction"),
        ({"numerator": 2, "denominator": 1}, "invalid:metric.fraction"),
    ],
)
def test_metric_observation_rejects_inconsistent_states(updates, error):
    with pytest.raises(schema.BenchmarkV3SchemaError, match=error):
        _metric(**updates)


def test_metric_observation_factories_round_trip_and_serializer_guard():
    unavailable = schema.MetricObservation.unavailable(
        "verified_recall",
        "completion_conditional",
        "not recorded",
    )
    assert unavailable.to_dict()["reason"] == "not recorded"
    available = schema.MetricObservation.from_dict(
        {
            "name": "custom-count",
            "population": "all_scheduled",
            "available": True,
            "reliability": "derived",
            "value": 3,
            "numerator": 1,
            "denominator": 2,
            "reason": "derived",
        }
    )
    assert available.to_dict() == {
        "available": True,
        "denominator": 2,
        "name": "custom-count",
        "numerator": 1,
        "population": "all_scheduled",
        "reason": "derived",
        "reliability": "derived",
        "value": 3.0,
    }
    restored = schema.MetricObservation.from_dict(unavailable.to_dict())
    assert restored == unavailable

    corrupted = _metric(name="custom-count")
    object.__setattr__(corrupted, "value", None)
    with pytest.raises(schema.BenchmarkV3SchemaError, match="available_metric_missing_value"):
        corrupted.to_dict()


@pytest.mark.parametrize(
    ("updates", "error"),
    [
        ({"matched_truth_id": "truth-one"}, "claim_support_mismatch"),
        ({"supported": True}, "claim_support_mismatch"),
        ({"verified": True}, "unmatched_claim_cannot_be_verified"),
    ],
)
def test_claim_assessment_rejects_support_mismatches(updates, error):
    with pytest.raises(schema.BenchmarkV3SchemaError, match=error):
        _claim(**updates)


def test_claim_assessment_round_trip_with_and_without_match():
    unmatched = schema.ClaimAssessment.from_dict(
        {
            "claim_id": "claim-one",
            "text": "one",
            "normalized_claim_id": "normalized-one",
            "supported": False,
            "verified": False,
        }
    )
    assert unmatched.to_dict()["matched_truth_id"] is None
    matched = _claim(
        matched_truth_id="truth-one",
        supported=True,
        verified=True,
        matcher_kind="exact",
        evidence_refs=["evidence-one"],
    )
    assert schema.ClaimAssessment.from_dict(matched.to_dict()) == matched


@pytest.mark.parametrize(
    ("updates", "error"),
    [
        ({"limit": 0}, "invalid:budget.limit"),
        ({"limit": math.inf}, "invalid:budget.limit"),
        ({"enforcement_mode": "bad"}, "invalid:budget.enforcement_mode"),
        ({"measured": -1}, "invalid:budget.measured"),
        ({"measured": math.nan}, "invalid:budget.measured"),
        ({"exceeded": None}, "measured_budget_requires_exceeded"),
        ({"measured": 11, "exceeded": False}, "budget_exceeded_mismatch"),
        ({"measured": None, "exceeded": False}, "unmeasured_budget_has_exceeded"),
        (
            {"measured": None, "exceeded": None, "enforcement_mode": "none", "reliable": True},
            "unenforced_budget_cannot_be_reliable",
        ),
    ],
)
def test_budget_enforcement_rejects_inconsistent_states(updates, error):
    with pytest.raises(schema.BenchmarkV3SchemaError, match=error):
        _budget(**updates)


def test_budget_enforcement_round_trip_optional_fields():
    unmeasured = _budget(
        measured=None,
        exceeded=None,
        enforcement_mode="none",
        reliable=False,
        evidence_refs=["artifact:one"],
        note="legacy",
    )
    assert schema.BudgetEnforcement.from_dict(unmeasured.to_dict()) == unmeasured
    assert schema.BudgetEnforcement.from_dict(_budget().to_dict()) == _budget()


@pytest.mark.parametrize(
    ("updates", "error"),
    [
        ({"sequence": -1}, "invalid:action.sequence"),
        ({"status": "bad"}, "invalid:action.status"),
        ({"started_offset_seconds": -1}, "invalid:action.started_offset_seconds"),
        ({"duration_seconds": math.inf}, "invalid:action.duration_seconds"),
        ({"method": "get"}, "invalid:action.method"),
        ({"output_bytes": -1}, "invalid:action.output_bytes"),
    ],
)
def test_action_event_rejects_invalid_states(updates, error):
    with pytest.raises(schema.BenchmarkV3SchemaError, match=error):
        _action(**updates)


def test_action_event_round_trip_with_all_optional_fields():
    event = schema.ActionEvent.from_dict(
        {
            "event_id": "event-one",
            "sequence": 1,
            "action_name": "http-read",
            "action_type": "http",
            "status": "succeeded",
            "started_offset_seconds": 0,
            "duration_seconds": 1.5,
            "method": "get",
            "target_class": "fixture-route",
            "output_bytes": 4,
            "evidence_refs": ["evidence-one"],
        }
    )
    assert event.method == "GET"
    assert schema.ActionEvent.from_dict(event.to_dict()) == event
    bare = _action()
    assert bare.to_dict()["method"] is None
    assert bare.to_dict()["target_class"] is None


@pytest.mark.parametrize(
    ("updates", "error"),
    [
        ({"task_status": "bad"}, "invalid:task_status"),
        ({"metrics": (_metric(), _metric())}, "duplicate_population_metric"),
        ({"claims": (_claim(), _claim())}, "duplicate_claim_id"),
    ],
)
def test_run_evaluation_rejects_invalid_states(updates, error):
    with pytest.raises(schema.BenchmarkV3SchemaError, match=error):
        _evaluation(**updates)


@pytest.mark.parametrize(
    ("payload", "error"),
    [
        ({"populations": []}, "invalid:evaluation.populations"),
        ({"populations": {"all_scheduled": []}}, "invalid:evaluation.metrics"),
        (
            {"populations": {"all_scheduled": {"metric": []}}},
            "invalid:evaluation.metric",
        ),
        (
            {
                "task_status": "completed",
                "completion_rule_id": "rule-one",
                "populations": {},
                "claims": "bad",
            },
            "invalid:evaluation.claims",
        ),
    ],
)
def test_run_evaluation_from_dict_rejects_invalid_shapes(payload, error):
    with pytest.raises(schema.BenchmarkV3SchemaError, match=error):
        schema.RunEvaluation.from_dict(payload)


def test_run_evaluation_round_trip_sorting_lookup_and_properties():
    evaluation = schema.RunEvaluation.from_dict(
        {
            "task_status": "completed",
            "completion_rule_id": "rule-one",
            "populations": {
                "completion_conditional": {},
                "all_scheduled": {
                    "z-count": {
                        "available": True,
                        "reliability": "measured",
                        "value": 2,
                    }
                },
            },
            "claims": [_claim().to_dict()],
        }
    )
    assert evaluation.metric("z-count", "all_scheduled").value == 2
    missing = evaluation.metric("missing", "all_scheduled")
    assert not missing.available and missing.reason == "not_recorded"
    assert schema.RunEvaluation.from_dict(evaluation.to_dict()) == evaluation

    run = _run(evaluation=evaluation, action_telemetry=(_action(),))
    assert run.task_status == "completed"
    assert run.completion_rule_id == "rule-one"
    assert run.action_event_count == 1


@pytest.mark.parametrize(
    ("updates", "error"),
    [
        ({"schema_version": "1.0"}, "unsupported_schema_version"),
        ({"repetition": 0}, "invalid:repetition"),
        ({"execution_status": "bad"}, "invalid:execution_status"),
        ({"matched_fixture_seed": -1}, "invalid:matched_fixture_seed"),
        ({"fixture_variant_digest": "bad"}, "invalid:fixture_variant_digest"),
        ({"fixture_variant_digest": ""}, "native_run_missing_fixture_digest"),
        ({"budget_enforcement": ()}, "native_run_missing_budget_enforcement"),
        ({"applied_model_seed": -1}, "invalid:applied_model_seed"),
        ({"model_seed_status": "bad"}, "invalid:model_seed_status"),
        ({"model_seed_status": "applied"}, "applied_model_seed_missing"),
        (
            {"budget_enforcement": (_budget(), _budget())},
            "duplicate_budget_enforcement",
        ),
        (
            {"budget_enforcement": (_budget(system_id="other"),)},
            "budget_system_mismatch",
        ),
        (
            {"action_telemetry": (_action(sequence=1), _action(event_id="event-two", sequence=0))},
            "action_telemetry_not_ordered",
        ),
        (
            {"action_telemetry": (_action(), _action(event_id="event-two"))},
            "duplicate_action_sequence",
        ),
        (
            {"action_telemetry": (_action(), _action(sequence=1))},
            "duplicate_action_event_id",
        ),
        (
            {
                "action_telemetry_available": True,
                "action_telemetry_reliability": "unavailable",
            },
            "invalid:action_telemetry_reliability",
        ),
        (
            {"action_telemetry_reliability": "measured"},
            "unavailable_action_telemetry_reliability",
        ),
        ({"duration_seconds": -1}, "invalid:duration_seconds"),
        (
            {"duration_censored": True},
            "censored_duration_requires_limit",
        ),
        (
            {"duration_censored": True, "censor_limit_seconds": -1},
            "invalid:censor_limit_seconds",
        ),
        (
            {"duration_censored": True, "censor_limit_seconds": 0.5},
            "duration_exceeds_censor_limit",
        ),
        (
            {"censor_limit_seconds": 0.5},
            "invalid:censor_limit_seconds",
        ),
        ({"started_at": math.inf}, "invalid:run_timestamp"),
        ({"finished_at": 9}, "run_timestamp_order"),
        ({"error_class": "bad value"}, "invalid:error_class"),
    ],
)
def test_benchmark_run_rejects_invalid_states(updates, error):
    with pytest.raises(schema.BenchmarkV3SchemaError, match=error):
        _run(**updates)


def test_benchmark_run_round_trip_all_optional_branches():
    run = _run(
        applied_model_seed=7,
        model_seed_status="applied",
        action_telemetry=(_action(),),
        action_telemetry_available=True,
        action_telemetry_reliability="verified",
        duration_censored=True,
        censor_limit_seconds=1.0,
        policy_violations=["policy-one"],
        artifact_refs=["artifact:one"],
        model_seed_evidence=["artifact:seed"],
        error_class="Timeout",
    )
    payload = run.to_dict()
    assert payload["fixture_variant_digest"] == "a" * 64
    assert schema.BenchmarkRunV3.from_dict(payload) == run
    assert isinstance(run.environment["nested"], tuple)

    legacy = _run(
        source_schema_version="1.0",
        fixture_variant_digest="",
        budget_enforcement=(),
        censor_limit_seconds=2.0,
    )
    assert legacy.to_dict()["fixture_variant_digest"] is None


@pytest.mark.parametrize(
    ("mutator", "error"),
    [
        (lambda payload: payload.update(schema_version="1.0"), "unsupported_schema_version"),
        (lambda payload: payload.update(budget_enforcement="bad"), "invalid:run_telemetry"),
        (lambda payload: payload.update(action_telemetry="bad"), "invalid:run_telemetry"),
    ],
)
def test_benchmark_run_from_dict_rejects_protocol_shapes(mutator, error):
    payload = _run().to_dict()
    mutator(payload)
    with pytest.raises(schema.BenchmarkV3SchemaError, match=error):
        schema.BenchmarkRunV3.from_dict(payload)


def test_load_run_mapping_file_and_failures(tmp_path):
    native = _run()
    assert schema.load_run(native.to_dict()) == native
    path = tmp_path / "run.json"
    path.write_text(json.dumps(native.to_dict()), encoding="utf-8")
    assert schema.load_run(path) == native

    missing = tmp_path / "missing.json"
    with pytest.raises(schema.BenchmarkV3SchemaError, match="run_load_failed"):
        schema.load_run(missing)
    malformed = tmp_path / "malformed.json"
    malformed.write_text("{", encoding="utf-8")
    with pytest.raises(schema.BenchmarkV3SchemaError, match="run_load_failed"):
        schema.load_run(malformed)
    wrong_shape = tmp_path / "wrong.json"
    wrong_shape.write_text("[]", encoding="utf-8")
    with pytest.raises(schema.BenchmarkV3SchemaError, match="invalid:run"):
        schema.load_run(wrong_shape)
    with pytest.raises(schema.BenchmarkV3SchemaError, match="unsupported_schema_version:missing"):
        schema.load_run({})


def test_validate_budget_enforcement_success_and_failures():
    first = _budget(budget_name="z-budget", limit=2, measured=1)
    second = _budget(budget_name="a-budget", limit=1, measured=1)
    ordered = schema.validate_budget_enforcement(
        system_id="system-a",
        declared_budgets={"z-budget": 2, "a-budget": 1},
        enforcement=[first, second],
    )
    assert [item.budget_name for item in ordered] == ["a-budget", "z-budget"]

    with pytest.raises(schema.BenchmarkV3SchemaError, match="missing:a-budget,extra:z-budget"):
        schema.validate_budget_enforcement(
            system_id="system-a",
            declared_budgets={"a-budget": 1},
            enforcement=[first],
        )
    with pytest.raises(schema.BenchmarkV3SchemaError, match="budget_system_mismatch"):
        schema.validate_budget_enforcement(
            system_id="other",
            declared_budgets={"z-budget": 2},
            enforcement=[first],
        )
    with pytest.raises(schema.BenchmarkV3SchemaError, match="invalid:declared_budget"):
        schema.validate_budget_enforcement(
            system_id="system-a",
            declared_budgets={"z-budget": "bad"},
            enforcement=[first],
        )
    with pytest.raises(schema.BenchmarkV3SchemaError, match="budget_limit_mismatch"):
        schema.validate_budget_enforcement(
            system_id="system-a",
            declared_budgets={"z-budget": 3},
            enforcement=[first],
        )


@pytest.mark.parametrize(
    ("old_status", "execution_status", "task_status"),
    [
        ("partial", "succeeded", "partial"),
        ("timeout", "timeout", "not_evaluated"),
        ("invalid", "invalid", "invalid"),
        ("cancelled", "cancelled", "not_evaluated"),
        ("other", "failed", "not_evaluated"),
    ],
)
def test_legacy_status_adaptation(old_status, execution_status, task_status):
    run = schema.load_run(
        {
            "schema_version": "1.0",
            "status": old_status,
            "duration_seconds": 2,
            "started_at": 5,
            "finished_at": 4,
        }
    )
    assert run.execution_status == execution_status
    assert run.task_status == task_status
    assert run.finished_at == 7
    assert run.duration_censored is (execution_status == "timeout")


def test_legacy_adaptation_handles_missing_and_malformed_optional_data():
    run = schema.load_run(
        {
            "schema_version": "1.0",
            "run_id": "***",
            "scenario_id": "Scenario Name",
            "status": "failed",
            "metrics": [],
            "result_summary": [],
            "actions": "bad",
            "policy_violations": "bad",
            "artifact_refs": "bad",
            "environment": [],
        }
    )
    assert run.run_id == "legacy-run"
    assert run.scenario_id == "scenario-name"
    assert run.action_telemetry == ()
    assert run.policy_violations == ()
    assert run.artifact_refs == ()
    assert all(not item.available for item in run.evaluation.metrics)

    nonsequence_claims = schema.load_run(
        {
            "schema_version": "1.0",
            "result_summary": {"reported_findings": "bad"},
        }
    )
    assert nonsequence_claims.evaluation.claims == ()

    run = schema.load_run(
        {
            "schema_version": "1.0",
            "status": "succeeded",
            "metrics": {"finding_recall": 0.5},
            "result_summary": {"reported_findings": ["", "claim"]},
            "actions": ["", "HTTP Probe"],
            "environment": {
                "runner": [],
                "budgets": {
                    "max_bytes": 100,
                    "bad": "x",
                    "zero": 0,
                },
            },
        }
    )
    assert len(run.evaluation.claims) == 1
    assert run.evaluation.claims[0].claim_id == "legacy-claim-2"
    assert len(run.action_telemetry) == 2
    assert len(run.budget_enforcement) == 1


@pytest.mark.parametrize(
    ("name", "unit"),
    [
        ("max_seconds", "seconds"),
        ("max_bytes", "bytes"),
        ("max_cost", "usd"),
        ("max_tokens", "tokens"),
        ("max_tools", "count"),
    ],
)
def test_legacy_budget_units(name, unit):
    assert schema._legacy_budget_unit(name) == unit


def test_legacy_identifier_and_reference_helpers():
    assert schema._legacy_identifier(" A Value ", "fallback") == "a-value"
    assert schema._legacy_identifier("***", "fallback") == "fallback"
    assert schema._legacy_identifiers("bad", "item") == ()
    assert schema._legacy_identifiers(["One", "***"], "item") == (
        "one",
        "item-2",
    )
    assert schema._legacy_references("bad") == ()
    assert schema._legacy_references([" one ", "", "two"]) == ("one", "two")


def test_scalar_helpers_accept_and_reject_boundaries():
    assert schema._identifier(" VALUE ", "name") == "value"
    with pytest.raises(schema.BenchmarkV3SchemaError, match="invalid:name"):
        schema._identifier("bad value", "name")
    assert schema._optional_identifier(None, "name") == ""
    assert schema._optional_identifier("", "name") == ""
    assert schema._optional_identifier("value", "name") == "value"

    assert schema._text(" value ", "text") == "value"
    for value in ("", "x" * (schema._MAX_TEXT + 1)):
        with pytest.raises(schema.BenchmarkV3SchemaError, match="invalid:text"):
            schema._text(value, "text")
    assert schema._optional_text(None, "text") == ""
    assert schema._optional_text("", "text") == ""
    assert schema._optional_text("value", "text") == "value"

    assert schema._number(1, "number") == 1.0
    with pytest.raises(schema.BenchmarkV3SchemaError, match="invalid:number"):
        schema._number("1", "number")
    assert schema._integer(1, "integer") == 1
    assert schema._integer(1.0, "integer") == 1
    for value in (True, "bad", "1.5", 1.2):
        with pytest.raises(schema.BenchmarkV3SchemaError, match="invalid:integer"):
            schema._integer(value, "integer")
    with pytest.raises(schema.BenchmarkV3SchemaError, match="invalid:integer"):
        schema._integer(0, "integer", minimum=1)
    assert schema._optional_integer(None) is None
    assert schema._optional_integer(1) == 1
    assert schema._finite(1)
    assert not schema._finite(True)
    assert not schema._finite("1")


def test_collection_helpers_accept_and_reject_boundaries(monkeypatch):
    assert schema._mapping({}, "mapping") == {}
    with pytest.raises(schema.BenchmarkV3SchemaError, match="invalid:mapping"):
        schema._mapping([], "mapping")
    assert schema._is_sequence([])
    assert not schema._is_sequence("bad")

    assert schema._identifier_tuple(["one"], "items") == ("one",)
    with pytest.raises(schema.BenchmarkV3SchemaError, match="invalid:items"):
        schema._identifier_tuple("bad", "items")
    assert schema._reference_tuple([" ref "], "refs") == ("ref",)
    with pytest.raises(schema.BenchmarkV3SchemaError, match="invalid:refs"):
        schema._reference_tuple("bad", "refs")

    monkeypatch.setattr(schema, "_MAX_ITEMS", 1)
    with pytest.raises(schema.BenchmarkV3SchemaError, match="too_many:items"):
        schema._bounded_identifiers(("one", "two"), "items")
    with pytest.raises(schema.BenchmarkV3SchemaError, match="too_many:refs"):
        schema._bounded_references(("one", "two"), "refs")


@pytest.mark.parametrize("value", ["", "x" * 2049, "line\nbreak"])
def test_reference_validation_rejects_unsafe_values(value):
    with pytest.raises(schema.BenchmarkV3SchemaError, match="invalid:refs"):
        schema._bounded_references((value,), "refs")


def test_json_mapping_freeze_and_thaw_boundaries(monkeypatch):
    value = {"items": [{"answer": 42}], 1: "key"}
    normalized = schema._json_mapping(value, "environment")
    frozen = schema._freeze_json(normalized)
    assert frozen["items"][0]["answer"] == 42
    assert schema._thaw_json(frozen) == normalized
    assert schema._freeze_json(1) == 1
    assert schema._thaw_json(1) == 1

    with pytest.raises(schema.BenchmarkV3SchemaError, match="invalid:environment"):
        schema._json_mapping([], "environment")
    with pytest.raises(schema.BenchmarkV3SchemaError, match="invalid:environment"):
        schema._json_mapping({"bad": object()}, "environment")
    monkeypatch.setattr(
        schema,
        "canonical_json",
        lambda _value: '{"x":"' + "x" * 1_000_001 + '"}',
    )
    with pytest.raises(schema.BenchmarkV3SchemaError, match="too_large:environment"):
        schema._json_mapping({}, "environment")
