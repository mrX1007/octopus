"""Validation and decision-boundary coverage for v3 evaluation."""

from __future__ import annotations

import pytest

import core.benchmarks.v3.evaluation as evaluation_module
from core.benchmarks.v3.evaluation import (
    CompletionRule,
    ReportedClaim,
    TruthClaim,
    build_budget_enforcement,
    evaluate_claims,
    verified_truth_ids_from_evidence,
)
from core.benchmarks.v3.schema import BenchmarkV3SchemaError

pytestmark = [pytest.mark.benchmark, pytest.mark.contract]


def _truth(**changes):
    values = {
        "truth_id": "truth-one",
        "canonical_text": "Service discovered",
        "aliases": ("service alias",),
        "required_evidence_ids": ("evidence-one",),
    }
    values.update(changes)
    return TruthClaim(**values)


def _rule(**changes):
    values = {
        "rule_id": "rule-one",
        "required_truth_ids": ("truth-one",),
    }
    values.update(changes)
    return CompletionRule(**values)


def test_truth_claim_validates_text_alias_and_evidence_identifiers():
    assert _truth().to_private_dict()["truth_id"] == "truth-one"
    with pytest.raises(BenchmarkV3SchemaError, match=r"invalid:truth.canonical_text"):
        _truth(canonical_text="   ")
    with pytest.raises(BenchmarkV3SchemaError, match=r"invalid:truth.alias"):
        _truth(aliases=("",))
    with pytest.raises(
        BenchmarkV3SchemaError, match=r"invalid:truth.required_evidence_id"
    ):
        _truth(required_evidence_ids=("bad value",))


def test_reported_claim_direct_and_mapping_validation_paths():
    assert ReportedClaim("claim", ("evidence-one",)).evidence_refs == (
        "evidence-one",
    )
    for text in ("", "x" * 16_385):
        with pytest.raises(BenchmarkV3SchemaError, match=r"invalid:reported_claim.text"):
            ReportedClaim(text)
    with pytest.raises(
        BenchmarkV3SchemaError, match=r"invalid:reported_claim.evidence_ref"
    ):
        ReportedClaim("claim", ("bad value",))
    with pytest.raises(
        BenchmarkV3SchemaError, match=r"invalid:reported_claim.evidence_refs"
    ):
        ReportedClaim.from_value({"text": "claim", "evidence_refs": "bad"})
    for value in ("", "x" * 16_385):
        with pytest.raises(BenchmarkV3SchemaError, match=r"invalid:reported_claim.text"):
            ReportedClaim.from_value(value)
    claim = ReportedClaim.from_value(
        {"claim": " Claim ", "evidence_refs": ["", "EVIDENCE-ONE"]}
    )
    assert claim.text == "Claim"
    assert claim.evidence_refs == ("evidence-one",)


def test_completion_rule_rejects_duplicate_and_out_of_range_threshold():
    assert _rule().to_private_dict()["rule_id"] == "rule-one"
    with pytest.raises(BenchmarkV3SchemaError, match="duplicate_completion_truth_id"):
        _rule(required_truth_ids=("truth-one", "truth-one"))
    for value in (-0.1, 1.1):
        with pytest.raises(
            BenchmarkV3SchemaError, match=r"invalid:minimum_verified_recall"
        ):
            _rule(minimum_verified_recall=value)


def test_evaluate_rejects_invalid_inputs_and_ambiguous_matchers():
    truth = _truth()
    with pytest.raises(BenchmarkV3SchemaError, match=r"invalid:execution_status"):
        evaluate_claims(
            execution_status="bad",
            reported_claims=(),
            truth_claims=(truth,),
            completion_rule=_rule(),
        )
    with pytest.raises(BenchmarkV3SchemaError, match="duplicate_truth_id"):
        evaluate_claims(
            execution_status="succeeded",
            reported_claims=(),
            truth_claims=(truth, truth),
            completion_rule=_rule(),
        )
    with pytest.raises(BenchmarkV3SchemaError, match="completion_rule_unknown_truth_id"):
        evaluate_claims(
            execution_status="succeeded",
            reported_claims=(),
            truth_claims=(truth,),
            completion_rule=_rule(required_truth_ids=("missing",)),
        )
    with pytest.raises(BenchmarkV3SchemaError, match="verified_unknown_truth_id"):
        evaluate_claims(
            execution_status="succeeded",
            reported_claims=(),
            truth_claims=(truth,),
            completion_rule=_rule(),
            verified_truth_ids=("missing",),
        )
    with pytest.raises(
        BenchmarkV3SchemaError, match=r"invalid:observed_evidence_id"
    ):
        evaluate_claims(
            execution_status="succeeded",
            reported_claims=(),
            truth_claims=(truth,),
            completion_rule=_rule(),
            observed_evidence_ids=("bad value",),
        )
    other = _truth(
        truth_id="truth-two",
        canonical_text="Other service",
        aliases=(truth.canonical_text,),
    )
    with pytest.raises(BenchmarkV3SchemaError, match="ambiguous_truth_matcher"):
        evaluate_claims(
            execution_status="succeeded",
            reported_claims=(),
            truth_claims=(truth, other),
            completion_rule=_rule(),
        )


def test_evaluate_invalid_policy_and_unmatched_claim_status_paths():
    truth = _truth()
    invalid = evaluate_claims(
        execution_status="succeeded",
        reported_claims=("unsupported",),
        truth_claims=(truth,),
        completion_rule=_rule(),
        policy_violations=("violation",),
    )
    assert invalid.task_status == "invalid"
    assert invalid.claims[0].matcher_kind == "unmatched"

    execution_invalid = evaluate_claims(
        execution_status="invalid",
        reported_claims=(),
        truth_claims=(truth,),
        completion_rule=_rule(allow_policy_violations=True),
    )
    assert execution_invalid.task_status == "invalid"
    assert all(
        not metric.available
        for metric in execution_invalid.metrics
        if metric.population == "completion_conditional"
    )

    completed_with_extra = evaluate_claims(
        execution_status="succeeded",
        reported_claims=("Service discovered", "unsupported"),
        truth_claims=(truth,),
        completion_rule=_rule(reject_unsupported_claims=False),
        verified_truth_ids=("truth-one",),
    )
    assert completed_with_extra.task_status == "completed"


def test_verified_truth_helper_validates_and_filters_evidence():
    truth = _truth()
    assert verified_truth_ids_from_evidence((truth,), ("evidence-one",)) == (
        "truth-one",
    )
    assert verified_truth_ids_from_evidence(
        (_truth(required_evidence_ids=()),), ("evidence-one",)
    ) == ()
    with pytest.raises(
        BenchmarkV3SchemaError, match=r"invalid:observed_evidence_id"
    ):
        verified_truth_ids_from_evidence((truth,), ("bad value",))


def test_budget_enforcement_rejects_incomplete_unknown_and_invalid_values():
    with pytest.raises(BenchmarkV3SchemaError, match="budget_enforcement_modes_incomplete"):
        build_budget_enforcement(
            system_id="system",
            declared_budgets={"max_tools": 1},
            observed_usage={},
            enforcement_modes={},
        )
    with pytest.raises(BenchmarkV3SchemaError, match="observed_unknown_budget"):
        build_budget_enforcement(
            system_id="system",
            declared_budgets={"max_tools": 1},
            observed_usage={"unknown": 1},
            enforcement_modes={"max_tools": "hard"},
        )
    with pytest.raises(BenchmarkV3SchemaError, match=r"invalid:declared_budget"):
        build_budget_enforcement(
            system_id="system",
            declared_budgets={"max_tools": "bad"},
            observed_usage={},
            enforcement_modes={"max_tools": "hard"},
        )


def test_budget_units_cover_every_suffix_and_reliability_path():
    budgets = {
        "max_seconds": 10,
        "max_bytes": 20,
        "max_tokens": 30,
        "max_usd": 40,
        "max_tools": 50,
    }
    records = build_budget_enforcement(
        system_id="system",
        declared_budgets=budgets,
        observed_usage={"max_seconds": 11, "max_bytes": 2},
        enforcement_modes={
            "max_seconds": "hard",
            "max_bytes": "observed",
            "max_tokens": "advisory",
            "max_usd": "advisory",
            "max_tools": "advisory",
        },
        units={"max_tools": "actions"},
        evidence_refs={"max_seconds": ("ref",)},
    )
    by_name = {record.budget_name: record for record in records}
    assert by_name["max_seconds"].unit == "seconds"
    assert by_name["max_bytes"].unit == "bytes"
    assert by_name["max_tokens"].unit == "tokens"
    assert by_name["max_usd"].unit == "usd"
    assert by_name["max_tools"].unit == "actions"
    assert by_name["max_seconds"].exceeded is True
    assert by_name["max_tokens"].measured is None
    assert by_name["max_tokens"].reliable is False


def test_private_helpers_identifier_rate_and_default_budget_unit():
    assert evaluation_module._normalize_text(" A   B ") == "a b"
    with pytest.raises(BenchmarkV3SchemaError, match="invalid:test"):
        evaluation_module._safe_identifier("bad value", "test")
    assert evaluation_module._rate(0, 0, empty=1.0) == 1.0
    assert evaluation_module._rate(1, 2, empty=1.0) == 0.5
    assert evaluation_module._budget_unit("max_tools") == "count"
