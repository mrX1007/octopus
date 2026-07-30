"""Complete validation and helper coverage for benchmark schema 1.0."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

import core.benchmarks.schema as schema_module
from core.benchmarks.schema import (
    BenchmarkScenario,
    BenchmarkSchemaError,
    load_scenario,
    load_scenarios,
)

pytestmark = [pytest.mark.benchmark, pytest.mark.contract]


def _payload():
    path = Path(__file__).resolve().parents[2] / "benchmarks" / "scenarios" / "01-service-discovery-verification.json"
    return json.loads(path.read_text(encoding="utf-8"))


def test_scenario_round_trip_and_optional_ablation():
    payload = _payload()
    payload["ablations"] = [{"toggle": "retry", "values": [False, True]}]
    scenario = BenchmarkScenario.from_dict(payload)
    assert scenario.to_dict() == payload


@pytest.mark.parametrize(
    ("mutator", "message"),
    [
        (lambda p: p.update(schema_version="999"), "unsupported_schema_version"),
        (lambda p: p["lab"].pop("version"), "missing:lab.version"),
        (lambda p: p["target"].pop("version"), "missing:target.version"),
        (lambda p: p["model"].pop("provider"), "missing:model.provider"),
        (lambda p: p["model"].pop("name"), "missing:model.name"),
        (lambda p: p["model"].pop("parameters"), "invalid:model.parameters"),
        (lambda p: p.update(tool_versions={}), "empty:tool_versions"),
        (lambda p: p.update(allowed_actions=[]), "empty:allowed_actions"),
        (lambda p: p.update(repetitions=4), "repetitions_below_minimum"),
        (lambda p: p.update(ablations="bad"), "invalid:ablations"),
        (
            lambda p: p.update(ablations=[{"toggle": "bad value", "values": [1, 2]}]),
            "invalid_identifier:ablation.toggle",
        ),
        (
            lambda p: p.update(ablations=[{"toggle": "valid", "values": "bad"}]),
            "invalid:ablation.values",
        ),
        (
            lambda p: p.update(ablations=[{"toggle": "valid", "values": [1]}]),
            "ablation_requires_multiple_values",
        ),
    ],
)
def test_scenario_rejects_invalid_contract_fields(mutator, message):
    payload = _payload()
    mutator(payload)
    with pytest.raises(BenchmarkSchemaError, match=message):
        BenchmarkScenario.from_dict(payload)


def test_load_scenario_errors_and_nonmapping(tmp_path):
    with pytest.raises(BenchmarkSchemaError, match="scenario_load_failed"):
        load_scenario(tmp_path / "missing.json")
    invalid = tmp_path / "invalid.json"
    invalid.write_text("{", encoding="utf-8")
    with pytest.raises(BenchmarkSchemaError, match="scenario_load_failed"):
        load_scenario(invalid)
    nonmapping = tmp_path / "list.json"
    nonmapping.write_text("[]", encoding="utf-8")
    with pytest.raises(BenchmarkSchemaError, match="scenario_not_mapping"):
        load_scenario(nonmapping)


def test_load_scenarios_empty_and_duplicate_ids(tmp_path):
    assert load_scenarios(tmp_path) == ()
    payload = _payload()
    for name in ("one.json", "two.json"):
        (tmp_path / name).write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(BenchmarkSchemaError, match="duplicate_scenario_id"):
        load_scenarios(tmp_path)


def test_budget_validation_missing_optional_policy_and_policy_shape():
    base = {"max_tools": 1, "max_seconds": 1, "max_output_bytes": 1}
    for missing in base:
        budgets = {key: value for key, value in base.items() if key != missing}
        with pytest.raises(BenchmarkSchemaError, match=f"missing:budgets.{missing}"):
            schema_module._validate_budgets(budgets)

    with pytest.raises(BenchmarkSchemaError, match=r"missing:budgets.policy"):
        schema_module._validate_budgets({**base, "max_model_tokens": 1})
    with pytest.raises(BenchmarkSchemaError, match=r"invalid:budgets.policy"):
        schema_module._validate_budgets({**base, "policy": []})
    with pytest.raises(BenchmarkSchemaError, match=r"invalid:budgets.policy"):
        schema_module._validate_budgets({**base, "policy": {}})

    complete = {
        **base,
        "max_model_tokens": 2,
        "max_cost_usd": 0.5,
        "policy": {
            "max_seconds": "hard",
            "max_output_bytes": "hard",
            "max_tools": "observational",
            "max_model_tokens": "observational",
            "max_cost_usd": "observational",
        },
    }
    schema_module._validate_budgets(complete)


@pytest.mark.parametrize("value", [True, 1.5, "1", 0, -1])
def test_strict_positive_integer_rejects_nonpositive_or_noninteger(value):
    with pytest.raises(BenchmarkSchemaError, match="invalid_positive_integer"):
        schema_module._strict_positive_integer(value, "value")


@pytest.mark.parametrize("value", [True, "1", 0, -1, float("inf"), float("-inf"), float("nan")])
def test_strict_positive_number_rejects_invalid_values(value):
    with pytest.raises(BenchmarkSchemaError, match="invalid_positive_number"):
        schema_module._strict_positive_number(value, "value")


def test_mapping_identifier_text_and_integer_boundaries():
    with pytest.raises(BenchmarkSchemaError, match="invalid:mapping"):
        schema_module._mapping([], "mapping")
    with pytest.raises(BenchmarkSchemaError, match="too_many_items:mapping"):
        schema_module._mapping({str(index): index for index in range(257)}, "mapping")
    with pytest.raises(BenchmarkSchemaError, match="invalid:values"):
        schema_module._identifiers("bad", "values")
    with pytest.raises(BenchmarkSchemaError, match="empty:values"):
        schema_module._identifiers([], "values")
    assert schema_module._identifiers([], "values", allow_empty=True) == ()
    with pytest.raises(BenchmarkSchemaError, match="invalid_identifier:value"):
        schema_module._identifier("bad value", "value")
    with pytest.raises(BenchmarkSchemaError, match="missing:text"):
        schema_module._text("", "text")
    with pytest.raises(BenchmarkSchemaError, match="text_too_long:text"):
        schema_module._text("x" * 4_097, "text")
    with pytest.raises(BenchmarkSchemaError, match="invalid_integer"):
        schema_module._integer([])
    with pytest.raises(BenchmarkSchemaError, match="integer_below_minimum:2"):
        schema_module._integer(1, minimum=2)


def test_json_safe_depth_nonfinite_collections_and_fallback_object():
    assert schema_module._json_safe(float("inf")) is None
    assert schema_module._json_safe(float("nan")) is None
    assert schema_module._json_safe({1: [True, 1.5]}) == {"1": [True, 1.5]}
    nested = [[[[[[["deep"]]]]]]]
    assert schema_module._json_safe(nested)[0][0][0][0][0][0] == "[depth-bounded]"
    value = object()
    assert schema_module._json_safe(value).startswith("<object object")
