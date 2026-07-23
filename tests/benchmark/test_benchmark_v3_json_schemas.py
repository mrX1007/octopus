from __future__ import annotations

import json
from pathlib import Path

import jsonschema
import pytest

from core.benchmarks.v3 import (
    CompletionRule,
    TruthClaim,
    build_analysis_plan,
    build_budget_enforcement,
    evaluate_claims,
    generate_fixture_variant,
    make_run,
)

pytestmark = [pytest.mark.benchmark, pytest.mark.contract]

ROOT = Path(__file__).resolve().parents[2]
SCHEMA_ROOT = ROOT / "docs" / "schemas"


@pytest.mark.parametrize(
    "name",
    [
        "benchmark-analysis-plan-v3.schema.json",
        "benchmark-fixture-private-v3.schema.json",
        "benchmark-fixture-product-view-v3.schema.json",
        "benchmark-run-v3.schema.json",
        "benchmark-statistics-v3.schema.json",
    ],
)
def test_v3_json_schema_is_valid_draft_2020_12(name: str) -> None:
    schema = json.loads((SCHEMA_ROOT / name).read_text(encoding="utf-8"))
    jsonschema.Draft202012Validator.check_schema(schema)


def test_plan_and_fixture_views_validate_against_json_schemas() -> None:
    plan = build_analysis_plan(
        track_id="small-model-stress-v3",
        system_ids=["alpha", "beta"],
        scenario_ids=["deep-navigation-v3"],
        repetitions=2,
        base_fixture_seed=4,
        publication_tier="canary",
        bootstrap_samples=100,
    )
    variant = generate_fixture_variant("deep_navigation", matched_fixture_seed=4)
    plan_schema = json.loads((SCHEMA_ROOT / "benchmark-analysis-plan-v3.schema.json").read_text(encoding="utf-8"))
    private_schema = json.loads((SCHEMA_ROOT / "benchmark-fixture-private-v3.schema.json").read_text(encoding="utf-8"))
    product_schema = json.loads(
        (SCHEMA_ROOT / "benchmark-fixture-product-view-v3.schema.json").read_text(encoding="utf-8")
    )

    jsonschema.validate(plan.to_dict(), plan_schema)
    jsonschema.validate(variant.to_private_dict(), private_schema)
    jsonschema.validate(variant.product_view(), product_schema)


def test_serialized_run_validates_against_json_schema() -> None:
    truth = TruthClaim("finding-one", "service one")
    evaluation = evaluate_claims(
        execution_status="succeeded",
        reported_claims=["service one"],
        truth_claims=[truth],
        completion_rule=CompletionRule("rule-one", (truth.truth_id,)),
        verified_truth_ids=[truth.truth_id],
    )
    run = make_run(
        track_id="small-model-stress-v3",
        system_id="alpha",
        scenario_id="scenario-one",
        repetition=1,
        execution_status="succeeded",
        evaluation=evaluation,
        matched_fixture_seed=1,
        fixture_variant_digest="a" * 64,
        applied_model_seed=1,
        model_seed_status="applied",
        budget_enforcement=build_budget_enforcement(
            system_id="alpha",
            declared_budgets={"max_seconds": 10},
            observed_usage={"max_seconds": 2},
            enforcement_modes={"max_seconds": "hard"},
        ),
        action_telemetry=[],
        action_telemetry_available=False,
        action_telemetry_reliability="unavailable",
        duration_seconds=2,
        timeout_limit_seconds=10,
        started_at=1,
        finished_at=3,
    )
    schema = json.loads((SCHEMA_ROOT / "benchmark-run-v3.schema.json").read_text(encoding="utf-8"))

    jsonschema.validate(run.to_dict(), schema)
