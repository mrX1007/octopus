"""Hermetic edge coverage for the competitor Benchmark v3 bridge."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

from core.benchmarks.competitors import v3_integration as integration
from core.benchmarks.schema import BenchmarkScenario
from core.benchmarks.v3.fixture import LAB_V3_VERSION
from core.benchmarks.v3.schema import BenchmarkV3SchemaError

pytestmark = [pytest.mark.benchmark, pytest.mark.contract]


def _scenario(
    scenario_id: str = "deep-navigation-v3",
    *,
    lab_version: str = LAB_V3_VERSION,
) -> BenchmarkScenario:
    return BenchmarkScenario(
        scenario_id=scenario_id,
        name=scenario_id,
        category="service_discovery_verification",
        lab={"version": lab_version, "snapshot_ref": "snapshot-v1"},
        target={"version": "target-v1"},
        model={"provider": "local", "name": "fixture", "parameters": {}},
        tool_versions={"fixture": "1.0"},
        strategy_config={},
        seed=7,
        budgets={"max_tools": 1, "max_seconds": 120, "max_output_bytes": 1024},
        allowed_actions=("inspect",),
        ground_truth={},
        artifacts={},
        tags=("read-only",),
    )


def _plan(**overrides):
    values = {
        "system_ids": ("alpha", "beta"),
        "scenario_ids": ("deep-navigation-v3",),
        "repetitions": 1,
        "fixture_seeds": {"deep-navigation-v3": (7,)},
        "track_id": "small-model-stress-v3",
        "digest": "a" * 64,
    }
    values.update(overrides)
    return SimpleNamespace(**values)


def _efficiency_plan(**overrides):
    source = _plan()
    values = {
        "source_analysis_plan_digest": source.digest,
        "source_track_id": source.track_id,
        "system_ids": source.system_ids,
        "scenario_ids": source.scenario_ids,
        "repetitions": source.repetitions,
        "schedule": (
            SimpleNamespace(
                scenario_id="deep-navigation-v3",
                repetition=1,
                matched_fixture_seed=7,
                system_order=("alpha", "beta"),
            ),
        ),
        "digest": "b" * 64,
    }
    values.update(overrides)
    return SimpleNamespace(**values)


def test_config_scenario_and_plan_validation_errors(tmp_path: Path) -> None:
    with pytest.raises(
        BenchmarkV3SchemaError,
        match="unsupported_v3_campaign_config_schema",
    ):
        integration.BenchmarkV3CampaignConfig.from_dict(
            {},
            base_directory=tmp_path,
        )
    with pytest.raises(
        BenchmarkV3SchemaError,
        match="unknown_v3_campaign_config_key",
    ):
        integration.BenchmarkV3CampaignConfig.from_dict(
            {"schema_version": "1.0", "unknown": True},
            base_directory=tmp_path,
        )
    with pytest.raises(BenchmarkV3SchemaError, match="unknown_v3_scenario_id"):
        integration.scenario_family("unknown-v3")

    plan = _plan()
    config = SimpleNamespace(plan=lambda: plan)
    with pytest.raises(
        BenchmarkV3SchemaError,
        match="v3_plan_requires_v3_lab_scenarios",
    ):
        integration.validate_campaign_plan(
            config,
            system_ids=plan.system_ids,
            scenarios=(_scenario(lab_version="legacy"),),
            repetitions=plan.repetitions,
        )
    with pytest.raises(BenchmarkV3SchemaError, match="v3_plan_system_mismatch"):
        integration.validate_campaign_plan(
            config,
            system_ids=("alpha", "other"),
            scenarios=(_scenario(),),
            repetitions=plan.repetitions,
        )
    with pytest.raises(BenchmarkV3SchemaError, match="v3_plan_scenario_mismatch"):
        integration.validate_campaign_plan(
            SimpleNamespace(plan=lambda: _plan(scenario_ids=("clean-negative-v3",))),
            system_ids=plan.system_ids,
            scenarios=(_scenario(),),
            repetitions=plan.repetitions,
        )
    with pytest.raises(
        BenchmarkV3SchemaError,
        match="v3_plan_repetition_mismatch",
    ):
        integration.validate_campaign_plan(
            config,
            system_ids=plan.system_ids,
            scenarios=(_scenario(),),
            repetitions=2,
        )


def test_efficiency_config_load_and_campaign_validation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = integration.BenchmarkV3CampaignConfig(
        analysis_plan_path=tmp_path / "analysis-plan.json",
        state_directory=tmp_path,
        batch_id="batch",
        host_id="host",
        efficiency_plan_path=tmp_path / "efficiency-plan.json",
    )
    monkeypatch.setattr(
        integration,
        "load_efficiency_plan",
        lambda _path: (_ for _ in ()).throw(integration.BenchmarkV4SchemaError("schema")),
    )
    with pytest.raises(BenchmarkV3SchemaError, match="schema"):
        config.efficiency_plan()

    monkeypatch.setattr(
        integration,
        "load_efficiency_plan",
        lambda _path: (_ for _ in ()).throw(ValueError("broken")),
    )
    with pytest.raises(BenchmarkV3SchemaError, match="efficiency_plan_load_failed"):
        config.efficiency_plan()

    source = _plan()
    efficiency = _efficiency_plan()
    validated = integration.validate_campaign_plan(
        SimpleNamespace(plan=lambda: source, efficiency_plan=lambda: efficiency),
        system_ids=source.system_ids,
        scenarios=(_scenario(),),
        repetitions=source.repetitions,
    )
    assert validated is source


@pytest.mark.parametrize(
    ("plan_updates", "source_updates", "expected"),
    (
        ({"system_ids": ("alpha", "other")}, {}, "efficiency_plan_system_mismatch"),
        ({"scenario_ids": ("clean-negative-v3",)}, {}, "efficiency_plan_scenario_mismatch"),
        ({"repetitions": 2}, {}, "efficiency_plan_repetition_mismatch"),
        ({"schedule": ()}, {}, "efficiency_plan_repetition_mismatch"),
        (
            {
                "schedule": (
                    SimpleNamespace(
                        scenario_id="deep-navigation-v3",
                        repetition=1,
                        matched_fixture_seed=8,
                        system_order=("alpha", "beta"),
                    ),
                ),
            },
            {},
            "efficiency_plan_schedule_mismatch",
        ),
        (
            {
                "schedule": (
                    SimpleNamespace(
                        scenario_id="deep-navigation-v3",
                        repetition=1,
                        matched_fixture_seed=7,
                        system_order=("alpha", "beta"),
                    ),
                    SimpleNamespace(
                        scenario_id="deep-navigation-v3",
                        repetition=1,
                        matched_fixture_seed=7,
                        system_order=("alpha", "beta"),
                    ),
                ),
            },
            {},
            "efficiency_plan_schedule_mismatch",
        ),
        (
            {
                "schedule": (
                    SimpleNamespace(
                        scenario_id="deep-navigation-v3",
                        repetition=1,
                        matched_fixture_seed=7,
                        system_order=("alpha", "alpha"),
                    ),
                ),
            },
            {},
            "efficiency_plan_schedule_mismatch",
        ),
        (
            {
                "schedule": (
                    SimpleNamespace(
                        scenario_id="deep-navigation-v3",
                        repetition=1,
                        matched_fixture_seed=7,
                        system_order=("alpha",),
                    ),
                ),
            },
            {},
            "efficiency_plan_schedule_mismatch",
        ),
        ({"source_analysis_plan_digest": "c" * 64}, {}, "efficiency_plan_source_digest_mismatch"),
        ({"source_track_id": "other-track"}, {}, "efficiency_plan_source_track_mismatch"),
    ),
)
def test_efficiency_campaign_validation_rejects_each_mismatch(
    plan_updates: dict[str, object],
    source_updates: dict[str, object],
    expected: str,
) -> None:
    source = _plan(**source_updates)
    efficiency = _efficiency_plan(**plan_updates)
    with pytest.raises(BenchmarkV3SchemaError, match=expected):
        integration.validate_efficiency_campaign_plan(
            efficiency,
            source_plan=source,
            system_ids=source.system_ids,
            scenario_ids=source.scenario_ids,
            repetitions=source.repetitions,
        )


def test_schedule_and_run_identity_errors(tmp_path: Path) -> None:
    plan = _plan()
    with pytest.raises(BenchmarkV3SchemaError, match="v3_plan_schedule_mismatch"):
        integration.planned_fixture_seed(
            plan,
            scenario_id="missing-v3",
            repetition=1,
        )
    with pytest.raises(BenchmarkV3SchemaError, match="invalid_v3_run_identity"):
        integration.run_artifacts(
            tmp_path,
            campaign_id="campaign",
            system_id="alpha",
            scenario_id="deep-navigation-v3",
            repetition=0,
            seed=7,
        )


def test_fixture_and_run_attestation_errors(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        integration,
        "generate_fixture_variant",
        lambda *_args, **_kwargs: SimpleNamespace(scenario_id="other-v3"),
    )
    with pytest.raises(
        BenchmarkV3SchemaError,
        match="v3_fixture_scenario_mismatch",
    ):
        integration.prepare_fixture_run(
            tmp_path,
            campaign_id="campaign",
            system_id="alpha",
            scenario_id="deep-navigation-v3",
            repetition=1,
            seed=7,
            base_url="http://127.0.0.1:8080",
        )

    config = SimpleNamespace(
        state_directory=tmp_path,
        batch_id="batch",
        host_id="host",
    )
    plan = _plan()
    common = {
        "config": config,
        "plan": plan,
        "scenario": _scenario(),
        "system_id": "alpha",
        "repetition": 1,
        "result": {},
        "started_at": 1.0,
        "finished_at": 2.0,
        "reset_attestation": {"campaign_id": "campaign"},
    }
    with pytest.raises(BenchmarkV3SchemaError, match="v3_run_seed_not_in_plan"):
        integration.build_v3_run(seed=8, **common)

    monkeypatch.setattr(
        integration,
        "load_private_fixture",
        lambda _path: SimpleNamespace(
            scenario_id="other-v3",
            matched_fixture_seed=7,
            lab_version=LAB_V3_VERSION,
        ),
    )
    with pytest.raises(
        BenchmarkV3SchemaError,
        match="v3_fixture_attestation_mismatch",
    ):
        integration.build_v3_run(seed=7, **common)


def test_efficiency_run_attestation_and_schedule_guards(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = _plan()
    efficiency = _efficiency_plan()
    variant = SimpleNamespace(
        scenario_id="deep-navigation-v3",
        matched_fixture_seed=7,
        lab_version=LAB_V3_VERSION,
        scenario_family="deep_navigation",
        variant_digest="c" * 64,
        truth_claims=(),
        completion_rule="all_required_truths",
    )
    snapshot = SimpleNamespace(
        violations=(),
        observed_evidence_ids=(),
        root_digest="d" * 64,
        entry_count=0,
    )
    ledger = SimpleNamespace(snapshot=lambda: snapshot, action_events=lambda: ())
    monkeypatch.setattr(integration, "load_private_fixture", lambda _path: variant)
    monkeypatch.setattr(integration, "ControlPlaneLedger", lambda **_kwargs: ledger)
    monkeypatch.setattr(integration, "evaluate_claims", lambda **_kwargs: SimpleNamespace())
    monkeypatch.setattr(integration, "make_run", lambda **kwargs: kwargs)

    common = {
        "plan": source,
        "scenario": _scenario(),
        "system_id": "alpha",
        "repetition": 1,
        "seed": 7,
        "result": {"status": "succeeded"},
        "started_at": 1.0,
        "finished_at": 2.0,
        "reset_attestation": {"campaign_id": "campaign"},
    }
    without_efficiency = SimpleNamespace(
        state_directory=tmp_path,
        batch_id="batch",
        host_id="host",
    )
    with pytest.raises(BenchmarkV3SchemaError, match="efficiency_plan_digest_mismatch"):
        integration.build_v3_run(
            config=without_efficiency,
            efficiency_plan=efficiency,
            **common,
        )

    configured = SimpleNamespace(
        state_directory=tmp_path,
        batch_id="batch",
        host_id="host",
        efficiency_plan=lambda: efficiency,
    )
    run = integration.build_v3_run(config=configured, **common)
    assert run["environment"]["efficiency_plan_digest"] == efficiency.digest

    invalid = _efficiency_plan(schedule=())
    invalid_config = SimpleNamespace(
        state_directory=tmp_path,
        batch_id="batch",
        host_id="host",
        efficiency_plan=lambda: invalid,
    )
    monkeypatch.setattr(
        integration,
        "validate_efficiency_campaign_plan",
        lambda *_args, **_kwargs: invalid,
    )
    with pytest.raises(BenchmarkV3SchemaError, match="efficiency_plan_schedule_mismatch"):
        integration.build_v3_run(config=invalid_config, **common)


def test_reveal_and_public_ledger_attestation_errors(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = SimpleNamespace(state_directory=tmp_path)
    plan = _plan()
    monkeypatch.setattr(
        integration,
        "load_private_fixture",
        lambda _path: SimpleNamespace(
            scenario_id="other-v3",
            matched_fixture_seed=7,
        ),
    )
    with pytest.raises(BenchmarkV3SchemaError, match="v3_fixture_reveal_mismatch"):
        integration.fixture_reveals(config, plan, campaign_id="campaign")

    run = SimpleNamespace(
        run_id="run-1",
        system_id="alpha",
        scenario_id="deep-navigation-v3",
        repetition=1,
        matched_fixture_seed=7,
        fixture_variant_digest="b" * 64,
        action_telemetry=(),
        artifact_refs=(),
    )
    monkeypatch.setattr(integration, "read_ledger", lambda *_args, **_kwargs: ())
    with pytest.raises(
        BenchmarkV3SchemaError,
        match="v3_public_ledger_run_mismatch",
    ):
        integration.controller_ledger_records(
            config,
            (run,),
            campaign_id="campaign",
        )


def test_claim_and_scalar_normalization_edges(tmp_path: Path) -> None:
    variant = SimpleNamespace(
        truth_claims=(
            SimpleNamespace(
                aliases=("human readable alias",),
                required_evidence_ids=("evidence-1",),
            ),
        ),
    )
    with pytest.raises(BenchmarkV3SchemaError, match="invalid_v3_reported_claims"):
        integration._reported_claims("not-a-claim-sequence", variant=variant)
    claims = integration._reported_claims(("", "  Useful Claim  "), variant=variant)
    assert tuple(item.text for item in claims) == ("Useful Claim",)
    assert claims[0].evidence_refs == ()

    assert integration._enforcement_mode("advisory", measured=True) == "advisory"
    assert integration._enforcement_mode("unknown", measured=True) == "none"
    with pytest.raises(BenchmarkV3SchemaError, match=r"invalid:v3\.identifier"):
        integration._identifier("not allowed!", "identifier")
    assert integration._policy_identifier("  Unsafe Policy Value!  ") == ("unsafe-policy-value")
    with pytest.raises(BenchmarkV3SchemaError, match=r"invalid:v3\.path"):
        integration._resolved_path("", base=tmp_path, name="path")
    assert integration._positive_number(True) is False
    assert integration._positive_number(object()) is False
    assert integration._nonnegative_number(True) is False
