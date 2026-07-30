"""Branch-complete validation and statistical edge cases for v3 analysis."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

import core.benchmarks.v3.analysis as analysis_module
from core.benchmarks.v3.analysis import (
    AnalysisPlan,
    analyze_runs,
    build_analysis_plan,
    freeze_analysis_plan,
    kaplan_meier,
    load_analysis_plan,
    paired_bootstrap,
    wilson_interval,
)
from core.benchmarks.v3.schema import BenchmarkV3SchemaError

pytestmark = [pytest.mark.benchmark, pytest.mark.contract]


def _plan_kwargs(**changes):
    values = {
        "track_id": "small-model-stress-v3",
        "system_ids": ("alpha", "beta"),
        "scenario_ids": ("scenario",),
        "repetitions": 2,
        "fixture_seeds": {"scenario": (1, 2)},
        "comparison_pairs": (("alpha", "beta"),),
        "bootstrap_samples": 100,
        "publication_tier": "canary",
        "paired_blocks": 2,
    }
    values.update(changes)
    return values


@pytest.mark.parametrize(
    ("changes", "message"),
    [
        ({"comparison_pairs": (None,)}, "invalid:analysis_plan.comparison_pair"),
        ({"comparison_pairs": (("alpha",),)}, "invalid:analysis_plan.comparison_pair"),
        ({"system_ids": ("alpha",)}, "analysis_plan_requires_unique_systems"),
        ({"system_ids": ("alpha", "alpha")}, "analysis_plan_requires_unique_systems"),
        ({"scenario_ids": ()}, "analysis_plan_requires_unique_scenarios"),
        ({"scenario_ids": ("scenario", "scenario")}, "analysis_plan_requires_unique_scenarios"),
        ({"repetitions": 0}, "invalid:analysis_plan.repetitions"),
        ({"batches": 0}, "invalid:analysis_plan.design_count"),
        ({"hosts": 0}, "invalid:analysis_plan.design_count"),
        ({"paired_blocks": -1}, "invalid:analysis_plan.design_count"),
        ({"fixture_seeds": {"other": (1, 2)}}, "analysis_plan_fixture_seed_scenarios"),
        ({"fixture_seeds": {"scenario": (1,)}}, "analysis_plan_fixture_seed_count"),
        ({"fixture_seeds": {"scenario": (1, 1)}}, "analysis_plan_fixture_seed_count"),
        ({"fixture_seeds": {"scenario": (-1, 2)}}, "invalid:analysis_plan.fixture_seed"),
        ({"fixture_seeds": {"scenario": (1, 2**63)}}, "invalid:analysis_plan.fixture_seed"),
        ({"comparison_pairs": (("alpha", "alpha"),)}, "invalid:analysis_plan.comparison_pair"),
        ({"comparison_pairs": (("alpha", "missing"),)}, "invalid:analysis_plan.comparison_pair"),
        (
            {"comparison_pairs": (("alpha", "beta"), ("beta", "alpha"))},
            "duplicate_analysis_comparison_pair",
        ),
        ({"comparison_pairs": ()}, "analysis_plan_requires_comparison_pair"),
        ({"metrics": ()}, "invalid:analysis_plan.metrics"),
        ({"metrics": ("metric", "metric")}, "invalid:analysis_plan.metrics"),
        ({"populations": ()}, "invalid:analysis_plan.populations"),
        ({"populations": ("invalid",)}, "invalid:analysis_plan.populations"),
        ({"deadlines_seconds": ()}, "invalid:analysis_plan.deadlines"),
        ({"deadlines_seconds": (0.0,)}, "invalid:analysis_plan.deadlines"),
        ({"deadlines_seconds": (2.0, 1.0)}, "invalid:analysis_plan.deadlines"),
        ({"alpha": 0.0}, "invalid:analysis_plan.alpha"),
        ({"bootstrap_samples": 99}, "analysis_plan_bootstrap_too_small"),
        ({"bootstrap_seed": -1}, "invalid:analysis_plan.bootstrap_seed"),
    ],
)
def test_analysis_plan_rejects_every_invalid_design(changes, message):
    with pytest.raises(BenchmarkV3SchemaError, match=message):
        AnalysisPlan(**_plan_kwargs(**changes))


@pytest.mark.parametrize(
    ("value", "message"),
    [
        ("", "invalid:test"),
        ("x" * 161, "invalid:test"),
        ("bad value", "invalid:test"),
        (".hidden", "invalid:test"),
        ("Upper", "invalid:test"),
    ],
)
def test_identifier_rejects_all_invalid_forms(value, message):
    with pytest.raises(BenchmarkV3SchemaError, match=message):
        analysis_module._identifier(value, "test")


def test_from_dict_validates_envelope_and_integrity_fields():
    plan = AnalysisPlan(**_plan_kwargs())
    payload = plan.to_dict()
    assert AnalysisPlan.from_dict(payload) == plan

    invalid_payloads = [
        ({**payload, "schema_version": "999"}, "unsupported_analysis_plan_schema"),
        ({**payload, "fixture_seeds": []}, "invalid_analysis_plan"),
        ({**payload, "comparison_pairs": "bad"}, "invalid_analysis_plan"),
        ({**payload, "frozen": False}, "analysis_plan_not_frozen"),
        ({**payload, "plan_digest": "bad"}, "analysis_plan_digest_mismatch"),
        ({**payload, "plan_id": "bad"}, "analysis_plan_id_mismatch"),
    ]
    for invalid, message in invalid_payloads:
        with pytest.raises(BenchmarkV3SchemaError, match=message):
            AnalysisPlan.from_dict(invalid)


def test_build_plan_seed_and_explicit_comparison_paths():
    for invalid_seed in (True, -1, 2**256):
        with pytest.raises(BenchmarkV3SchemaError, match="invalid:base_fixture_seed"):
            build_analysis_plan(
                track_id="small-model-stress-v3",
                system_ids=("alpha", "beta"),
                scenario_ids=("scenario",),
                repetitions=2,
                base_fixture_seed=invalid_seed,
                publication_tier="canary",
                bootstrap_samples=100,
            )

    plan = build_analysis_plan(
        track_id="small-model-stress-v3",
        system_ids=("alpha", "beta"),
        scenario_ids=("scenario",),
        repetitions=2,
        base_fixture_seed=1,
        publication_tier="canary",
        paired_blocks=2,
        bootstrap_samples=100,
        comparison_pairs=(("beta", "alpha"),),
    )
    assert plan.comparison_pairs == (("beta", "alpha"),)


def test_freeze_equal_file_and_cleanup_after_replace_failure(tmp_path, monkeypatch):
    plan = AnalysisPlan(**_plan_kwargs())
    destination = freeze_analysis_plan(plan, tmp_path / "plan.json")
    assert freeze_analysis_plan(plan, destination) == destination

    broken = tmp_path / "broken.json"
    monkeypatch.setattr(
        analysis_module.os,
        "replace",
        lambda *_args: (_ for _ in ()).throw(OSError("replace failed")),
    )
    with pytest.raises(OSError, match="replace failed"):
        freeze_analysis_plan(plan, broken)
    assert not broken.exists()


def test_freeze_suppresses_cleanup_error_and_preserves_original_failure(tmp_path, monkeypatch):
    plan = AnalysisPlan(**_plan_kwargs())
    monkeypatch.setattr(
        analysis_module.os,
        "replace",
        lambda *_args: (_ for _ in ()).throw(RuntimeError("replace failed")),
    )
    monkeypatch.setattr(
        analysis_module.os,
        "unlink",
        lambda *_args: (_ for _ in ()).throw(OSError("unlink failed")),
    )
    with pytest.raises(RuntimeError, match="replace failed"):
        freeze_analysis_plan(plan, tmp_path / "broken.json")


def test_load_analysis_plan_error_paths(tmp_path):
    with pytest.raises(BenchmarkV3SchemaError, match="analysis_plan_load_failed"):
        load_analysis_plan(tmp_path / "missing.json")
    invalid_json = tmp_path / "invalid.json"
    invalid_json.write_text("{", encoding="utf-8")
    with pytest.raises(BenchmarkV3SchemaError, match="analysis_plan_load_failed"):
        load_analysis_plan(invalid_json)
    non_mapping = tmp_path / "list.json"
    non_mapping.write_text("[]", encoding="utf-8")
    with pytest.raises(BenchmarkV3SchemaError, match="invalid_analysis_plan"):
        load_analysis_plan(non_mapping)


def test_statistical_helpers_cover_empty_invalid_and_degenerate_inputs():
    for args in ((-1, 1), (1, -1), (2, 1)):
        with pytest.raises(BenchmarkV3SchemaError, match="invalid_wilson_counts"):
            wilson_interval(*args)
    with pytest.raises(BenchmarkV3SchemaError, match="invalid_wilson_alpha"):
        wilson_interval(0, 0, alpha=1)
    assert wilson_interval(0, 0)["estimate"] is None

    assert paired_bootstrap([])["reason"] == "no_complete_pairs"
    with pytest.raises(BenchmarkV3SchemaError, match="invalid_paired_bootstrap_design"):
        paired_bootstrap([(0, 1)], samples=99)
    with pytest.raises(BenchmarkV3SchemaError, match="invalid_paired_bootstrap_design"):
        paired_bootstrap([(0, 1)], samples=100, alpha=0)
    with pytest.raises(BenchmarkV3SchemaError, match="nonfinite"):
        paired_bootstrap([(0, float("inf"))], samples=100)
    assert paired_bootstrap([(0, 1)], samples=100)["standardized_paired_effect"] is None
    assert paired_bootstrap([(0, 1), (1, 2)], samples=100)["standardized_paired_effect"] is None

    assert kaplan_meier([])["reason"] == "no_duration_observations"
    for observations in ([(-1, False)], [(float("inf"), False)]):
        with pytest.raises(BenchmarkV3SchemaError, match="invalid_duration_observation"):
            kaplan_meier(observations)
    with pytest.raises(BenchmarkV3SchemaError, match="invalid_survival_horizon"):
        kaplan_meier([(1, False)], horizon_seconds=-1)
    result = kaplan_meier([(1, False)], horizon_seconds=1)
    assert result["restricted_mean_completion_seconds"] == 1

    with pytest.raises(BenchmarkV3SchemaError, match="percentile_requires_values"):
        analysis_module._percentile([], 0.5)
    assert analysis_module._percentile([2.0], 0.0) == 2.0


class _Metric:
    def __init__(self, *, available, value):
        self.available = available
        self.value = value


class _Evaluation:
    def __init__(self, metric):
        self._metric = metric

    def metric(self, _name, _population):
        return self._metric


def _analysis_stub_inputs(metric):
    plan = SimpleNamespace(
        system_ids=("left", "right"),
        scenario_ids=("scenario",),
        fixture_seeds={"scenario": (1,)},
        comparison_pairs=(("left", "right"),),
        populations=("all_scheduled",),
        metrics=("metric",),
        bootstrap_samples=100,
        alpha=0.05,
        bootstrap_seed=1,
        digest="digest",
        plan_id="plan",
    )
    runs = tuple(
        SimpleNamespace(
            system_id=system_id,
            scenario_id="scenario",
            matched_fixture_seed=1,
            track_id="small-model-stress-v3",
            evaluation=_Evaluation(metric),
        )
        for system_id in plan.system_ids
    )
    return plan, runs


def test_analyze_runs_skips_unavailable_pairs(monkeypatch):
    plan, runs = _analysis_stub_inputs(_Metric(available=False, value=None))
    monkeypatch.setattr(analysis_module, "_validate_schedule", lambda *_args: None)
    monkeypatch.setattr(analysis_module, "_group_statistics", lambda *_args: {})
    result = analyze_runs(plan, runs)
    assert result["paired_effects"][0]["statistics"]["available"] is False


def test_analyze_runs_rejects_available_metric_without_value(monkeypatch):
    plan, runs = _analysis_stub_inputs(_Metric(available=True, value=None))
    monkeypatch.setattr(analysis_module, "_validate_schedule", lambda *_args: None)
    monkeypatch.setattr(analysis_module, "_group_statistics", lambda *_args: {})
    with pytest.raises(BenchmarkV3SchemaError, match="available_metric_missing_value"):
        analyze_runs(plan, runs)


def _schedule_plan(**changes):
    values = {
        "system_ids": ("left", "right"),
        "scenario_ids": ("scenario",),
        "fixture_seeds": {"scenario": (1,)},
        "track_id": "track",
        "require_run_plan_attestation": True,
        "digest": "digest",
        "publication_tier": "canary",
        "batches": 1,
        "hosts": 1,
    }
    values.update(changes)
    return SimpleNamespace(**values)


def _schedule_runs(**changes):
    runs = [
        SimpleNamespace(
            system_id=system_id,
            scenario_id="scenario",
            repetition=1,
            matched_fixture_seed=1,
            track_id="track",
            environment={
                "analysis_plan_digest": "digest",
                "batch_id": f"batch-{index}",
                "host_id": f"host-{index}",
            },
            fixture_variant_digest="variant",
        )
        for index, system_id in enumerate(("left", "right"), start=1)
    ]
    for index, values in changes.items():
        runs[int(index)] = SimpleNamespace(**{**vars(runs[int(index)]), **values})
    return tuple(runs)


def test_schedule_validation_rejects_each_mismatch():
    valid_plan = _schedule_plan()
    valid_runs = _schedule_runs()
    analysis_module._validate_schedule(valid_plan, valid_runs)

    invalid_cases = [
        ((valid_runs[0], valid_runs[0]), "duplicate_scheduled_run"),
        ((valid_runs[0],), "runs_do_not_match_frozen_schedule"),
        (_schedule_runs(**{"1": {"track_id": "other"}}), "run_track_differs"),
        (_schedule_runs(**{"1": {"environment": {}}}), "run_missing_analysis_plan_attestation"),
        (_schedule_runs(**{"1": {"fixture_variant_digest": "different"}}), "matched_seed_fixture_variant_mismatch"),
        (
            _schedule_runs(**{"0": {"fixture_variant_digest": ""}, "1": {"fixture_variant_digest": ""}}),
            "matched_seed_fixture_variant_mismatch",
        ),
    ]
    for runs, message in invalid_cases:
        with pytest.raises(BenchmarkV3SchemaError, match=message):
            analysis_module._validate_schedule(valid_plan, runs)

    analysis_module._validate_schedule(
        _schedule_plan(require_run_plan_attestation=False),
        _schedule_runs(**{"0": {"environment": {}}, "1": {"environment": {}}}),
    )


def test_full_schedule_requires_attested_batch_and_host_counts():
    runs = _schedule_runs()
    with pytest.raises(BenchmarkV3SchemaError, match="insufficient_attested_batches"):
        analysis_module._validate_schedule(_schedule_plan(publication_tier="full", batches=3, hosts=1), runs)
    same_host = _schedule_runs(
        **{
            "0": {"environment": {**runs[0].environment, "host_id": "same"}},
            "1": {"environment": {**runs[1].environment, "host_id": "same"}},
        }
    )
    with pytest.raises(BenchmarkV3SchemaError, match="insufficient_attested_hosts"):
        analysis_module._validate_schedule(_schedule_plan(publication_tier="full", batches=2, hosts=2), same_host)
    analysis_module._validate_schedule(_schedule_plan(publication_tier="full", batches=2, hosts=2), runs)


def test_sequence_deadline_round_and_stable_helpers():
    assert analysis_module._sequence([1]) is True
    assert analysis_module._sequence("x") is False
    assert analysis_module._sequence(b"x") is False
    assert analysis_module._sequence(bytearray(b"x")) is False
    assert analysis_module._deadline_key(1.5) == "1.5s"
    assert analysis_module._round(None) is None
    assert analysis_module._stable_small_int("stream") >= 0
