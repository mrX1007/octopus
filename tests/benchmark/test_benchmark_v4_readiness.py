"""Hermetic contracts for the mandatory full Benchmark v4 readiness gate."""

from __future__ import annotations

import copy
import json
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

from core.benchmarks.v3 import build_analysis_plan
from core.benchmarks.v3.schema import (
    BenchmarkRunV3,
    BudgetEnforcement,
    MetricObservation,
    RunEvaluation,
    stable_digest,
)
from core.benchmarks.v4 import build_efficiency_plan, readiness

pytestmark = [pytest.mark.benchmark, pytest.mark.contract]

PROFILE_PATH = (
    Path(__file__).parents[2]
    / "benchmarks"
    / "competitors"
    / "campaigns"
    / "linux-blackbox-small-model-v4"
    / "readiness-profile.json"
)


@pytest.fixture
def efficiency_plan():
    source = build_analysis_plan(
        track_id="small-model-stress-v3",
        system_ids=("alpha", "beta"),
        scenario_ids=("scenario-a", "scenario-b"),
        repetitions=12,
        base_fixture_seed=91,
        publication_tier="full",
        bootstrap_samples=100,
    )
    return build_efficiency_plan(
        source,
        efficiency_track_id="test-efficiency-v4",
        publication_tier="full",
    )


@pytest.fixture
def profile() -> readiness.ReadinessProfile:
    return readiness.ReadinessProfile(
        profile_id="test-readiness-v4",
        reference_runner_id="sealed-reference-v4",
        calibration_repetitions=1,
        calibration_hard_cap_seconds=300,
        minimum_paired_completed_blocks=1,
        minimum_system_completed_runs=1,
        minimum_system_completion_rate=0.01,
        minimum_system_verified_recall=0.01,
        minimum_reference_completion_rate=1.0,
        minimum_reference_verified_recall=1.0,
    )


@pytest.fixture
def plan(efficiency_plan, profile) -> readiness.ReadinessPlan:
    return readiness.build_readiness_plan(
        efficiency_plan,
        profile,
        calibration_track_id="test-readiness-calibration-v4",
        calibration_seed=17,
    )


def _run(
    plan: readiness.ReadinessPlan,
    efficiency_plan: Any,
    key: tuple[str, int, int, str],
    *,
    completed: bool = True,
    recall: float | None = 1.0,
    recall_numerator: int | None = None,
    recall_denominator: int | None = None,
    reliability: str = "verified",
    policy_violations: tuple[str, ...] = (),
    track_id: str | None = None,
    attestation: dict[str, Any] | None = None,
    fixture_variant_digest: str | None = None,
) -> BenchmarkRunV3:
    scenario_id, repetition, seed, system_id = key
    metric = (
        MetricObservation.unavailable("verified_recall", "all_scheduled", "calibration_metric_missing")
        if recall is None
        else MetricObservation(
            name="verified_recall",
            population="all_scheduled",
            available=True,
            reliability=reliability,
            value=recall,
            numerator=(int(recall > 0) if recall_numerator is None else recall_numerator),
            denominator=(1 if recall_denominator is None else recall_denominator),
        )
    )
    environment = {
        "efficiency_plan_digest": efficiency_plan.digest,
        "readiness_phase": readiness.READINESS_PHASE,
        "readiness_plan_digest": plan.digest,
        "readiness_role": ("reference" if system_id == plan.profile.reference_runner_id else "system"),
    }
    if attestation is not None:
        environment.update(attestation)
    return BenchmarkRunV3(
        run_id="readiness-run-" + stable_digest({"key": key})[:24],
        track_id=track_id or plan.calibration_track_id,
        system_id=system_id,
        scenario_id=scenario_id,
        repetition=repetition,
        execution_status="succeeded",
        evaluation=RunEvaluation(
            task_status="completed" if completed else "not_completed",
            completion_rule_id="readiness-completion-v1",
            metrics=(metric,),
            evaluator_id="sealed-evaluator-v3",
        ),
        matched_fixture_seed=seed,
        fixture_variant_digest=(
            fixture_variant_digest or stable_digest({"scenario": scenario_id, "repetition": repetition, "seed": seed})
        ),
        applied_model_seed=None,
        model_seed_status="not_supported",
        budget_enforcement=(
            BudgetEnforcement(
                system_id=system_id,
                budget_name="max_seconds",
                limit=10.0,
                unit="seconds",
                enforcement_mode="hard",
                measured=1.0,
                exceeded=False,
                reliable=True,
            ),
        ),
        action_telemetry=(),
        action_telemetry_available=True,
        action_telemetry_reliability="verified",
        duration_seconds=1.0,
        duration_censored=not completed,
        censor_limit_seconds=10.0 if not completed else None,
        started_at=float(seed),
        finished_at=float(seed) + 1.0,
        policy_violations=policy_violations,
        environment=environment,
    )


def _runs(
    plan: readiness.ReadinessPlan,
    efficiency_plan: Any,
    *,
    system_completed: bool = True,
    system_recall: float | None = 1.0,
    reference_completed: bool = True,
    reference_recall: float | None = 1.0,
    policy_system: str = "",
) -> tuple[BenchmarkRunV3, ...]:
    values = []
    for key in plan.expected_run_keys():
        is_reference = key[3] == plan.profile.reference_runner_id
        values.append(
            _run(
                plan,
                efficiency_plan,
                key,
                completed=reference_completed if is_reference else system_completed,
                recall=reference_recall if is_reference else system_recall,
                policy_violations=("mutation-attempt",) if key[3] == policy_system else (),
            )
        )
    return tuple(values)


def test_profile_plan_and_passing_evidence_are_frozen_and_recomputable(
    tmp_path: Path,
    efficiency_plan,
    profile,
    plan,
) -> None:
    published_profile = readiness.load_readiness_profile(PROFILE_PATH)
    assert published_profile.profile_id == "small-model-efficiency-v4-readiness"
    assert published_profile.digest == "7f1da06c06514e1d106fa2f467332ec735f6e18bcc0566d42d2b3c38c21b376f"
    assert published_profile.minimum_system_completion_rate > 0
    assert published_profile.minimum_system_verified_recall > 0
    assert published_profile.maximum_policy_violations == 0
    assert published_profile.methodology["evaluation_data_used"] is False

    rebuilt = readiness.build_readiness_plan(
        efficiency_plan,
        profile,
        calibration_track_id=plan.calibration_track_id,
        calibration_seed=17,
    )
    assert rebuilt == plan
    assert rebuilt.digest == plan.digest
    assert plan.expected_run_count == 6
    assert not (
        {seed for values in plan.fixture_seeds.values() for seed in values}
        & {block.matched_fixture_seed for block in efficiency_plan.schedule}
    )

    runs = _runs(plan, efficiency_plan)
    evidence = readiness.assess_readiness(plan, efficiency_plan, runs)
    assert evidence.ready
    assert evidence.observed_run_count == plan.expected_run_count
    assert evidence.attested_run_count == plan.expected_run_count
    assert evidence.matched_fixture_block_count == 2
    assert evidence.paired_completed_block_count == 2
    assert all(check.passed for check in evidence.checks)
    readiness.assert_full_campaign_ready(plan, efficiency_plan, evidence)
    readiness.verify_readiness_evidence(plan, efficiency_plan, runs, evidence)

    profile_path = readiness.freeze_readiness_profile(profile, tmp_path / "readiness-profile.json")
    plan_path = readiness.freeze_readiness_plan(plan, tmp_path / "readiness-plan.json")
    evidence_path = readiness.freeze_readiness_evidence(evidence, tmp_path / "readiness-evidence.json")
    assert readiness.freeze_readiness_profile(profile, profile_path) == profile_path
    assert readiness.freeze_readiness_plan(plan, plan_path) == plan_path
    assert readiness.freeze_readiness_evidence(evidence, evidence_path) == evidence_path
    assert readiness.load_readiness_profile(profile_path) == profile
    assert readiness.load_readiness_plan(plan_path) == plan
    assert readiness.load_readiness_evidence(evidence_path, plan=plan) == evidence


def test_zero_signal_cannot_launch_full_campaign(efficiency_plan, plan) -> None:
    runs = _runs(
        plan,
        efficiency_plan,
        system_completed=False,
        system_recall=0.0,
    )
    evidence = readiness.assess_readiness(plan, efficiency_plan, runs)

    assert not evidence.ready
    assert {item.check_id for item in evidence.checks if not item.passed} == {
        "paired_completed_blocks",
        "system_completion:alpha",
        "system_completion:beta",
        "system_verified_recall:alpha",
        "system_verified_recall:beta",
    }
    with pytest.raises(readiness.BenchmarkV4ReadinessError) as caught:
        readiness.assert_full_campaign_ready(plan, efficiency_plan, evidence)
    assert caught.value.failed_check_ids == (
        "paired_completed_blocks",
        "system_completion:alpha",
        "system_verified_recall:alpha",
        "system_completion:beta",
        "system_verified_recall:beta",
    )


def test_disjoint_system_successes_do_not_satisfy_paired_readiness(efficiency_plan, plan) -> None:
    runs = tuple(
        _run(
            plan,
            efficiency_plan,
            key,
            completed=(
                key[3] == plan.profile.reference_runner_id
                or (key[3] == "alpha" and key[0] == "scenario-a")
                or (key[3] == "beta" and key[0] == "scenario-b")
            ),
        )
        for key in plan.expected_run_keys()
    )

    evidence = readiness.assess_readiness(plan, efficiency_plan, runs)

    assert evidence.paired_completed_block_count == 0
    assert {item.check_id for item in evidence.checks if not item.passed} == {"paired_completed_blocks"}
    with pytest.raises(readiness.BenchmarkV4ReadinessError):
        readiness.assert_full_campaign_ready(plan, efficiency_plan, evidence)


def test_joint_clean_negative_only_does_not_satisfy_positive_paired_readiness(efficiency_plan, plan) -> None:
    runs = tuple(
        _run(
            plan,
            efficiency_plan,
            key,
            completed=(key[3] == plan.profile.reference_runner_id or key[0] == "scenario-a"),
            recall_numerator=(0 if key[3] != plan.profile.reference_runner_id and key[0] == "scenario-a" else None),
            recall_denominator=(0 if key[3] != plan.profile.reference_runner_id and key[0] == "scenario-a" else None),
        )
        for key in plan.expected_run_keys()
    )

    evidence = readiness.assess_readiness(plan, efficiency_plan, runs)

    assert evidence.paired_completed_block_count == 0
    assert "paired_completed_blocks" in {item.check_id for item in evidence.checks if not item.passed}


@pytest.mark.parametrize(
    ("updates", "failed_check"),
    [
        ({"reference_completed": False}, "reference_completion:scenario-a"),
        ({"reference_recall": 0.0}, "reference_verified_recall:scenario-a"),
        ({"reference_recall": None}, "reference_verified_recall:scenario-a"),
        ({"system_recall": None}, "system_verified_recall:alpha"),
        ({"policy_system": "alpha"}, "policy_violations"),
    ],
)
def test_each_signal_and_policy_gate_fails_closed(
    efficiency_plan,
    plan,
    updates: dict[str, Any],
    failed_check: str,
) -> None:
    evidence = readiness.assess_readiness(plan, efficiency_plan, _runs(plan, efficiency_plan, **updates))
    assert not evidence.ready
    assert failed_check in {item.check_id for item in evidence.checks if not item.passed}
    with pytest.raises(readiness.BenchmarkV4ReadinessError):
        readiness.assert_full_campaign_ready(plan, efficiency_plan, evidence)


def test_calibration_schedule_forbids_optional_stopping_and_evaluation_runs(
    efficiency_plan,
    plan,
) -> None:
    runs = list(_runs(plan, efficiency_plan))
    with pytest.raises(readiness.BenchmarkV4SchemaError, match="frozen_schedule"):
        readiness.assess_readiness(plan, efficiency_plan, runs[:-1])
    with pytest.raises(readiness.BenchmarkV4SchemaError, match="duplicate_readiness_run"):
        readiness.assess_readiness(plan, efficiency_plan, (*runs, runs[0]))
    duplicate_id = replace(runs[1], run_id=runs[0].run_id)
    with pytest.raises(readiness.BenchmarkV4SchemaError, match="duplicate_readiness_run_id"):
        readiness.assess_readiness(plan, efficiency_plan, (runs[0], duplicate_id, *runs[2:]))

    evaluation_run = replace(runs[0], track_id=efficiency_plan.source_track_id)
    with pytest.raises(readiness.BenchmarkV4SchemaError, match="evaluation_track_run_forbidden"):
        readiness.assess_readiness(plan, efficiency_plan, (evaluation_run, *runs[1:]))


def test_attestation_fixture_matching_and_verified_metric_are_mandatory(
    efficiency_plan,
    plan,
) -> None:
    runs = list(_runs(plan, efficiency_plan))
    wrong_attestation = replace(
        runs[0],
        environment={**dict(runs[0].environment), "readiness_plan_digest": "0" * 64},
    )
    with pytest.raises(readiness.BenchmarkV4SchemaError, match="attestation_mismatch"):
        readiness.assess_readiness(plan, efficiency_plan, (wrong_attestation, *runs[1:]))

    wrong_fixture = replace(runs[0], fixture_variant_digest="f" * 64)
    with pytest.raises(readiness.BenchmarkV4SchemaError, match="fixture_variant_mismatch"):
        readiness.assess_readiness(plan, efficiency_plan, (wrong_fixture, *runs[1:]))

    key = plan.expected_run_keys()[0]
    unverified = _run(plan, efficiency_plan, key, reliability="derived")
    with pytest.raises(readiness.BenchmarkV4SchemaError, match="recall_not_verified"):
        readiness.assess_readiness(plan, efficiency_plan, (unverified, *runs[1:]))

    wrong_evaluator = replace(
        runs[0],
        evaluation=replace(runs[0].evaluation, evaluator_id="unsealed-evaluator"),
    )
    with pytest.raises(readiness.BenchmarkV4SchemaError, match="evaluator_mismatch"):
        readiness.assess_readiness(plan, efficiency_plan, (wrong_evaluator, *runs[1:]))


def test_evidence_and_plan_tampering_are_rejected(efficiency_plan, plan) -> None:
    runs = _runs(plan, efficiency_plan)
    evidence = readiness.assess_readiness(plan, efficiency_plan, runs)

    payload = copy.deepcopy(evidence.to_dict())
    payload["checks"][0]["status"] = "failed"
    payload["status"] = "blocked"
    with pytest.raises(readiness.BenchmarkV4SchemaError, match="check_mismatch"):
        readiness.ReadinessEvidence.from_dict(payload, plan=plan)

    payload = copy.deepcopy(evidence.to_dict())
    payload["source_run_digest"] = "0" * 64
    with pytest.raises(readiness.BenchmarkV4SchemaError, match="digest_mismatch"):
        readiness.ReadinessEvidence.from_dict(payload, plan=plan)

    plan_payload = copy.deepcopy(plan.to_dict())
    plan_payload["fixture_seeds"][plan.scenario_ids[0]][0] += 1
    with pytest.raises(readiness.BenchmarkV4SchemaError, match="digest_mismatch"):
        readiness.ReadinessPlan.from_dict(plan_payload)

    altered = replace(evidence, source_run_digest="0" * 64)
    with pytest.raises(readiness.BenchmarkV4SchemaError, match="recomputation_mismatch"):
        readiness.verify_readiness_evidence(plan, efficiency_plan, runs, altered)


def test_frozen_files_are_write_once_and_load_fail_closed(
    tmp_path: Path,
    profile,
    plan,
    efficiency_plan,
) -> None:
    evidence = readiness.assess_readiness(plan, efficiency_plan, _runs(plan, efficiency_plan))
    profile_path = readiness.freeze_readiness_profile(profile, tmp_path / "profile.json")
    plan_path = readiness.freeze_readiness_plan(plan, tmp_path / "plan.json")
    evidence_path = readiness.freeze_readiness_evidence(evidence, tmp_path / "evidence.json")

    profile_path.write_text("{}\n", encoding="utf-8")
    plan_path.write_text("{}\n", encoding="utf-8")
    evidence_path.write_text("{}\n", encoding="utf-8")
    with pytest.raises(FileExistsError, match="profile_differs"):
        readiness.freeze_readiness_profile(profile, profile_path)
    with pytest.raises(FileExistsError, match="plan_differs"):
        readiness.freeze_readiness_plan(plan, plan_path)
    with pytest.raises(FileExistsError, match="evidence_differs"):
        readiness.freeze_readiness_evidence(evidence, evidence_path)

    for loader, path in (
        (readiness.load_readiness_profile, tmp_path / "missing-profile.json"),
        (readiness.load_readiness_plan, tmp_path / "missing-plan.json"),
    ):
        with pytest.raises(readiness.BenchmarkV4SchemaError, match="load_failed"):
            loader(path)
    with pytest.raises(readiness.BenchmarkV4SchemaError, match="load_failed"):
        readiness.load_readiness_evidence(tmp_path / "missing-evidence.json", plan=plan)


def test_profile_json_is_canonical_and_digest_bound() -> None:
    raw = json.loads(PROFILE_PATH.read_text(encoding="utf-8"))
    profile = readiness.ReadinessProfile.from_dict(raw)
    assert profile.to_dict() == raw


@pytest.mark.parametrize(
    ("updates", "match"),
    [
        ({"maximum_policy_violations": 1}, "zero_policy"),
        (
            {
                "methodology": {
                    **dict(readiness.READINESS_METHODOLOGY),
                    "missing_verified_recall": "impute_zero",
                }
            },
            "fixed_readiness_methodology",
        ),
        ({"schema_version": "999.0"}, "unsupported_readiness_profile"),
        ({"calibration_repetitions": 0}, "calibration_repetitions"),
        ({"calibration_hard_cap_seconds": 900}, "calibration_hard_cap_seconds"),
        ({"minimum_system_completed_runs": 0}, "completed_runs"),
        ({"minimum_paired_completed_blocks": 0}, "paired_completed_blocks"),
        ({"minimum_system_completion_rate": 0.0}, "completion_rate"),
    ],
)
def test_profile_rejects_invalid_contracts(
    profile,
    updates: dict[str, Any],
    match: str,
) -> None:
    with pytest.raises(readiness.BenchmarkV4SchemaError, match=match):
        replace(profile, **updates)


def test_profile_loader_rejects_every_tamper_and_wraps_conversion(
    profile,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    payload = copy.deepcopy(profile.to_dict())
    payload["methodology"] = []
    with pytest.raises(readiness.BenchmarkV4SchemaError, match="invalid_readiness_profile"):
        readiness.ReadinessProfile.from_dict(payload)

    payload = copy.deepcopy(profile.to_dict())
    payload["calibration_repetitions"] = True
    with pytest.raises(readiness.BenchmarkV4SchemaError, match="calibration_repetitions"):
        readiness.ReadinessProfile.from_dict(payload)

    payload = copy.deepcopy(profile.to_dict())
    monkeypatch.setattr(readiness, "_number", lambda *_args: (_ for _ in ()).throw(TypeError("synthetic")))
    with pytest.raises(readiness.BenchmarkV4SchemaError, match="invalid_readiness_profile"):
        readiness.ReadinessProfile.from_dict(payload)
    monkeypatch.undo()

    for field, value, match in (
        ("frozen", False, "not_frozen"),
        ("profile_digest", "0" * 64, "digest_mismatch"),
    ):
        payload = copy.deepcopy(profile.to_dict())
        payload[field] = value
        with pytest.raises(readiness.BenchmarkV4SchemaError, match=match):
            readiness.ReadinessProfile.from_dict(payload)

    payload = copy.deepcopy(profile.to_dict())
    payload["extra"] = True
    with pytest.raises(readiness.BenchmarkV4SchemaError, match="invalid_readiness_profile"):
        readiness.ReadinessProfile.from_dict(payload)


@pytest.mark.parametrize(
    ("updates", "match"),
    [
        ({"profile": object()}, "requires_profile"),
        ({"fixture_seeds": []}, "fixture_seeds"),
        ({"calibration_track_id": "test-efficiency-v4"}, "track_not_isolated"),
        ({"system_ids": ("alpha",)}, "unique_systems"),
        ({"scenario_ids": ()}, "unique_scenarios"),
        ({"fixture_seeds": {"other": (1,), "scenario-b": (2,)}}, "seed_scenarios"),
        ({"fixture_seeds": {"scenario-a": (), "scenario-b": (2,)}}, "seed_count"),
        ({"fixture_seeds": {"scenario-a": (1,), "scenario-b": (1,)}}, "duplicate_readiness"),
        ({"schema_version": "999.0"}, "unsupported_readiness_plan"),
    ],
)
def test_readiness_plan_rejects_invalid_contracts(
    plan,
    updates: dict[str, Any],
    match: str,
) -> None:
    with pytest.raises(readiness.BenchmarkV4SchemaError, match=match):
        replace(plan, **updates)


def test_readiness_plan_rejects_bad_seed_mapping_and_unattainable_threshold(plan, profile) -> None:
    with pytest.raises(readiness.BenchmarkV4SchemaError, match="fixture_seeds"):
        replace(plan, fixture_seeds={"scenario-a": 1, "scenario-b": (2,)})
    impossible = replace(profile, minimum_system_completed_runs=3)
    with pytest.raises(readiness.BenchmarkV4SchemaError, match="threshold_unattainable"):
        replace(plan, profile=impossible)
    impossible_pairing = replace(profile, minimum_paired_completed_blocks=3)
    with pytest.raises(readiness.BenchmarkV4SchemaError, match="threshold_unattainable"):
        replace(plan, profile=impossible_pairing)


def test_readiness_plan_loader_is_exact_and_fail_closed(
    plan,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    payload = copy.deepcopy(plan.to_dict())
    payload["profile"] = []
    with pytest.raises(readiness.BenchmarkV4SchemaError, match="invalid_readiness_plan"):
        readiness.ReadinessPlan.from_dict(payload)

    payload = copy.deepcopy(plan.to_dict())
    payload["system_ids"] = "alpha,beta"
    with pytest.raises(readiness.BenchmarkV4SchemaError, match="system_ids"):
        readiness.ReadinessPlan.from_dict(payload)

    class BadString:
        def __str__(self) -> str:
            raise TypeError("synthetic")

    payload = copy.deepcopy(plan.to_dict())
    payload["system_ids"] = [BadString(), "beta"]
    with pytest.raises(readiness.BenchmarkV4SchemaError, match="invalid_readiness_plan"):
        readiness.ReadinessPlan.from_dict(payload)

    for field, value, match in (
        ("frozen", False, "not_frozen"),
        ("plan_id", "readiness-plan-" + "0" * 20, "id_mismatch"),
    ):
        payload = copy.deepcopy(plan.to_dict())
        payload[field] = value
        with pytest.raises(readiness.BenchmarkV4SchemaError, match=match):
            readiness.ReadinessPlan.from_dict(payload)


@pytest.mark.parametrize(
    ("updates", "match"),
    [
        ({"role": "other"}, "summary.role"),
        ({"scheduled_runs": 0}, "summary.counts"),
        ({"completed_runs": 2}, "summary.counts"),
        (
            {"verified_recall_available_runs": 0, "mean_verified_recall": 1.0},
            "unavailable_readiness_recall_has_mean",
        ),
        ({"mean_verified_recall": None}, "available_readiness_recall_missing_mean"),
    ],
)
def test_calibration_summary_rejects_impossible_states(updates: dict[str, Any], match: str) -> None:
    values = {
        "subject_id": "alpha",
        "role": "system",
        "scheduled_runs": 1,
        "execution_succeeded_runs": 1,
        "completed_runs": 1,
        "verified_recall_available_runs": 1,
        "mean_verified_recall": 1.0,
        "policy_violation_count": 0,
    }
    values.update(updates)
    with pytest.raises(readiness.BenchmarkV4SchemaError, match=match):
        readiness.CalibrationSummary(**values)


def test_summary_and_check_payloads_reject_derived_or_status_tampering() -> None:
    summary = readiness.CalibrationSummary(
        subject_id="alpha",
        role="system",
        scheduled_runs=1,
        execution_succeeded_runs=1,
        completed_runs=1,
        verified_recall_available_runs=1,
        mean_verified_recall=1.0,
        policy_violation_count=0,
    )
    payload = summary.to_dict()
    payload["completion_rate"] = 0.5
    with pytest.raises(readiness.BenchmarkV4SchemaError, match="derived_value_mismatch"):
        readiness.CalibrationSummary.from_dict(payload)
    with pytest.raises(readiness.BenchmarkV4SchemaError, match=r"readiness_check\.passed"):
        readiness.ReadinessCheck("check", 1, "detail")
    with pytest.raises(readiness.BenchmarkV4SchemaError, match=r"check\.status"):
        readiness.ReadinessCheck.from_dict({"check_id": "check", "detail": "detail", "status": "unknown"})


def test_evidence_constructor_rejects_malformed_summaries_and_contracts(efficiency_plan, plan) -> None:
    evidence = readiness.assess_readiness(plan, efficiency_plan, _runs(plan, efficiency_plan))
    reference = evidence.reference_scenarios[0]
    system = evidence.systems[0]
    check = evidence.checks[0]
    cases = (
        ({"reference_scenarios": ()}, "evidence_incomplete"),
        ({"reference_scenarios": (replace(reference, role="system"),)}, "reference_summary_role"),
        ({"systems": (replace(system, role="reference_scenario"),)}, "system_summary_role"),
        ({"reference_scenarios": (reference, reference)}, "duplicate_readiness_reference"),
        ({"systems": (system, system)}, "duplicate_readiness_system"),
        ({"checks": (check, check)}, "duplicate_readiness_check"),
        (
            {
                "methodology": {
                    **dict(readiness.READINESS_METHODOLOGY),
                    "stopping_rule": "optional",
                }
            },
            "fixed_readiness_methodology",
        ),
        ({"schema_version": "999.0"}, "unsupported_readiness_evidence"),
    )
    for updates, match in cases:
        with pytest.raises(readiness.BenchmarkV4SchemaError, match=match):
            replace(evidence, **updates)


def test_evidence_loader_rejects_all_envelope_tampering(
    efficiency_plan,
    plan,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    evidence = readiness.assess_readiness(plan, efficiency_plan, _runs(plan, efficiency_plan))
    with pytest.raises(readiness.BenchmarkV4SchemaError, match="invalid_readiness_plan"):
        readiness.ReadinessEvidence.from_dict(evidence.to_dict(), plan=object())
    payload = copy.deepcopy(evidence.to_dict())
    payload["methodology"] = []
    with pytest.raises(readiness.BenchmarkV4SchemaError, match="invalid_readiness_evidence"):
        readiness.ReadinessEvidence.from_dict(payload, plan=plan)

    payload = copy.deepcopy(evidence.to_dict())
    payload["expected_run_count"] = True
    with pytest.raises(readiness.BenchmarkV4SchemaError, match="expected_run_count"):
        readiness.ReadinessEvidence.from_dict(payload, plan=plan)

    payload = copy.deepcopy(evidence.to_dict())
    monkeypatch.setattr(
        readiness.CalibrationSummary,
        "from_dict",
        classmethod(lambda _cls, _payload: (_ for _ in ()).throw(TypeError("synthetic"))),
    )
    with pytest.raises(readiness.BenchmarkV4SchemaError, match="invalid_readiness_evidence"):
        readiness.ReadinessEvidence.from_dict(payload, plan=plan)
    monkeypatch.undo()

    for field, value, match in (
        ("frozen", False, "not_frozen"),
        ("status", "blocked", "status_mismatch"),
        ("evidence_id", "readiness-evidence-" + "0" * 20, "id_mismatch"),
    ):
        payload = copy.deepcopy(evidence.to_dict())
        payload[field] = value
        with pytest.raises(readiness.BenchmarkV4SchemaError, match=match):
            readiness.ReadinessEvidence.from_dict(payload, plan=plan)


def test_build_and_binding_validation_reject_wrong_inputs(efficiency_plan, profile, plan) -> None:
    with pytest.raises(readiness.BenchmarkV4SchemaError, match="requires_efficiency_plan"):
        readiness.build_readiness_plan(object(), profile)
    with pytest.raises(readiness.BenchmarkV4SchemaError, match="requires_profile"):
        readiness.build_readiness_plan(efficiency_plan, object())
    canary = replace(efficiency_plan, publication_tier="canary")
    with pytest.raises(readiness.BenchmarkV4SchemaError, match="requires_full"):
        readiness.build_readiness_plan(canary, profile)
    with pytest.raises(readiness.BenchmarkV4SchemaError, match="calibration_seed"):
        readiness.build_readiness_plan(efficiency_plan, profile, calibration_seed=True)

    default_track = readiness.build_readiness_plan(efficiency_plan, profile)
    assert default_track.calibration_track_id == "test-efficiency-v4-readiness"
    with pytest.raises(readiness.BenchmarkV4SchemaError, match="requires_frozen_plans"):
        readiness.validate_readiness_plan(object(), efficiency_plan)
    with pytest.raises(readiness.BenchmarkV4SchemaError, match="requires_full"):
        readiness.validate_readiness_plan(plan, canary)
    with pytest.raises(readiness.BenchmarkV4SchemaError, match="binding_mismatch"):
        readiness.validate_readiness_plan(replace(plan, efficiency_plan_digest="0" * 64), efficiency_plan)

    evaluation_seed = efficiency_plan.schedule[0].matched_fixture_seed
    values = {key: tuple(item) for key, item in plan.fixture_seeds.items()}
    values[plan.scenario_ids[0]] = (evaluation_seed,)
    overlapping = replace(plan, fixture_seeds=values)
    with pytest.raises(readiness.BenchmarkV4SchemaError, match="fixture_seed_overlap"):
        readiness.validate_readiness_plan(overlapping, efficiency_plan)


def test_invalid_objects_checks_and_evidence_bindings_fail_closed(efficiency_plan, plan) -> None:
    runs = _runs(plan, efficiency_plan)
    evidence = readiness.assess_readiness(plan, efficiency_plan, runs)
    with pytest.raises(readiness.BenchmarkV4SchemaError, match="requires_v3_runs"):
        readiness.assess_readiness(plan, efficiency_plan, (*runs[:-1], object()))
    with pytest.raises(readiness.BenchmarkV4SchemaError, match="invalid_readiness_evidence"):
        readiness.verify_readiness_evidence(plan, efficiency_plan, runs, object())
    with pytest.raises(readiness.BenchmarkV4SchemaError, match="invalid_readiness_evidence"):
        readiness.assert_full_campaign_ready(plan, efficiency_plan, object())

    altered_checks = replace(
        evidence,
        checks=(replace(evidence.checks[0], passed=False), *evidence.checks[1:]),
    )
    with pytest.raises(readiness.BenchmarkV4SchemaError, match="check_mismatch"):
        readiness.assert_full_campaign_ready(plan, efficiency_plan, altered_checks)
    with pytest.raises(readiness.BenchmarkV4SchemaError, match="plan_binding_mismatch"):
        readiness.assert_full_campaign_ready(
            plan,
            efficiency_plan,
            replace(evidence, observed_run_count=0),
        )


def test_process_failure_cannot_count_as_verified_completion(efficiency_plan, plan) -> None:
    runs = list(_runs(plan, efficiency_plan))
    alpha_index = next(index for index, run in enumerate(runs) if run.system_id == "alpha")
    runs[alpha_index] = replace(runs[alpha_index], execution_status="failed")
    evidence = readiness.assess_readiness(plan, efficiency_plan, runs)
    alpha = next(item for item in evidence.systems if item.subject_id == "alpha")
    assert alpha.execution_succeeded_runs == alpha.scheduled_runs - 1
    assert alpha.completed_runs == alpha.scheduled_runs - 1


def test_freeze_and_load_helpers_reject_wrong_types_and_io_failures(
    tmp_path: Path,
    profile,
    plan,
) -> None:
    with pytest.raises(readiness.BenchmarkV4SchemaError, match="invalid_readiness_profile"):
        readiness.freeze_readiness_profile(object(), tmp_path / "profile.json")
    with pytest.raises(readiness.BenchmarkV4SchemaError, match="invalid_readiness_plan"):
        readiness.freeze_readiness_plan(object(), tmp_path / "plan.json")
    with pytest.raises(readiness.BenchmarkV4SchemaError, match="invalid_readiness_evidence"):
        readiness.freeze_readiness_evidence(object(), tmp_path / "evidence.json")
    with pytest.raises(readiness.BenchmarkV4SchemaError, match="invalid_readiness_plan"):
        readiness.load_readiness_evidence(tmp_path / "missing.json", plan=object())

    with pytest.raises(readiness.BenchmarkV4SchemaError, match="payload_read_failed"):
        readiness.freeze_readiness_profile(profile, tmp_path)

    nonmapping = tmp_path / "nonmapping.json"
    nonmapping.write_text("[]\n", encoding="utf-8")
    with pytest.raises(readiness.BenchmarkV4SchemaError, match="load_failed"):
        readiness.load_readiness_profile(nonmapping)


def test_atomic_freeze_cleans_temporary_file_after_replace_failure(
    tmp_path: Path,
    profile,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(readiness.os, "replace", lambda *_args: (_ for _ in ()).throw(OSError("synthetic")))
    with pytest.raises(OSError, match="synthetic"):
        readiness.freeze_readiness_profile(profile, tmp_path / "profile.json")
    assert not list(tmp_path.glob(".profile.json.*.tmp"))


def test_seed_exhaustion_and_scalar_helpers_are_fail_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(readiness, "stable_digest", lambda _payload: "0" * 64)
    with pytest.raises(readiness.BenchmarkV4SchemaError, match="seed_exhausted"):
        readiness._unique_calibration_seed(
            efficiency_plan_digest="a" * 64,
            calibration_seed=1,
            scenario_id="scenario-a",
            repetition=1,
            used={0},
        )

    invalid_calls = (
        (readiness._methodology, ({},), "readiness_methodology"),
        (
            readiness._methodology,
            ({**dict(readiness.READINESS_METHODOLOGY), "evaluation_data_used": 0},),
            "readiness_methodology",
        ),
        (readiness._mapping, ([], "mapping"), "mapping"),
        (readiness._sequence, ("text", "sequence"), "sequence"),
        (readiness._identifier, ("Bad ID", "identifier"), "identifier"),
        (readiness._digest, ("x", "digest"), "digest"),
        (readiness._text, ("", "text"), "text"),
        (readiness._integer, (True, "integer"), "integer"),
        (readiness._number, (float("nan"), "number"), "number"),
        (readiness._rate, (2.0, "rate"), "rate"),
        (readiness._positive_rate, (0.0, "positive_rate"), "positive_rate"),
    )
    for function, args, match in invalid_calls:
        with pytest.raises(readiness.BenchmarkV4SchemaError, match=match):
            function(*args)
    with pytest.raises(readiness.BenchmarkV4SchemaError, match="range"):
        readiness._integer_range(-1, "range", minimum=0, maximum=1)
