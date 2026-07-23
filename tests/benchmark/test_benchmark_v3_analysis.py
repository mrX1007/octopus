from __future__ import annotations

import hashlib
import json
from pathlib import Path

import jsonschema
import pytest

from core.benchmarks.v3 import (
    BenchmarkRunV3,
    BenchmarkV3SchemaError,
    ControlPlaneLedger,
    TrackIsolationError,
    analyze_runs,
    build_analysis_plan,
    build_budget_enforcement,
    evaluate_claims,
    freeze_analysis_plan,
    generate_fixture_variant,
    kaplan_meier,
    load_analysis_plan,
    make_run,
    paired_bootstrap,
    publish_v3_results,
    render_run_records,
    render_runs_csv,
    render_statistics_svg,
    validate_single_track,
    verified_truth_ids_from_evidence,
    verify_v3_results,
    wilson_interval,
)

pytestmark = [pytest.mark.benchmark, pytest.mark.contract]


def test_wilson_paired_bootstrap_and_censored_duration_are_deterministic() -> None:
    interval = wilson_interval(5, 10)
    assert interval["estimate"] == 0.5
    assert interval["lower"] == pytest.approx(0.236593091)
    assert interval["upper"] == pytest.approx(0.763406909)

    pairs = [(0.2, 0.4), (0.4, 0.7), (0.6, 0.8)]
    first = paired_bootstrap(pairs, samples=500, seed=17)
    second = paired_bootstrap(pairs, samples=500, seed=17)
    assert first == second
    assert first["effect_right_minus_left"] == pytest.approx(0.233333333)

    survival = kaplan_meier([(2.0, False), (5.0, True), (8.0, False)], horizon_seconds=10)
    assert survival["completion_events"] == 2
    assert survival["median_completion_seconds"] == 8.0
    assert survival["restricted_mean_completion_seconds"] == pytest.approx(6.0)


def test_tracks_cannot_merge_into_one_leaderboard() -> None:
    with pytest.raises(TrackIsolationError, match="mixed_tracks_forbidden"):
        validate_single_track(["small-model-stress-v3", "vendor-native-v1"])


def test_frozen_plan_detects_byte_different_replacement(tmp_path: Path) -> None:
    plan = build_analysis_plan(
        track_id="small-model-stress-v3",
        system_ids=["alpha", "beta"],
        scenario_ids=["deep-navigation-v3"],
        repetitions=2,
        base_fixture_seed=9,
        publication_tier="canary",
        bootstrap_samples=100,
    )
    path = freeze_analysis_plan(plan, tmp_path / "analysis-plan.json")
    assert load_analysis_plan(path) == plan
    path.write_text("{}\n", encoding="utf-8")

    with pytest.raises(FileExistsError, match="differs"):
        freeze_analysis_plan(plan, path)


def test_analysis_and_publication_are_complete_and_byte_stable(tmp_path: Path) -> None:
    plan = build_analysis_plan(
        track_id="small-model-stress-v3",
        system_ids=["alpha", "beta"],
        scenario_ids=["deep-navigation-v3"],
        repetitions=2,
        base_fixture_seed=91,
        publication_tier="canary",
        bootstrap_samples=200,
        deadlines_seconds=(5.0, 10.0),
    )
    runs, campaign_context, controller_ledgers = _canary_inputs(plan)

    statistics = analyze_runs(plan, runs)
    assert statistics["run_count"] == 4
    assert statistics["leaderboard_contract"]["mixed_tracks"] == "forbidden"
    assert statistics["systems"]["alpha"]["overall"]["task_outcomes"]["counts"] == {"completed": 2}
    assert statistics["systems"]["beta"]["overall"]["task_outcomes"]["counts"] == {
        "completed": 1,
        "partial": 1,
    }

    first = publish_v3_results(
        plan,
        runs,
        tmp_path / "publication-one",
        campaign_context=campaign_context,
        controller_ledgers=controller_ledgers,
    )
    second = publish_v3_results(
        plan,
        runs,
        tmp_path / "publication-two",
        campaign_context=campaign_context,
        controller_ledgers=controller_ledgers,
    )
    expected_files = {
        "SHA256SUMS",
        "analysis-plan.json",
        "campaign-context.json",
        "comparison.svg",
        "ledgers.jsonl",
        "publication.json",
        "runs.csv",
        "runs.jsonl",
        "statistics.json",
    }
    assert {item.name for item in first.iterdir()} == expected_files
    assert verify_v3_results(first)["runs"] == 4
    for name in expected_files:
        assert (first / name).read_bytes() == (second / name).read_bytes()
    svg = (first / "comparison.svg").read_text(encoding="utf-8")
    for panel_id in (
        "execution-outcomes",
        "task-outcomes",
        "verified-recall",
        "censored-completion-time",
    ):
        assert f'id="{panel_id}"' in svg
    assert "<script" not in svg
    csv_text = (first / "runs.csv").read_text(encoding="utf-8")
    assert "all_scheduled.verified_recall.value" in csv_text.splitlines()[0]
    assert len(csv_text.splitlines()) == 5
    statistics_schema = json.loads(
        (Path(__file__).resolve().parents[2] / "docs" / "schemas" / "benchmark-statistics-v3.schema.json").read_text(
            encoding="utf-8"
        )
    )
    jsonschema.validate(statistics, statistics_schema)


def test_verifier_rejects_rechecksummed_evaluation_tamper(tmp_path: Path) -> None:
    plan = build_analysis_plan(
        track_id="small-model-stress-v3",
        system_ids=["alpha", "beta"],
        scenario_ids=["deep-navigation-v3"],
        repetitions=2,
        base_fixture_seed=97,
        publication_tier="canary",
        bootstrap_samples=100,
    )
    runs, campaign_context, controller_ledgers = _canary_inputs(plan)
    bundle = publish_v3_results(
        plan,
        runs,
        tmp_path / "tampered-publication",
        campaign_context=campaign_context,
        controller_ledgers=controller_ledgers,
    )
    payloads = [run.to_dict() for run in runs]
    payloads[0]["evaluation"]["task_status"] = "not_completed"
    tampered_runs = tuple(BenchmarkRunV3.from_dict(item) for item in payloads)
    (bundle / "runs.jsonl").write_text(
        render_run_records(tampered_runs),
        encoding="utf-8",
    )
    (bundle / "runs.csv").write_text(
        render_runs_csv(plan, tampered_runs),
        encoding="utf-8",
    )
    tampered_statistics = analyze_runs(plan, tampered_runs)
    (bundle / "statistics.json").write_text(
        json.dumps(
            tampered_statistics,
            indent=2,
            sort_keys=True,
            ensure_ascii=False,
            allow_nan=False,
        )
        + "\n",
        encoding="utf-8",
    )
    (bundle / "comparison.svg").write_text(
        render_statistics_svg(plan, tampered_statistics),
        encoding="utf-8",
    )
    checksum_paths = sorted(
        path
        for path in bundle.iterdir()
        if path.is_file() and path.name != "SHA256SUMS"
    )
    (bundle / "SHA256SUMS").write_text(
        "".join(
            f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.name}\n"
            for path in checksum_paths
        ),
        encoding="utf-8",
    )

    with pytest.raises(BenchmarkV3SchemaError, match="v3_run_evaluation_mismatch"):
        verify_v3_results(bundle)


def _canary_inputs(plan):
    runs = []
    controller_ledgers = []
    reveals = []
    scenario_id = plan.scenario_ids[0]
    for repetition, seed in enumerate(plan.fixture_seeds[scenario_id], start=1):
        variant = generate_fixture_variant("deep_navigation", matched_fixture_seed=seed)
        reveals.append(variant.reveal_manifest(campaign_closed=True))
        for system_id in plan.system_ids:
            ledger = ControlPlaneLedger(variant_digest=variant.variant_digest)
            ledger.record(
                method="GET",
                target=variant.entry_target,
                route_id=variant.routes[-1].route_id,
                status=200,
                evidence_ids=variant.truth_claims[0].required_evidence_ids,
            )
            snapshot = ledger.snapshot()
            reported = [variant.truth_claims[0].canonical_text]
            if system_id == "beta" and repetition == 2:
                reported.append("invented beta-only service")
            evaluation = evaluate_claims(
                execution_status="succeeded",
                reported_claims=reported,
                truth_claims=variant.truth_claims,
                completion_rule=variant.completion_rule,
                observed_evidence_ids=variant.truth_claims[0].required_evidence_ids,
                verified_truth_ids=verified_truth_ids_from_evidence(
                    variant.truth_claims,
                    snapshot.observed_evidence_ids,
                ),
            )
            budgets = {"max_output_bytes": 1000, "max_seconds": 10, "max_tools": 5}
            enforcement = build_budget_enforcement(
                system_id=system_id,
                declared_budgets=budgets,
                observed_usage={
                    "max_output_bytes": 200,
                    "max_seconds": 2 + repetition,
                    "max_tools": 2,
                },
                enforcement_modes={
                    "max_output_bytes": "hard",
                    "max_seconds": "hard",
                    "max_tools": "observed",
                },
            )
            runs.append(
                make_run(
                    track_id=plan.track_id,
                    system_id=system_id,
                    scenario_id=scenario_id,
                    repetition=repetition,
                    execution_status="succeeded",
                    evaluation=evaluation,
                    matched_fixture_seed=seed,
                    fixture_variant_digest=variant.variant_digest,
                    applied_model_seed=seed,
                    model_seed_status="applied",
                    budget_enforcement=enforcement,
                    action_telemetry=ledger.action_events(),
                    action_telemetry_available=True,
                    action_telemetry_reliability="verified",
                    duration_seconds=float(2 + repetition),
                    timeout_limit_seconds=10,
                    started_at=float(repetition * 10),
                    finished_at=float(repetition * 10 + 2 + repetition),
                    environment={
                        "analysis_plan_digest": plan.digest,
                        "batch_id": "batch-one",
                        "controller_ledger_entries": snapshot.entry_count,
                        "host_id": "host-one",
                    },
                    artifact_refs=(f"sha256:{snapshot.root_digest}",),
                )
            )
            run = runs[-1]
            controller_ledgers.append(
                {
                    "entries": [item.to_dict() for item in ledger.entries()],
                    "fixture_variant_digest": run.fixture_variant_digest,
                    "ledger_root_digest": snapshot.root_digest,
                    "matched_fixture_seed": run.matched_fixture_seed,
                    "repetition": run.repetition,
                    "run_id": run.run_id,
                    "scenario_id": run.scenario_id,
                    "schema_version": "1.0",
                    "system_id": run.system_id,
                }
            )
    campaign_context = {
        "campaign": {
            "benchmark_v3": {
                "analysis_plan_digest": plan.digest,
                "track_id": plan.track_id,
            }
        },
        "fixture_reveals": reveals,
        "schema_version": "1.0",
    }
    return tuple(runs), campaign_context, tuple(controller_ledgers)
