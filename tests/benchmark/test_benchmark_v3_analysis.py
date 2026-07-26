from __future__ import annotations

import hashlib
import json
from pathlib import Path

import jsonschema
import pytest

import core.benchmarks.v3.publication as publication_module
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
    repack_v3_results,
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
        "ledgers-0000.jsonl",
        "publication.json",
        "runs.csv",
        "runs-0000.jsonl",
        "statistics.json",
    }
    assert {item.name for item in first.iterdir()} == expected_files
    assert verify_v3_results(first)["runs"] == 4
    publication = json.loads((first / "publication.json").read_text(encoding="utf-8"))
    assert publication["schema_version"] == "1.1"
    assert publication["artifacts"]["run_records"] == ["runs-0000.jsonl"]
    assert publication["artifacts"]["controller_ledgers"] == ["ledgers-0000.jsonl"]
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


def test_publication_shards_large_jsonl_artifacts_deterministically(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    plan = build_analysis_plan(
        track_id="small-model-stress-v3",
        system_ids=["alpha", "beta"],
        scenario_ids=["deep-navigation-v3"],
        repetitions=2,
        base_fixture_seed=93,
        publication_tier="canary",
        bootstrap_samples=100,
    )
    runs, campaign_context, controller_ledgers = _canary_inputs(
        plan,
        ledger_entries=8,
    )
    largest_record = max(
        *(len((publication_module.canonical_json(run.to_dict()) + "\n").encode("utf-8")) for run in runs),
        *(len((publication_module.canonical_json(record) + "\n").encode("utf-8")) for record in controller_ledgers),
    )
    monkeypatch.setattr(
        publication_module,
        "_MAX_JSONL_SHARD_BYTES",
        largest_record + 1,
    )

    first = publish_v3_results(
        plan,
        runs,
        tmp_path / "sharded-one",
        campaign_context=campaign_context,
        controller_ledgers=controller_ledgers,
    )
    second = publish_v3_results(
        plan,
        runs,
        tmp_path / "sharded-two",
        campaign_context=campaign_context,
        controller_ledgers=controller_ledgers,
    )
    manifest = json.loads((first / "publication.json").read_text(encoding="utf-8"))
    run_names = manifest["artifacts"]["run_records"]
    ledger_names = manifest["artifacts"]["controller_ledgers"]

    assert len(run_names) > 1
    assert len(ledger_names) > 1
    assert all((first / name).stat().st_size <= largest_record + 1 for name in (*run_names, *ledger_names))
    assert verify_v3_results(first)["runs"] == 4
    assert {path.name: path.read_bytes() for path in first.iterdir()} == {
        path.name: path.read_bytes() for path in second.iterdir()
    }


def test_verifier_accepts_legacy_single_files_and_repack_shards_them(
    tmp_path: Path,
) -> None:
    plan = build_analysis_plan(
        track_id="small-model-stress-v3",
        system_ids=["alpha", "beta"],
        scenario_ids=["deep-navigation-v3"],
        repetitions=2,
        base_fixture_seed=95,
        publication_tier="canary",
        bootstrap_samples=100,
    )
    runs, campaign_context, controller_ledgers = _canary_inputs(plan)
    legacy = publish_v3_results(
        plan,
        runs,
        tmp_path / "legacy-publication",
        campaign_context=campaign_context,
        controller_ledgers=controller_ledgers,
    )
    manifest = json.loads((legacy / "publication.json").read_text(encoding="utf-8"))
    for artifact, legacy_name in (
        ("run_records", "runs.jsonl"),
        ("controller_ledgers", "ledgers.jsonl"),
    ):
        shard_names = manifest["artifacts"][artifact]
        (legacy / legacy_name).write_bytes(b"".join((legacy / name).read_bytes() for name in shard_names))
        for name in shard_names:
            (legacy / name).unlink()
        manifest["artifacts"][artifact] = legacy_name
    manifest["schema_version"] = "1.0"
    legacy_ledgers = [json.loads(line) for line in (legacy / "ledgers.jsonl").read_text(encoding="utf-8").splitlines()]
    (legacy / "ledgers.jsonl").write_text(
        "".join(json.dumps(item, ensure_ascii=False, sort_keys=False) + "\n" for item in reversed(legacy_ledgers)),
        encoding="utf-8",
    )
    (legacy / "publication.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    _rewrite_checksums(legacy)

    assert verify_v3_results(legacy)["runs"] == 4
    repacked = repack_v3_results(legacy, tmp_path / "repacked-publication")
    assert verify_v3_results(repacked)["runs"] == 4
    repacked_manifest = json.loads((repacked / "publication.json").read_text(encoding="utf-8"))
    assert repacked_manifest["schema_version"] == "1.1"
    assert repacked_manifest["artifacts"]["run_records"] == ["runs-0000.jsonl"]
    assert repacked_manifest["artifacts"]["controller_ledgers"] == ["ledgers-0000.jsonl"]
    repacked_ledger_lines = (repacked / "ledgers-0000.jsonl").read_text(encoding="utf-8").splitlines()
    assert [json.loads(line)["run_id"] for line in repacked_ledger_lines] == sorted(
        item["run_id"] for item in legacy_ledgers
    )
    assert all(line == publication_module.canonical_json(json.loads(line)) for line in repacked_ledger_lines)


def test_verifier_rejects_reordered_rechecksummed_ledger_shard(
    tmp_path: Path,
) -> None:
    plan = build_analysis_plan(
        track_id="small-model-stress-v3",
        system_ids=["alpha", "beta"],
        scenario_ids=["deep-navigation-v3"],
        repetitions=2,
        base_fixture_seed=96,
        publication_tier="canary",
        bootstrap_samples=100,
    )
    runs, campaign_context, controller_ledgers = _canary_inputs(plan)
    bundle = publish_v3_results(
        plan,
        runs,
        tmp_path / "reordered-ledgers",
        campaign_context=campaign_context,
        controller_ledgers=controller_ledgers,
    )
    manifest = json.loads((bundle / "publication.json").read_text(encoding="utf-8"))
    ledger_names = manifest["artifacts"]["controller_ledgers"]
    assert ledger_names == ["ledgers-0000.jsonl"]
    ledger_path = bundle / ledger_names[0]
    lines = ledger_path.read_text(encoding="utf-8").splitlines()
    ledger_path.write_text("\n".join(reversed(lines)) + "\n", encoding="utf-8")
    _rewrite_checksums(bundle)

    with pytest.raises(
        BenchmarkV3SchemaError,
        match="v3_publication_controller_ledgers_mismatch",
    ):
        verify_v3_results(bundle)


def test_streaming_verifier_rejects_action_ledger_projection_mismatch(
    tmp_path: Path,
) -> None:
    plan = build_analysis_plan(
        track_id="small-model-stress-v3",
        system_ids=["alpha", "beta"],
        scenario_ids=["deep-navigation-v3"],
        repetitions=2,
        base_fixture_seed=98,
        publication_tier="canary",
        bootstrap_samples=100,
    )
    runs, campaign_context, controller_ledgers = _canary_inputs(plan)
    bundle = publish_v3_results(
        plan,
        runs,
        tmp_path / "telemetry-mismatch",
        campaign_context=campaign_context,
        controller_ledgers=controller_ledgers,
    )
    publication = json.loads((bundle / "publication.json").read_text(encoding="utf-8"))
    run_path = bundle / publication["artifacts"]["run_records"][0]
    payloads = [json.loads(line) for line in run_path.read_text(encoding="utf-8").splitlines()]
    payloads[0]["action_telemetry"][0]["method"] = "POST"
    run_path.write_text(
        "".join(publication_module.canonical_json(item) + "\n" for item in payloads),
        encoding="utf-8",
    )
    _rewrite_checksums(bundle)

    with pytest.raises(BenchmarkV3SchemaError, match="v3_public_ledger_telemetry_mismatch"):
        verify_v3_results(bundle)


@pytest.mark.parametrize("tamper_target", ["run", "action"])
def test_streaming_verifier_rejects_noncanonical_numeric_types(
    tmp_path: Path,
    tamper_target: str,
) -> None:
    plan = build_analysis_plan(
        track_id="small-model-stress-v3",
        system_ids=["alpha", "beta"],
        scenario_ids=["deep-navigation-v3"],
        repetitions=2,
        base_fixture_seed=101,
        publication_tier="canary",
        bootstrap_samples=100,
    )
    runs, campaign_context, controller_ledgers = _canary_inputs(plan)
    bundle = publish_v3_results(
        plan,
        runs,
        tmp_path / f"noncanonical-{tamper_target}",
        campaign_context=campaign_context,
        controller_ledgers=controller_ledgers,
    )
    publication = json.loads((bundle / "publication.json").read_text(encoding="utf-8"))
    run_path = bundle / publication["artifacts"]["run_records"][0]
    payloads = [json.loads(line) for line in run_path.read_text(encoding="utf-8").splitlines()]
    if tamper_target == "run":
        assert payloads[0]["duration_seconds"] == 3.0
        payloads[0]["duration_seconds"] = 3
    else:
        assert payloads[0]["action_telemetry"][0]["started_offset_seconds"] is None
        payloads[0]["action_telemetry"][0]["started_offset_seconds"] = 0
    run_path.write_text(
        "".join(publication_module.canonical_json(item) + "\n" for item in payloads),
        encoding="utf-8",
    )
    _rewrite_checksums(bundle)

    with pytest.raises(BenchmarkV3SchemaError, match="v3_publication_run_records_mismatch"):
        verify_v3_results(bundle)


def test_streaming_verifier_rejects_null_action_telemetry(tmp_path: Path) -> None:
    plan = build_analysis_plan(
        track_id="small-model-stress-v3",
        system_ids=["alpha", "beta"],
        scenario_ids=["deep-navigation-v3"],
        repetitions=2,
        base_fixture_seed=102,
        publication_tier="canary",
        bootstrap_samples=100,
    )
    runs, campaign_context, controller_ledgers = _canary_inputs(plan)
    bundle = publish_v3_results(
        plan,
        runs,
        tmp_path / "null-action-telemetry",
        campaign_context=campaign_context,
        controller_ledgers=controller_ledgers,
    )
    publication = json.loads((bundle / "publication.json").read_text(encoding="utf-8"))
    run_path = bundle / publication["artifacts"]["run_records"][0]
    payloads = [json.loads(line) for line in run_path.read_text(encoding="utf-8").splitlines()]
    payloads[0]["action_telemetry"] = None
    run_path.write_text(
        "".join(publication_module.canonical_json(item) + "\n" for item in payloads),
        encoding="utf-8",
    )
    _rewrite_checksums(bundle)

    with pytest.raises(BenchmarkV3SchemaError, match="invalid:run_telemetry"):
        verify_v3_results(bundle)


def test_streaming_verifier_rejects_premature_run_shard_boundary(
    tmp_path: Path,
) -> None:
    plan = build_analysis_plan(
        track_id="small-model-stress-v3",
        system_ids=["alpha", "beta"],
        scenario_ids=["deep-navigation-v3"],
        repetitions=2,
        base_fixture_seed=99,
        publication_tier="canary",
        bootstrap_samples=100,
    )
    runs, campaign_context, controller_ledgers = _canary_inputs(plan)
    bundle = publish_v3_results(
        plan,
        runs,
        tmp_path / "premature-shard",
        campaign_context=campaign_context,
        controller_ledgers=controller_ledgers,
    )
    publication = json.loads((bundle / "publication.json").read_text(encoding="utf-8"))
    original_name = publication["artifacts"]["run_records"][0]
    lines = (bundle / original_name).read_bytes().splitlines(keepends=True)
    assert len(lines) == 4
    (bundle / "runs-0000.jsonl").write_bytes(b"".join(lines[:2]))
    (bundle / "runs-0001.jsonl").write_bytes(b"".join(lines[2:]))
    publication["artifacts"]["run_records"] = ["runs-0000.jsonl", "runs-0001.jsonl"]
    (bundle / "publication.json").write_text(
        json.dumps(publication, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    _rewrite_checksums(bundle)

    with pytest.raises(BenchmarkV3SchemaError, match="v3_publication_run_records_mismatch"):
        verify_v3_results(bundle)


def test_verify_and_repack_do_not_use_eager_jsonl_loaders(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    plan = build_analysis_plan(
        track_id="small-model-stress-v3",
        system_ids=["alpha", "beta"],
        scenario_ids=["deep-navigation-v3"],
        repetitions=2,
        base_fixture_seed=100,
        publication_tier="canary",
        bootstrap_samples=100,
    )
    runs, campaign_context, controller_ledgers = _canary_inputs(plan)
    bundle = publish_v3_results(
        plan,
        runs,
        tmp_path / "streaming-source",
        campaign_context=campaign_context,
        controller_ledgers=controller_ledgers,
    )

    def fail_eager_load(*_args, **_kwargs):
        raise AssertionError("eager JSONL loader must not be used")

    monkeypatch.setattr(publication_module, "_load_run_records", fail_eager_load, raising=False)
    monkeypatch.setattr(publication_module, "_load_jsonl_mappings", fail_eager_load, raising=False)

    assert verify_v3_results(bundle)["runs"] == 4
    repacked = repack_v3_results(bundle, tmp_path / "streaming-repacked")
    assert verify_v3_results(repacked)["runs"] == 4


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
    publication = json.loads((bundle / "publication.json").read_text(encoding="utf-8"))
    run_record_names = publication["artifacts"]["run_records"]
    assert run_record_names == ["runs-0000.jsonl"]
    (bundle / run_record_names[0]).write_text(
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
    _rewrite_checksums(bundle)

    with pytest.raises(BenchmarkV3SchemaError, match="v3_run_evaluation_mismatch"):
        verify_v3_results(bundle)


def test_publication_layout_guards_reject_invalid_contracts(monkeypatch: pytest.MonkeyPatch) -> None:
    artifacts = {
        "analysis_plan": "analysis-plan.json",
        "campaign_context": "campaign-context.json",
        "runs": "runs.csv",
        "statistics": "statistics.json",
        "visualization": "comparison.svg",
        "run_records": ["runs-0000.jsonl"],
        "controller_ledgers": ["ledgers-0000.jsonl"],
    }

    with pytest.raises(BenchmarkV3SchemaError, match="v3_publication_contract_mismatch"):
        publication_module._validated_publication_artifacts({}, {})
    with pytest.raises(BenchmarkV3SchemaError, match="v3_publication_contract_mismatch"):
        publication_module._validated_publication_artifacts({"schema_version": 1}, artifacts)
    with pytest.raises(BenchmarkV3SchemaError, match="v3_publication_contract_mismatch"):
        publication_module._validated_publication_artifacts({"schema_version": "1.0"}, artifacts)
    with pytest.raises(BenchmarkV3SchemaError, match="v3_publication_contract_mismatch"):
        publication_module._validated_publication_artifacts({"schema_version": "9.9"}, artifacts)

    for invalid_names in ("runs-0000.jsonl", [], [1], ["runs-0001.jsonl"]):
        with pytest.raises(BenchmarkV3SchemaError, match="v3_publication_contract_mismatch"):
            publication_module._validated_shard_names(invalid_names, prefix="runs")

    with pytest.raises(BenchmarkV3SchemaError, match="invalid_v3_publication_jsonl"):
        tuple(publication_module._iter_jsonl_shards(prefix="runs", records=({"bad": object()},)))

    monkeypatch.setattr(publication_module, "_MAX_JSONL_SHARD_BYTES", 1)
    with pytest.raises(BenchmarkV3SchemaError, match="v3_publication_jsonl_record_too_large"):
        tuple(publication_module._iter_jsonl_shards(prefix="runs", records=({"ok": "value"},)))

    monkeypatch.setattr(publication_module, "_MAX_JSONL_SHARD_BYTES", 1_000)
    monkeypatch.setattr(publication_module, "_MAX_JSONL_ARTIFACT_BYTES", 1)
    with pytest.raises(BenchmarkV3SchemaError, match="v3_publication_jsonl_too_large"):
        tuple(publication_module._iter_jsonl_shards(prefix="runs", records=({"ok": "value"},)))

    monkeypatch.setattr(publication_module, "_MAX_JSONL_ARTIFACT_BYTES", 1_000)
    with pytest.raises(BenchmarkV3SchemaError, match="invalid_v3_publication_jsonl"):
        tuple(publication_module._iter_jsonl_shards(prefix="runs", records=()))


def _rewrite_checksums(bundle: Path) -> None:
    checksum_paths = sorted(path for path in bundle.iterdir() if path.is_file() and path.name != "SHA256SUMS")
    (bundle / "SHA256SUMS").write_text(
        "".join(f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.name}\n" for path in checksum_paths),
        encoding="utf-8",
    )


def _canary_inputs(plan, *, ledger_entries=1):
    runs = []
    controller_ledgers = []
    reveals = []
    scenario_id = plan.scenario_ids[0]
    for repetition, seed in enumerate(plan.fixture_seeds[scenario_id], start=1):
        variant = generate_fixture_variant("deep_navigation", matched_fixture_seed=seed)
        reveals.append(variant.reveal_manifest(campaign_closed=True))
        for system_id in plan.system_ids:
            ledger = ControlPlaneLedger(variant_digest=variant.variant_digest)
            for _ in range(ledger_entries):
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
