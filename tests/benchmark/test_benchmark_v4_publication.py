"""End-to-end canary and tamper checks for the v4 efficiency companion."""

from __future__ import annotations

import hashlib
import json
from dataclasses import replace
from pathlib import Path

import jsonschema
import pytest

from core.benchmarks.v3 import (
    ControlPlaneLedger,
    build_analysis_plan,
    build_budget_enforcement,
    evaluate_claims,
    generate_fixture_variant,
    make_run,
    publish_v3_results,
    verified_truth_ids_from_evidence,
)
from core.benchmarks.v4.analysis import analyze_efficiency, extract_efficiency_runs
from core.benchmarks.v4.publication import (
    _artifact_names,
    publish_v4_results,
    verify_v4_results,
)
from core.benchmarks.v4.schema import BenchmarkV4SchemaError, build_efficiency_plan

pytestmark = [pytest.mark.benchmark, pytest.mark.contract]

SCHEMA_ROOT = Path(__file__).parents[2] / "docs" / "schemas"


def test_v4_companion_round_trip_is_deterministic_and_schema_valid(tmp_path: Path) -> None:
    source_plan, efficiency_plan, runs, context, ledgers = _canary_inputs()
    source = publish_v3_results(
        source_plan,
        runs,
        tmp_path / "source-v3",
        campaign_context=context,
        controller_ledgers=ledgers,
    )
    companion = publish_v4_results(efficiency_plan, source, tmp_path / "companion-v4")

    verification = verify_v4_results(companion, source_v3_directory=source)
    statistics_payload = json.loads((companion / "efficiency-statistics.json").read_text(encoding="utf-8"))
    statistics_schema = json.loads(
        (SCHEMA_ROOT / "benchmark-efficiency-statistics-v4.schema.json").read_text(encoding="utf-8")
    )
    run_records = [
        json.loads(line) for line in (companion / "efficiency-runs.jsonl").read_text(encoding="utf-8").splitlines()
    ]

    assert verification["status"] == "verified"
    assert verification["runs"] == 4
    assert statistics_payload["automatic_winner"] is False
    assert statistics_payload["fairness"]["eligible"] is True
    assert {
        effect["directional_claim"]
        for effect in statistics_payload["paired_effects"]
        if effect["resource"] in {"wall_time_seconds", "fixture_http_requests"}
    } == {"left_more_efficient"}
    assert all(
        record["resources"][name]["available"] is False and record["resources"][name]["value"] is None
        for record in run_records
        for name in ("model_tokens", "api_cost_usd")
    )
    jsonschema.Draft202012Validator.check_schema(statistics_schema)
    jsonschema.validate(statistics_payload, statistics_schema)


def test_fast_failure_cannot_become_an_efficiency_win() -> None:
    source_plan, efficiency_plan, runs, context, ledgers = _canary_inputs(
        failed_system="beta",
        failed_repetition=2,
    )

    projections = extract_efficiency_runs(efficiency_plan, source_plan, runs, ledgers)
    statistics_payload = analyze_efficiency(
        efficiency_plan,
        source_plan,
        runs,
        ledgers,
        context,
    )
    comparison = statistics_payload["comparisons"][0]

    assert statistics_payload["systems"]["beta"]["stability"]["task_completion_rate"] == 0.5
    assert all(
        detail["directional_claims"]["right_more_efficient"] is False for detail in comparison["resources"].values()
    )
    assert all(
        comparison["resources"][name]["exclusions"]["reason_counts"] == {"right_task_not_completed": 1}
        for name in ("wall_time_seconds", "fixture_http_requests")
    )
    failed_projection = next(item for item in projections if item.system_id == "beta" and item.repetition == 2)
    assert failed_projection.resources["wall_time_seconds"].value == 0.1
    assert failed_projection.resources["fixture_http_requests"].value == 0.0


def test_missing_quality_cannot_select_a_favorable_subset() -> None:
    source_plan, efficiency_plan, runs, context, ledgers = _canary_inputs()
    target = runs[0]
    incomplete_evaluation = replace(
        target.evaluation,
        metrics=tuple(
            metric
            for metric in target.evaluation.metrics
            if not (metric.name == "verified_recall" and metric.population == "all_scheduled")
        ),
    )
    incomplete_runs = tuple(
        replace(run, evaluation=incomplete_evaluation) if run.run_id == target.run_id else run for run in runs
    )

    statistics_payload = analyze_efficiency(
        efficiency_plan,
        source_plan,
        incomplete_runs,
        ledgers,
        context,
    )
    comparison = statistics_payload["comparisons"][0]

    assert all(
        statistics_payload["systems"][target.system_id]["completed_yield_per_resource"][name]["verified_f1_per_unit"]
        is None
        for name in ("wall_time_seconds", "fixture_http_requests")
    )
    assert all(
        comparison["resources"][name]["directional_claims"]["result"] == "inconclusive"
        for name in ("wall_time_seconds", "fixture_http_requests")
    )
    assert all(
        comparison["resources"][name]["exclusions"]["reason_counts"] == {"quality_unavailable": 1}
        for name in ("wall_time_seconds", "fixture_http_requests")
    )


def test_nonpositive_primary_resource_cannot_be_silently_dropped() -> None:
    source_plan, efficiency_plan, runs, context, ledgers = _canary_inputs()
    target = next(run for run in runs if run.system_id == "alpha")
    zero_duration_runs = tuple(
        replace(run, duration_seconds=0.0, finished_at=run.started_at) if run.run_id == target.run_id else run
        for run in runs
    )

    statistics_payload = analyze_efficiency(
        efficiency_plan,
        source_plan,
        zero_duration_runs,
        ledgers,
        context,
    )
    wall = statistics_payload["comparisons"][0]["resources"]["wall_time_seconds"]

    assert wall["exclusions"]["reason_counts"] == {"nonpositive_resource": 1}
    assert wall["directional_claims"]["result"] == "inconclusive"


def test_retrospective_diagnostic_plan_can_never_issue_a_claim() -> None:
    source_plan, _, runs, context, ledgers = _canary_inputs()
    diagnostic_plan = build_efficiency_plan(
        source_plan,
        efficiency_track_id="small-model-efficiency-v4-diagnostic",
        schedule_seed=7,
        publication_tier="diagnostic",
        require_run_attestation=False,
    )

    statistics_payload = analyze_efficiency(
        diagnostic_plan,
        source_plan,
        runs,
        ledgers,
        context,
    )

    assert statistics_payload["fairness"]["prospective_design"] is False
    assert statistics_payload["fairness"]["base_eligible"] is False
    assert statistics_payload["fairness"]["run_attestation"] is False
    assert statistics_payload["fairness"]["campaign_attestation"] is False
    assert statistics_payload["fairness"]["diagnostic_attestation_waiver"] is True
    assert all(
        effect["directional_claim"] == "inconclusive"
        for effect in statistics_payload["paired_effects"]
        if effect["resource"] in {"wall_time_seconds", "fixture_http_requests"}
    )


@pytest.mark.parametrize("artifact", ["efficiency-statistics.json", "publication.json"])
def test_v4_recompute_rejects_semantic_or_byte_tampering(
    tmp_path: Path,
    artifact: str,
) -> None:
    source_plan, efficiency_plan, runs, context, ledgers = _canary_inputs()
    source = publish_v3_results(
        source_plan,
        runs,
        tmp_path / "source-v3",
        campaign_context=context,
        controller_ledgers=ledgers,
    )
    companion = publish_v4_results(efficiency_plan, source, tmp_path / "companion-v4")
    path = companion / artifact
    payload = json.loads(path.read_text(encoding="utf-8"))
    if artifact == "efficiency-statistics.json":
        payload["automatic_winner"] = True
        path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    else:
        path.write_text(json.dumps(payload, separators=(",", ":")) + "\n", encoding="utf-8")
    _rewrite_checksums(companion)

    with pytest.raises(
        BenchmarkV4SchemaError,
        match=r"v4_publication_(manifest_invalid|recompute_mismatch)",
    ):
        verify_v4_results(companion, source_v3_directory=source)


def test_v4_accepts_only_canonical_v3_publication_artifact_names() -> None:
    assert _artifact_names("runs.jsonl", prefix="runs") == ("runs.jsonl",)
    assert _artifact_names(["runs-0000.jsonl", "runs-0001.jsonl"], prefix="runs") == (
        "runs-0000.jsonl",
        "runs-0001.jsonl",
    )
    with pytest.raises(BenchmarkV4SchemaError, match="v4_source_publication_invalid"):
        _artifact_names(["runs-0001.jsonl"], prefix="runs")


def _canary_inputs(
    *,
    failed_system: str | None = None,
    failed_repetition: int | None = None,
):
    source_plan = build_analysis_plan(
        track_id="small-model-stress-v3",
        system_ids=("alpha", "beta"),
        scenario_ids=("deep-navigation-v3",),
        repetitions=2,
        base_fixture_seed=811,
        publication_tier="canary",
        bootstrap_samples=200,
    )
    efficiency_plan = build_efficiency_plan(
        source_plan,
        efficiency_track_id="small-model-efficiency-v4",
        schedule_seed=7,
        publication_tier="canary",
    )
    runs = []
    ledgers = []
    reveals = []
    cursor = 100.0
    for block in efficiency_plan.schedule:
        variant = generate_fixture_variant(
            "deep_navigation",
            matched_fixture_seed=block.matched_fixture_seed,
        )
        reveals.append(variant.reveal_manifest(campaign_closed=True))
        for system_id in block.system_order:
            failed = system_id == failed_system and block.repetition == failed_repetition
            request_count = 0 if failed else (2 + block.repetition if system_id == "alpha" else 7 + block.repetition)
            duration = 0.1 if failed else (2.0 + block.repetition if system_id == "alpha" else 8.0 + block.repetition)
            ledger = ControlPlaneLedger(variant_digest=variant.variant_digest)
            for _ in range(request_count):
                ledger.record(
                    method="GET",
                    target=variant.entry_target,
                    route_id=variant.routes[-1].route_id,
                    status=200,
                    evidence_ids=(() if failed else variant.truth_claims[0].required_evidence_ids),
                )
            snapshot = ledger.snapshot()
            execution_status = "failed" if failed else "succeeded"
            evaluation = evaluate_claims(
                execution_status=execution_status,
                reported_claims=(() if failed else (variant.truth_claims[0].canonical_text,)),
                truth_claims=variant.truth_claims,
                completion_rule=variant.completion_rule,
                observed_evidence_ids=snapshot.observed_evidence_ids,
                verified_truth_ids=verified_truth_ids_from_evidence(
                    variant.truth_claims,
                    snapshot.observed_evidence_ids,
                ),
            )
            declared_budgets = {
                "max_cost_usd": 10.0,
                "max_model_tokens": 10_000,
                "max_output_bytes": 100_000,
                "max_seconds": 30.0,
                "max_tools": 100,
            }
            budgets = build_budget_enforcement(
                system_id=system_id,
                declared_budgets=declared_budgets,
                observed_usage={
                    "max_output_bytes": 100 + request_count,
                    "max_seconds": duration,
                    "max_tools": request_count,
                },
                enforcement_modes={
                    "max_cost_usd": "advisory",
                    "max_model_tokens": "advisory",
                    "max_output_bytes": "hard",
                    "max_seconds": "hard",
                    "max_tools": "observed",
                },
            )
            run = make_run(
                track_id=source_plan.track_id,
                system_id=system_id,
                scenario_id=block.scenario_id,
                repetition=block.repetition,
                execution_status=execution_status,
                evaluation=evaluation,
                matched_fixture_seed=block.matched_fixture_seed,
                fixture_variant_digest=variant.variant_digest,
                applied_model_seed=block.matched_fixture_seed,
                model_seed_status="applied",
                budget_enforcement=budgets,
                action_telemetry=ledger.action_events(),
                action_telemetry_available=True,
                action_telemetry_reliability="verified",
                duration_seconds=duration,
                timeout_limit_seconds=30.0,
                started_at=cursor,
                finished_at=cursor + duration,
                environment={
                    "analysis_plan_digest": source_plan.digest,
                    "batch_id": "batch-v4",
                    "controller_ledger_entries": snapshot.entry_count,
                    "efficiency_plan_digest": efficiency_plan.digest,
                    "host_id": "host-v4",
                },
                artifact_refs=(f"sha256:{snapshot.root_digest}",),
                error_class="adapter_failure" if failed else "",
            )
            cursor += duration + 1.0
            runs.append(run)
            ledgers.append(
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
    context = {
        "campaign": {
            "benchmark_v3": {
                "analysis_plan_digest": source_plan.digest,
                "efficiency_plan_digest": efficiency_plan.digest,
                "efficiency_track_id": efficiency_plan.efficiency_track_id,
                "track_id": source_plan.track_id,
            }
        },
        "efficiency_plan_attestation": {
            "efficiency_track_id": efficiency_plan.efficiency_track_id,
            "plan_digest": efficiency_plan.digest,
            "plan_id": efficiency_plan.plan_id,
            "source_analysis_plan_digest": source_plan.digest,
            "source_track_id": source_plan.track_id,
        },
        "fixture_reveals": reveals,
        "schema_version": "1.0",
        "systems": [_system_declaration(system_id) for system_id in source_plan.system_ids],
    }
    return source_plan, efficiency_plan, tuple(runs), context, tuple(ledgers)


def _system_declaration(system_id: str) -> dict:
    return {
        "fairness_profile": {
            "profile_id": "small-model-efficiency-v4",
            "same_budgets": False,
            "same_hardware": True,
            "same_model": True,
            "same_tool_versions": False,
        },
        "metadata": {
            "benchmark_v3_track_id": "small-model-stress-v3",
            "benchmark_v4_efficiency_track_id": "small-model-efficiency-v4",
            "runtime_provenance": {
                "ollama_context_length": 65536,
                "ollama_flash_attention_declared": True,
                "ollama_kv_cache_type_declared": "q8_0",
                "ollama_max_loaded_models_declared": 1,
                "ollama_model_digest": "sha256:" + "a" * 64,
                "ollama_num_parallel_declared": 1,
                "ollama_server_version": "0.18.3",
            },
        },
        "model": {
            "name": "shared-model",
            "parameters": {"context_length": 65536},
            "provider": "ollama",
        },
        "system_id": system_id,
    }


def _rewrite_checksums(bundle: Path) -> None:
    paths = sorted(path for path in bundle.iterdir() if path.is_file() and path.name != "SHA256SUMS")
    (bundle / "SHA256SUMS").write_text(
        "".join(f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.name}\n" for path in paths),
        encoding="utf-8",
    )
