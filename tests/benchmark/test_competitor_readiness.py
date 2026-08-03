"""Execution lifecycle contracts for the private v4 readiness calibration."""

from __future__ import annotations

import json
import os
import stat
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any

import pytest

from core.benchmarks.competitors import campaign, launch, readiness
from core.benchmarks.competitors.lab import LabRunContext, ResetAttestation
from core.benchmarks.competitors.state import CampaignFingerprintMismatch
from core.benchmarks.v3.schema import (
    BenchmarkRunV3,
    BudgetEnforcement,
    MetricObservation,
    RunEvaluation,
    stable_digest,
)
from core.benchmarks.v4.readiness import load_readiness_evidence

pytestmark = [pytest.mark.benchmark, pytest.mark.contract]


def _environment() -> dict[str, str]:
    model = launch._SMALL_MODEL_CAMPAIGN_OLLAMA_MODEL
    return {
        "OCTOBENCH_ACK_AUTHORIZED": "YES",
        "OCTOBENCH_ACK_ISOLATED_HOST": "YES",
        "OCTOPUS_OLLAMA_URL": "http://127.0.0.1:11434/api/generate",
        "OCTOPUS_OLLAMA_MODEL": model,
        "OCTOBENCH_OLLAMA_CONTEXT_LENGTH": "65536",
        "OCTOBENCH_OLLAMA_SERVER_VERSION": "0.18.3",
        "OCTOBENCH_OLLAMA_NUM_PARALLEL": "1",
        "OCTOBENCH_OLLAMA_MAX_LOADED_MODELS": "1",
        "OCTOBENCH_OLLAMA_FLASH_ATTENTION": "1",
        "OCTOBENCH_OLLAMA_KV_CACHE_TYPE": "q8_0",
        "OCTOBENCH_STRIX_BIN": "/opt/strix/bin/strix",
        "STRIX_IMAGE": launch._STRIX_IMAGE,
        "STRIX_LLM": f"ollama/{model}",
        "LLM_API_BASE": "http://127.0.0.1:11434",
        "OCTOBENCH_V3_BASE_FIXTURE_SEED": "9a" * 32,
        "OCTOBENCH_V3_BATCH_ID": "readiness-batch",
        "OCTOBENCH_V3_HOST_ID": "readiness-host",
    }


def _prepared_config(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, campaign_id: str):
    monkeypatch.setattr(launch, "ROOT", tmp_path)
    definition = launch._CAMPAIGN_DEFINITIONS[launch._SMALL_MODEL_CAMPAIGN_V4_DEFINITION_ID]
    path = launch._prepare_generated_campaign(
        campaign_id,
        profile="core",
        environment=_environment(),
        environment_file=None,
        octopus_revision="c" * 40,
        campaign_definition=definition,
    )
    return campaign.load_campaign_config(path)


@dataclass
class _RecordingLab:
    fail_first_reset: bool = False
    reset_command_sha256: str = "a" * 64
    health_command_sha256: str = "b" * 64

    def __post_init__(self) -> None:
        self.resets: list[LabRunContext] = []
        self.cleanups: list[LabRunContext] = []

    def reset_and_health(self, context: LabRunContext) -> ResetAttestation:
        self.resets.append(context)
        if self.fail_first_reset and len(self.resets) == 1:
            raise RuntimeError("reset failed")
        return ResetAttestation(
            context=context,
            reset_duration_seconds=0.1,
            health_duration_seconds=0.1,
            reset_command_sha256=self.reset_command_sha256,
            health_command_sha256=self.health_command_sha256,
            observed_at=1.0,
        )

    def cleanup(self, context: LabRunContext) -> None:
        self.cleanups.append(context)


def _passing_v3_run(**kwargs: Any) -> BenchmarkRunV3:
    plan = kwargs["plan"]
    system_id = str(kwargs["system_id"])
    scenario = kwargs["scenario"]
    repetition = int(kwargs["repetition"])
    seed = int(kwargs["seed"])
    recall = MetricObservation(
        name="verified_recall",
        population="all_scheduled",
        available=True,
        reliability="verified",
        value=1.0,
        numerator=1,
        denominator=1,
    )
    return BenchmarkRunV3(
        run_id="calibration-run-"
        + stable_digest(
            {
                "scenario": scenario.scenario_id,
                "repetition": repetition,
                "seed": seed,
                "system": system_id,
            }
        )[:24],
        track_id=plan.track_id,
        system_id=system_id,
        scenario_id=scenario.scenario_id,
        repetition=repetition,
        execution_status="succeeded",
        evaluation=RunEvaluation(
            task_status="completed",
            completion_rule_id="readiness-completion-v1",
            metrics=(recall,),
            evaluator_id="sealed-evaluator-v3",
        ),
        matched_fixture_seed=seed,
        fixture_variant_digest=stable_digest(
            {"scenario": scenario.scenario_id, "repetition": repetition, "seed": seed}
        ),
        applied_model_seed=None,
        model_seed_status="not_supported",
        budget_enforcement=(
            BudgetEnforcement(
                system_id=system_id,
                budget_name="max_seconds",
                limit=float(scenario.budgets["max_seconds"]),
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
        duration_censored=False,
        censor_limit_seconds=None,
        started_at=float(kwargs["started_at"]),
        finished_at=float(kwargs["finished_at"]),
        environment={
            "analysis_plan_digest": plan.digest,
            "reset_attestation": dict(kwargs["reset_attestation"]),
        },
    )


def _install_passing_execution(monkeypatch: pytest.MonkeyPatch):
    factory_ids: list[str] = []
    product_calls: list[tuple[str, str, int, int, float]] = []
    reference_calls: list[tuple[str, str, int, int]] = []

    def factory(manifest):
        factory_ids.append(manifest.system_id)

        def run(scenario, repetition, seed):
            product_calls.append(
                (
                    manifest.system_id,
                    scenario.scenario_id,
                    repetition,
                    seed,
                    float(scenario.budgets["max_seconds"]),
                )
            )
            return {"status": "succeeded", "duration_seconds": 1.0}

        return run

    def reference_result(_v3_config, context, _environment, **_kwargs):
        reference_calls.append((context.system_id, context.scenario_id, context.repetition, context.seed))
        return {"status": "succeeded", "duration_seconds": 1.0}

    monkeypatch.setattr(readiness, "build_v3_run", _passing_v3_run)
    monkeypatch.setattr(readiness, "_reference_result", reference_result)
    return factory, factory_ids, product_calls, reference_calls


def test_calibration_runs_exact_frozen_schedule_and_full_gate_recomputes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = _prepared_config(tmp_path, monkeypatch, "readiness-exact")
    readiness_config = config.benchmark_v4_readiness
    assert readiness_config is not None
    plan = readiness_config.plan()
    factory, factory_ids, product_calls, reference_calls = _install_passing_execution(monkeypatch)
    lab = _RecordingLab(
        reset_command_sha256=readiness._command_digest(config.reset_command),
        health_command_sha256=readiness._command_digest(config.health_command),
    )

    evidence_path = readiness.run_readiness_calibration(
        config,
        environment=_environment(),
        runner_factory=factory,
        lab_controller=lab,
        clock=lambda: 10.0,
        monotonic=lambda: 1.0,
    )

    assert plan.expected_run_count == 36
    assert factory_ids == ["octopus", "strix"]
    assert len(product_calls) == 24
    assert len(reference_calls) == 12
    assert len(lab.resets) == 36
    assert [(item.scenario_id, item.repetition, item.seed, item.system_id) for item in lab.resets] == list(
        plan.expected_run_keys()
    )
    assert {item[4] for item in product_calls} == {float(plan.profile.calibration_hard_cap_seconds)}
    assert all(item[0] == plan.profile.reference_runner_id for item in reference_calls)
    assert stat.S_IMODE(evidence_path.stat().st_mode) == 0o600
    evidence = load_readiness_evidence(evidence_path, plan=plan)
    assert evidence.ready
    assert evidence.paired_completed_block_count == 12
    assert (
        readiness.require_full_campaign_readiness(
            config,
            manifests=tuple(readiness._calibration_manifests(config, plan)),
            scenarios=tuple(readiness._calibration_scenarios(config, plan)),
            efficiency_plan=config.benchmark_v3.efficiency_plan(),
            environment=_environment(),
        )
        == evidence
    )

    raw_files = sorted((readiness_config.journal_directory / config.campaign_id / "runs").glob("*.json"))
    assert len(raw_files) == 36
    raw_files[0].unlink()
    with pytest.raises(readiness.ReadinessCalibrationError, match="readiness_calibration_incomplete"):
        readiness.require_full_campaign_readiness(
            config,
            manifests=readiness._calibration_manifests(config, plan),
            scenarios=readiness._calibration_scenarios(config, plan),
            efficiency_plan=config.benchmark_v3.efficiency_plan(),
            environment=_environment(),
        )


def test_interrupted_calibration_cannot_retry_or_substitute(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = _prepared_config(tmp_path, monkeypatch, "readiness-no-retry")
    factory, factory_ids, product_calls, reference_calls = _install_passing_execution(monkeypatch)
    failed_lab = _RecordingLab(fail_first_reset=True)
    with pytest.raises(RuntimeError, match="reset failed"):
        readiness.run_readiness_calibration(
            config,
            environment=_environment(),
            runner_factory=factory,
            lab_controller=failed_lab,
        )
    factory_count_after_interruption = len(factory_ids)

    second_lab = _RecordingLab()
    with pytest.raises(readiness.ReadinessCalibrationError, match="readiness_calibration_retry_forbidden"):
        readiness.run_readiness_calibration(
            config,
            environment=_environment(),
            runner_factory=factory,
            lab_controller=second_lab,
        )
    assert len(factory_ids) == factory_count_after_interruption == 2
    assert product_calls == []
    assert reference_calls == []
    assert second_lab.resets == []


def test_calibration_does_not_freeze_semantically_invalid_reset_attestations(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = _prepared_config(tmp_path, monkeypatch, "readiness-invalid-reset")
    factory, *_unused = _install_passing_execution(monkeypatch)

    with pytest.raises(readiness.ReadinessCalibrationError, match="readiness_reset_attestation_invalid"):
        readiness.run_readiness_calibration(
            config,
            environment=_environment(),
            runner_factory=factory,
            lab_controller=_RecordingLab(),
            clock=lambda: 10.0,
            monotonic=lambda: 1.0,
        )

    assert not config.benchmark_v4_readiness.evidence_path.exists()


def test_full_gate_rejects_reset_run_and_cleanup_attestation_mutations(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = _prepared_config(tmp_path, monkeypatch, "readiness-attestation-mutations")
    readiness_config = config.benchmark_v4_readiness
    assert readiness_config is not None
    plan = readiness_config.plan()
    factory, *_unused = _install_passing_execution(monkeypatch)
    readiness.run_readiness_calibration(
        config,
        environment=_environment(),
        runner_factory=factory,
        lab_controller=_RecordingLab(
            reset_command_sha256=readiness._command_digest(config.reset_command),
            health_command_sha256=readiness._command_digest(config.health_command),
        ),
        clock=lambda: 10.0,
        monotonic=lambda: 1.0,
    )
    root = readiness_config.journal_directory / config.campaign_id
    reset_path = sorted((root / "attestations").glob("*.json"))[0]
    run_path = root / "runs" / reset_path.name
    cleanup_path = root / "cleanup.json"
    gate_kwargs = {
        "manifests": readiness._calibration_manifests(config, plan),
        "scenarios": readiness._calibration_scenarios(config, plan),
        "efficiency_plan": config.benchmark_v3.efficiency_plan(),
        "environment": _environment(),
    }
    calibration_kwargs = {
        "environment": _environment(),
        "runner_factory": factory,
        "lab_controller": _RecordingLab(),
        "clock": lambda: 10.0,
        "monotonic": lambda: 1.0,
    }

    def rejects(path: Path, mutate: Any, error: str) -> None:
        original = path.read_bytes()
        payload = json.loads(original)
        mutate(payload)
        path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        try:
            with pytest.raises(readiness.ReadinessCalibrationError, match=error):
                readiness.run_readiness_calibration(config, **calibration_kwargs)
            with pytest.raises(readiness.ReadinessCalibrationError, match=error):
                readiness.require_full_campaign_readiness(config, **gate_kwargs)
        finally:
            path.write_bytes(original)

    rejects(
        reset_path,
        lambda payload: payload.__setitem__("reset_command_sha256", "0" * 64),
        "readiness_reset_attestation_invalid",
    )
    rejects(
        reset_path,
        lambda payload: payload.__setitem__("seed", int(payload["seed"]) + 1),
        "readiness_reset_attestation_invalid",
    )
    rejects(
        reset_path,
        lambda payload: payload.__setitem__("repetition", True),
        "readiness_reset_attestation_invalid",
    )
    rejects(
        run_path,
        lambda payload: payload["benchmark_v3"]["environment"]["reset_attestation"].__setitem__("status", "failed"),
        "readiness_reset_attestation_run_mismatch",
    )
    rejects(
        cleanup_path,
        lambda payload: payload.__setitem__("scenario_id", "wrong-final-scenario"),
        "readiness_cleanup_attestation_invalid",
    )
    rejects(
        cleanup_path,
        lambda payload: payload.__setitem__("cleanup_command_sha256", "0" * 64),
        "readiness_cleanup_attestation_invalid",
    )

    material = readiness.require_full_campaign_readiness_material(config, **gate_kwargs)
    assert material.evidence.ready
    assert set(material.public_attestation) == {
        "campaign_id",
        "cleanup_attestation_digest",
        "evidence_digest",
        "plan_digest",
        "profile_digest",
        "reset_attestation_set_digest",
        "source_run_digest",
        "status",
    }
    assert material.public_attestation["status"] == "ready"

    changed_environment = _environment()
    changed_environment["OCTOPUS_OLLAMA_MODEL"] = "different-model"
    with pytest.raises(CampaignFingerprintMismatch, match="campaign_fingerprint_mismatch"):
        readiness.require_full_campaign_readiness(
            config,
            **{**gate_kwargs, "environment": changed_environment},
        )

    changed_config = replace(
        config,
        reset_command=replace(
            config.reset_command,
            timeout_seconds=config.reset_command.timeout_seconds + 1.0,
        ),
    )
    with pytest.raises(CampaignFingerprintMismatch, match="campaign_fingerprint_mismatch"):
        readiness.require_full_campaign_readiness(changed_config, **gate_kwargs)


def test_direct_full_campaign_without_calibration_aborts_before_adapter_or_reset(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = _prepared_config(tmp_path, monkeypatch, "readiness-direct-gate")
    factory_calls: list[str] = []
    lab = _RecordingLab()

    def factory(manifest):
        factory_calls.append(manifest.system_id)
        raise AssertionError("evaluation adapter must not be constructed")

    with pytest.raises(readiness.ReadinessCalibrationError, match="readiness_journal_not_private"):
        campaign.run_campaign(
            config,
            environment=_environment(),
            runner_factory=factory,
            lab_controller=lab,
        )
    assert factory_calls == []
    assert lab.resets == []
    assert not config.output_directory.exists()
    assert not config.state_directory.exists()


def test_raw_calibration_records_are_owner_only(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    config = _prepared_config(tmp_path, monkeypatch, "readiness-private")
    factory, *_unused = _install_passing_execution(monkeypatch)
    readiness.run_readiness_calibration(
        config,
        environment=_environment(),
        runner_factory=factory,
        lab_controller=_RecordingLab(
            reset_command_sha256=readiness._command_digest(config.reset_command),
            health_command_sha256=readiness._command_digest(config.health_command),
        ),
        clock=lambda: 10.0,
        monotonic=lambda: 1.0,
    )
    readiness_config = config.benchmark_v4_readiness
    assert readiness_config is not None
    root = readiness_config.journal_directory / config.campaign_id
    for directory in (
        readiness_config.journal_directory,
        root,
        root / "runs",
        root / "attempts",
        root / "attestations",
    ):
        assert stat.S_IMODE(os.lstat(directory).st_mode) == 0o700
    for path in root.rglob("*.json"):
        assert stat.S_IMODE(os.lstat(path).st_mode) == 0o600


def test_blocked_calibration_freezes_evidence_before_failing(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = _prepared_config(tmp_path, monkeypatch, "readiness-blocked")
    factory, *_unused = _install_passing_execution(monkeypatch)

    def blocked_run(**kwargs: Any) -> BenchmarkRunV3:
        run = _passing_v3_run(**kwargs)
        if run.system_id == config.benchmark_v4_readiness.plan().profile.reference_runner_id:
            return run
        return replace(run, evaluation=replace(run.evaluation, task_status="not_completed"))

    monkeypatch.setattr(readiness, "build_v3_run", blocked_run)
    with pytest.raises(readiness.BenchmarkV4ReadinessError):
        readiness.run_readiness_calibration(
            config,
            environment=_environment(),
            runner_factory=factory,
            lab_controller=_RecordingLab(
                reset_command_sha256=readiness._command_digest(config.reset_command),
                health_command_sha256=readiness._command_digest(config.health_command),
            ),
            clock=lambda: 10.0,
            monotonic=lambda: 1.0,
        )

    evidence_path = config.benchmark_v4_readiness.evidence_path
    payload = json.loads(evidence_path.read_text(encoding="utf-8"))
    assert payload["status"] == "blocked"
    assert stat.S_IMODE(evidence_path.stat().st_mode) == 0o600
