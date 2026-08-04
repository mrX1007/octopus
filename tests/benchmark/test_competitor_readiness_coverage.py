"""Hermetic branch coverage for the private v4 readiness lifecycle."""

from __future__ import annotations

import io
import json
import urllib.error
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from core.benchmarks import schema as benchmark_schema
from core.benchmarks.competitors import readiness
from core.benchmarks.competitors import schema as competitor_schema
from core.benchmarks.competitors.lab import LabRunContext
from core.benchmarks.competitors.state import CampaignJournal
from tests.benchmark import test_competitor_readiness as fixtures

pytestmark = [pytest.mark.benchmark, pytest.mark.contract]


def _raises(error: BaseException):
    def raise_error(*_args: Any, **_kwargs: Any) -> Any:
        raise error

    return raise_error


def _inputs(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    campaign_id: str,
):
    config = fixtures._prepared_config(tmp_path, monkeypatch, campaign_id)
    readiness_config = config.benchmark_v4_readiness
    v3_config = config.benchmark_v3
    assert readiness_config is not None
    assert v3_config is not None
    plan = readiness_config.plan()
    efficiency_plan = v3_config.efficiency_plan()
    assert efficiency_plan is not None
    manifests = readiness._calibration_manifests(config, plan)
    scenarios = readiness._calibration_scenarios(config, plan)
    return config, readiness_config, v3_config, plan, efficiency_plan, manifests, scenarios


def _passing_lab(config: Any) -> fixtures._RecordingLab:
    return fixtures._RecordingLab(
        reset_command_sha256=readiness._command_digest(config.reset_command),
        health_command_sha256=readiness._command_digest(config.health_command),
    )


def _run_passing_calibration(
    config: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> Any:
    factory, *_unused = fixtures._install_passing_execution(monkeypatch)
    return readiness.run_readiness_calibration(
        config,
        environment=fixtures._environment(),
        runner_factory=factory,
        lab_controller=_passing_lab(config),
        clock=lambda: 10.0,
        monotonic=lambda: 1.0,
    )


def _rewrite_json(path: Path, mutate: Any) -> bytes:
    original = path.read_bytes()
    payload = json.loads(original)
    mutate(payload)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return original


def _restore_private(path: Path, payload: bytes) -> None:
    path.write_bytes(payload)
    path.chmod(0o600)


def test_readiness_config_protocol_and_path_contracts(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    context = SimpleNamespace()
    assert readiness.LabController.reset_and_health(object(), context) is None
    assert readiness.LabController.cleanup(object(), context) is None

    valid = {
        "schema_version": "1.0",
        "profile": "profile.json",
        "plan": "plan.json",
        "evidence": "journal/campaign/readiness-evidence.json",
        "journal_directory": "journal",
    }
    with pytest.raises(readiness.ReadinessCalibrationError, match="unsupported_readiness_campaign_config_schema"):
        readiness.ReadinessCampaignConfig.from_dict({**valid, "schema_version": "2.0"}, base_directory=tmp_path)
    with pytest.raises(readiness.ReadinessCalibrationError, match="invalid_readiness_campaign_config"):
        readiness.ReadinessCampaignConfig.from_dict({**valid, "extra": True}, base_directory=tmp_path)
    with pytest.raises(readiness.ReadinessCalibrationError, match="invalid_readiness_path:profile"):
        readiness.ReadinessCampaignConfig.from_dict({**valid, "profile": ""}, base_directory=tmp_path)

    config, readiness_config, _v3, plan, _efficiency, _manifests, _scenarios = _inputs(
        tmp_path,
        monkeypatch,
        "readiness-config-coverage",
    )
    assert readiness_config.public_payload() == readiness_config.fingerprint_payload()
    wrong_path = replace(readiness_config, evidence_path=tmp_path / "wrong-evidence.json")
    with pytest.raises(readiness.ReadinessCalibrationError, match="readiness_evidence_path_mismatch"):
        wrong_path.validate_campaign_path(config.campaign_id)

    mismatched_profile = replace(plan.profile, profile_id="different-readiness-profile")
    with monkeypatch.context() as scoped:
        scoped.setattr(readiness, "load_readiness_profile", lambda _path: mismatched_profile)
        with pytest.raises(readiness.ReadinessCalibrationError, match="readiness_profile_plan_mismatch"):
            readiness_config.plan()


def test_bound_inputs_and_public_gate_reject_every_mismatch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config, readiness_config, v3_config, plan, efficiency, manifests, scenarios = _inputs(
        tmp_path,
        monkeypatch,
        "readiness-input-coverage",
    )

    with pytest.raises(readiness.ReadinessCalibrationError, match="readiness_config_required"):
        readiness._bound_inputs(replace(config, benchmark_v4_readiness=None))
    with pytest.raises(readiness.ReadinessCalibrationError, match="readiness_v3_config_required"):
        readiness._bound_inputs(replace(config, benchmark_v3=None))
    with pytest.raises(readiness.ReadinessCalibrationError, match="readiness_efficiency_plan_required"):
        readiness._bound_inputs(replace(config, benchmark_v3=replace(v3_config, efficiency_plan_path=None)))

    altered_profile = replace(plan.profile, profile_id="unapproved-readiness-profile")
    altered_plan = replace(plan, profile=altered_profile)
    with monkeypatch.context() as scoped:
        scoped.setattr(readiness.ReadinessCampaignConfig, "plan", lambda _self: altered_plan)
        with pytest.raises(readiness.ReadinessCalibrationError, match="readiness_campaign_contract_mismatch"):
            readiness._bound_inputs(config)

    different_efficiency = replace(efficiency, efficiency_track_id="different-efficiency-track")
    with pytest.raises(readiness.ReadinessCalibrationError, match="readiness_efficiency_plan_mismatch"):
        readiness.require_full_campaign_readiness_material(
            config,
            manifests=manifests,
            scenarios=scenarios,
            efficiency_plan=different_efficiency,
        )
    with pytest.raises(readiness.ReadinessCalibrationError, match="readiness_system_manifest_mismatch"):
        readiness.require_full_campaign_readiness_material(
            config,
            manifests=(),
            scenarios=scenarios,
            efficiency_plan=efficiency,
        )
    with pytest.raises(readiness.ReadinessCalibrationError, match="readiness_scenario_mismatch"):
        readiness.require_full_campaign_readiness_material(
            config,
            manifests=manifests,
            scenarios=(),
            efficiency_plan=efficiency,
        )

    with monkeypatch.context() as scoped:
        scoped.setattr(competitor_schema, "load_system_manifest", lambda _path: manifests[0])
        with pytest.raises(readiness.ReadinessCalibrationError, match="readiness_system_manifest_mismatch"):
            readiness._calibration_manifests(config, plan)
    with monkeypatch.context() as scoped:
        scoped.setattr(benchmark_schema, "load_scenarios", lambda _path: ())
        with pytest.raises(readiness.ReadinessCalibrationError, match="readiness_scenario_mismatch"):
            readiness._calibration_scenarios(config, plan)

    assert readiness_config.profile_path.is_absolute()


def test_calibration_captures_runner_failures_and_cleanup_boundaries(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = fixtures._prepared_config(tmp_path, monkeypatch, "readiness-runner-errors")
    monkeypatch.setattr(readiness, "build_v3_run", fixtures._passing_v3_run)
    monkeypatch.setattr(readiness, "_reference_result", _raises(RuntimeError("reference failed")))

    def factory(manifest: Any):
        if manifest.system_id == "octopus":
            return lambda *_args: object()
        return lambda *_args: {"status": "succeeded", "duration_seconds": 1.0}

    readiness.run_readiness_calibration(
        config,
        environment=fixtures._environment(),
        runner_factory=factory,
        lab_controller=_passing_lab(config),
        clock=lambda: 10.0,
        monotonic=lambda: 1.0,
    )

    no_context = fixtures._prepared_config(tmp_path, monkeypatch, "readiness-no-final-context")
    base_factory, *_unused = fixtures._install_passing_execution(monkeypatch)
    with monkeypatch.context() as scoped:
        scoped.setattr(CampaignJournal, "begin_run_attempt", _raises(RuntimeError("attempt failed")))
        with pytest.raises(RuntimeError, match="attempt failed"):
            readiness.run_readiness_calibration(
                no_context,
                environment=fixtures._environment(),
                runner_factory=base_factory,
                lab_controller=_passing_lab(no_context),
            )

    empty_loop = fixtures._prepared_config(tmp_path, monkeypatch, "readiness-empty-loop")

    class FalsyNotEqualToZero:
        def __bool__(self) -> bool:
            return False

        def __eq__(self, _other: object) -> bool:
            return False

    completed_counts = iter((FalsyNotEqualToZero(), 1))
    with monkeypatch.context() as scoped:
        scoped.setattr(readiness, "_calibration_schedule", lambda _plan: ())
        scoped.setattr(readiness, "_validate_attempt_markers", lambda *_args, **_kwargs: 0)
        scoped.setattr(CampaignJournal, "initialize", lambda _self, _schedule: None)
        scoped.setattr(CampaignJournal, "completed_run_count", lambda _self: next(completed_counts))
        with pytest.raises(readiness.ReadinessCalibrationError, match="readiness_calibration_incomplete"):
            readiness.run_readiness_calibration(
                empty_loop,
                environment=fixtures._environment(),
                runner_factory=base_factory,
                lab_controller=_passing_lab(empty_loop),
            )

    cleanup_failure = fixtures._prepared_config(tmp_path, monkeypatch, "readiness-cleanup-failure")

    class CleanupFails(fixtures._RecordingLab):
        def cleanup(self, context: LabRunContext) -> None:
            super().cleanup(context)
            raise RuntimeError("cleanup failed")

    with pytest.raises(readiness.ReadinessCalibrationError, match="readiness_calibration_cleanup_failed"):
        readiness.run_readiness_calibration(
            cleanup_failure,
            environment=fixtures._environment(),
            runner_factory=base_factory,
            lab_controller=CleanupFails(
                reset_command_sha256=readiness._command_digest(cleanup_failure.reset_command),
                health_command_sha256=readiness._command_digest(cleanup_failure.health_command),
            ),
            clock=lambda: 10.0,
            monotonic=lambda: 1.0,
        )

    incomplete = fixtures._prepared_config(tmp_path, monkeypatch, "readiness-incomplete-count")
    with monkeypatch.context() as scoped:
        scoped.setattr(CampaignJournal, "completed_run_count", lambda _self: 0)
        with pytest.raises(readiness.ReadinessCalibrationError, match="readiness_calibration_incomplete"):
            readiness.run_readiness_calibration(
                incomplete,
                environment=fixtures._environment(),
                runner_factory=base_factory,
                lab_controller=_passing_lab(incomplete),
                clock=lambda: 10.0,
                monotonic=lambda: 1.0,
            )


class _Response:
    def __enter__(self) -> _Response:
        return self

    def __exit__(self, *_args: Any) -> None:
        return None

    def read(self, _limit: int) -> bytes:
        return b"response"


class _Opener:
    def __init__(self, outcomes: list[Any]) -> None:
        self.outcomes = outcomes

    def open(self, *_args: Any, **_kwargs: Any) -> Any:
        outcome = self.outcomes.pop(0)
        if isinstance(outcome, BaseException):
            raise outcome
        return outcome


def test_reference_runner_http_loop_and_result_normalization(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config, _readiness_config, v3_config, _plan, _efficiency, _manifests, _scenarios = _inputs(
        tmp_path,
        monkeypatch,
        "readiness-reference-coverage",
    )
    context = LabRunContext(
        campaign_id=config.campaign_id,
        system_id="sealed-reference-v3",
        scenario_id="scenario",
        repetition=1,
        seed=7,
        lab_version="discovery-lab-v3",
        snapshot_ref="snapshot",
    )
    artifacts = SimpleNamespace(private_manifest=tmp_path / "private-fixture.json")
    monkeypatch.setattr(readiness, "run_artifacts", lambda *_args, **_kwargs: artifacts)

    empty_variant = SimpleNamespace(routes=(), truth_claims=())
    monkeypatch.setattr(readiness, "load_private_fixture", lambda _path: empty_variant)
    with monkeypatch.context() as scoped:
        scoped.setattr(readiness, "_canonical_target", _raises(readiness.LabCtlError("missing target")))
        with pytest.raises(readiness.ReadinessCalibrationError, match="readiness_reference_target_missing"):
            readiness._reference_result(
                v3_config,
                context,
                {},
                hard_cap_seconds=10,
                monotonic=lambda: 0.0,
            )

    routes = (
        SimpleNamespace(target="/ignored", evidence_ids=(), response_statuses=()),
        SimpleNamespace(target="/ok", evidence_ids=("evidence-ok",), response_statuses=()),
        SimpleNamespace(target="/http-error", evidence_ids=("evidence-error",), response_statuses=()),
    )
    variant = SimpleNamespace(
        routes=routes,
        truth_claims=(SimpleNamespace(canonical_text="OCTOBENCH_V3_0123456789ABCDEF"),),
    )
    monkeypatch.setattr(readiness, "load_private_fixture", lambda _path: variant)
    http_error = urllib.error.HTTPError(
        "http://127.0.0.1/http-error",
        404,
        "missing",
        {},
        io.BytesIO(b"missing"),
    )
    opener = _Opener([_Response(), http_error])
    monkeypatch.setattr(readiness.urllib.request, "build_opener", lambda *_args: opener)
    result = readiness._reference_result(
        v3_config,
        context,
        {"OCTOBENCH_TARGET_URL": "http://127.0.0.1:8080"},
        hard_cap_seconds=10,
        monotonic=lambda: 0.0,
    )
    assert result["status"] == "succeeded"
    assert result["metrics"] == {"tool_calls": 2.0}

    timeout_variant = SimpleNamespace(
        routes=(SimpleNamespace(target="/timeout", evidence_ids=("evidence",), response_statuses=()),),
        truth_claims=(),
    )
    monkeypatch.setattr(readiness, "load_private_fixture", lambda _path: timeout_variant)
    times = iter((0.0, 2.0))
    with pytest.raises(TimeoutError, match="readiness_reference_timeout"):
        readiness._reference_result(
            v3_config,
            context,
            {"OCTOBENCH_TARGET_URL": "http://127.0.0.1:8080"},
            hard_cap_seconds=1,
            monotonic=lambda: next(times),
        )

    assert readiness._NoRedirectHandler().redirect_request(None, None, 302, "moved", {}, "unused") is None
    assert (
        readiness._normalize_result(
            {"status": "unknown"},
            default_duration=2.0,
            hard_cap_seconds=1,
        )["error_class"]
        == "InvalidRunnerStatus"
    )
    assert (
        readiness._normalize_result(
            {"status": "succeeded", "duration_seconds": "invalid"},
            default_duration=2.0,
            hard_cap_seconds=3,
        )["duration_seconds"]
        == 2.0
    )
    assert (
        readiness._normalize_result(
            {"status": "succeeded", "duration_seconds": float("nan")},
            default_duration=2.0,
            hard_cap_seconds=3,
        )["duration_seconds"]
        == 2.0
    )


def test_raw_journal_validators_fail_closed_on_every_boundary(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config, readiness_config, _v3, plan, efficiency, manifests, scenarios = _inputs(
        tmp_path,
        monkeypatch,
        "readiness-journal-coverage",
    )
    factory, *_unused = fixtures._install_passing_execution(monkeypatch)
    _run_passing_calibration(config, monkeypatch)
    schedule = readiness._calibration_schedule(plan)
    root = readiness_config.journal_directory / config.campaign_id
    campaign_payload = json.loads((root / "campaign.json").read_text(encoding="utf-8"))
    journal = CampaignJournal(
        readiness_config.journal_directory,
        campaign_id=config.campaign_id,
        fingerprint=campaign_payload["fingerprint"],
    )
    journal.initialize(schedule)
    gate = {
        "manifests": manifests,
        "scenarios": scenarios,
        "efficiency_plan": efficiency,
        "environment": fixtures._environment(),
    }

    run_path = sorted((root / "runs").glob("*.json"))[0]
    original = _rewrite_json(run_path, lambda payload: payload.__setitem__("benchmark_v3", None))
    try:
        with pytest.raises(readiness.ReadinessCalibrationError, match="readiness_raw_run_missing"):
            readiness.require_full_campaign_readiness(config, **gate)
    finally:
        _restore_private(run_path, original)

    original = _rewrite_json(
        run_path,
        lambda payload: payload["benchmark_v3"].__setitem__(
            "matched_fixture_seed",
            int(payload["benchmark_v3"]["matched_fixture_seed"]) + 1,
        ),
    )
    try:
        with pytest.raises(readiness.ReadinessCalibrationError, match="readiness_raw_run_identity_mismatch"):
            readiness.require_full_campaign_readiness(config, **gate)
    finally:
        _restore_private(run_path, original)

    attempt_path = sorted((root / "attempts").glob("*.json"))[0]
    original = attempt_path.read_bytes()
    attempt_path.write_text("{", encoding="utf-8")
    try:
        with pytest.raises(readiness.ReadinessCalibrationError, match="readiness_attempt_marker_invalid"):
            readiness.require_full_campaign_readiness(config, **gate)
    finally:
        _restore_private(attempt_path, original)

    original = _rewrite_json(attempt_path, lambda payload: payload.__setitem__("status", "finished"))
    try:
        with pytest.raises(readiness.ReadinessCalibrationError, match="readiness_attempt_marker_invalid"):
            readiness.require_full_campaign_readiness(config, **gate)
    finally:
        _restore_private(attempt_path, original)

    original = attempt_path.read_bytes()
    attempt_path.unlink()
    try:
        with pytest.raises(readiness.ReadinessCalibrationError, match="readiness_calibration_attempt_set_incomplete"):
            readiness.require_full_campaign_readiness(config, **gate)
        with pytest.raises(readiness.ReadinessCalibrationError, match="readiness_calibration_attempt_set_incomplete"):
            readiness.run_readiness_calibration(
                config,
                environment=fixtures._environment(),
                runner_factory=factory,
                lab_controller=_passing_lab(config),
            )
    finally:
        _restore_private(attempt_path, original)

    attestation_path = sorted((root / "attestations").glob("*.json"))[0]
    original = attestation_path.read_bytes()
    attestation_path.unlink()
    try:
        with pytest.raises(readiness.ReadinessCalibrationError, match="readiness_reset_attestation_set_incomplete"):
            readiness.require_full_campaign_readiness(config, **gate)
    finally:
        _restore_private(attestation_path, original)

    runs = readiness._read_calibration_runs(journal, schedule)
    with monkeypatch.context() as scoped:
        scoped.setattr(readiness, "_read_calibration_runs", lambda *_args: runs[:-1])
        with pytest.raises(readiness.ReadinessCalibrationError, match="readiness_raw_run_count_mismatch"):
            readiness.require_full_campaign_readiness(config, **gate)

    original = _rewrite_json(attestation_path, lambda payload: payload.pop("status"))
    try:
        with pytest.raises(readiness.ReadinessCalibrationError, match="readiness_reset_attestation_invalid"):
            readiness.require_full_campaign_readiness(config, **gate)
    finally:
        _restore_private(attestation_path, original)

    cleanup_path = root / "cleanup.json"
    original = _rewrite_json(cleanup_path, lambda payload: payload.pop("error_class"))
    try:
        with pytest.raises(readiness.ReadinessCalibrationError, match="readiness_cleanup_attestation_invalid"):
            readiness.require_full_campaign_readiness(config, **gate)
    finally:
        _restore_private(cleanup_path, original)

    with pytest.raises(readiness.ReadinessCalibrationError, match="readiness_calibration_incomplete"):
        readiness._validate_semantic_attestations(
            config=config,
            journal=journal,
            schedule=(),
            scenarios={},
            runs=(),
        )

    original = _rewrite_json(cleanup_path, lambda payload: payload.__setitem__("status", "failed"))
    try:
        with pytest.raises(readiness.ReadinessCalibrationError, match="readiness_calibration_cleanup_failed"):
            readiness.run_readiness_calibration(
                config,
                environment=fixtures._environment(),
                runner_factory=factory,
                lab_controller=_passing_lab(config),
            )
    finally:
        _restore_private(cleanup_path, original)


def test_private_path_validation_rejects_symlinks_modes_and_missing_files(
    tmp_path: Path,
) -> None:
    target = tmp_path / "target"
    target.mkdir(mode=0o700)
    linked = tmp_path / "linked"
    linked.symlink_to(target, target_is_directory=True)
    with pytest.raises(readiness.ReadinessCalibrationError, match="readiness_journal_not_private"):
        readiness._prepare_private_journal_root(linked)

    unsafe_directory = tmp_path / "unsafe-directory"
    unsafe_directory.mkdir(mode=0o755)
    unsafe_directory.chmod(0o755)
    with pytest.raises(readiness.ReadinessCalibrationError, match="readiness_journal_not_private"):
        readiness._require_private_directory(unsafe_directory)

    with pytest.raises(readiness.ReadinessCalibrationError, match="readiness_file_not_private"):
        readiness._require_private_file(tmp_path / "missing.json")
    unsafe_file = tmp_path / "unsafe.json"
    unsafe_file.write_text("{}", encoding="utf-8")
    unsafe_file.chmod(0o644)
    with pytest.raises(readiness.ReadinessCalibrationError, match="readiness_file_not_private"):
        readiness._require_private_file(unsafe_file)
