"""Hermetic branch coverage for the competitor campaign lifecycle."""

from __future__ import annotations

import copy
import json
import runpy
import sys
from collections.abc import Mapping
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from core.benchmarks.competitors import campaign
from core.benchmarks.competitors.lab import LabControlError, LabResetError
from core.benchmarks.competitors.preflight import CampaignPreflightError
from core.benchmarks.v3.schema import BenchmarkV3SchemaError
from tests.benchmark import test_competitor_campaign_lifecycle as lifecycle

pytestmark = [pytest.mark.benchmark, pytest.mark.contract]


def _raises(error: BaseException):
    def raise_error(*_args: Any, **_kwargs: Any) -> Any:
        raise error

    return raise_error


def _valid_payload() -> dict[str, Any]:
    command = {
        "argv": [sys.executable, "-c", "raise SystemExit(0)"],
        "working_directory": ".",
    }
    return {
        "schema_version": "1.0",
        "campaign_id": "coverage-campaign",
        "system_manifests": ["alpha.json", "beta.json"],
        "scenario_directory": "scenarios",
        "output_directory": "publication",
        "state_directory": "state",
        "repetitions": 5,
        "required_environment": [],
        "secret_environment": [],
        "strict_statuses": ["failed", "invalid", "partial", "timeout"],
        "lab": {"reset": command, "health": command},
    }


def _mutated_payload(**updates: Any) -> dict[str, Any]:
    payload = copy.deepcopy(_valid_payload())
    payload.update(updates)
    return payload


def test_campaign_config_rejects_each_top_level_contract_violation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    invalid_payloads = (
        _mutated_payload(schema_version="2.0"),
        _mutated_payload(unknown=True),
        _mutated_payload(system_manifests=["alpha.json"]),
        _mutated_payload(repetitions=1),
        _mutated_payload(lab=[]),
        _mutated_payload(
            lab={**_valid_payload()["lab"], "unknown": {}},
        ),
        _mutated_payload(lab={"reset": _valid_payload()["lab"]["reset"]}),
        _mutated_payload(
            required_environment=[],
            secret_environment=["SECRET_TOKEN"],
        ),
        _mutated_payload(benchmark_v3=[]),
        _mutated_payload(strict_statuses=["succeeded"]),
    )
    for payload in invalid_payloads:
        with pytest.raises(campaign.CampaignConfigError):
            campaign.CampaignConfig.from_dict(payload)

    with monkeypatch.context() as patch:
        patch.setattr(
            campaign.LabCommand,
            "from_dict",
            _raises(LabControlError("invalid_lab_command")),
        )
        with pytest.raises(campaign.CampaignConfigError, match="invalid_lab_command"):
            campaign.CampaignConfig.from_dict(_valid_payload())

    with monkeypatch.context() as patch:
        patch.setattr(
            campaign.BenchmarkV3CampaignConfig,
            "from_dict",
            _raises(BenchmarkV3SchemaError("invalid_v3_config")),
        )
        with pytest.raises(campaign.CampaignConfigError, match="invalid_v3_config"):
            campaign.CampaignConfig.from_dict(_mutated_payload(benchmark_v3={}))


def test_campaign_config_loader_failures_and_success(tmp_path: Path) -> None:
    with pytest.raises(campaign.CampaignConfigError, match="campaign_config_load_failed"):
        campaign.load_campaign_config(tmp_path / "missing.json")

    not_mapping = tmp_path / "list.json"
    not_mapping.write_text("[]", encoding="utf-8")
    with pytest.raises(campaign.CampaignConfigError, match="campaign_config_not_mapping"):
        campaign.load_campaign_config(not_mapping)

    valid = tmp_path / "campaign.json"
    valid.write_text(json.dumps(_valid_payload()), encoding="utf-8")
    assert campaign.load_campaign_config(valid).campaign_id == "coverage-campaign"


def _campaign_fixture(tmp_path: Path, name: str) -> campaign.CampaignConfig:
    root = tmp_path / name
    root.mkdir()
    config, _manifest_paths = lifecycle._campaign_fixture(
        root,
        campaign_id=f"campaign-{name}",
    )
    return config


def _patch_hermetic_provenance(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(campaign, "_repository_revision", lambda: "0" * 40)
    monkeypatch.setattr(
        campaign,
        "_controller_source_identity",
        lambda: {"campaign.py": "a" * 64},
    )


def test_runner_boundary_failures_are_persisted_and_published(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = _campaign_fixture(tmp_path, "runner-guards")
    _patch_hermetic_provenance(monkeypatch)
    successful = lifecycle._successful_runner_factory([])

    def factory(manifest: Any):
        fallback = successful(manifest)

        def run(scenario: Any, repetition: int, seed: int) -> Any:
            if manifest.system_id == "alpha" and repetition == 1:
                return []
            if manifest.system_id == "alpha" and repetition == 2:
                return {"status": "unknown-runner-status"}
            if manifest.system_id == "alpha" and repetition == 3:
                result = dict(fallback(scenario, repetition, seed))
                result["artifact_refs"] = [lifecycle.SECRET_VALUE]
                return result
            return fallback(scenario, repetition, seed)

        return run

    outcome = campaign.run_campaign(
        config,
        environment={"CAMPAIGN_TEST_TOKEN": lifecycle.SECRET_VALUE},
        runner_factory=factory,
        lab_controller=lifecycle.RecordingLab(),
        clock=lambda: 100.0,
        monotonic=lambda: 1.0,
    )
    assert outcome.status == "completed_with_failures"
    assert outcome.exit_code == 1


def test_missing_cleanup_attestation_fails_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = _campaign_fixture(tmp_path, "missing-cleanup")
    _patch_hermetic_provenance(monkeypatch)
    monkeypatch.setattr(
        campaign.CampaignJournal,
        "read_cleanup_attestation",
        lambda _self: None,
    )
    with pytest.raises(RuntimeError, match="campaign_cleanup_attestation_missing"):
        campaign.run_campaign(
            config,
            environment={"CAMPAIGN_TEST_TOKEN": "configured"},
            runner_factory=lifecycle._successful_runner_factory([]),
            lab_controller=lifecycle.RecordingLab(),
            clock=lambda: 100.0,
            monotonic=lambda: 1.0,
        )


class _FakeBenchmarkV3Config:
    def fingerprint_payload(self) -> dict[str, str]:
        return {"track": "fake-v3"}

    def public_payload(self) -> dict[str, str]:
        return {"track": "fake-v3"}


class _FakeSerializedV3Run:
    def to_dict(self) -> dict[str, str]:
        return {"schema_version": "fake-v3"}


class _FakeBenchmarkV4Config:
    def __init__(self, efficiency_plan: Any, *, public_digest: str | None = None) -> None:
        self._efficiency_plan = efficiency_plan
        self._public_digest = public_digest or efficiency_plan.digest

    def efficiency_plan(self) -> Any:
        return self._efficiency_plan

    def fingerprint_payload(self) -> dict[str, str]:
        return {
            "efficiency_plan_digest": self._efficiency_plan.digest,
            "efficiency_track_id": self._efficiency_plan.efficiency_track_id,
            "track": "fake-v3",
        }

    def public_payload(self) -> dict[str, str]:
        return {
            "efficiency_plan_digest": self._public_digest,
            "efficiency_track_id": self._efficiency_plan.efficiency_track_id,
            "track": "fake-v3",
        }


def _fake_v3_campaign(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    name: str,
) -> campaign.CampaignConfig:
    config = replace(
        _campaign_fixture(tmp_path, name),
        benchmark_v3=_FakeBenchmarkV3Config(),
    )
    plan = SimpleNamespace(track_id="fake-v3")
    monkeypatch.setattr(campaign, "validate_campaign_plan", lambda *_args, **_kwargs: plan)
    monkeypatch.setattr(
        campaign,
        "planned_fixture_seed",
        lambda _plan, *, scenario_id, repetition: repetition,
    )
    monkeypatch.setattr(
        campaign,
        "build_v3_run",
        lambda **_kwargs: _FakeSerializedV3Run(),
    )
    monkeypatch.setattr(
        campaign,
        "_journal_v3_runs",
        lambda *_args, **_kwargs: (
            SimpleNamespace(
                execution_status="succeeded",
                task_status="completed",
                policy_violations=(),
            ),
        ),
    )
    monkeypatch.setattr(campaign, "fixture_reveals", lambda *_args, **_kwargs: {})
    monkeypatch.setattr(
        campaign,
        "controller_ledger_records",
        lambda *_args, **_kwargs: (),
    )
    monkeypatch.setattr(
        campaign,
        "_controller_source_identity",
        lambda: {"campaign.py": "a" * 64},
    )
    return config


def _fake_v4_campaign(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    name: str,
    *,
    public_digest: str | None = None,
) -> tuple[campaign.CampaignConfig, Any]:
    config = _fake_v3_campaign(tmp_path, monkeypatch, name)
    efficiency_plan = SimpleNamespace(
        digest="b" * 64,
        efficiency_track_id="fake-efficiency-v4",
        plan_id="fake-plan-v4",
        source_analysis_plan_digest="a" * 64,
        source_track_id="fake-v3",
    )
    config = replace(
        config,
        benchmark_v3=_FakeBenchmarkV4Config(
            efficiency_plan,
            public_digest=public_digest,
        ),
    )
    original_build_schedule = campaign._build_schedule

    def legacy_schedule(resolved: Any, manifests: Any, scenarios: Any, **kwargs: Any):
        return original_build_schedule(
            SimpleNamespace(repetitions=resolved.repetitions),
            manifests,
            scenarios,
            v3_plan=kwargs.get("v3_plan"),
            efficiency_plan=None,
        )

    monkeypatch.setattr(campaign, "_build_schedule", legacy_schedule)
    monkeypatch.setattr(
        campaign,
        "validate_efficiency_campaign_plan",
        lambda *_args, **_kwargs: efficiency_plan,
    )
    monkeypatch.setattr(
        campaign,
        "require_full_campaign_readiness_material",
        lambda *_args, **_kwargs: None,
    )
    return config, efficiency_plan


def _attested_v4_run(efficiency_plan: Any, *, digest: str | None = None) -> Any:
    return SimpleNamespace(
        execution_status="succeeded",
        task_status="completed",
        policy_violations=(),
        environment={"efficiency_plan_digest": digest or efficiency_plan.digest},
    )


def test_v3_context_secret_guard_fails_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = _fake_v3_campaign(tmp_path, monkeypatch, "v3-secret")
    monkeypatch.setattr(campaign, "_provenance", lambda *_args, **_kwargs: {})
    monkeypatch.setattr(
        campaign,
        "_contains_secret_canary",
        lambda value, _canaries: isinstance(value, Mapping) and "campaign" in value,
    )
    with pytest.raises(campaign.CampaignConfigError, match="secret_canary_detected"):
        campaign.run_campaign(
            config,
            environment={"CAMPAIGN_TEST_TOKEN": "configured"},
            runner_factory=lifecycle._successful_runner_factory([]),
            lab_controller=lifecycle.RecordingLab(),
            clock=lambda: 100.0,
            monotonic=lambda: 1.0,
        )


def test_v3_plan_without_config_defensive_guard(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = _fake_v3_campaign(tmp_path, monkeypatch, "v3-config-guard")

    def remove_config(
        resolved: campaign.CampaignConfig,
        *_args: Any,
        **_kwargs: Any,
    ) -> dict[str, Any]:
        object.__setattr__(resolved, "benchmark_v3", None)
        return {}

    monkeypatch.setattr(campaign, "_provenance", remove_config)
    with pytest.raises(campaign.CampaignConfigError, match="missing_benchmark_v3_config"):
        campaign.run_campaign(
            config,
            environment={"CAMPAIGN_TEST_TOKEN": "configured"},
            runner_factory=lifecycle._successful_runner_factory([]),
            lab_controller=lifecycle.RecordingLab(),
            clock=lambda: 100.0,
            monotonic=lambda: 1.0,
        )


def test_v4_run_attestation_mismatch_fails_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config, efficiency_plan = _fake_v4_campaign(tmp_path, monkeypatch, "v4-run-attestation")
    monkeypatch.setattr(
        campaign,
        "_journal_v3_runs",
        lambda *_args, **_kwargs: (_attested_v4_run(efficiency_plan, digest="wrong"),),
    )
    with pytest.raises(BenchmarkV3SchemaError, match="efficiency_run_attestation_mismatch"):
        campaign.run_campaign(
            config,
            environment={"CAMPAIGN_TEST_TOKEN": "configured"},
            runner_factory=lifecycle._successful_runner_factory([]),
            lab_controller=lifecycle.RecordingLab(),
            clock=lambda: 100.0,
            monotonic=lambda: 1.0,
        )


def test_v4_public_plan_attestation_mismatch_fails_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config, efficiency_plan = _fake_v4_campaign(
        tmp_path,
        monkeypatch,
        "v4-public-attestation",
        public_digest="wrong",
    )
    monkeypatch.setattr(
        campaign,
        "_journal_v3_runs",
        lambda *_args, **_kwargs: (_attested_v4_run(efficiency_plan),),
    )
    with pytest.raises(BenchmarkV3SchemaError, match="efficiency_plan_digest_mismatch"):
        campaign.run_campaign(
            config,
            environment={"CAMPAIGN_TEST_TOKEN": "configured"},
            runner_factory=lifecycle._successful_runner_factory([]),
            lab_controller=lifecycle.RecordingLab(),
            clock=lambda: 100.0,
            monotonic=lambda: 1.0,
        )


def test_v4_context_includes_plan_attestation_before_publication(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config, efficiency_plan = _fake_v4_campaign(tmp_path, monkeypatch, "v4-context")
    monkeypatch.setattr(
        campaign,
        "_journal_v3_runs",
        lambda *_args, **_kwargs: (_attested_v4_run(efficiency_plan),),
    )
    monkeypatch.setattr(
        campaign,
        "_contains_secret_canary",
        lambda value, _canaries: isinstance(value, Mapping) and "efficiency_plan_attestation" in value,
    )
    with pytest.raises(campaign.CampaignConfigError, match="secret_canary_detected"):
        campaign.run_campaign(
            config,
            environment={"CAMPAIGN_TEST_TOKEN": "configured"},
            runner_factory=lifecycle._successful_runner_factory([]),
            lab_controller=lifecycle.RecordingLab(),
            clock=lambda: 100.0,
            monotonic=lambda: 1.0,
        )


def test_v4_campaign_fingerprint_binds_public_readiness_attestation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config, _efficiency_plan = _fake_v4_campaign(tmp_path, monkeypatch, "v4-readiness-fingerprint")
    attestation = {
        "campaign_id": config.campaign_id,
        "cleanup_attestation_digest": "1" * 64,
        "evidence_digest": "2" * 64,
        "plan_digest": "3" * 64,
        "profile_digest": "4" * 64,
        "reset_attestation_set_digest": "5" * 64,
        "source_run_digest": "6" * 64,
        "status": "ready",
    }
    monkeypatch.setattr(
        campaign,
        "require_full_campaign_readiness_material",
        lambda *_args, **_kwargs: SimpleNamespace(public_attestation=attestation),
    )
    captured: dict[str, Any] = {}

    class FingerprintObserved(Exception):
        pass

    def observe(payload: Mapping[str, Any]) -> str:
        captured.update(payload)
        raise FingerprintObserved

    monkeypatch.setattr(campaign, "campaign_fingerprint", observe)
    with pytest.raises(FingerprintObserved):
        campaign.run_campaign(config, environment={"CAMPAIGN_TEST_TOKEN": "configured"})

    assert captured["readiness_attestation"] == attestation


def test_main_maps_each_outcome_and_failure(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    outcome = SimpleNamespace(bundle_path=Path("bundle"), exit_code=7)
    monkeypatch.setattr(campaign, "run_campaign", lambda _config: outcome)
    assert campaign.main(["--config", "campaign.json"]) == 7
    assert capsys.readouterr().out == "bundle\n"

    report = SimpleNamespace(to_dict=lambda: {"status": "failed"})
    failures = (
        (CampaignPreflightError(report), 2, '"status": "failed"'),
        (campaign.CampaignAbortedError("aborted"), 3, "aborted"),
        (campaign.CampaignConfigError("invalid"), 2, "campaign failed: invalid"),
    )
    for error, expected_code, expected_text in failures:
        monkeypatch.setattr(campaign, "run_campaign", _raises(error))
        assert campaign.main(["--config", "campaign.json"]) == expected_code
        assert expected_text in capsys.readouterr().err


def test_schedule_journal_and_environment_helper_guards(
    tmp_path: Path,
) -> None:
    protocol_instance = object()
    assert campaign.LabController.reset_and_health(protocol_instance, SimpleNamespace()) is None
    assert campaign.LabController.cleanup(protocol_instance, SimpleNamespace()) is None
    assert campaign._counterbalanced_order((), 1) == ()

    missing_journal = SimpleNamespace(read_run=lambda _key: None)
    replay = campaign._journal_runner_factory(missing_journal)(SimpleNamespace(system_id="alpha"))
    with pytest.raises(RuntimeError, match="campaign_journal_run_missing"):
        replay(SimpleNamespace(scenario_id="scenario"), 1, 1)

    invalid_journal = SimpleNamespace(read_run=lambda _key: {"result": []})
    replay = campaign._journal_runner_factory(invalid_journal)(SimpleNamespace(system_id="alpha"))
    with pytest.raises(RuntimeError, match="campaign_journal_result_invalid"):
        replay(SimpleNamespace(scenario_id="scenario"), 1, 1)

    with pytest.raises(BenchmarkV3SchemaError, match="campaign_v3_run_missing"):
        campaign._journal_v3_runs(
            SimpleNamespace(read_run=lambda _key: None),
            ({"run_key": "missing"},),
        )

    with pytest.raises(campaign.CampaignConfigError, match="environment_file_load_failed"):
        campaign._load_environment_file(tmp_path / "missing.env")

    valid = tmp_path / "valid.env"
    valid.write_text("# comment\n\nQUOTED='value'\n", encoding="utf-8")
    assert campaign._load_environment_file(valid) == {"QUOTED": "value"}

    invalid = tmp_path / "invalid.env"
    for contents, expected in (
        ("export A=1\n", "invalid_environment_file"),
        ("BAD-NAME=value\n", "invalid_environment_file_name"),
        ("A=before\x00after\n", "invalid_environment_file_value"),
    ):
        invalid.write_text(contents, encoding="utf-8")
        with pytest.raises(campaign.CampaignConfigError, match=expected):
            campaign._load_environment_file(invalid)


def test_efficiency_schedule_and_configuration_guards() -> None:
    manifests = (SimpleNamespace(system_id="alpha"), SimpleNamespace(system_id="beta"))
    scenarios = (SimpleNamespace(scenario_id="scenario-v4"),)
    block = SimpleNamespace(
        scenario_id="scenario-v4",
        repetition=1,
        matched_fixture_seed=7,
        system_order=("alpha", "beta"),
    )

    def efficiency_plan(**updates: Any) -> Any:
        values = {
            "system_ids": ("alpha", "beta"),
            "scenario_ids": ("scenario-v4",),
            "schedule": (block,),
            "digest": "b" * 64,
            "efficiency_track_id": "efficiency-v4",
            "plan_id": "plan-v4",
            "source_analysis_plan_digest": "a" * 64,
            "source_track_id": "source-v3",
        }
        values.update(updates)
        return SimpleNamespace(**values)

    configured = SimpleNamespace(
        repetitions=1,
        benchmark_v3=SimpleNamespace(efficiency_plan=lambda: efficiency_plan()),
    )
    with pytest.raises(BenchmarkV3SchemaError, match="efficiency_plan_requires_v3_plan"):
        campaign._build_schedule(configured, manifests, scenarios)

    with pytest.raises(BenchmarkV3SchemaError, match="efficiency_plan_schedule_mismatch"):
        campaign._build_efficiency_schedule(
            (manifests[0], manifests[0]),
            scenarios,
            efficiency_plan(),
        )

    unknown_scenario = SimpleNamespace(**{**vars(block), "scenario_id": "missing-v4"})
    with pytest.raises(BenchmarkV3SchemaError, match="efficiency_plan_schedule_mismatch"):
        campaign._build_efficiency_schedule(
            manifests,
            scenarios,
            efficiency_plan(schedule=(unknown_scenario,)),
        )

    unknown_system = SimpleNamespace(**{**vars(block), "system_order": ("alpha", "missing")})
    with pytest.raises(BenchmarkV3SchemaError, match="efficiency_plan_schedule_mismatch"):
        campaign._build_efficiency_schedule(
            manifests,
            scenarios,
            efficiency_plan(schedule=(unknown_system,)),
        )

    with pytest.raises(BenchmarkV3SchemaError, match="efficiency_plan_schedule_mismatch"):
        campaign._build_efficiency_schedule(
            manifests,
            scenarios,
            efficiency_plan(schedule=(block, block)),
        )

    assert (
        campaign._configured_analysis_plan(SimpleNamespace(benchmark_v3=SimpleNamespace(plan=lambda: "source-plan")))
        == "source-plan"
    )
    assert campaign._efficiency_plan_attestation(efficiency_plan()) == {
        "efficiency_track_id": "efficiency-v4",
        "plan_digest": "b" * 64,
        "plan_id": "plan-v4",
        "source_analysis_plan_digest": "a" * 64,
        "source_track_id": "source-v3",
    }


def test_campaign_rejects_efficiency_plan_without_validated_v3_source(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manifests = (SimpleNamespace(system_id="alpha"), SimpleNamespace(system_id="beta"))
    scenarios = (SimpleNamespace(scenario_id="scenario-v4"),)
    efficiency_plan = SimpleNamespace(digest="b" * 64)
    config = SimpleNamespace(
        system_manifest_paths=(Path("alpha.json"), Path("beta.json")),
        scenario_directory=Path("scenarios"),
        benchmark_v3=SimpleNamespace(efficiency_plan=lambda: efficiency_plan),
        repetitions=1,
    )
    loaded_manifests = iter(manifests)
    monkeypatch.setattr(campaign, "load_system_manifest", lambda _path: next(loaded_manifests))
    monkeypatch.setattr(campaign, "load_scenarios", lambda _path: scenarios)
    monkeypatch.setattr(campaign, "validate_campaign_plan", lambda *_args, **_kwargs: None)

    with pytest.raises(BenchmarkV3SchemaError, match="efficiency_plan_requires_v3_plan"):
        campaign.run_campaign(config)


def test_repository_result_duration_and_diagnostic_guards(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        campaign.subprocess,
        "run",
        lambda *_args, **_kwargs: SimpleNamespace(stdout="a" * 40 + "\n"),
    )
    assert campaign._repository_revision() == "a" * 40
    monkeypatch.setattr(
        campaign.subprocess,
        "run",
        lambda *_args, **_kwargs: SimpleNamespace(stdout="invalid"),
    )
    assert campaign._repository_revision() == "unknown"
    monkeypatch.setattr(campaign.subprocess, "run", _raises(OSError("no git")))
    assert campaign._repository_revision() == "unknown"

    assert campaign._failed_result(1.25)["duration_seconds"] == 1.25
    assert campaign._nonnegative_duration(True, default=2.5) == 2.5
    assert campaign._nonnegative_duration("invalid", default=3.5) == 3.5

    diagnostics = tmp_path / "diagnostics"
    diagnostics.mkdir(mode=0o700)
    diagnostics.chmod(0o700)
    journal = SimpleNamespace(diagnostics_directory=diagnostics)

    outside = tmp_path / "lab-outside.log"
    assert (
        campaign._diagnostic_reference(
            journal,
            LabResetError("failed", diagnostic_path=outside),
        )
        is None
    )
    invalid_name = diagnostics / "invalid.log"
    assert (
        campaign._diagnostic_reference(
            journal,
            LabResetError("failed", diagnostic_path=invalid_name),
        )
        is None
    )
    missing = diagnostics / "lab-missing.log"
    assert (
        campaign._diagnostic_reference(
            journal,
            LabResetError("failed", diagnostic_path=missing),
        )
        is None
    )

    unsafe_directory = tmp_path / "unsafe-diagnostics"
    unsafe_directory.mkdir(mode=0o755)
    unsafe_directory.chmod(0o755)
    unsafe_file = unsafe_directory / "lab-unsafe.log"
    unsafe_file.write_text("diagnostic", encoding="utf-8")
    unsafe_file.chmod(0o600)
    unsafe_journal = SimpleNamespace(diagnostics_directory=unsafe_directory)
    assert (
        campaign._diagnostic_reference(
            unsafe_journal,
            LabResetError("failed", diagnostic_path=unsafe_file),
        )
        is None
    )


def test_scalar_sequence_and_identifier_guards(tmp_path: Path) -> None:
    with pytest.raises(campaign.CampaignConfigError, match="invalid:path"):
        campaign._resolved_path("", base=tmp_path, name="path")
    with pytest.raises(campaign.CampaignConfigError, match="invalid:paths"):
        campaign._path_sequence("one", base=tmp_path, name="paths")
    with pytest.raises(campaign.CampaignConfigError, match="duplicate:paths"):
        campaign._path_sequence(["one", "one"], base=tmp_path, name="paths")

    for value in (True, "not-an-integer", 0):
        with pytest.raises(campaign.CampaignConfigError, match="invalid_integer"):
            campaign._positive_integer(value)

    with pytest.raises(campaign.CampaignConfigError, match="invalid_identifier:item"):
        campaign._identifier("../invalid", "item")
    with pytest.raises(campaign.CampaignConfigError, match="invalid:items"):
        campaign._identifiers("one", "items")
    with pytest.raises(campaign.CampaignConfigError, match="invalid:names"):
        campaign._environment_names("NAME", "names")
    with pytest.raises(campaign.CampaignConfigError, match="invalid:names"):
        campaign._environment_names(["BAD-NAME"], "names")
    assert campaign._environment_names(["NAME", "NAME"], "names") == ("NAME",)


def test_module_entrypoint_uses_main_guard(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(
        sys,
        "argv",
        ["campaign", "--config", "/definitely/missing/campaign.json"],
    )
    with pytest.warns(RuntimeWarning, match="found in sys.modules"), pytest.raises(SystemExit) as captured:
        runpy.run_module(
            "core.benchmarks.competitors.campaign",
            run_name="__main__",
            alter_sys=True,
        )
    assert captured.value.code == 2
    assert "campaign_config_load_failed" in capsys.readouterr().err
