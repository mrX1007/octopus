"""Hermetic edge coverage for private competitor diagnostics."""

from __future__ import annotations

import json
import stat
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest

from core.benchmarks.competitors import diagnostic
from core.benchmarks.competitors.campaign import CampaignConfig
from core.benchmarks.competitors.lab import LabCommand
from core.benchmarks.competitors.schema import SystemManifest
from core.benchmarks.schema import BenchmarkScenario

pytestmark = [pytest.mark.benchmark, pytest.mark.contract]


def _manifest(tmp_path: Path) -> SystemManifest:
    source = tmp_path / "system.json"
    source.write_text("{}\n", encoding="utf-8")
    return SystemManifest.from_dict(
        {
            "schema_version": "1.0",
            "system_id": "system",
            "name": "System",
            "version": "1.0",
            "source_revision": "a" * 40,
            "execution_mode": "live",
            "track": "full_system",
            "fairness_profile": {
                "profile_id": "diagnostic-coverage",
                "same_model": True,
                "same_tool_versions": True,
                "same_hardware": True,
                "same_budgets": True,
            },
            "model": {
                "provider": "local",
                "name": "fixture",
                "parameters": {},
            },
            "tool_versions": {"fixture": "1.0"},
            "adapter": {
                "kind": "command",
                "argv": ["unused", "{scenario_path}", "{output_path}"],
                "working_directory": ".",
                "environment_passthrough": [],
            },
            "metadata": {},
        },
        source_path=source,
    )


def _scenario(scenario_id: str, *, smoke: bool = True) -> BenchmarkScenario:
    return BenchmarkScenario(
        scenario_id=scenario_id,
        name=scenario_id,
        category=("service_discovery_verification" if smoke else "web_api_mapping"),
        lab={"version": "lab-v1", "snapshot_ref": "snapshot-v1"},
        target={"version": "target-v1"},
        model={"provider": "local", "name": "fixture", "parameters": {}},
        tool_versions={"fixture": "1.0"},
        strategy_config={},
        seed=7,
        budgets={"max_tools": 1, "max_seconds": 120, "max_output_bytes": 1024},
        allowed_actions=("inspect",),
        ground_truth={},
        artifacts={},
        tags=("read-only",) if smoke else (),
    )


def _config(tmp_path: Path, manifest: SystemManifest, campaign_id: str) -> CampaignConfig:
    command = LabCommand(argv=("unused",), working_directory=tmp_path)
    assert manifest.source_path is not None
    return CampaignConfig(
        campaign_id=campaign_id,
        system_manifest_paths=(manifest.source_path,),
        scenario_directory=tmp_path,
        output_directory=tmp_path / "unused-output",
        state_directory=tmp_path / "unused-state",
        repetitions=5,
        reset_command=command,
        health_command=command,
        cleanup_command=command,
    )


def test_pilot_rejects_missing_system_and_empty_inputs(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manifest = _manifest(tmp_path)
    scenario = _scenario("scenario")
    config = _config(tmp_path, manifest, "missing-inputs")
    monkeypatch.setattr(diagnostic, "load_system_manifest", lambda _path: manifest)

    with pytest.raises(
        diagnostic.DiagnosticError,
        match="diagnostic_system_unavailable",
    ):
        diagnostic.run_diagnostic_pilot(
            config,
            environment={},
            root=tmp_path / "unused-system-root",
            budget_seconds=120,
            selected_system="missing",
        )

    monkeypatch.setattr(diagnostic, "load_scenarios", lambda _path: (scenario,))
    with pytest.raises(
        diagnostic.DiagnosticError,
        match="diagnostic_inputs_unavailable",
    ):
        diagnostic.run_diagnostic_pilot(
            replace(config, system_manifest_paths=()),
            environment={},
            root=tmp_path / "unused-input-root",
            budget_seconds=120,
        )


def test_pilot_records_runner_and_controller_failures_without_external_calls(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manifest = _manifest(tmp_path)
    scenarios = tuple(
        _scenario(scenario_id)
        for scenario_id in (
            "runner-system-error",
            "reset-system-error",
            "runner-generic-error",
            "reset-generic-error",
            "reset-interrupt",
        )
    )
    config = _config(tmp_path, manifest, "exception-paths")
    cleanup_ids: list[str] = []
    monkeypatch.setattr(diagnostic, "load_system_manifest", lambda _path: manifest)
    monkeypatch.setattr(diagnostic, "load_scenarios", lambda _path: scenarios)

    class Controller:
        def __init__(self, *_args, **_kwargs) -> None:
            pass

        def reset_and_health(self, context) -> None:
            if context.scenario_id == "reset-system-error":
                raise diagnostic.SystemRunnerError()
            if context.scenario_id == "reset-generic-error":
                raise RuntimeError("private reset detail")
            if context.scenario_id == "reset-interrupt":
                raise KeyboardInterrupt

        def cleanup(self, context) -> None:
            cleanup_ids.append(context.scenario_id)

    class Runner:
        def __init__(self, _manifest, *, private_log_path) -> None:
            self.private_log_path = private_log_path

        def __call__(self, scenario, _repetition, _seed):
            if scenario.scenario_id == "runner-system-error":
                raise diagnostic.SystemRunnerError()
            if scenario.scenario_id == "runner-generic-error":
                raise RuntimeError("private runner detail")
            raise AssertionError("unexpected runner invocation")

    monkeypatch.setattr(diagnostic, "CommandLabController", Controller)
    monkeypatch.setattr(diagnostic, "CommandSystemRunner", Runner)

    outcome = diagnostic.run_diagnostic_pilot(
        config,
        environment={"SAFE": "value"},
        root=tmp_path / "diagnostics",
        budget_seconds=120,
    )

    payload = json.loads(outcome.summary_path.read_text(encoding="utf-8"))
    assert outcome.status == "interrupted"
    assert outcome.exit_code == 130
    assert cleanup_ids == [item.scenario_id for item in scenarios]
    assert [item["error_class"] for item in payload["runs"]] == [
        "SystemRunnerError",
        "SystemRunnerError",
        "RuntimeError",
        "RuntimeError",
        "OperatorInterrupt",
    ]
    assert [item["reset_healthy"] for item in payload["runs"]] == [
        True,
        False,
        True,
        False,
        False,
    ]
    assert (outcome.summary_path.parent / "raw/system/runner-system-error/adapter.log").is_file()
    assert (outcome.summary_path.parent / "raw/system/runner-generic-error/adapter.log").is_file()


def test_scalar_validation_worker_and_calibration_scope(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with pytest.raises(diagnostic.DiagnosticError, match="diagnostic_budget_invalid"):
        diagnostic._pilot_seconds(True)
    with pytest.raises(diagnostic.DiagnosticError, match="diagnostic_budget_invalid"):
        diagnostic._pilot_seconds(object())
    assert diagnostic._nonnegative_number(True, default=-1) == 0
    assert diagnostic._nonnegative_number(object(), default=2.5) == 2.5
    assert diagnostic._scenario_scope((_scenario("not-smoke", smoke=False),)) == ("calibration_only")

    monkeypatch.setattr(Path, "is_file", lambda _self: False)
    with pytest.raises(
        diagnostic.DiagnosticError,
        match="diagnostic_worker_unavailable",
    ):
        diagnostic._diagnostic_worker_path()


def test_private_directory_rejects_unsafe_mode_and_maps_creation_errors(
    tmp_path: Path,
) -> None:
    unsafe = tmp_path / "unsafe"
    unsafe.mkdir(mode=0o755)
    unsafe.chmod(0o755)
    with pytest.raises(
        diagnostic.DiagnosticError,
        match="diagnostic_directory_unsafe",
    ):
        diagnostic._create_private_directory(unsafe)

    class FailingPath:
        def __init__(self, error: OSError) -> None:
            self.error = error

        def exists(self) -> bool:
            return False

        def is_symlink(self) -> bool:
            return False

        def mkdir(self, **_kwargs) -> None:
            raise self.error

    with pytest.raises(
        diagnostic.DiagnosticError,
        match="diagnostic_destination_exists",
    ):
        diagnostic._create_new_private_directory(
            FailingPath(FileExistsError("race")),
        )
    with pytest.raises(
        diagnostic.DiagnosticError,
        match="diagnostic_directory_unsafe",
    ):
        diagnostic._create_new_private_directory(FailingPath(OSError("denied")))


def test_private_byte_writer_error_paths(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    without_nofollow = tmp_path / "without-nofollow.log"
    with monkeypatch.context() as scoped:
        scoped.delattr(diagnostic.os, "O_NOFOLLOW", raising=False)
        diagnostic._write_private_bytes(without_nofollow, b"safe")
    assert without_nofollow.read_bytes() == b"safe"

    closed: list[int] = []
    with monkeypatch.context() as scoped:
        scoped.setattr(diagnostic.os, "open", lambda *_args: 41)
        scoped.setattr(diagnostic.os, "fchmod", lambda *_args: None)
        scoped.setattr(
            diagnostic.os,
            "fstat",
            lambda _descriptor: SimpleNamespace(st_mode=stat.S_IFDIR | 0o700),
        )
        scoped.setattr(diagnostic.os, "close", closed.append)
        with pytest.raises(
            diagnostic.DiagnosticError,
            match="diagnostic_file_unsafe",
        ):
            diagnostic._write_private_bytes(tmp_path / "not-regular", b"x")
    assert closed == [41]

    closed.clear()
    with monkeypatch.context() as scoped:
        scoped.setattr(diagnostic.os, "open", lambda *_args: 42)
        scoped.setattr(diagnostic.os, "fchmod", lambda *_args: None)
        scoped.setattr(
            diagnostic.os,
            "fstat",
            lambda _descriptor: SimpleNamespace(st_mode=stat.S_IFREG | 0o600),
        )
        scoped.setattr(diagnostic.os, "write", lambda *_args: 0)
        scoped.setattr(diagnostic.os, "close", closed.append)
        with pytest.raises(
            diagnostic.DiagnosticError,
            match="diagnostic_file_unavailable",
        ):
            diagnostic._write_private_bytes(tmp_path / "zero-write", b"x")
    assert closed == [42]

    def unavailable_open(*_args):
        raise OSError("unavailable")

    with monkeypatch.context() as scoped:
        scoped.setattr(diagnostic.os, "open", unavailable_open)
        with pytest.raises(
            diagnostic.DiagnosticError,
            match="diagnostic_file_unavailable",
        ):
            diagnostic._write_private_bytes(tmp_path / "unavailable", b"x")


def test_optional_file_errors_and_nonmapping_runtime_provenance(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class UnavailablePath:
        def open(self, _mode):
            raise OSError("unreadable")

        def stat(self):
            raise OSError("unstatable")

    unavailable = UnavailablePath()
    monkeypatch.setattr(diagnostic, "_private_log_exists", lambda _path: True)
    assert diagnostic._optional_file_digest(unavailable) is None
    assert diagnostic._optional_file_size(unavailable) is None

    manifest = replace(
        _manifest(tmp_path),
        metadata={"runtime_provenance": ["not", "a", "mapping"]},
    )
    assert diagnostic._system_provenance(manifest)["runtime_provenance"] == {}
