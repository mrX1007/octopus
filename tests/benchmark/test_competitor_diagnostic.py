from __future__ import annotations

import json
import os
import stat
import sys
from pathlib import Path

import pytest

from core.benchmarks.competitors import adapter, diagnostic, diagnostic_worker
from core.benchmarks.competitors.campaign import CampaignConfig
from core.benchmarks.competitors.lab import LabCommand
from core.benchmarks.competitors.schema import SystemManifest
from core.benchmarks.schema import load_scenario

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
SCENARIO_PATH = (
    REPOSITORY_ROOT
    / "benchmarks"
    / "competitors"
    / "campaigns"
    / "linux-blackbox-v1"
    / "scenarios"
    / "authorized-discovery-v1.json"
)


def _manifest(tmp_path: Path, system_id: str) -> SystemManifest:
    source = tmp_path / f"{system_id}.json"
    source.write_text("{}\n", encoding="utf-8")
    return SystemManifest.from_dict(
        {
            "schema_version": "1.0",
            "system_id": system_id,
            "name": system_id.title(),
            "version": "v1.0.0",
            "source_revision": "a" * 40,
            "execution_mode": "live",
            "track": "full_system",
            "fairness_profile": {
                "profile_id": "diagnostic-fixture",
                "same_model": True,
                "same_tool_versions": False,
                "same_hardware": True,
                "same_budgets": False,
            },
            "model": {
                "provider": "ollama",
                "name": "fixture",
                "parameters": {},
            },
            "tool_versions": {system_id: "v1.0.0"},
            "adapter": {
                "kind": "command",
                "argv": [
                    sys.executable,
                    str(tmp_path / "adapter.py"),
                    "{scenario_path}",
                    "{output_path}",
                ],
                "working_directory": ".",
                "environment_passthrough": [],
            },
        },
        source_path=source,
    )


def _config(tmp_path: Path, manifests: tuple[SystemManifest, ...]) -> CampaignConfig:
    command = LabCommand(argv=(sys.executable, "-c", "pass"), working_directory=tmp_path)
    return CampaignConfig(
        campaign_id="diagnostic-fixture-v1",
        system_manifest_paths=tuple(
            item.source_path for item in manifests if item.source_path is not None
        ),
        scenario_directory=SCENARIO_PATH.parent,
        output_directory=tmp_path / "unused-results",
        state_directory=tmp_path / "unused-state",
        repetitions=6,
        reset_command=command,
        health_command=command,
        cleanup_command=command,
    )


def test_private_pilot_runs_once_per_system_without_publication(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manifests = (_manifest(tmp_path, "octopus"), _manifest(tmp_path, "strix"))
    config = _config(tmp_path, manifests)
    scenario = load_scenario(SCENARIO_PATH)
    observed: dict[str, list[object]] = {"reset": [], "cleanup": [], "budgets": []}

    monkeypatch.setattr(
        diagnostic,
        "load_system_manifest",
        lambda path: next(item for item in manifests if item.source_path == path),
    )
    monkeypatch.setattr(diagnostic, "load_scenarios", lambda _path: (scenario,))

    class FakeController:
        def __init__(self, *_args, **_kwargs):
            return None

        def reset_and_health(self, context):
            observed["reset"].append(context)

        def cleanup(self, context):
            observed["cleanup"].append(context)

    class FakeRunner:
        def __init__(self, manifest, *, private_log_path):
            self.manifest = manifest
            self.private_log_path = Path(private_log_path)

        def __call__(self, selected_scenario, repetition, seed):
            observed["budgets"].append(selected_scenario.budgets["max_seconds"])
            self.private_log_path.write_bytes(b"private adapter diagnostic\n")
            self.private_log_path.chmod(0o600)
            product = Path(os.environ["OCTOBENCH_DIAGNOSTIC_PRODUCT_LOG"])
            product.write_bytes(b"private product diagnostic\n")
            product.chmod(0o600)
            assert repetition == 1
            assert seed == scenario.seed
            return {
                "status": "succeeded",
                "duration_seconds": 12.5,
                "error_class": "",
            }

    monkeypatch.setattr(diagnostic, "CommandLabController", FakeController)
    monkeypatch.setattr(diagnostic, "CommandSystemRunner", FakeRunner)

    outcome = diagnostic.run_diagnostic_pilot(
        config,
        environment={"PATH": os.environ.get("PATH", "")},
        root=tmp_path / "diagnostics",
        budget_seconds=1_800,
    )

    payload = json.loads(outcome.summary_path.read_text(encoding="utf-8"))
    assert outcome.status == "succeeded"
    assert outcome.exit_code == 0
    assert payload["publishable"] is False
    assert payload["purpose"] == "runtime_calibration"
    assert payload["scenario_scope"] == "smoke_only"
    assert payload["budget_seconds"] == 1_800.0
    assert len(payload["runs"]) == 2
    assert {item["system_id"] for item in payload["runs"]} == {
        "octopus",
        "strix",
    }
    assert observed["budgets"] == [1_800.0, 1_800.0]
    assert len(observed["reset"]) == len(observed["cleanup"]) == 2
    assert all(item["reset_healthy"] is True for item in payload["runs"])
    assert all(item["adapter_log_bytes"] > 0 for item in payload["runs"])
    assert all(item["product_log_bytes"] > 0 for item in payload["runs"])
    assert all(item["adapter_wall_seconds"] >= 0 for item in payload["runs"])
    assert all(item["lifecycle_wall_seconds"] >= 0 for item in payload["runs"])
    assert {item["system"]["version"] for item in payload["runs"]} == {"v1.0.0"}
    assert stat.S_IMODE(outcome.summary_path.stat().st_mode) == 0o600
    for path in outcome.summary_path.parent.rglob("*.log"):
        assert stat.S_IMODE(path.stat().st_mode) == 0o600
        assert str(path) not in json.dumps(payload)


def test_pilot_budget_override_preserves_scenario_schema_repetitions(
    tmp_path: Path,
) -> None:
    scenario = load_scenario(SCENARIO_PATH)

    calibrated = diagnostic._with_budget(scenario, 1_800)
    materialized = tmp_path / "scenario.json"
    materialized.write_text(
        json.dumps(calibrated.to_dict()) + "\n",
        encoding="utf-8",
    )
    reloaded = load_scenario(materialized)

    assert reloaded.repetitions == scenario.repetitions
    assert reloaded.repetitions >= 5
    assert reloaded.budgets["max_seconds"] == 1_800


def test_pilot_can_select_one_system_and_rejects_unsafe_budget(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manifests = (_manifest(tmp_path, "octopus"), _manifest(tmp_path, "strix"))
    config = _config(tmp_path, manifests)
    monkeypatch.setattr(
        diagnostic,
        "load_system_manifest",
        lambda path: next(item for item in manifests if item.source_path == path),
    )
    monkeypatch.setattr(
        diagnostic,
        "load_scenarios",
        lambda _path: (load_scenario(SCENARIO_PATH),),
    )

    class FakeController:
        def __init__(self, *_args, **_kwargs):
            return None

        def reset_and_health(self, _context):
            return None

        def cleanup(self, _context):
            return None

    class FailedRunner:
        def __init__(self, _manifest, *, private_log_path):
            self.private_log_path = Path(private_log_path)

        def __call__(self, _scenario, _repetition, _seed):
            self.private_log_path.write_bytes(b"failure\n")
            self.private_log_path.chmod(0o600)
            return {
                "status": "failed",
                "duration_seconds": 2.0,
                "error_class": "ProductExitCode1",
            }

    monkeypatch.setattr(diagnostic, "CommandLabController", FakeController)
    monkeypatch.setattr(diagnostic, "CommandSystemRunner", FailedRunner)

    outcome = diagnostic.run_diagnostic_pilot(
        config,
        environment={"PATH": os.environ.get("PATH", "")},
        root=tmp_path / "diagnostics",
        budget_seconds=120,
        selected_system="strix",
    )
    payload = json.loads(outcome.summary_path.read_text(encoding="utf-8"))
    assert outcome.exit_code == 1
    assert [item["system_id"] for item in payload["runs"]] == ["strix"]
    assert payload["runs"][0]["error_class"] == "ProductExitCode1"

    with pytest.raises(diagnostic.DiagnosticError, match="diagnostic_budget_invalid"):
        diagnostic.run_diagnostic_pilot(
            replace_campaign_id(config, "invalid-budget"),
            environment={},
            root=tmp_path / "other-diagnostics",
            budget_seconds=59,
        )


def test_cleanup_failure_is_nonzero_and_partial_destination_is_not_reused(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manifest = _manifest(tmp_path, "strix")
    config = _config(tmp_path, (manifest,))
    scenario = load_scenario(SCENARIO_PATH)
    monkeypatch.setattr(diagnostic, "load_system_manifest", lambda _path: manifest)
    monkeypatch.setattr(diagnostic, "load_scenarios", lambda _path: (scenario,))

    class CleanupFails:
        def __init__(self, *_args, **_kwargs):
            return None

        def reset_and_health(self, _context):
            return None

        def cleanup(self, _context):
            raise RuntimeError("private cleanup detail")

    class SuccessfulRunner:
        def __init__(self, _manifest, *, private_log_path):
            self.private_log_path = Path(private_log_path)

        def __call__(self, _scenario, _repetition, _seed):
            self.private_log_path.write_bytes(b"adapter\n")
            self.private_log_path.chmod(0o600)
            return {
                "status": "succeeded",
                "duration_seconds": 1.0,
                "error_class": "",
            }

    monkeypatch.setattr(diagnostic, "CommandLabController", CleanupFails)
    monkeypatch.setattr(diagnostic, "CommandSystemRunner", SuccessfulRunner)
    root = tmp_path / "diagnostics"
    outcome = diagnostic.run_diagnostic_pilot(
        config,
        environment={},
        root=root,
        budget_seconds=120,
        selected_system="strix",
    )
    payload = json.loads(outcome.summary_path.read_text(encoding="utf-8"))
    assert outcome.exit_code == 1
    assert payload["status"] == "completed_with_failures"
    assert payload["cleanup_status"] == "failed"
    assert payload["runs"][0]["status"] == "succeeded"
    assert payload["runs"][0]["cleanup_status"] == "failed"
    assert "private cleanup detail" not in json.dumps(payload)

    partial = root / "interrupted-v1"
    partial.mkdir(mode=0o700)
    (partial / "stale.log").write_text("stale\n", encoding="utf-8")
    with pytest.raises(
        diagnostic.DiagnosticError,
        match="diagnostic_destination_exists",
    ):
        diagnostic.run_diagnostic_pilot(
            replace_campaign_id(config, "interrupted-v1"),
            environment={},
            root=root,
            budget_seconds=120,
            selected_system="strix",
        )


def test_diagnostic_worker_captures_only_bounded_private_product_output(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    private = tmp_path / "private"
    private.mkdir(mode=0o700)
    product_log = diagnostic_worker._initialize_private_log(
        str(private / "product.log")
    )
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    payload = b"private-product-detail" * 100

    def bounded_process(*_args, **kwargs):
        (Path(kwargs["cwd"]) / "adapter-stdout.log").write_bytes(payload)
        return 1, False, False, "publicly-scrubbed", 1.0

    def run_product(_system, _scenario):
        adapter._run_bounded_process(
            ["unused"],
            cwd=workspace,
            environment={},
            timeout=1.0,
            max_output=17,
        )
        return {"status": "failed", "error_class": "ProductExitCode1"}

    monkeypatch.setattr(adapter, "_run_bounded_process", bounded_process)
    monkeypatch.setattr(adapter, "run_product_adapter", run_product)

    result = diagnostic_worker._run_with_private_capture(
        "strix",
        object(),
        product_log,
    )

    assert result["error_class"] == "ProductExitCode1"
    assert product_log.read_bytes() == payload[:17]
    assert stat.S_IMODE(product_log.stat().st_mode) == 0o600


def test_diagnostic_worker_rejects_unsafe_parent_and_final_symlink(
    tmp_path: Path,
) -> None:
    unsafe = tmp_path / "unsafe"
    unsafe.mkdir(mode=0o755)
    with pytest.raises(
        diagnostic_worker.DiagnosticWorkerError,
        match="private_log_parent_unsafe",
    ):
        diagnostic_worker._initialize_private_log(str(unsafe / "product.log"))

    private = tmp_path / "private"
    private.mkdir(mode=0o700)
    target = private / "target.log"
    target.write_bytes(b"do-not-overwrite")
    link = private / "product.log"
    link.symlink_to(target)
    with pytest.raises(
        diagnostic_worker.DiagnosticWorkerError,
        match="private_log_unavailable",
    ):
        diagnostic_worker._initialize_private_log(str(link))
    assert target.read_bytes() == b"do-not-overwrite"


def test_operator_interrupt_still_writes_private_summary_and_cleans_up(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manifest = _manifest(tmp_path, "strix")
    config = _config(tmp_path, (manifest,))
    monkeypatch.setattr(diagnostic, "load_system_manifest", lambda _path: manifest)
    monkeypatch.setattr(
        diagnostic,
        "load_scenarios",
        lambda _path: (load_scenario(SCENARIO_PATH),),
    )
    cleanup_calls: list[object] = []

    class Controller:
        def __init__(self, *_args, **_kwargs):
            return None

        def reset_and_health(self, _context):
            return None

        def cleanup(self, context):
            cleanup_calls.append(context)

    class InterruptedRunner:
        def __init__(self, _manifest, *, private_log_path):
            self.private_log_path = Path(private_log_path)

        def __call__(self, _scenario, _repetition, _seed):
            self.private_log_path.write_bytes(b"interrupted\n")
            self.private_log_path.chmod(0o600)
            raise KeyboardInterrupt

    monkeypatch.setattr(diagnostic, "CommandLabController", Controller)
    monkeypatch.setattr(diagnostic, "CommandSystemRunner", InterruptedRunner)

    outcome = diagnostic.run_diagnostic_pilot(
        config,
        environment={},
        root=tmp_path / "diagnostics",
        budget_seconds=120,
        selected_system="strix",
    )
    payload = json.loads(outcome.summary_path.read_text(encoding="utf-8"))
    assert outcome.exit_code == 130
    assert payload["status"] == "interrupted"
    assert payload["runs"][0]["status"] == "interrupted"
    assert payload["runs"][0]["error_class"] == "OperatorInterrupt"
    assert len(cleanup_calls) == 1


def replace_campaign_id(config: CampaignConfig, campaign_id: str) -> CampaignConfig:
    from dataclasses import replace

    return replace(config, campaign_id=campaign_id)
