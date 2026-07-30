"""Hermetic branch coverage for competitor campaign preflight checks."""

from __future__ import annotations

import os
from pathlib import Path
from types import SimpleNamespace

import pytest

from core.benchmarks.competitors import preflight

pytestmark = [pytest.mark.unit, pytest.mark.benchmark]


def _manifest(
    base: Path,
    system_id: str,
    *,
    track: str = "framework_only",
    execution_mode: str = "replay",
    fairness_id: str = "fixture-fairness",
    model_name: str = "fixture-model",
    tool_version: str = "1.0",
    cwd: str = ".",
    argv: tuple[str, ...] = ("fixture-adapter",),
    env_passthrough: tuple[str, ...] = (),
    public_value: str = "complete",
):
    fairness = {
        "profile_id": fairness_id,
        "same_model": True,
        "same_tool_versions": True,
        "same_hardware": True,
        "same_budgets": True,
    }
    public = {
        "system_id": system_id,
        "metadata": {"configuration": public_value},
    }
    return SimpleNamespace(
        system_id=system_id,
        source_path=base / f"{system_id}.json",
        adapter=SimpleNamespace(
            cwd=cwd,
            argv=argv,
            env_passthrough=env_passthrough,
        ),
        track=track,
        execution_mode=execution_mode,
        fairness_profile=SimpleNamespace(to_dict=lambda: dict(fairness)),
        model={"provider": "fixture", "name": model_name},
        tool_versions={"fixture": tool_version},
        to_dict=lambda: dict(public),
    )


def _scenario(*, public_value: str = "complete"):
    payload = {
        "scenario_id": "fixture-scenario",
        "metadata": {"configuration": public_value},
    }
    return SimpleNamespace(
        scenario_id="fixture-scenario",
        to_dict=lambda: dict(payload),
    )


def _checks_by_id(report: preflight.PreflightReport):
    return {item.check_id: item for item in report.checks}


def test_campaign_preflight_passes_complete_inputs_without_executing_commands(
    tmp_path,
    monkeypatch,
) -> None:
    manifests = (
        _manifest(tmp_path, "alpha"),
        _manifest(tmp_path, "beta"),
    )
    secure_environment_file = tmp_path / "campaign.env"
    secure_environment_file.write_text("TOKEN=value\n", encoding="utf-8")
    secure_environment_file.chmod(0o600)

    monkeypatch.setattr(
        preflight,
        "_manifest_adapter_available",
        lambda _manifest, _environment: (tmp_path, True),
    )
    monkeypatch.setattr(
        preflight,
        "_environment_executable_available",
        lambda executable, _environment: executable == "fixture-tool",
    )
    monkeypatch.setattr(
        preflight,
        "command_executable_available",
        lambda command, _environment: command.available,
    )

    report = preflight.run_campaign_preflight(
        campaign_id="passing-campaign",
        output_directory=tmp_path / "new-publication",
        manifests=manifests,
        scenarios=(_scenario(),),
        required_environment=("TOKEN", "TOOL_BIN", "TOKEN"),
        environment={"TOKEN": "value", "TOOL_BIN": "fixture-tool"},
        reset_command=SimpleNamespace(available=True),
        health_command=SimpleNamespace(available=True),
        placeholder_inputs=(("campaign", {"configuration": ["complete"]}),),
        environment_file=secure_environment_file,
    )

    report.raise_for_failure()
    serialized = report.to_dict()
    checks = _checks_by_id(report)
    assert report.passed is True
    assert serialized["status"] == "passed"
    assert serialized["failed_check_count"] == 0
    assert serialized["check_count"] == len(report.checks)
    assert checks["required_environment"].detail == ("all_required_environment_present")
    assert checks["environment_executable:TOOL_BIN"].passed is True
    assert checks["environment_file_permissions"].detail == "private_mode"
    assert checks["completed_placeholders"].detail == "no_placeholders"


def test_campaign_preflight_collects_every_failure_before_raising(
    tmp_path,
    monkeypatch,
) -> None:
    existing_output = tmp_path / "existing-publication"
    existing_output.mkdir()
    manifest = _manifest(
        tmp_path,
        "incomplete",
        public_value="replace-with-version",
    )
    missing_cwd = tmp_path / "missing-cwd"

    monkeypatch.setattr(
        preflight,
        "_manifest_adapter_available",
        lambda _manifest, _environment: (missing_cwd, False),
    )
    monkeypatch.setattr(
        preflight,
        "_environment_executable_available",
        lambda _executable, _environment: False,
    )
    monkeypatch.setattr(
        preflight,
        "command_executable_available",
        lambda _command, _environment: False,
    )

    report = preflight.run_campaign_preflight(
        campaign_id="failing-campaign",
        output_directory=existing_output,
        manifests=(manifest,),
        scenarios=(),
        required_environment=(
            "MISSING",
            "OCTOBENCH_ACK_AUTHORIZED",
            "TOOL_BIN",
        ),
        environment={
            "OCTOBENCH_ACK_AUTHORIZED": "NO",
            "TOOL_BIN": "change-me",
        },
        reset_command=object(),
        health_command=object(),
        placeholder_inputs=(
            (
                "campaign",
                {"targets": ["https://authorized-target.invalid"]},
            ),
        ),
    )

    checks = _checks_by_id(report)
    assert report.passed is False
    assert checks["output_destination_new"].detail == "destination_exists"
    assert checks["minimum_systems"].passed is False
    assert checks["scenario_catalog"].passed is False
    assert checks["matrix_compatibility"].passed is False
    assert checks["required_environment"].detail == "missing:MISSING"
    assert checks["authorized_lab_acknowledgement"].detail == ("authorization_ack_required")
    assert checks["environment_executable:TOOL_BIN"].passed is False
    assert checks["adapter_cwd:incomplete"].passed is False
    assert checks["adapter_executable:incomplete"].passed is False
    assert checks["lab_reset_command"].passed is False
    assert checks["lab_health_command"].passed is False
    assert checks["completed_placeholders"].detail == (
        "placeholder_inputs:campaign,system:incomplete,environment:TOOL_BIN"
    )

    with pytest.raises(
        preflight.CampaignPreflightError,
        match="campaign_preflight_failed",
    ) as raised:
        report.raise_for_failure()
    assert raised.value.report is report
    assert report.to_dict()["failed_check_count"] == 12


def test_campaign_preflight_rejects_non_private_environment_file(
    tmp_path,
    monkeypatch,
) -> None:
    environment_file = tmp_path / "public.env"
    environment_file.write_text("TOKEN=value\n", encoding="utf-8")
    environment_file.chmod(0o644)
    manifests = (_manifest(tmp_path, "alpha"), _manifest(tmp_path, "beta"))
    monkeypatch.setattr(
        preflight,
        "_manifest_adapter_available",
        lambda _manifest, _environment: (tmp_path, True),
    )
    monkeypatch.setattr(
        preflight,
        "command_executable_available",
        lambda _command, _environment: True,
    )

    report = preflight.run_campaign_preflight(
        campaign_id="public-environment-file",
        output_directory=tmp_path / "publication",
        manifests=manifests,
        scenarios=(_scenario(),),
        required_environment=(),
        environment={},
        reset_command=object(),
        health_command=object(),
        environment_file=environment_file,
    )

    assert _checks_by_id(report)["environment_file_permissions"].detail == ("environment_file_not_private")


def test_manifest_adapter_rejects_escape_missing_cwd_and_placeholder(
    tmp_path,
) -> None:
    base = tmp_path / "manifests"
    base.mkdir()

    escaped_cwd, escaped_available = preflight._manifest_adapter_available(
        _manifest(base, "escaped", cwd="../outside"),
        {},
    )
    assert escaped_cwd == (tmp_path / "outside").resolve()
    assert escaped_available is False

    missing_cwd, missing_available = preflight._manifest_adapter_available(
        _manifest(base, "missing", cwd="missing"),
        {},
    )
    assert missing_cwd == (base / "missing").resolve()
    assert missing_available is False

    placeholder_cwd, placeholder_available = preflight._manifest_adapter_available(
        _manifest(base, "placeholder", argv=("{adapter_path}",)),
        {},
    )
    assert placeholder_cwd == base.resolve()
    assert placeholder_available is False


def test_manifest_adapter_resolves_absolute_relative_and_path_executables(
    tmp_path,
    monkeypatch,
) -> None:
    base = tmp_path / "manifests"
    binary_directory = base / "bin"
    binary_directory.mkdir(parents=True)
    absolute_executable = tmp_path / "absolute-adapter"
    relative_executable = binary_directory / "relative-adapter"
    absolute_executable.write_text("fixture", encoding="utf-8")
    relative_executable.write_text("fixture", encoding="utf-8")
    monkeypatch.setattr(preflight.os, "access", lambda _path, _mode: True)

    assert preflight._manifest_adapter_available(
        _manifest(base, "absolute", argv=(str(absolute_executable),)),
        {},
    ) == (base.resolve(), True)
    assert preflight._manifest_adapter_available(
        _manifest(base, "relative", argv=("bin/relative-adapter",)),
        {},
    ) == (base.resolve(), True)

    which_calls = []

    def fake_which(executable, *, path):
        which_calls.append((executable, path))
        return "/resolved/fixture-adapter"

    monkeypatch.setattr(preflight.shutil, "which", fake_which)
    assert preflight._manifest_adapter_available(
        _manifest(
            base,
            "path-passthrough",
            env_passthrough=("PATH",),
        ),
        {"PATH": "/fixture/path"},
    ) == (base.resolve(), True)
    assert preflight._manifest_adapter_available(
        _manifest(base, "default-path"),
        {"PATH": "/ignored/path"},
    ) == (base.resolve(), True)
    assert which_calls == [
        ("fixture-adapter", "/fixture/path"),
        ("fixture-adapter", os.defpath),
    ]


def test_environment_executable_resolution_is_hermetic(tmp_path, monkeypatch) -> None:
    executable = tmp_path / "fixture-tool"
    executable.write_text("fixture", encoding="utf-8")
    monkeypatch.setattr(preflight.os, "access", lambda _path, _mode: True)

    assert preflight._environment_executable_available("", {}) is False
    assert preflight._environment_executable_available("bad\x00name", {}) is False
    assert preflight._environment_executable_available(str(executable), {}) is True

    calls = []

    def fake_which(name, *, path):
        calls.append((name, path))
        return "/resolved/tool" if name == "available" else None

    monkeypatch.setattr(preflight.shutil, "which", fake_which)
    environment = {"PATH": "/fixture/path"}
    assert preflight._environment_executable_available("available", environment)
    assert not preflight._environment_executable_available("missing", environment)
    assert calls == [
        ("available", "/fixture/path"),
        ("missing", "/fixture/path"),
    ]


def test_placeholder_detection_traverses_strings_mappings_and_sequences() -> None:
    assert preflight._contains_placeholder(" Change-Me ") is True
    assert preflight._contains_placeholder({"configuration": ["your-key-here"]}) is True
    assert preflight._contains_placeholder({"replace-with-name": "complete"}) is True
    assert preflight._contains_placeholder("complete") is False
    assert preflight._contains_placeholder(["complete", 1]) is False
    assert preflight._contains_placeholder(b"change-me") is False
    assert preflight._contains_placeholder(object()) is False


def test_matrix_compatibility_covers_all_contract_dimensions(tmp_path) -> None:
    alpha = _manifest(tmp_path, "alpha")
    beta = _manifest(tmp_path, "beta")
    assert preflight._matrix_inputs_compatible((alpha, beta)) is True
    assert preflight._matrix_inputs_compatible((alpha,)) is False

    incompatible_pairs = (
        (alpha, _manifest(tmp_path, "track", track="blackbox")),
        (alpha, _manifest(tmp_path, "mode", execution_mode="live")),
        (alpha, _manifest(tmp_path, "fairness", fairness_id="other")),
        (alpha, _manifest(tmp_path, "model", model_name="other")),
        (alpha, _manifest(tmp_path, "tools", tool_version="2.0")),
    )
    assert all(not preflight._matrix_inputs_compatible(pair) for pair in incompatible_pairs)

    blackbox = (
        _manifest(tmp_path, "blackbox-alpha", track="blackbox"),
        _manifest(
            tmp_path,
            "blackbox-beta",
            track="blackbox",
            model_name="different-model",
            tool_version="different-tool-version",
        ),
    )
    assert preflight._matrix_inputs_compatible(blackbox) is True
