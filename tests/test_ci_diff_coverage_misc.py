"""Hermetic regression coverage for CI-only changed-line branches."""

from __future__ import annotations

import json
import os
import subprocess
import types
import zipfile
from pathlib import Path, PurePosixPath

import pytest

from core.actions.adapters import RegisteredToolAdapter
from core.actions.models import ActionRequest
from core.ai.parsers import IntelligenceParser
from core.c2 import builder
from core.execution.models import ExecutionContext, contains_sensitive_command_material
from core.opsec.artifact_mgr import ArtifactManager
from core.tools.registry import get_tool
from core.tools.targeting import canonical_check_url
from scripts.quality import verify_vendor, wheel_smoke

pytestmark = [pytest.mark.unit, pytest.mark.security]


def test_builder_windows_state_paths_are_portable(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    local_state = tmp_path / "local-state"
    os_proxy = types.SimpleNamespace(
        environ={"LOCALAPPDATA": str(local_state)},
        name="nt",
        path=os.path,
    )
    monkeypatch.setattr(builder, "os", os_proxy)

    assert builder._runtime_data_dir() == str(local_state / "Octopus")

    os_proxy.environ.clear()
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    assert builder._runtime_data_dir() == str(tmp_path / "home" / "AppData" / "Local" / "Octopus")


@pytest.mark.parametrize(
    ("payload", "message"),
    (
        ([], "fields"),
        ({"schema_version": 1}, "fields"),
        ({"schema_version": 2, "go": "go1.21.13", "garble": "v0.12.1"}, "schema"),
        ({"schema_version": 1, "go": 12113, "garble": "v0.12.1"}, "Go version"),
        ({"schema_version": 1, "go": "1.21.13", "garble": "v0.12.1"}, "Go version"),
        ({"schema_version": 1, "go": "go1.21.13", "garble": 121}, "Garble version"),
        ({"schema_version": 1, "go": "go1.21.13", "garble": "0.12.1"}, "Garble version"),
    ),
)
def test_builder_rejects_malformed_toolchain_contracts(
    tmp_path: Path,
    payload: object,
    message: str,
) -> None:
    (tmp_path / "toolchain.json").write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(RuntimeError, match=message):
        builder._load_toolchain_contract(str(tmp_path))


@pytest.mark.parametrize(
    ("failure", "detail"),
    (
        (subprocess.CalledProcessError(1, ["go"], stderr="probe stderr"), "probe stderr"),
        (subprocess.CalledProcessError(1, ["go"], output="probe stdout"), "probe stdout"),
        (subprocess.CalledProcessError(1, ["go"]), "version probe failed"),
    ),
)
def test_builder_reports_toolchain_probe_failures_without_leaking_arguments(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    failure: subprocess.CalledProcessError,
    detail: str,
) -> None:
    monkeypatch.setenv("OCTOPUS_DATA_DIR", str(tmp_path / "state"))
    monkeypatch.setattr(builder, "load_server_pub_key", lambda _path: "server-public")
    monkeypatch.setattr(builder, "encrypt_config", lambda *_args: ("encrypted", "a" * 64))

    def fail_probe(_module_dir: str, _env: dict[str, str]) -> tuple[str, str]:
        raise failure

    monkeypatch.setattr(builder, "_verify_toolchain", fail_probe)

    with pytest.raises(SystemExit, match="1"):
        builder.build_implant(enrollment_token="fixture-token")

    output = capsys.readouterr().out
    assert detail in output
    assert "fixture-token" not in output
    assert "encrypted" not in output


def test_intelligence_parser_bounds_references_and_tolerates_invalid_urls() -> None:
    parser = IntelligenceParser()
    invalid = parser.parse("web_search", "https://[invalid", "session")
    assert invalid == []

    urls = " ".join(f"https://host{index}.example.test/path" for index in range(51))
    cves = " ".join(f"CVE-2026-{1000 + index}" for index in range(51))
    facts = parser.parse("web_search", f"{urls}\n{cves}", "session")

    assert sum(item["type"] == "external_reference" for item in facts) == 50
    assert sum(item["type"] == "external_cve_reference" for item in facts) == 50


@pytest.mark.parametrize(
    ("argv", "expected"),
    (
        (("/usr/bin/sshpass",), True),
        (("killchain_full", "target", "user", "opaque"), True),
        (("curl", "--user=opaque", "https://example.test"), True),
        (("docker", "login", "--password-stdin"), True),
        (("mysql", "-popaque"), True),
        (("ssh", "-oIdentityFile=/tmp/key", "host"), True),
        (("rpcclient", "-U", "user"), True),
        (("curl", "--head", "https://example.test"), False),
        (("docker", "run", "fixture"), False),
        (("mysql", "--host", "database.example.test"), False),
        (("ssh", "host"), False),
        (("rpcclient", "--help"), False),
    ),
)
def test_sensitive_command_detector_covers_typed_argv_consumers(
    argv: tuple[str, ...],
    expected: bool,
) -> None:
    assert contains_sensitive_command_material("safe-command", argv=argv) is expected


def test_sensitive_command_detector_handles_empty_and_unparseable_text() -> None:
    assert not contains_sensitive_command_material("")
    assert not contains_sensitive_command_material("'unterminated")


def test_registered_adapter_fails_closed_when_availability_probe_errors() -> None:
    def unavailable() -> object:
        raise OSError("fixture probe failure")

    tool_def = types.SimpleNamespace(
        name="fixture",
        aliases=(),
        category="recon",
        description="fixture",
        requires=("fixture-binary",),
        needs_target=False,
        enabled=True,
        availability=unavailable,
        dependency_manifest=lambda: {"kind": "binary", "name": "fixture-binary"},
    )
    adapter = RegisteredToolAdapter(tool_def, lambda *_args: "must not run")

    result = adapter.applicability(ActionRequest("", ExecutionContext.automatic()))

    assert not result.applicable
    assert result.missing_requirements == ("dependency:fixture-binary",)


@pytest.mark.parametrize(
    ("value", "expected"),
    (
        ("HTTP://Example.Test:80/path", "http://example.test/path"),
        ("https://Example.Test:443/", "https://example.test"),
        ("https://Example.Test:8443/path?q=1", "https://example.test:8443/path?q=1"),
    ),
)
def test_canonical_check_url_normalizes_default_and_explicit_ports(
    value: str,
    expected: str,
) -> None:
    assert canonical_check_url(value) == expected


def test_artifact_manager_tracks_and_cleans_one_inserted_line(tmp_path: Path) -> None:
    database = tmp_path / "artifacts.sqlite"
    manager = ArtifactManager(str(database), target_ip="192.0.2.10")
    other = ArtifactManager(str(database), target_ip="192.0.2.11")

    manager.record_file_line("/etc/fixture", "octopus:fixture", user="alice")
    other.record_file_line("/etc/fixture", "octopus:fixture", user="bob")
    tracked = manager.get_pending_cleanups()

    assert len(tracked) == 1
    assert tracked[0]["artifact_type"] == "file_line"
    assert tracked[0]["user"] == "alice"

    manager.mark_cleaned_by_id(tracked[0]["artifact_id"])
    assert manager.get_pending_cleanups() == []
    assert len(other.get_pending_cleanups()) == 1


def test_quarantined_provider_stub_remains_fail_closed() -> None:
    definition = get_tool("pth")

    assert definition is not None
    assert definition.enabled is False
    assert definition.func is not None
    assert definition.func() == "[!] Execution denied: unsafe_provider_contract_not_mounted"


@pytest.mark.parametrize(
    ("submodules", "artifacts", "message"),
    (
        ({}, [], "submodules must be a list"),
        ([], {}, "artifacts must be a list"),
        ([], [{}], "submodules must be non-empty"),
        ([{}], [], "artifacts must be non-empty"),
    ),
)
def test_vendor_manifest_rejects_mismatched_inventory_shapes(
    tmp_path: Path,
    submodules: object,
    artifacts: object,
    message: str,
) -> None:
    manifest = tmp_path / "vendor-manifest.json"
    manifest.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "submodules": submodules,
                "artifacts": artifacts,
            }
        ),
        encoding="utf-8",
    )

    with pytest.raises(verify_vendor.VendorVerificationError, match=message):
        verify_vendor.load_manifest(manifest)


def test_vendor_manifest_reports_missing_and_unknown_keys() -> None:
    with pytest.raises(verify_vendor.VendorVerificationError, match="invalid keys") as raised:
        verify_vendor._require_exact_keys({"unknown": True}, {"required"}, "fixture")

    assert "required" in str(raised.value)
    assert "unknown" in str(raised.value)


def test_vendor_gate_rejects_platform_without_an_approved_artifact(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    manifest_path = tmp_path / "vendor-manifest.json"
    manifest_path.write_text("{}", encoding="utf-8")
    manifest = verify_vendor.VendorManifest(
        submodules=(verify_vendor.SubmoduleSpec(PurePosixPath("vendor/tool"), "a" * 40),),
        artifacts=(
            verify_vendor.ArtifactSpec(
                PurePosixPath("vendor/tool/bin/tool"),
                PurePosixPath("vendor/tool"),
                "linux",
                "amd64",
                "b" * 64,
            ),
        ),
    )
    monkeypatch.setattr(verify_vendor, "load_manifest", lambda _path: manifest)
    monkeypatch.setattr(verify_vendor, "_verify_submodule", lambda *_args, **_kwargs: None)

    with pytest.raises(verify_vendor.VendorVerificationError, match="no approved artifacts"):
        verify_vendor.verify_repository(
            tmp_path,
            manifest_path,
            platform_selector="darwin/arm64",
        )


def _write_wheel(path: Path, names: set[str]) -> None:
    with zipfile.ZipFile(path, mode="w") as archive:
        for name in names:
            payload = (
                "Metadata-Version: 2.1\nName: octopus-security\nVersion: 1.0.0\n"
                if name.endswith(".dist-info/METADATA")
                else "{}"
            )
            archive.writestr(name, payload)


def test_wheel_gate_reports_missing_portable_systemd_unit(tmp_path: Path) -> None:
    wheel = tmp_path / "missing-service.whl"
    _write_wheel(wheel, {"octopus_security-1.0.0.dist-info/METADATA"})

    with pytest.raises(wheel_smoke.WheelSmokeError, match="systemd_service_count=0"):
        wheel_smoke.validate_wheel(wheel)


def test_wheel_gate_rejects_nonportable_installed_transport(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    wheel = tmp_path / "transport.whl"
    names = {
        "config.yaml",
        "benchmarks/results/noop-repeat-comparison-v1.json",
        "benchmarks/competitors/labs/discovery-lab-v3/Dockerfile",
        "benchmarks/competitors/labs/discovery-lab-v3/Dockerfile.dockerignore",
        "benchmarks/competitors/labs/discovery-lab-v3/app.py",
        "benchmarks/competitors/labs/discovery-lab-v3/compose.yaml",
        "core/benchmarks/v3/fixture.py",
        "core/benchmarks/v3/publication.py",
        "octopus_security-1.0.0.dist-info/METADATA",
        "octopus_security-1.0.0.data/data/share/octopus-security/systemd/octopus-c2.service",
        *wheel_smoke._REQUIRED_WHEEL_RESOURCES,
        *(f"benchmarks/scenarios/{index}.json" for index in range(10)),
    }
    _write_wheel(wheel, names)

    class FakeBuilder:
        def __init__(self, **_kwargs: object) -> None:
            pass

        def create(self, _environment: Path) -> None:
            pass

    def fake_run(argv: list[str], **_kwargs: object) -> str:
        if "-c" not in argv:
            return ""
        code = argv[argv.index("-c") + 1]
        if "find_spec('config')" in code:
            return "config.yaml\n"
        if "OpsecClient" in code:
            return "UnexpectedTransport\n"
        raise AssertionError(f"unexpected command: {argv}")

    monkeypatch.setattr(wheel_smoke.venv, "EnvBuilder", FakeBuilder)
    monkeypatch.setattr(wheel_smoke, "_run", fake_run)

    with pytest.raises(wheel_smoke.WheelSmokeError, match="installed_opsec_default_not_portable"):
        wheel_smoke.validate_wheel(wheel)
